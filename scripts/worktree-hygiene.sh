#!/usr/bin/env bash
# Worktree hygiene loop body -- see the bootstrap doc's worktree-hygiene
# section for WHEN this runs (60m cron) and WHY it's auto-run instead of
# approval-gated. This file is the WHAT: the mechanical STEP A-E body,
# extracted out of that doc so a routine hygiene tick no longer costs an
# orchestrator model turn parsing `ps`/`git` output by hand.
#
# STEP A: kill host-side `u7s-apiserver`/`u7s-scheduler`/`konnectivity-server`/
#   `sample-run-metrics.sh` processes left running after their worktree was
#   removed. `git worktree remove` does not touch these -- all four are plain
#   backgrounded (or disowned) host processes that outlive their worktree.
#   apiserver/scheduler/konnectivity-server keep squatting on that VM slot's
#   ports and serve a stale CA-signed cert that breaks the next dispatch to
#   that slot with a cert-verification error instead of a clean port-bind
#   error; an orphaned sample-run-metrics.sh instead keeps polling that VM's
#   RSS/free-memory metrics indefinitely, invisible resource use on a slot
#   that then looks free to the next dispatch. `kubelet`/`kube-controller-manager`
#   need no host-side handling -- they run guest-side inside the Lima VM and
#   die with it. Binary-path matching doesn't work here: every worker's
#   binary builds into the same shared `target/` path, so processes are
#   matched on the worktree-specific argument instead (the
#   `.../temp/u7s/kubeconfig` path for apiserver/scheduler, the `.../temp/u7s`
#   workdir path for konnectivity-server and sample-run-metrics.sh).
# STEP B: `git worktree prune -v` -- safe by definition, only removes
#   metadata for worktrees whose directories are already gone.
# STEP C: delete stale `worker/agent-*` branches, guarded so an in-flight
#   worker's branch (checked out in some worktree, or with a live worktree
#   directory even if currently checked out elsewhere), any branch unmerged
#   by patch-id (catches squash-merges too, which `git branch --merged`
#   would miss), and any branch with an open PR (patch-id alone can't see
#   this: a PR's commits can reach main via a DIFFERENT PR while the
#   original stays open, and force-deleting that branch auto-closes it,
#   destroying review state) are never touched.
# STEP D: delete non-worker branches whose tracked upstream is gone, via
#   `-d` (refuses anything unmerged -- an extra safety net on top of D's
#   own scope, which never matches branches with no upstream at all), guarded
#   by the same in-flight check STEP C uses so a branch still checked out in
#   a live worktree is skipped rather than erroring the whole run when git
#   refuses to delete it.
# STEP E: warn (never delete) about tracked ai/findings/*.md files whose
#   `Bead:` header is closed or absent from LIVE bd state -- the drift
#   backstop for check-findings-closed-bead-refs.sh's CI-side check, which
#   can only see the git-tracked bd export and so misses a bead closed
#   since the export's last commit, or pruned after closing.
#
# Exit codes: 0 = clean tick, nothing found. Non-zero = an anomaly for the
# mayor to look at -- currently only STEP A's kill-verify failure (a process
# that survives its kill signal may be zombied/reparented and needs manual
# investigation, not an automatic retry); STEP B-D failures surface via this
# script's own `set -e` (a `git fetch`/`branch` failure aborts the run with
# git's exit code, which is itself already non-zero). STEP E never
# contributes to the exit code -- it only reports, it never mutates.
#
# DRY_RUN=1 turns every destructive command (pkill, git branch -D/-d) into a
# logged no-op via run_cmd() -- same idiom the sibling merge/dashboard
# script uses for its own dry-run gate -- so this script's test suite
# (scripts/test-worktree-hygiene-logic.sh) never kills a real process or
# deletes a real branch.
#
# Testability: `worktree-hygiene.sh __call <fn> [args...]` invokes a single
# function from this file and exits, the same convention used across
# scripts/ for exercising real logic (not a reimplementation) from tests.
set -euo pipefail

REPO_ROOT="${WORKTREE_HYGIENE_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

run_cmd() {
  if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "[dry-run] would run: $*"
  else
    "$@"
  fi
}

# ---------------------------------------------------------------------------
# STEP A -- orphaned host processes.
# ---------------------------------------------------------------------------

# Which of the four tracked process types (if any) a `ps aux` line
# belongs to.
proc_type_from_psline() {
  case "$1" in
    *u7s-apiserver*) printf 'apiserver' ;;
    *u7s-scheduler*) printf 'scheduler' ;;
    *konnectivity-server*) printf 'konnectivity-server' ;;
    *sample-run-metrics.sh*) printf 'sample-run-metrics' ;;
    *) printf '' ;;
  esac
}

# The worktree root path embedded in a process's command line. Apiserver/
# scheduler pass `--kubeconfig <path>/temp/u7s/kubeconfig` (space-
# separated, see scripts/u7s-start.sh); konnectivity-server's flags are
# `=`-joined instead, e.g. `--server-cert=<path>/temp/u7s/...`. Excluding
# `=` (not just space) from the greedy match is what stops the extracted
# path from leaking the `--server-cert=` prefix into the result for that
# second style -- both contain `/temp/u7s` as a substring with the
# worktree root immediately before it, so one extraction covers both
# argument styles and all four process types.
extract_worktree_path_from_psline() {
  printf '%s' "$1" | grep -oE '[^ =]*/temp/u7s' | head -1 | sed -E 's#/temp/u7s$##'
}

pid_from_psline() {
  printf '%s' "$1" | awk '{print $2}'
}

# Cross-references candidate process lines (pre-filtered `ps aux` output)
# against the live-worktree path list and emits one
# `pid|proc_type|dead_worktree_path` record per orphan: a process whose
# embedded worktree path is no longer in the live set. Pure text
# processing, so the test suite can feed synthetic `ps`/worktree-list
# output instead of needing real orphaned processes on the test machine.
find_orphans() {
  local ps_output="$1" live_worktrees="$2"
  local line ptype wpath pid
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    ptype=$(proc_type_from_psline "$line")
    [ -n "$ptype" ] || continue
    wpath=$(extract_worktree_path_from_psline "$line")
    [ -n "$wpath" ] || continue
    if ! printf '%s\n' "$live_worktrees" | grep -qxF "$wpath"; then
      pid=$(pid_from_psline "$line")
      printf '%s|%s|%s\n' "$pid" "$ptype" "$wpath"
    fi
  done <<< "$ps_output"
}

# The pkill -f pattern for one orphan record. Kept as its own function so
# the kill step and the "did it actually die" verify step derive the exact
# same pattern instead of two independently-written regexes drifting apart.
kill_pattern_for() {
  local proc_type="$1" wpath="$2"
  case "$proc_type" in
    apiserver) printf 'u7s-apiserver.*%s/temp/u7s/kubeconfig' "$wpath" ;;
    scheduler) printf 'u7s-scheduler.*%s/temp/u7s/kubeconfig' "$wpath" ;;
    konnectivity-server) printf 'konnectivity-server.*%s/temp/u7s' "$wpath" ;;
    sample-run-metrics) printf 'sample-run-metrics.sh.*%s/temp/u7s' "$wpath" ;;
  esac
}

step_a_orphaned_processes() {
  local live ps_out line pid ptype wpath pat
  local orphans=() still_alive=()

  live=$(git -C "$REPO_ROOT" worktree list --porcelain | awk '/^worktree / {print $2}')
  ps_out=$(ps aux | grep -E 'u7s-apiserver|u7s-scheduler|konnectivity-server|sample-run-metrics.sh' | grep -v grep) || true
  [ -z "$ps_out" ] && return 0

  while IFS= read -r line; do
    [ -n "$line" ] && orphans+=("$line")
  done < <(find_orphans "$ps_out" "$live")
  [ "${#orphans[@]}" -eq 0 ] && return 0

  for line in "${orphans[@]}"; do
    IFS='|' read -r pid ptype wpath <<< "$line"
    echo "[hygiene] orphan-kill: ${ptype} pid=${pid} workdir=${wpath}"
    pat=$(kill_pattern_for "$ptype" "$wpath")
    run_cmd pkill -f "$pat"
  done

  # Dry-run never actually killed anything, so a re-scan finding the same
  # processes still alive isn't a failure -- skip verification entirely.
  [ "${DRY_RUN:-0}" = "1" ] && return 0

  # Verify: any orphan pattern that still matches after the kill is a
  # failure -- surface it instead of silently retrying (a process that
  # survives one kill may be zombied/reparented and needs manual
  # investigation).
  ps_out=$(ps aux | grep -E 'u7s-apiserver|u7s-scheduler|konnectivity-server|sample-run-metrics.sh' | grep -v grep) || true
  while IFS= read -r line; do
    [ -n "$line" ] && still_alive+=("$line")
  done < <(find_orphans "$ps_out" "$live")

  if [ "${#still_alive[@]}" -gt 0 ]; then
    for line in "${still_alive[@]}"; do
      echo "[hygiene] orphan-kill-FAILED: $line" >&2
    done
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# STEP B -- worktree metadata.
# ---------------------------------------------------------------------------
step_b_prune_worktrees() {
  run_cmd git -C "$REPO_ROOT" worktree prune -v
}

# ---------------------------------------------------------------------------
# STEP C -- stale worker branches, in-flight-safe.
# ---------------------------------------------------------------------------

# Branches currently checked out in ANY worktree (the `branch
# refs/heads/<name>` lines of `git worktree list --porcelain`) -- these are
# in-flight workers (or the mayor's own checkout) and must never be
# force-deleted, including ones with no upstream pushed yet.
checked_out_branches() {
  printf '%s' "$1" | awk '/^branch refs\/heads\// {sub("refs/heads/","",$2); print $2}'
}

# True (exit 0) iff `branch` is in the given newline-separated
# checked_out_branches set -- the in-flight guard.
is_checked_out() {
  local branch="$1" checked_out="$2"
  printf '%s\n' "$checked_out" | grep -qxF "$branch"
}

# True (exit 0) iff `branch` has commits not yet reflected (by patch-id) in
# origin/main -- still unmerged, even via a squash-merge that `git branch
# --merged` would miss. Exercises real git rather than synthetic text
# because patch-id comparison genuinely needs two commit graphs; the test
# suite runs this against a disposable sandbox git repo.
is_unmerged_by_patch_id() {
  local branch="$1"
  [ -n "$(git -C "$REPO_ROOT" cherry origin/main "$branch" 2>/dev/null)" ]
}

# True (exit 0) iff `branch` appears in the given newline-separated list of
# open PRs' head branch names. Observed 2026-08-28: PR #1433's commits
# reached main via a different PR (#1435) while #1433 itself was still
# open -- is_unmerged_by_patch_id alone would call #1433's branch "safe to
# delete" since its patch-id is already in origin/main, but deleting a
# branch with an open PR makes GitHub auto-close that PR, destroying its
# review state and any unresolved threads. patch-id cannot see this; only
# a PR-state check can.
has_open_pr() {
  local branch="$1" open_pr_branches="$2"
  printf '%s\n' "$open_pr_branches" | grep -qxF "$branch"
}

# True (exit 0) iff `branch` is `worker/agent-<id>` and a live worktree
# directory ai/worktrees/agent-<id> exists, regardless of which branch that
# worktree currently has checked out. Observed 2026-08-28: a worker
# switched its worktree to a scratch branch mid-dispatch to build a
# throwaway PR, leaving worker/agent-<id> checked out nowhere -- the
# in-flight guard (is_checked_out) alone is blind to this, since it only
# protects a branch that's CURRENTLY checked out somewhere. The worktree
# directory name encodes the agent id directly, so this is a plain
# name-to-directory lookup rather than a snapshot of what's checked out
# right now.
has_live_worktree_dir() {
  local branch="$1" repo_root="$2"
  local agent_id="${branch#worker/agent-}"
  [ "$agent_id" != "$branch" ] && [ -d "$repo_root/ai/worktrees/agent-$agent_id" ]
}

step_c_stale_worker_branches() {
  run_cmd git -C "$REPO_ROOT" fetch origin main
  local porcelain checked_out branch open_pr_branches
  porcelain=$(git -C "$REPO_ROOT" worktree list --porcelain)
  checked_out=$(checked_out_branches "$porcelain")
  # Fetched once up front (not per-branch) to keep this to a single `gh`
  # call regardless of how many worker/agent-* branches exist. A `gh`
  # failure here aborts the whole tick via this script's own `set -e`
  # (see file header) rather than silently deleting branches without the
  # PR check that motivated this guard in the first place.
  open_pr_branches=$(gh pr list -R litehop/u7s --state open --json headRefName --jq '.[].headRefName')
  while IFS= read -r branch; do
    [ -n "$branch" ] || continue
    case "$branch" in
      worker/agent-*) ;;
      *) continue ;;
    esac
    is_checked_out "$branch" "$checked_out" && continue
    is_unmerged_by_patch_id "$branch" && continue
    has_open_pr "$branch" "$open_pr_branches" && continue
    has_live_worktree_dir "$branch" "$REPO_ROOT" && continue
    run_cmd git -C "$REPO_ROOT" branch -D "$branch"
  done < <(git -C "$REPO_ROOT" for-each-ref --format='%(refname:short)' refs/heads/)
}

# ---------------------------------------------------------------------------
# STEP D -- non-worker branches with a gone upstream.
# ---------------------------------------------------------------------------

# Extracts branch names whose tracked upstream is `[gone]` from
# `git for-each-ref --format='%(refname:short) %(upstream:track)'` output.
# Pure text processing, so the test suite can feed synthetic for-each-ref
# lines without needing a real stale-upstream branch on disk.
gone_upstream_branches() {
  printf '%s' "$1" | awk '$2 == "[gone]" {print $1}'
}

step_d_gone_upstream_branches() {
  local refs branch checked_out
  refs=$(git -C "$REPO_ROOT" for-each-ref --format='%(refname:short) %(upstream:track)' refs/heads/)
  checked_out=$(checked_out_branches "$(git -C "$REPO_ROOT" worktree list --porcelain)")
  while IFS= read -r branch; do
    [ -n "$branch" ] || continue
    # A merged worker branch's upstream goes [gone] the instant the merge
    # queue deletes its remote head, which can race ahead of the tick that
    # reaps its worktree. `git branch -d` refuses to delete a branch checked
    # out in ANY live worktree regardless of merge state, and that refusal
    # would otherwise abort this whole run via `set -e` (see file header) --
    # leave it for the tick's reap (or the next hygiene run once the
    # worktree is gone) instead of erroring on a benign, self-resolving race.
    is_checked_out "$branch" "$checked_out" && continue
    run_cmd git -C "$REPO_ROOT" branch -d "$branch"
  done < <(gone_upstream_branches "$refs")
}

# ---------------------------------------------------------------------------
# STEP E -- findings-enforcement drift backstop.
#
# CI's check-findings-closed-bead-refs.sh reads .beads/issues.jsonl, the
# git-tracked bd export, which only refreshes at session-wrap commits and
# loses a bead entirely once it closes AND is later `bd prune`-d -- two
# documented holes on that check's own bead. This step reads LIVE bd
# state instead (bd IS available in the mayor's own environment, unlike
# CI's), closing both: a bead closed since the export was last committed,
# and a bead pruned after closing, which the export-based check can only
# treat as "no signal" since it can't tell "pruned" apart from "not
# exported yet". Live bd has no such staleness excuse, so this step
# treats "no live record at all" as ALSO stale, unlike the CI check.
#
# WARN-ONLY, not auto-delete: unlike STEP A-D (process kills, worktree
# metadata pruning, branch deletion -- none of which touch the tracked
# tree or need a commit), deleting a findings/*.md file requires
# committing that deletion. An unattended cron sweep committing tree
# changes on its own is a materially bigger action than anything else in
# this loop, so this step reports loudly and leaves the delete-and-commit
# to a human or a follow-up workflow.
# ---------------------------------------------------------------------------

# Bead ID from a findings file's `Bead: <id>` header (first 5 lines), or
# empty if absent. Extracts only the leading bead-ID token, stopping before
# any trailing descriptive text (e.g. a parenthetical naming related beads)
# -- the old whitespace-stripped whole-line slurp mangled such a header into
# a compound string that would never match any live bd record, making this
# step warn to delete a finding that's actually still open.
bead_id_from_finding() {
  local f="$1" bead_line
  bead_line=$(head -n 5 "$f" | grep -m1 -E '^Bead: ' || true)
  printf '%s' "$bead_line" | grep -oE 'mayor-[a-z0-9.]+' | head -1
}

# True (exit 0) iff a bead in the given live-bd status is stale enough to
# warn about: closed, or an empty status (bd has no live record at all --
# pruned after closing, or a bad reference; either way there's nothing left
# to cross-reference).
is_stale_bead_status() {
  local status="$1"
  [ "$status" = "closed" ] || [ -z "$status" ]
}

step_e_stale_findings() {
  local findings f bead_id status
  findings=$(git -C "$REPO_ROOT" ls-files 'ai/findings/*.md' | grep -v '^ai/findings/legacy/') || true
  [ -n "$findings" ] || return 0

  while IFS= read -r f; do
    [ -n "$f" ] || continue
    bead_id=$(bead_id_from_finding "$REPO_ROOT/$f")
    [ -n "$bead_id" ] || continue
    status=$(bd -C "$REPO_ROOT" show "$bead_id" --json 2>/dev/null | jq -r '.[0]?.status // empty') || true
    if is_stale_bead_status "$status"; then
      if [ -z "$status" ]; then
        echo "[hygiene] stale-finding: $f references $bead_id, which bd has no live record of (pruned, or a bad reference) -- delete it, git history is the archive"
      else
        echo "[hygiene] stale-finding: $f references $bead_id, which is closed -- delete it, git history is the archive"
      fi
    fi
  done <<< "$findings"
}

main() {
  local rc=0
  step_a_orphaned_processes || rc=1
  step_b_prune_worktrees
  step_c_stale_worker_branches
  step_d_gone_upstream_branches
  step_e_stale_findings
  exit "$rc"
}

if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  if [ "${1:-}" = "__call" ]; then
    shift
    "$@"
  else
    main "$@"
  fi
fi
