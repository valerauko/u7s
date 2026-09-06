#!/usr/bin/env bash
# Unit test for scripts/conformance/sample-run-metrics.sh.
#
# Exercises the REAL script as subprocesses (start/stop/snapshot), not a
# copied-out fragment of its logic — unlike reset.sh's teardown_vm(), this
# script has a clean, self-contained CLI, so invoking it for real is both
# simpler and more faithful than duplicating its body into the test (no risk
# of the test's copy drifting from the actual implementation).
#
# Covers the three failure modes the bead exists to prevent:
#
#   1. start/reap happy path — a real listener stands in for the apiserver so
#      resolve_apiserver_pid's real lsof-based lookup is exercised, not mocked.
#   2. missing-process robustness — the sampler must survive an interval with
#      NO apiserver, NO scheduler, NO konnectivity-server, NO VM, and a dead
#      /metrics endpoint without the background loop dying, AND `stop` must be
#      a no-op (not an error) on a PID that already died on its own or on a
#      workdir that was never started at all.
#   3. /metrics snapshot ordering — one file per snapshot (never appended, the
#      exact bug the bead's operator-run-by-hand loop had: repeated dumps
#      concatenated into one file, silently breaking last-wins-on-gauges
#      parsing), and a snapshot call after the apiserver is already down must
#      degrade gracefully (exit 0, no partial file) rather than fail the
#      caller's teardown — this is WHY run-all.sh must call snapshot BEFORE
#      stopping the apiserver: calling it after gets exactly this empty case.
#
# A stub `kubectl` on PATH stands in for the apiserver's /metrics endpoint
# (real lsof/pgrep/ps/limactl-absence are exercised directly; only the
# kubectl --raw /metrics call is faked, since a real one needs a live
# cluster this test does not stand up).
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO/scripts/conformance/sample-run-metrics.sh"

PASS=0
FAIL=0
LEFTOVER_PIDS=()
TMPDIR_TEST="$(mktemp -d)"

cleanup() {
  local p
  for p in "${LEFTOVER_PIDS[@]:-}"; do
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
  done
  rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT

assert_dead() {
  local label="$1" pid="$2"
  if kill -0 "$pid" 2>/dev/null; then
    echo "FAIL: $label — PID $pid is still alive, expected dead"
    FAIL=$(( FAIL + 1 ))
  else
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  fi
}

assert_alive() {
  local label="$1" pid="$2"
  if kill -0 "$pid" 2>/dev/null; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — PID $pid is dead, expected still alive"
    FAIL=$(( FAIL + 1 ))
  fi
}

assert_true() {
  local label="$1" cond="$2"
  if [ "$cond" = "0" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

find_free_port() {
  local port
  for _ in $(seq 1 30); do
    port=$(( (RANDOM % 20000) + 20000 ))
    if ! lsof -ti tcp:"$port" >/dev/null 2>&1; then
      echo "$port"
      return 0
    fi
  done
  echo "ERROR: could not find a free port" >&2
  return 1
}

# ---------------------------------------------------------------------------
# Stub kubectl: stands in for the apiserver's /metrics endpoint. Controlled
# by $KUBECTL_STUB_STATE — "down" makes it fail like a stopped apiserver,
# anything else (including absent) serves a fixed, two-shard metrics body.
# ---------------------------------------------------------------------------
STUBDIR="$TMPDIR_TEST/stubbin"
mkdir -p "$STUBDIR"
KUBECTL_STUB_STATE="$TMPDIR_TEST/kubectl-state"
export KUBECTL_STUB_STATE
cat > "$STUBDIR/kubectl" <<'STUB'
#!/usr/bin/env bash
if [ -f "$KUBECTL_STUB_STATE" ] && [ "$(cat "$KUBECTL_STUB_STATE")" = "down" ]; then
  echo "stub kubectl: connection refused (simulated apiserver down)" >&2
  exit 1
fi
cat <<'EOF'
# HELP u7s_watch_ring_occupancy stub
# TYPE u7s_watch_ring_occupancy gauge
u7s_watch_ring_occupancy{shard="/registry/pods/"} 7
u7s_watch_ring_occupancy{shard="/registry/configmaps/"} 3
# HELP u7s_watch_ring_span_seconds stub
# TYPE u7s_watch_ring_span_seconds histogram
u7s_watch_ring_span_seconds_bucket{shard="/registry/pods/",le="1"} 0
u7s_watch_ring_span_seconds_bucket{shard="/registry/pods/",le="2"} 0
u7s_watch_ring_span_seconds_bucket{shard="/registry/pods/",le="4"} 1
u7s_watch_ring_span_seconds_bucket{shard="/registry/pods/",le="+Inf"} 1
u7s_watch_ring_span_seconds_sum{shard="/registry/pods/"} 4
u7s_watch_ring_span_seconds_count{shard="/registry/pods/"} 1
u7s_watch_ring_span_seconds_bucket{shard="/registry/configmaps/",le="1"} 1
u7s_watch_ring_span_seconds_bucket{shard="/registry/configmaps/",le="+Inf"} 1
u7s_watch_ring_span_seconds_sum{shard="/registry/configmaps/"} 1
u7s_watch_ring_span_seconds_count{shard="/registry/configmaps/"} 1
EOF
STUB
chmod +x "$STUBDIR/kubectl"

# ---------------------------------------------------------------------------
# Stub limactl: only intercepts the exact `shell <vm> -- curl ... 10257/metrics`
# invocation take_kcm_snapshot makes, controlled by $LIMACTL_STUB_STATE ("up"
# serves a fixed metrics body, anything else simulates KCM being unreachable).
# Every other invocation (sample_vm_rss/sample_vm_free's real `limactl shell
# no-such-vm-N -- ps/free` calls elsewhere in this test, which rely on the
# REAL binary's fast-fail against a nonexistent instance) execs straight
# through to the real limactl found below, so this stub can sit on PATH for
# the whole test file without changing any test's existing behavior.
# ---------------------------------------------------------------------------
# CI runners (script-tests' ubuntu-latest job) have no lima installed at all,
# so `command -v limactl` finding nothing is the expected case there, not an
# error -- `|| true` keeps that from tripping this file's own `set -e` and
# killing it before a single PASS/FAIL line prints. An empty REAL_LIMACTL
# still behaves correctly below: `exec ""` fails with the same "not found"
# exit status a genuinely absent limactl binary would have produced anyway,
# which every real caller (sample_vm_rss/sample_vm_free) already tolerates.
REAL_LIMACTL="$(command -v limactl || true)"
LIMACTL_STUB_STATE="$TMPDIR_TEST/limactl-state"
export LIMACTL_STUB_STATE
cat > "$STUBDIR/limactl" <<STUB
#!/usr/bin/env bash
if [ "\$1" = "shell" ] && [[ "\$*" == *"curl"*"10257/metrics"* ]]; then
  if [ -f "\$LIMACTL_STUB_STATE" ] && [ "\$(cat "\$LIMACTL_STUB_STATE")" = "up" ]; then
    cat <<'EOF'
# HELP go_goroutines stub
# TYPE go_goroutines gauge
go_goroutines 42
EOF
    exit 0
  fi
  echo "stub limactl: connection refused (simulated kcm down)" >&2
  exit 1
fi
exec "$REAL_LIMACTL" "\$@"
STUB
chmod +x "$STUBDIR/limactl"

export PATH="$STUBDIR:$PATH"
echo "up" > "$KUBECTL_STUB_STATE"
echo "down" > "$LIMACTL_STUB_STATE"

# ===========================================================================
# 1. Start/reap happy path — real listener stands in for the apiserver.
# ===========================================================================
PORT1="$(find_free_port)"
# A plain `< <(sleep 300)` process substitution here would leak that sleep as
# an untracked, unkillable-via-$! orphan: killing nc's own PID does not
# touch the separate subshell feeding its stdin, so it would keep running
# for its own full 300s after this file has already exited (GH Actions'
# post-job "Terminate orphan process" cleanup is what actually reaps it, not
# this script). A named FIFO gives sleep a real, trackable PID instead.
NC_STDIN_FIFO="$TMPDIR_TEST/nc-stdin-fifo"
mkfifo "$NC_STDIN_FIFO"
sleep 300 > "$NC_STDIN_FIFO" &
LEFTOVER_PIDS+=("$!")
nc -l "$PORT1" < "$NC_STDIN_FIFO" &
STANDIN_PID=$!
LEFTOVER_PIDS+=("$STANDIN_PID")
sleep 0.3

WORKDIR1="$TMPDIR_TEST/work1"
bash "$SCRIPT" start --workdir "$WORKDIR1" --interval 1 --port "$PORT1" --vm no-such-vm-1
sleep 2.2

SAMPLER_PID1="$(cat "$WORKDIR1/sample-run-metrics.pid" 2>/dev/null || true)"
if [ -n "$SAMPLER_PID1" ]; then
  LEFTOVER_PIDS+=("$SAMPLER_PID1")
  assert_alive "sampler loop is running after start" "$SAMPLER_PID1"
else
  echo "FAIL: sampler pidfile missing after start"
  FAIL=$(( FAIL + 1 ))
fi

if grep -q ",host,${STANDIN_PID},apiserver," "$WORKDIR1/rss.csv" 2>/dev/null; then
  echo "PASS: rss.csv records the real apiserver stand-in's actual PID and RSS"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: rss.csv missing expected apiserver row — got:"
  cat "$WORKDIR1/rss.csv" 2>/dev/null || echo "  (no file)"
  FAIL=$(( FAIL + 1 ))
fi

if grep -q "^[^,]*,/registry/pods/,7,4$" "$WORKDIR1/ring-age.csv" 2>/dev/null; then
  echo "PASS: ring-age.csv joins occupancy with the span histogram's smallest nonzero-count bucket (4, skipping the empty le=1/le=2 buckets) — the reading that replaced a plain gauge value when u7s_watch_ring_span_seconds became a histogram (bd:ukbhp); a sampler still parsing it as a gauge would match nothing and silently emit zero rows, exactly the regression this test guards against"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: ring-age.csv missing expected joined row (occupancy=7, span=4 from the smallest nonzero-count bucket) — got:"
  cat "$WORKDIR1/ring-age.csv" 2>/dev/null || echo "  (no file)"
  FAIL=$(( FAIL + 1 ))
fi

bash "$SCRIPT" stop --workdir "$WORKDIR1"
if [ -n "$SAMPLER_PID1" ]; then
  assert_dead "sampler loop is reaped by stop" "$SAMPLER_PID1"
fi
if [ -f "$WORKDIR1/sample-run-metrics.pid" ]; then
  echo "FAIL: pidfile still present after stop"
  FAIL=$(( FAIL + 1 ))
else
  echo "PASS: stop removes the pidfile"
  PASS=$(( PASS + 1 ))
fi

kill -9 "$STANDIN_PID" 2>/dev/null || true

# ===========================================================================
# 2. Missing-process robustness — nothing exists: no apiserver, no scheduler,
#    no konnectivity-server, no VM, and a down /metrics endpoint. The loop
#    must survive; `stop` must be a no-op on an already-dead PID and on a
#    workdir that was never started.
# ===========================================================================
echo "down" > "$KUBECTL_STUB_STATE"
PORT2="$(find_free_port)"
WORKDIR2="$TMPDIR_TEST/work2"
bash "$SCRIPT" start --workdir "$WORKDIR2" --interval 1 --port "$PORT2" --vm no-such-vm-2
sleep 2.2

SAMPLER_PID2="$(cat "$WORKDIR2/sample-run-metrics.pid" 2>/dev/null || true)"
if [ -n "$SAMPLER_PID2" ]; then
  LEFTOVER_PIDS+=("$SAMPLER_PID2")
  assert_alive "sampler loop survives a full interval with every process/VM/metrics endpoint absent" "$SAMPLER_PID2"
else
  echo "FAIL: sampler pidfile missing — loop likely crashed on startup"
  FAIL=$(( FAIL + 1 ))
fi

RSS_LINES="$(wc -l < "$WORKDIR2/rss.csv" 2>/dev/null | tr -d ' ')"
if [ "$RSS_LINES" = "1" ]; then
  echo "PASS: rss.csv holds only its header when nothing exists to sample (no crash artifacts, no phantom rows)"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: rss.csv expected exactly 1 line (header only), got $RSS_LINES:"
  cat "$WORKDIR2/rss.csv" 2>/dev/null
  FAIL=$(( FAIL + 1 ))
fi

bash "$SCRIPT" stop --workdir "$WORKDIR2"
[ -n "$SAMPLER_PID2" ] && assert_dead "sampler loop from the all-absent case is still reaped cleanly" "$SAMPLER_PID2"
echo "up" > "$KUBECTL_STUB_STATE"

# --- stop on a PID that already died on its own (not via our stop) ---------
WORKDIR3="$TMPDIR_TEST/work3"
bash "$SCRIPT" start --workdir "$WORKDIR3" --interval 5 --port "$(find_free_port)" --vm no-such-vm-3
SAMPLER_PID3="$(cat "$WORKDIR3/sample-run-metrics.pid")"
kill -9 "$SAMPLER_PID3" 2>/dev/null || true
sleep 0.3
set +e
STOP_OUT3="$(bash "$SCRIPT" stop --workdir "$WORKDIR3" 2>&1)"
STOP_EXIT3=$?
set -e
if [ "$STOP_EXIT3" -eq 0 ]; then
  echo "PASS: stop on a PID that already died on its own exits 0 (no error) — matches: $STOP_OUT3"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: stop on an already-dead PID exited $STOP_EXIT3: $STOP_OUT3"
  FAIL=$(( FAIL + 1 ))
fi

# --- stop on a workdir that was never started -------------------------------
WORKDIR4="$TMPDIR_TEST/work4-never-started"
set +e
STOP_OUT4="$(bash "$SCRIPT" stop --workdir "$WORKDIR4" 2>&1)"
STOP_EXIT4=$?
set -e
assert_true "stop on a workdir with no pidfile at all exits 0 (run-all.sh's teardown must be able to call stop unconditionally)" "$STOP_EXIT4"
echo "  (output: $STOP_OUT4)"

# ===========================================================================
# 3. /metrics snapshot ordering — one file per snapshot, never appended; a
#    snapshot after the apiserver is down degrades gracefully instead of
#    failing the caller.
# ===========================================================================
echo "up" > "$KUBECTL_STUB_STATE"
WORKDIR5="$TMPDIR_TEST/work5"
mkdir -p "$WORKDIR5"
bash "$SCRIPT" snapshot --workdir "$WORKDIR5" --label first
bash "$SCRIPT" snapshot --workdir "$WORKDIR5" --label second

FIRST_FILE="$WORKDIR5/metrics-01-first.prom"
SECOND_FILE="$WORKDIR5/metrics-02-second.prom"
if [ -f "$FIRST_FILE" ] && [ -f "$SECOND_FILE" ]; then
  echo "PASS: two snapshot calls produce two distinct, sequentially numbered files"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: expected $FIRST_FILE and $SECOND_FILE to both exist — got:"
  ls "$WORKDIR5" 2>/dev/null
  FAIL=$(( FAIL + 1 ))
fi

FIRST_LINES="$(wc -l < "$FIRST_FILE" 2>/dev/null | tr -d ' ')"
if [ "$FIRST_LINES" = "16" ]; then
  echo "PASS: the first snapshot's file is untouched by the second snapshot (not appended-to — the exact bug in the operator's old by-hand loop)"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: first snapshot file has $FIRST_LINES lines, expected 16 (unchanged) — got:"
  cat "$FIRST_FILE" 2>/dev/null
  FAIL=$(( FAIL + 1 ))
fi

echo "down" > "$KUBECTL_STUB_STATE"
set +e
SNAP_OUT="$(bash "$SCRIPT" snapshot --workdir "$WORKDIR5" --label after-stop 2>&1)"
SNAP_EXIT=$?
set -e
assert_true "snapshot after the apiserver is already down exits 0 — a caller's teardown must not fail just because metrics capture couldn't reach a dead server" "$SNAP_EXIT"
if [ -f "$WORKDIR5/metrics-03-after-stop.prom" ]; then
  echo "FAIL: a snapshot taken while the apiserver is down must not leave a (misleadingly present but empty) file behind"
  FAIL=$(( FAIL + 1 ))
else
  echo "PASS: no file is left behind for a snapshot that couldn't reach the apiserver — demonstrates why run-all.sh must snapshot BEFORE stopping it, not after"
  PASS=$(( PASS + 1 ))
fi
echo "  (output: $SNAP_OUT)"

# ===========================================================================
# 4. KCM /metrics snapshot — reachable KCM produces a
#    kcm-metrics-NN-<label>.prom sibling of the apiserver's own snapshot;
#    unreachable KCM degrades gracefully like every other scrape in this
#    script (no partial file, no failed exit code for the caller).
# ===========================================================================
echo "up" > "$KUBECTL_STUB_STATE"
echo "up" > "$LIMACTL_STUB_STATE"
WORKDIR6="$TMPDIR_TEST/work6"
mkdir -p "$WORKDIR6"
bash "$SCRIPT" snapshot --workdir "$WORKDIR6" --label startup --vm fake-vm

KCM_FILE="$WORKDIR6/kcm-metrics-01-startup.prom"
if grep -q "^go_goroutines 42$" "$KCM_FILE" 2>/dev/null; then
  echo "PASS: a reachable KCM produces its own kcm-metrics-NN-<label>.prom snapshot alongside the apiserver's — KCM's memory numbers were previously inferred from RSS growth, never measured"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: expected $KCM_FILE to contain the stub KCM metrics body — got:"
  cat "$KCM_FILE" 2>/dev/null || echo "  (no file)"
  FAIL=$(( FAIL + 1 ))
fi

echo "down" > "$LIMACTL_STUB_STATE"
bash "$SCRIPT" snapshot --workdir "$WORKDIR6" --label second --vm fake-vm
if [ -f "$WORKDIR6/kcm-metrics-02-second.prom" ]; then
  echo "FAIL: a snapshot taken while KCM is unreachable must not leave a (misleadingly present but empty) file behind"
  FAIL=$(( FAIL + 1 ))
else
  echo "PASS: an unreachable KCM leaves no kcm-metrics file behind, same non-fatal contract as the apiserver scrape"
  PASS=$(( PASS + 1 ))
fi

# ===========================================================================
# 5. This whole file must run to completion on a PATH with no limactl
#    anywhere on it -- the actual shape of script-tests' CI runner, which has
#    no lima installed. Before the fix, resolving REAL_LIMACTL above failed
#    under this file's own set -e and killed it before a single PASS/FAIL
#    line printed, which silently tripped the outer script-tests harness's
#    fail=1 even though zero real assertions had failed: a green suite must
#    exit 0, or CI reports failure on passing tests and blocks every merge.
#    NO_LIMACTL_CHILD guards the nested re-invocation from recursing into
#    this same section again.
# ===========================================================================
# Redirected to a real FILE, deliberately not captured via "$(...)": a
# command substitution blocks until every process holding its pipe's write
# end has closed it, so any future background job in this file that forgets
# to redirect away from stdout/stderr would silently turn this check into a
# multi-minute stall instead of the few seconds it actually takes. A file
# has no such "wait for every writer to close" requirement, so this reads
# the exact same way script-tests' own `bash "$t" || fail=1` runs it: the
# parent only waits on the direct child.
if [ -z "${NO_LIMACTL_CHILD:-}" ]; then
  NO_LIMACTL_LOG="$TMPDIR_TEST/no-limactl-run.log"
  set +e
  NO_LIMACTL_CHILD=1 PATH="/usr/bin:/bin:/usr/sbin:/sbin" bash "${BASH_SOURCE[0]}" > "$NO_LIMACTL_LOG" 2>&1
  NO_LIMACTL_STATUS=$?
  set -e
  assert_true "the whole suite exits 0 with no limactl anywhere on PATH" "$NO_LIMACTL_STATUS"
  if grep -q "^Results: [0-9]* passed, 0 failed$" "$NO_LIMACTL_LOG"; then
    echo "PASS: the no-limactl run actually reached its own summary line (ran every assertion, not just exiting 0 for an unrelated early reason)"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: no-limactl run never reached its own summary line — got:"
    cat "$NO_LIMACTL_LOG"
    FAIL=$(( FAIL + 1 ))
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
