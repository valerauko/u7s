#!/usr/bin/env bash
# Regression test for reset.sh's host-process kill scope.
#
# Exercises the REAL script's host_kill_pattern_for() via its
# `__call <fn> [args...]` entry point (same "real script, not a
# reimplementation" technique scripts/test-worktree-hygiene-logic.sh uses for
# worktree-hygiene.sh's kill_pattern_for()) -- a hardcoded copy of the
# pattern strings would keep passing even if reset.sh's real function
# regressed or reverted to the old blanket port-based kill.
#
# reset.sh's --host-only (and full --reset) fallback used to be a blanket
# 'lsof -ti tcp:$PORT | kill': it killed whatever held the apiserver's port,
# no matter what process that was. Lima's shared 'limactl usernet' network
# daemon legitimately holds that same host port too -- it proxies a guest
# VM's host.lima.internal:$PORT connections (kubelet/KCM/kube-proxy talking
# to the apiserver) through it -- so the blanket kill took the daemon out as
# collateral, breaking guest->host connectivity for every OTHER worker VM
# sharing that Lima network, not just the worktree being reset (confirmed
# live: 'ip neigh' gateway goes INCOMPLETE). The fix scopes the kill to this
# worktree's own u7s process by full cmdline (binary name + --workdir path)
# via 'pkill -f' against reset.sh's own host_kill_pattern_for() output, which
# by construction cannot match a process whose argv contains neither string.
#
# Covers two levels for each component:
#   1. host_kill_pattern_for() itself returns the expected pattern string.
#   2. That REAL pattern, fed to a real 'pkill -f', kills a spawned process
#      standing in for the u7s component and leaves a spawned process
#      standing in for the shared Lima daemon alive -- a test that only
#      inspected strings could not prove the daemon process actually
#      survives a real kill signal dispatch.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO/scripts/conformance/reset.sh"

PASS=0
FAIL=0
LEFTOVER_PIDS=()

cleanup() {
  local p
  for p in "${LEFTOVER_PIDS[@]:-}"; do
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
  done
}
trap cleanup EXIT

# Runs the real script's __call entry point, capturing stdout.
call() {
  bash "$SCRIPT" __call "$@"
}

assert_eq() {
  local label="$1" actual="$2" expected="$3"
  if [ "$actual" = "$expected" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — got '$actual', expected '$expected'"
    FAIL=$(( FAIL + 1 ))
  fi
}

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

# Spawns a background process whose full command line (as pgrep -f/ps sees
# it) is exactly $1, standing in for a real u7s component or the shared Lima
# daemon without needing to build/run either. Echoes the spawned PID.
# NOTE: called via "$(...)" command substitution, which forks a subshell --
# callers must append the echoed PID to LEFTOVER_PIDS themselves.
spawn_fake_process() {
  local cmdline="$1"
  bash -c "exec -a '${cmdline}' sleep 60" >/dev/null 2>&1 &
  echo $!
}

WORKDIR="/tmp/fake-worktree-$$/temp/u7s"
FAKE_DAEMON_CMDLINE="limactl usernet -p /Users/x/.lima/_networks/user-v2-workers-b/usernet.pid --subnet 192.168.109.0/24"

# ---------------------------------------------------------------------------
# 1. host_kill_pattern_for() itself: exact pattern strings, so a drift in
#    reset.sh's derivation (e.g. anchoring on the wrong file, or dropping the
#    workdir scope entirely) fails here even before any process is spawned.
# ---------------------------------------------------------------------------
assert_eq "host_kill_pattern_for builds the apiserver pattern anchored on this workdir's kubeconfig path" \
  "$(call host_kill_pattern_for apiserver "$WORKDIR")" "u7s-apiserver.*${WORKDIR}/kubeconfig"
assert_eq "host_kill_pattern_for builds the scheduler pattern anchored on this workdir's kubeconfig path" \
  "$(call host_kill_pattern_for scheduler "$WORKDIR")" "u7s-scheduler.*${WORKDIR}/kubeconfig"
assert_eq "host_kill_pattern_for builds the konnectivity-server pattern anchored on this workdir (no /kubeconfig suffix -- it has no such flag)" \
  "$(call host_kill_pattern_for konnectivity-server "$WORKDIR")" "konnectivity-server.*${WORKDIR}"

# ---------------------------------------------------------------------------
# 2. apiserver: the REAL derived pattern, fed to a real 'pkill -f', must kill
#    this worktree's fake apiserver and leave the shared network daemon (a
#    real port holder in the bug report, but cmdline-unrelated) untouched.
#    Reverting reset.sh's scoping (e.g. back to a bare port-based kill, or a
#    pattern that drops the workdir anchor) would either fail assertion 1
#    above or make this pkill match the daemon too -- this cannot pass
#    against the old blanket-kill behavior.
# ---------------------------------------------------------------------------
APISERVER_PATTERN="$(call host_kill_pattern_for apiserver "$WORKDIR")"
FAKE_APISERVER_PID="$(spawn_fake_process "u7s-apiserver --db ${WORKDIR}/state.db --kubeconfig ${WORKDIR}/kubeconfig")"
LEFTOVER_PIDS+=("$FAKE_APISERVER_PID")
FAKE_NETWORK_DAEMON_PID="$(spawn_fake_process "$FAKE_DAEMON_CMDLINE")"
LEFTOVER_PIDS+=("$FAKE_NETWORK_DAEMON_PID")
sleep 0.2 # let the backgrounded exec -a actually take effect before pkill -f

pkill -f "$APISERVER_PATTERN" 2>/dev/null || true
sleep 0.2
assert_dead "apiserver fallback (real host_kill_pattern_for output) kills this worktree's own u7s-apiserver" "$FAKE_APISERVER_PID"
assert_alive "apiserver fallback leaves the shared Lima network daemon untouched (the bug this guards against)" "$FAKE_NETWORK_DAEMON_PID"
kill -9 "$FAKE_NETWORK_DAEMON_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 3. konnectivity-server: same proof, same reasoning -- a guest VM's
#    konnectivity-agent talking to host.lima.internal:<agent-port> makes the
#    shared daemon a legitimate holder of that port too.
# ---------------------------------------------------------------------------
KONNECTIVITY_PATTERN="$(call host_kill_pattern_for konnectivity-server "$WORKDIR")"
FAKE_KONNECTIVITY_PID="$(spawn_fake_process "proxy-server-darwin-arm64 --cluster-cert=${WORKDIR}/konnectivity-server.crt --cluster-key=${WORKDIR}/konnectivity-server.key")"
LEFTOVER_PIDS+=("$FAKE_KONNECTIVITY_PID")
FAKE_NETWORK_DAEMON_PID2="$(spawn_fake_process "$FAKE_DAEMON_CMDLINE")"
LEFTOVER_PIDS+=("$FAKE_NETWORK_DAEMON_PID2")
sleep 0.2

pkill -f "$KONNECTIVITY_PATTERN" 2>/dev/null || true
sleep 0.2
assert_dead "konnectivity-server fallback (real host_kill_pattern_for output) kills this worktree's own konnectivity-server" "$FAKE_KONNECTIVITY_PID"
assert_alive "konnectivity-server fallback leaves the shared Lima network daemon untouched" "$FAKE_NETWORK_DAEMON_PID2"
kill -9 "$FAKE_NETWORK_DAEMON_PID2" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
