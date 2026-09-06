#!/usr/bin/env bash
# Regression test for reset.sh's host-process kill scope.
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
# via 'pkill -f', which by construction cannot match a process whose argv
# contains neither string.
#
# Exercises real spawned processes standing in for "this worktree's
# u7s-apiserver / konnectivity-server" and "the shared Lima network daemon"
# -- a test that only inspected strings/regexes could not prove the daemon
# process actually survives a real kill signal dispatch.
#
# The two 'pkill -f' invocations below are copied verbatim from reset.sh's
# host-process fallback -- keep them in sync if reset.sh's patterns change.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

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

# ---------------------------------------------------------------------------
# 1. apiserver fallback: 'pkill -f "u7s-apiserver.*${WORKDIR}/kubeconfig"'
#    must kill this worktree's fake apiserver and leave the shared network
#    daemon (a real port holder in the bug report, but cmdline-unrelated)
#    untouched.
# ---------------------------------------------------------------------------
FAKE_APISERVER_PID="$(spawn_fake_process "u7s-apiserver --db ${WORKDIR}/state.db --kubeconfig ${WORKDIR}/kubeconfig")"
LEFTOVER_PIDS+=("$FAKE_APISERVER_PID")
FAKE_NETWORK_DAEMON_PID="$(spawn_fake_process "limactl usernet -p /Users/x/.lima/_networks/user-v2-workers-b/usernet.pid --subnet 192.168.109.0/24")"
LEFTOVER_PIDS+=("$FAKE_NETWORK_DAEMON_PID")
sleep 0.2 # let the backgrounded exec -a actually take effect before pkill -f

pkill -f "u7s-apiserver.*${WORKDIR}/kubeconfig" 2>/dev/null || true
sleep 0.2
assert_dead "apiserver fallback kills this worktree's own u7s-apiserver" "$FAKE_APISERVER_PID"
assert_alive "apiserver fallback leaves the shared Lima network daemon untouched (the bug this guards against)" "$FAKE_NETWORK_DAEMON_PID"
kill -9 "$FAKE_NETWORK_DAEMON_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 2. konnectivity-server fallback: 'pkill -f "konnectivity-server.*${WORKDIR}"'
#    must kill this worktree's fake konnectivity-server and leave the shared
#    network daemon untouched, same reasoning -- a guest VM's
#    konnectivity-agent talking to host.lima.internal:<agent-port> makes the
#    shared daemon a legitimate holder of that port too.
# ---------------------------------------------------------------------------
FAKE_KONNECTIVITY_PID="$(spawn_fake_process "proxy-server-darwin-arm64 --cluster-cert=${WORKDIR}/konnectivity-server.crt --cluster-key=${WORKDIR}/konnectivity-server.key")"
LEFTOVER_PIDS+=("$FAKE_KONNECTIVITY_PID")
FAKE_NETWORK_DAEMON_PID2="$(spawn_fake_process "limactl usernet -p /Users/x/.lima/_networks/user-v2-workers-b/usernet.pid --subnet 192.168.109.0/24")"
LEFTOVER_PIDS+=("$FAKE_NETWORK_DAEMON_PID2")
sleep 0.2

pkill -f "konnectivity-server.*${WORKDIR}" 2>/dev/null || true
sleep 0.2
assert_dead "konnectivity-server fallback kills this worktree's own konnectivity-server" "$FAKE_KONNECTIVITY_PID"
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
