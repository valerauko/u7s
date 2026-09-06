#!/usr/bin/env bash
# Full teardown for the conformance stack — kills host processes, kills
# in-VM processes, and deletes the VM so the next run starts clean.
#
# Usage:
#   scripts/conformance/reset.sh [--vm <name>] [--workdir <path>] [--port <N>]
#                                 [--extra-node <vm>] [--host-only]
#
# After this script:
#   - ./temp/u7s/ is gone (DB, certs, kubeconfig, PID files all wiped)
#   - The VM is deleted (full disk wipe — no stale certs/containers). If
#     --extra-node is given, that VM is deleted too — --reset means "fresh
#     everything", not "fresh primary, stale peer" (Lima only applies a yaml's
#     `networks:` stanza at instance creation, so an extra node left over from
#     before that stanza existed would otherwise be silently reused on a
#     network with no route to the freshly-recreated primary).
#
# --host-only: kill this worktree's host-side processes (apiserver, scheduler,
#   konnectivity-server) and exit immediately after — skip wiping $WORKDIR and
#   skip all VM teardown. Intended as a worker's final teardown step, run right
#   before `git worktree remove`: those three processes do NOT die with the
#   worktree (apiserver/scheduler are plain backgrounded processes,
#   konnectivity-server is started via `disown`) and otherwise squat on this
#   VM slot's ports for the next worker to collide with (bd memory
#   worktree-remove-does-not-kill-host-processes). --extra-node's only
#   host-side artifact — its kubelet-port hostPort forward — is owned by that
#   VM's own Lima hostagent, not a standalone process, so it dies with the VM
#   and needs no extra handling here; --host-only leaving the VM alone is
#   correct, not a gap.
#
# To resume a fresh run:
#   scripts/conformance/run-all.sh
set -euo pipefail

WORKDIR="$PWD/temp/u7s"
VM_NAME="${U7S_VM_NAME:-lima-node}"
EXTRA_NODE=""
HOST_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --workdir) WORKDIR="$2"; shift 2 ;;
    --vm) VM_NAME="$2"; shift 2 ;;
    --extra-node) EXTRA_NODE="$2"; shift 2 ;;
    --host-only) HOST_ONLY=1; shift ;;
    # --port and --konnectivity-server-port are accepted for compatibility
    # with run-all.sh's unconditional pass-through, but otherwise unused:
    # host processes are killed by cmdline pattern (binary name + --workdir
    # path) below, never by port number, so no port math is needed here.
    --port) shift 2 ;;
    --konnectivity-server-port) shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# Resolve to absolute without requiring WORKDIR to exist (a fresh worktree's
# first --reset targets a WORKDIR that isn't there yet) so the pkill match
# below is worktree-unique instead of matching another worktree that was
# invoked with the same relative --workdir.
case "$WORKDIR" in
  /*) ;;
  *) WORKDIR="$PWD/$WORKDIR" ;;
esac

echo "=== [reset] Conformance teardown ==="

# ── 1. Kill host processes ────────────────────────────────────────────────────

echo "[reset] Stopping host processes ..."

for name in apiserver scheduler; do
  pidfile="$WORKDIR/${name}.pid"
  if [ -f "$pidfile" ]; then
    pid="$(cat "$pidfile")"
    if kill -0 "$pid" 2>/dev/null; then
      echo "[reset]   killing u7s-${name} (PID $pid)"
      kill "$pid" 2>/dev/null || true
    else
      echo "[reset]   u7s-${name} PID $pid already gone"
    fi
  fi
done

# Fallback: kill this worktree's own u7s-apiserver / u7s-scheduler, scoped by
# full cmdline (binary name + this workdir's path) — NOT by "whatever holds
# the apiserver's port". A blanket 'lsof -ti tcp:$PORT | kill' also matches
# Lima's shared 'limactl usernet' network daemon: it proxies the guest VM's
# host.lima.internal:$PORT connections (kubelet/KCM/kube-proxy talking to the
# apiserver) through this exact host port, so it legitimately shows up as a
# port holder. SIGTERMing it as blanket-kill collateral breaks guest->host
# connectivity for every OTHER worker VM sharing this Lima network, not just
# this worktree's own VM (confirmed live: 'ip neigh' gateway goes
# INCOMPLETE). pkill -f matches only OUR processes' argv, never the shared
# daemon's ('limactl usernet ...' contains neither binary name nor workdir).
pkill -f "u7s-apiserver.*${WORKDIR}/kubeconfig" 2>/dev/null || true
pkill -f "u7s-scheduler.*${WORKDIR}/kubeconfig" 2>/dev/null || true

# The run-metrics sampler (started by run-all.sh alongside the stack, see
# sample-run-metrics.sh) is a peer of apiserver/scheduler for teardown
# purposes too — without this, a --stack-only session's sampler survives
# `rm -rf "$WORKDIR"` below as an orphan still appending to its now-unlinked
# CSVs. Its own `stop` does the SIGTERM+poll reap; harmless if none is running.
bash scripts/conformance/sample-run-metrics.sh stop --workdir "$WORKDIR" >/dev/null 2>&1 || true

# konnectivity-server is started via `disown` (scripts/u7s-start.sh), so it survives
# even after its origin worktree is deleted, still bound to this port slot and still
# serving its old CA-signed cert. If left running, the next run's fresh CA/agent
# reject that stale cert with "certificate signed by unknown authority ... ECDSA
# verification failure" — kill it before regenerating certs. Scoped by cmdline, not
# by port, for the same reason as the apiserver fallback above: a guest VM's
# konnectivity-agent talking to host.lima.internal:<agent-port> makes the shared
# Lima network daemon a legitimate holder of that port too.
pkill -f "konnectivity-server.*${WORKDIR}" 2>/dev/null || true

if [ "$HOST_ONLY" -eq 1 ]; then
  echo "[reset] --host-only: skipping \$WORKDIR wipe and VM teardown"
  echo "[reset] Done (host-only)."
  exit 0
fi

# ── 2. Wipe host state ────────────────────────────────────────────────────────

if [ -d "$WORKDIR" ]; then
  echo "[reset] Removing $WORKDIR ..."
  rm -rf "$WORKDIR"
else
  echo "[reset] $WORKDIR already absent"
fi

# ── 3. Kill in-VM processes + delete the VM (best-effort) ───────────────────
# Applied to the primary VM and, if named, the --extra-node VM — see the
# --extra-node usage note above for why the extra node must not be skipped.

# SIGKILL is not synchronous: 'kill -0 $pid' checked immediately after
# 'kill -9 $pid' can still report the PID alive for a brief moment before the
# kernel finishes tearing the process down (confirmed live), which would
# otherwise make teardown_vm() spuriously fail a reset that actually worked.
# Poll briefly before concluding the kill genuinely failed.
pid_still_alive_after_kill() {
  local pid="$1"
  for _ in 1 2 3 4 5; do
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.2
  done
  kill -0 "$pid" 2>/dev/null
}

teardown_vm() {
  local vm="$1"
  local vm_dir="${HOME}/.lima/${vm}"
  local ha_pidfile="${vm_dir}/ha.pid"
  local ha_sock="${vm_dir}/ha.sock"

  # Capture the hostagent PID *before* delete, not after: a hostagent spawned
  # by a LATER provisioning step overwrites this same pidfile with its own
  # PID, so reading it post-delete can silently point at the wrong (new,
  # innocent) process instead of the one we're actually trying to reap.
  local ha_pid=""
  if [ -f "$ha_pidfile" ]; then
    ha_pid="$(cat "$ha_pidfile")"
  fi

  if limactl list --format '{{.Name}}' 2>/dev/null | grep -q "^${vm}$"; then
    local vm_status
    vm_status="$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | awk "/^${vm} / {print \$2}")"
    if [ "$vm_status" = "Running" ]; then
      echo "[reset] Stopping processes inside $vm VM ..."
      # limactl shell connects as the unprivileged 'lima' user; kubelet and
      # kube-controller-manager run as root in the guest, so a plain pkill
      # fails with "Operation not permitted" and never actually kills them
      # (confirmed live — 'sudo' is required here, not optional hardening).
      # '|| true' tolerates pkill's exit 1 ("no matching process"), which is
      # the normal case when a component already died or was never started;
      # stderr is left visible so a real sudo/permission regression shows up.
      limactl shell "$vm" sudo pkill -f kubelet                || true
      limactl shell "$vm" sudo pkill -f kube-controller-manager || true
      limactl shell "$vm" sudo pkill -f sonobuoy                || true
    else
      echo "[reset] $vm VM exists but is not running (status: $vm_status) — skipping in-VM kill"
    fi
  else
    echo "[reset] $vm VM does not exist — skipping in-VM kill"
  fi

  echo "[reset] Deleting $vm VM (full disk wipe) ..."
  # No '|| true': 'limactl delete --force' on an already-absent VM exits 0
  # with just a warning (confirmed live), so a nonzero exit here is a real
  # failure and 'set -e' should abort the reset rather than let a stale VM
  # silently linger with the next run's fresh CA layered on top of it.
  limactl delete --force "$vm"

  # 'limactl delete --force' is not reliable about actually terminating the
  # underlying hostagent OS process: it can survive, get reparented to
  # launchd, and keep squatting on the VM's forwarded kubelet port for hours
  # across later --reset cycles (confirmed live) — every exec/log/attach call
  # then silently hits the zombie's stale, now-CA-mismatched cert instead of
  # the freshly-provisioned guest, while everything else looks clean. Verify
  # the PID captured above is actually dead; if not, kill it and re-verify.
  if [ -n "$ha_pid" ] && kill -0 "$ha_pid" 2>/dev/null; then
    echo "[reset]   hostagent PID $ha_pid for $vm survived 'limactl delete' — killing it"
    # '|| true': tolerates the tiny race where the process dies between the
    # kill -0 check above and this kill -9; the re-check below still catches
    # a genuine failure to kill.
    kill -9 "$ha_pid" 2>/dev/null || true
    if pid_still_alive_after_kill "$ha_pid"; then
      echo "[reset] ERROR: hostagent PID $ha_pid for $vm still alive after SIGKILL" >&2
      return 1
    fi
  fi

  # Backstop beyond the pidfile: search by the VM's own socket path for any
  # other stray 'limactl hostagent' process still bound to it (e.g. one whose
  # PID was never in ha.pid to begin with). Match the full socket path, not a
  # bare VM-name substring — "lima-node" is a substring of "lima-node-2" and
  # "lima-node-3", so a name-only match could kill a sibling VM's hostagent.
  local stray_pids
  stray_pids="$(pgrep -f "limactl hostagent.*${ha_sock}" 2>/dev/null || true)"
  if [ -n "$stray_pids" ]; then
    echo "[reset]   found stray hostagent process(es) for $vm bound to $ha_sock — killing: $stray_pids"
    # shellcheck disable=SC2086 # word-split intentionally: pgrep can return multiple PIDs, one per line.
    kill -9 $stray_pids
    for p in $stray_pids; do
      if pid_still_alive_after_kill "$p"; then
        echo "[reset] ERROR: stray hostagent PID $p for $vm still alive after SIGKILL" >&2
        return 1
      fi
    done
  fi
}

teardown_vm "$VM_NAME"
if [ -n "$EXTRA_NODE" ]; then
  teardown_vm "$EXTRA_NODE"
fi

echo "[reset] Done. Run scripts/conformance/run-all.sh for a fresh conformance run."
