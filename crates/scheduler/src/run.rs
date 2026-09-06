/// The scheduler's watch/schedule loop, callable both from `u7s-scheduler`'s own thin
/// `main.rs` binary shell and — embedded — from `u7s-apiserver`'s `run()` (see
/// `crates/apiserver/src/lib.rs`, `--embedded-scheduler`). Extracted out of
/// `main.rs` into the lib target for exactly that reason: a binary's `main()` cannot be
/// called as a library function, but `run_scheduler` here can be `tokio::spawn`ed inside
/// another process's own runtime.
///
/// Watches ALL pods cluster-wide via a long-poll watch on the API server: an
/// unscheduled pod (spec.nodeName absent) enters the scheduling cycle below;
/// every other ADDED/MODIFIED/DELETED event instead feeds `NodeTally`, an
/// in-memory running tally of each node's committed resource usage that
/// `pick_node`/`find_preemption_plan` read instead of issuing a live GET per
/// candidate node. The scheduler picks the first available node and binds
/// via POST /api/v1/namespaces/:ns/pods/:name/binding.
///
/// When no node has free capacity, falls back to preemption: evicts
/// lower-priority pods to make room rather than leaving a higher-priority pod
/// Pending forever (see `find_preemption_plan`/`select_preemption_victims` in
/// lib.rs — pod-count, cpu/memory/ephemeral-storage, and extended resources
/// are all accounted for).
///
/// No leader election logic is implemented; `u7s-scheduler`'s `--leader-elect` flag is
/// accepted and silently ignored, and there is no embedded equivalent.
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use tokio_rustls::TlsConnector;
use tracing::{error, info};
use u7s_kubeconfig::{build_tls_connector, parse_kubeconfig};

use crate::{
    bind_pod, delete_pod, disruption_target_patch, emit_scheduling_event,
    failed_scheduling_status_patch, fetch_bound_pv_node_affinities, fetch_csi_volume_counts,
    fetch_node, fetch_read_write_once_pod_pvc_names, fetch_unbound_csi_pvc_drivers,
    find_preemption_plan, http_get, is_bind_already_assigned, needs_scheduling,
    nominated_node_name_patch, patch_pod_status, pick_node, pods_needing_resync,
    preemption_reservation_still_fits, scheduling_gate_status_patch, scheduling_gate_status_reset,
    should_retry_after_preemption_plan_error, should_retry_without_preempting, should_schedule,
    stamp_selected_node_for_pvcs, stream_watch_events, BindError, NodeTally, PendingPod, PodList,
};

/// Bind `pending` to `node`, which `pick_node` has already reserved in
/// `tally` atomically with its fit check (see `pick_node`'s doc comment for
/// why the reservation must not happen in a second, later lock acquisition
/// here instead). Rolls the reservation back if the bind itself fails, so a
/// failed bind never permanently overcounts `node`'s tallied usage — UNLESS
/// the bind was rejected as `BindError::AlreadyAssigned`: that means an
/// EARLIER, successful bind of this exact pod already claimed this
/// reservation, so it is already correct and must be left alone (removing it
/// here would under-count `node`'s real usage for a pod that is actually
/// running fine).
async fn bind_reserved_node(
    connector: &TlsConnector,
    server: &str,
    tally: &Mutex<NodeTally>,
    pending: &PendingPod,
    node: &str,
) -> Result<(), BindError> {
    // Stamp selected-node on any of `pending`'s unbound WaitForFirstConsumer
    // PVCs BEFORE the bind POST below, so external-provisioner sees the node
    // choice the instant the pod is bound rather than after (see
    // `stamp_selected_node_for_pvcs`'s doc comment).
    stamp_selected_node_for_pvcs(
        connector,
        server,
        &pending.namespace,
        &pending.pvc_names,
        node,
    )
    .await;
    if let Err(e) = bind_pod(
        connector,
        server,
        &pending.namespace,
        &pending.pod_name,
        node,
    )
    .await
    {
        if !is_bind_already_assigned(&e) {
            tally
                .lock()
                .expect("tally lock poisoned")
                .remove(&pending.namespace, &pending.pod_name);
        }
        return Err(e);
    }
    Ok(())
}

/// Maximum number of times `preempt_and_pick_node` re-plans preemption for
/// the same pending pod before giving up — bounds the retry below so a
/// pathological cluster that keeps recreating evicted pods can't stall this
/// pod's scheduling task forever.
const MAX_PREEMPTION_ATTEMPTS: u32 = 5;

/// Distinguishes, once `preempt_and_pick_node` gives up, a genuine
/// scheduling failure (`Fail` — no viable plan, or eviction itself failed;
/// worth a `FailedScheduling` event) from a run whose every attempt's
/// failure was `find_preemption_plan`'s own GET-nodes error (`Skip` — no
/// node was ever actually checked, so the pod should stay Pending for the
/// watch to retry instead of being marked unschedulable off a transient
/// infra hiccup). Mirrors `PickNodeError`'s `NoCapacity`/`ApiError` split,
/// but as its own type since the caller (`handle_pod_event`'s `outcome`
/// block) needs to fold this in alongside a plain bind failure, one level
/// deeper than where `PickNodeError` is consumed.
enum PreemptionFailure {
    Skip(anyhow::Error),
    Fail(anyhow::Error),
}

/// The outcome of one scheduling attempt's core decision in
/// `handle_pod_event`, controlling exactly when `key` may be released from
/// `in_flight`.
///
/// `Deferred` is the one variant that must NOT release it immediately:
/// `preempt_and_pick_node` returning `Ok(())` means victims have already been
/// evicted but the bind itself is deferred until `attempt_deferred_bind`
/// resolves it (see that function's doc comment) — releasing `in_flight`
/// here, before that resolution, is exactly the race that let a second,
/// independent scheduling attempt for the same still-Pending pod start,
/// preempt an unrelated bystander pod on a different node, and double-bind
/// the pod. `Skipped` and `Done` both represent an attempt that made no
/// lasting commitment beyond this point (a transient retry, or an outcome
/// worth reporting), so `key` is safe to release right away for either.
/// `Skipped` also covers a bind rejected as `BindError::AlreadyAssigned`
/// (see `bind_reserved_node`): the pod was already correctly bound by an
/// earlier attempt, so there is nothing left to report — no
/// Scheduled/FailedScheduling event, no PodScheduled patch — and the pod's
/// own `spec.nodeName` (already set from that earlier bind) keeps it out of
/// `needs_scheduling` on every future tick anyway.
enum SchedulingOutcome {
    Deferred,
    Skipped,
    Done(anyhow::Result<String>),
}

/// Plan preemption for `pending` and evict its victims, retrying up to
/// `MAX_PREEMPTION_ATTEMPTS` times if `find_preemption_plan`'s atomic
/// reservation loses to a fresher read.
///
/// Does NOT bind `pending` on success — only registers it as waiting for its
/// victims' real removal (see `NodeTally::register_preemption_waiter`). A
/// victim's graceful DELETE (see `delete_pod`'s doc comment) only stamps
/// `deletionTimestamp`; the real, out-of-process kubelet running it keeps the
/// container up, and the node's actual capacity occupied, until it finishes
/// tearing it down — live-reproduced at ~1.2s after the DELETE call returns.
/// Binding here, synchronously, is exactly what a live kubelet's own
/// admission check then rejects with `OutOfResource`, which sets a bare
/// Pod's `phase` to the terminal `Failed` — unrecoverable, since nothing
/// retries a pod once it leaves a non-terminal phase. `handle_pod_event`
/// instead attempts the deferred bind once `NodeTally::apply_event`'s
/// DELETED-branch hook confirms every victim is actually gone (see
/// `attempt_deferred_bind`).
///
/// `find_preemption_plan` reserves `pending` on the chosen node before this
/// function evicts anyone (see its doc comment for why: reserving only
/// AFTER eviction leaves a window where a third, concurrently-scheduled pod —
/// e.g. a controller's replacement for a pod just evicted — can repeatedly
/// claim each freed slot first; reproduced live against the
/// PreemptionExecutionPath conformance scenario, fast enough that even a
/// several-attempt "evict, then re-check" retry never won). So once a plan
/// comes back here, `pending`'s slot is already safely held — eviction
/// failing partway through is the only way this loop needs to retry, and if
/// it does, the reservation is rolled back first so the failed attempt does
/// not permanently strand that capacity.
async fn preempt_and_pick_node(
    connector: &TlsConnector,
    server: &str,
    pending: &PendingPod,
    tally: &Mutex<NodeTally>,
    namespace: &str,
    pod_name: &str,
) -> Result<(), PreemptionFailure> {
    let mut last_err: Option<PreemptionFailure> = None;
    for _ in 0..MAX_PREEMPTION_ATTEMPTS {
        let plan = match find_preemption_plan(pending, tally) {
            Ok(plan) => plan,
            Err(e) => {
                last_err = Some(if should_retry_after_preemption_plan_error(&e) {
                    PreemptionFailure::Skip(e.into())
                } else {
                    PreemptionFailure::Fail(e.into())
                });
                continue;
            }
        };
        info!(
            "preempting {} pod(s) on {} to schedule higher-priority pod {namespace}/{pod_name}",
            plan.victims.len(),
            plan.node_name
        );
        // Nominate BEFORE evicting anyone, matching upstream kube-scheduler's
        // nominate-then-evict-async ordering: a client polling this pod's
        // status.nominatedNodeName (e.g. SchedulerAsyncPreemption's e2e test)
        // must see it non-empty while eviction is still in flight, not only
        // once binding finally completes. Best-effort: a failed PATCH here
        // must not block the eviction itself, since freeing the slot for the
        // higher-priority pod matters more than the nomination annotation.
        if let Err(e) = patch_pod_status(
            connector,
            server,
            namespace,
            pod_name,
            &nominated_node_name_patch(&plan.node_name),
        )
        .await
        {
            error!(
                "failed to set nominatedNodeName={} on preempting pod {namespace}/{pod_name}: {e}",
                plan.node_name
            );
        }
        match evict_victims(connector, server, &plan.victims, tally, pod_name).await {
            Ok(()) => {
                // Every victim in `plan.victims` has had its graceful DELETE
                // acknowledged — NOT confirmed physically gone (see this
                // function's doc comment). Release the claim bookkeeping
                // `verify_and_reserve_preemption` set up (`pods_on` already
                // hides them via `tally.remove`, done inside `evict_victims`)
                // and defer the actual bind until `apply_event` observes each
                // victim's real removal.
                let mut guard = tally.lock().expect("tally lock poisoned");
                guard.release_victims(&plan.victims);
                guard.register_preemption_waiter(
                    pending.clone(),
                    plan.node_name.clone(),
                    &plan.victims,
                );
                return Ok(());
            }
            Err(e) => {
                // Unlike the success path, some of `plan.victims` may still
                // be real, un-evicted pods here — releasing their claim is
                // what matters: without it, they would stay excluded from
                // every future preemption plan's candidate pool forever,
                // even though nothing is actually still trying to evict them.
                let mut guard = tally.lock().expect("tally lock poisoned");
                guard.remove(&pending.namespace, &pending.pod_name);
                guard.release_victims(&plan.victims);
                last_err = Some(PreemptionFailure::Fail(e));
            }
        }
    }
    match last_err.expect("loop runs at least once, so this is always Some") {
        PreemptionFailure::Skip(e) => Err(PreemptionFailure::Skip(e)),
        PreemptionFailure::Fail(e) => Err(PreemptionFailure::Fail(e.context(
            "no node still fits after preemption, even after retrying \
             (capacity kept being claimed concurrently)",
        ))),
    }
}

/// Evict every pod in `victims` ("namespace/name" keys), stamping the
/// DisruptionTarget condition on each first (best-effort, mirrors upstream
/// kube-scheduler). Split out of `preempt_and_pick_node` so a mid-loop
/// eviction failure is a single `?` there, making the reservation-rollback
/// path easy to see.
async fn evict_victims(
    connector: &TlsConnector,
    server: &str,
    victims: &[String],
    tally: &Mutex<NodeTally>,
    pod_name: &str,
) -> anyhow::Result<()> {
    for victim in victims {
        let Some((v_ns, v_name)) = victim.split_once('/') else {
            continue;
        };
        // Best-effort: mirrors upstream kube-scheduler, which stamps
        // DisruptionTarget on the victim before deleting it. A patch
        // failure must not block the eviction itself — freeing the slot
        // for the higher-priority pod matters more than the condition.
        if let Err(e) = patch_pod_status(
            connector,
            server,
            v_ns,
            v_name,
            &disruption_target_patch(pod_name),
        )
        .await
        {
            error!(
                "failed to set DisruptionTarget condition on preemption victim {v_ns}/{v_name}: {e}"
            );
        }
        delete_pod(connector, server, v_ns, v_name).await?;
        tally
            .lock()
            .expect("tally lock poisoned")
            .remove(v_ns, v_name);
    }
    Ok(())
}

/// Attempt the bind `preempt_and_pick_node` deferred, once
/// `NodeTally::apply_event`'s DELETED-branch hook confirms every victim in
/// `pending`'s plan is actually gone (see `handle_pod_event`'s
/// `ready_deferred_binds` loop, the only caller).
///
/// Re-verifies `pending`'s reservation on `node_name` against the CURRENT
/// tally first (`preemption_reservation_still_fits`) — the plan may have
/// committed seconds ago, and a watch reconnect (`NodeTally::clear`) can
/// erase that reservation in the meantime, so this must never bind purely
/// because `PreemptionWaiters` says the plan's victims are gone (see that
/// function's doc comment for the concrete drift scenario this guards
/// against).
///
/// On a fit-check or bind failure, does NOT mark `pending` FailedScheduling
/// or emit any event — unlike a direct scheduling failure, this is not
/// `pending`'s last chance: it stays Pending, still `spec.nodeName`-empty, so
/// `pods_needing_resync` (see its doc comment) re-plans it from scratch
/// within `RESYNC_INTERVAL`, exactly as it would for any other stranded pod.
///
/// Releases `pending`'s key from `in_flight` once this resolves, whichever
/// way — this is the OTHER place (besides `handle_pod_event`'s own immediate
/// bind path) allowed to do so: `preempt_and_pick_node`'s `Ok(())` deliberately
/// leaves the key reserved so a second, independent scheduling attempt for
/// this same still-Pending pod can never start while this deferred bind is
/// outstanding — releasing it any earlier reproduces the exact race where
/// such a second attempt preempts a DIFFERENT node's innocent bystander pod
/// and the pod ends up bound twice.
async fn attempt_deferred_bind(
    connector: &TlsConnector,
    server: &str,
    tally: &Mutex<NodeTally>,
    in_flight: &Arc<Mutex<HashSet<String>>>,
    pending: PendingPod,
    node_name: String,
) {
    let key = format!("{}/{}", pending.namespace, pending.pod_name);
    async {
        let node = match fetch_node(tally, &node_name) {
            Some(node) => node,
            None => {
                info!(
                    "deferred bind for {key}: node {node_name} no longer exists — \
                     leaving pod Pending for the periodic resync to re-plan"
                );
                tally
                    .lock()
                    .expect("tally lock poisoned")
                    .remove(&pending.namespace, &pending.pod_name);
                return;
            }
        };
        if !preemption_reservation_still_fits(&pending, &node, tally) {
            info!(
                "deferred bind for {key}: reservation on {node_name} no longer fits \
                 (capacity drifted while waiting for the victim's real removal) — \
                 leaving pod Pending for the periodic resync to re-plan"
            );
            tally
                .lock()
                .expect("tally lock poisoned")
                .remove(&pending.namespace, &pending.pod_name);
            return;
        }
        info!(
            "deferred bind for {key}: every victim confirmed gone and fit re-verified — \
             attempting bind to {node_name}"
        );
        match bind_reserved_node(connector, server, tally, &pending, &node_name).await {
            Ok(()) => {
                let message = format!(
                    "Successfully assigned {}/{} to {node_name}",
                    pending.namespace, pending.pod_name
                );
                if let Err(e) = emit_scheduling_event(
                    connector,
                    server,
                    &pending.namespace,
                    &pending.pod_name,
                    "Scheduled",
                    &message,
                    "Normal",
                )
                .await
                {
                    error!("failed to emit Scheduled event for {key}: {e}");
                }
            }
            Err(e) => {
                error!(
                    "deferred bind failed for {key}: {e} — leaving pod Pending for \
                     the periodic resync to re-plan"
                );
            }
        }
    }
    .await;
    in_flight
        .lock()
        .expect("in_flight lock poisoned")
        .remove(&key);
}

/// How often the periodic resync (spawned in `run_scheduler`) re-lists `/api/v1/pods`
/// and re-attempts scheduling for anything still unscheduled, independent of
/// whatever the watch stream has delivered. Matches upstream kube-scheduler's
/// `flushUnschedulablePodsLeftover`, which runs on this same 30s cadence: a
/// pod that fails a scheduling attempt (e.g. exhausts preemption retries)
/// now gets its own `PodScheduled=False` status PATCH, which echoes back
/// through the watch and retries it almost immediately, but that PATCH is
/// itself best-effort and can be dropped by a transient failure — this
/// timer is the independent backstop that still catches such a pod even if
/// its own retry-triggering event never arrives.
const RESYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Path the periodic resync GETs on every `RESYNC_INTERVAL` tick.
///
/// Deliberately NOT `fieldSelector=spec.nodeName=`: the store's fast-path
/// field-selector match compares against SQL `json_extract`, which yields
/// SQL-NULL (never equal to anything, including `''`) for a pod whose
/// `spec.nodeName` key is entirely absent — and an unscheduled pod's
/// `nodeName` is always absent, never present-and-empty, because it's an
/// `Option<String>` with `skip_serializing_if` on the wire. A `nodeName=`
/// selector therefore matches zero pods in a real cluster, silently
/// disabling this resync's stranded-pod safety net. Every pod is listed
/// here and filtered in-process by `pods_needing_resync` instead, which
/// already handles the absent-vs-empty distinction correctly.
const RESYNC_PODS_PATH: &str = "/api/v1/pods";

/// Path for the scheduler's cluster-wide pod watch. `allowWatchBookmarks=true`
/// requests the apiserver's 60s bookmark heartbeat so `watch_stream`'s 5-min
/// per-frame idle timeout (`WATCH_IDLE_TIMEOUT` in `kubeconfig::lib`) never
/// trips on a healthy cluster that is simply quiet — without it, an idle
/// cluster forces a harmless but unnecessary reconnect every 5 minutes.
///
/// `sendInitialEvents=true` is load-bearing: this watch never carries a
/// `resourceVersion`, so the apiserver's default for a bare `resourceVersion`-
/// less watch is `from_revision=0` — which replays the store's raw
/// ring-buffer write history (every ADDED/MODIFIED write still retained),
/// NOT a snapshot of current state. Without `sendInitialEvents=true`, EVERY
/// (re)connect on this path — including the one the apiserver forces on any
/// open watch after its ~30-minute default `stream_timeout_secs` — replays
/// each pod's original, long-superseded creation event (`spec.nodeName`
/// still empty at that point in history) alongside its later bind. Because
/// `needs_scheduling` only ever looks at the event's own embedded object
/// body, it cannot tell that stale replayed ADDED apart from a genuinely new
/// unscheduled pod, and re-issues a bind for a pod that has been Running for
/// however long — wasted apiserver load and confusing 201/404 log noise,
/// every ~30 minutes, for the life of the scheduler process. With
/// `sendInitialEvents=true`, every (re)connect instead gets one ADDED event
/// per currently-existing pod reflecting its CURRENT `spec.nodeName`
/// (`fetch_initial_events`/`core_list_resource` LIST the store, they don't
/// replay history), so `needs_scheduling`'s already-scheduled check works
/// the same on a reconnect as it does on the live tail.
const POD_WATCH_PATH: &str =
    "/api/v1/pods?watch=true&allowWatchBookmarks=true&sendInitialEvents=true";

/// Cluster-wide watch paths feeding `NodeTally`'s PVC/PV/StorageClass/CSINode
/// caches (see `NodeTally::resolve_csi_driver`) — same
/// `allowWatchBookmarks=true&sendInitialEvents=true` rationale as
/// `POD_WATCH_PATH`'s doc comment.
const PVC_WATCH_PATH: &str =
    "/api/v1/persistentvolumeclaims?watch=true&allowWatchBookmarks=true&sendInitialEvents=true";
const PV_WATCH_PATH: &str =
    "/api/v1/persistentvolumes?watch=true&allowWatchBookmarks=true&sendInitialEvents=true";
const STORAGE_CLASS_WATCH_PATH: &str = "/apis/storage.k8s.io/v1/storageclasses?watch=true&allowWatchBookmarks=true&sendInitialEvents=true";
const CSI_NODE_WATCH_PATH: &str =
    "/apis/storage.k8s.io/v1/csinodes?watch=true&allowWatchBookmarks=true&sendInitialEvents=true";

/// Watch path feeding `NodeTally`'s node cache (`NodeTally::apply_node_event`)
/// — the same query params as `POD_WATCH_PATH`, for the same reason: this
/// replaces the live GET /api/v1/nodes `pick_node`/`find_preemption_plan`/
/// `fetch_node` used to issue once per scheduling decision, so it needs the
/// same "current state, not raw history" (`sendInitialEvents=true`) and
/// idle-reconnect (`allowWatchBookmarks=true`) guarantees that GET's
/// replacement now depends on.
const NODE_WATCH_PATH: &str =
    "/api/v1/nodes?watch=true&allowWatchBookmarks=true&sendInitialEvents=true";

/// Run one of the scheduler's secondary cache-maintenance watches (PVC/PV/
/// StorageClass/CSINode). Unlike the primary pod watch, these never trigger
/// scheduling directly — they only keep `NodeTally`'s CSI-driver-resolution
/// caches current, so `populate_csi_driver_headroom` can resolve a PVC's
/// backing driver synchronously (zero I/O) at scheduling-decision time
/// instead of a live GET chain per decision (see that function's doc
/// comment for why the live-GET version raced under concurrent scheduling).
///
/// `clear` runs before every (re)connect, including the first, for the same
/// reason `NodeTally::clear` runs on the pod watch's own reconnect: a delete
/// missed while disconnected would otherwise leave a phantom cache entry the
/// fresh `sendInitialEvents=true` relist never corrects (it only re-adds
/// what still exists).
///
/// `ready`, when given, is set to `true` the first time this watch's initial
/// `sendInitialEvents=true` relist completes (the apiserver's
/// `k8s.io/initial-events-end` BOOKMARK — see `is_initial_events_end_bookmark`)
/// — the readiness signal `run_scheduler`'s primary pod watch and periodic
/// resync loop both await before serving any scheduling decision, so a
/// restart with a pending-pod backlog never fail-safes every decision for
/// lack of cached nodes (see those await sites' own comments for the full
/// story).
async fn run_cache_watch_loop(
    connector: TlsConnector,
    server: String,
    tally: Arc<Mutex<NodeTally>>,
    path: &'static str,
    apply: fn(&mut NodeTally, &serde_json::Value),
    clear: fn(&mut NodeTally),
    ready: Option<tokio::sync::watch::Sender<bool>>,
) {
    loop {
        info!("starting cache watch on {path}");
        clear(&mut tally.lock().expect("tally lock poisoned"));
        let tally_ref = &tally;
        let mut synced = false;
        let result = stream_watch_events(&connector, &server, path, |event| {
            if !synced && is_initial_events_end_bookmark(&event) {
                synced = true;
                if let Some(ready) = &ready {
                    let _ = ready.send(true);
                }
            }
            apply(&mut tally_ref.lock().expect("tally lock poisoned"), &event);
        })
        .await;
        if let Err(e) = result {
            error!("cache watch on {path} error: {e} — reconnecting in 5s");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

/// True for the single synthetic BOOKMARK the apiserver sends to mark the end
/// of a `sendInitialEvents=true` relist (Kubernetes 1.27+ informer protocol —
/// see `crates/apiserver/src/handlers/watch.rs`). Distinct from an ordinary
/// watch bookmark (a bare resourceVersion heartbeat, no annotation): only
/// THIS one means "you have now seen every object that existed at connect
/// time," which is the signal `run_cache_watch_loop`'s `ready` barrier needs.
fn is_initial_events_end_bookmark(event: &serde_json::Value) -> bool {
    event["type"] == "BOOKMARK"
        && event["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"] == "true"
}

/// Periodic re-sync, independent of the primary pod watch: every
/// `RESYNC_INTERVAL`, re-list every still-unscheduled pod and feed it back
/// through `handle_pod_event`, exactly as a live watch event would. This is
/// what eventually retries a pod stranded by a failed scheduling attempt
/// (see `RESYNC_INTERVAL`'s doc comment for why the watch alone cannot be
/// relied on to do that).
///
/// `node_cache_synced_rx` gates the very first tick on the same node-cache
/// readiness signal `run_scheduler`'s primary pod watch awaits, for the same
/// reason: a tick that fired before the node cache's initial sync landed
/// would fail-safe every decision for lack of cached nodes, reproducing the
/// primary watch's own restart-backlog gap via this independent 30s timer
/// instead of a fresh connect. A function of its own (not inlined in
/// `run_scheduler`) so this gating can be exercised directly in a test
/// without also standing up the primary pod watch and every secondary cache
/// watch.
///
/// `interval` is always `RESYNC_INTERVAL` in production; a parameter only so
/// a test can shrink it to a few milliseconds instead of waiting out the
/// real 30s cadence to prove the gate holds across several ticks.
async fn run_resync_loop(
    connector: TlsConnector,
    server: String,
    in_flight: Arc<Mutex<HashSet<String>>>,
    tally: Arc<Mutex<NodeTally>>,
    mut node_cache_synced_rx: tokio::sync::watch::Receiver<bool>,
    interval: std::time::Duration,
) {
    if !*node_cache_synced_rx.borrow() {
        let _ = node_cache_synced_rx.changed().await;
    }
    loop {
        tokio::time::sleep(interval).await;
        let (status, body) = match http_get(&connector, &server, RESYNC_PODS_PATH).await {
            Ok(resp) => resp,
            Err(e) => {
                error!("resync: GET {RESYNC_PODS_PATH} failed: {e}");
                continue;
            }
        };
        if !status.is_success() {
            error!("resync: GET {RESYNC_PODS_PATH} returned {status}");
            continue;
        }
        let list: PodList = match serde_json::from_str(&body) {
            Ok(list) => list,
            Err(e) => {
                error!("resync: failed to parse pod list: {e}");
                continue;
            }
        };
        let in_flight_snapshot = in_flight.lock().expect("in_flight lock poisoned").clone();
        for event in pods_needing_resync(&list.items, &in_flight_snapshot) {
            handle_pod_event(event, &connector, &server, &in_flight, &tally);
        }
    }
}

/// Handle one pod watch event — a real one from the live watch, or a
/// synthetic `{"type": "MODIFIED", "object": ...}` manufactured by the
/// periodic resync loop from a fresh `/api/v1/pods` list (see
/// `RESYNC_INTERVAL`). Both callers feed events through this same function
/// so a resync-triggered scheduling attempt is handled identically to a
/// watch-triggered one — in particular, the `in_flight` dedup below is
/// shared between them, so a resync tick can never spawn a second,
/// concurrent `bind_pod` for a pod the watch is already scheduling.
fn handle_pod_event(
    event: serde_json::Value,
    connector: &TlsConnector,
    server: &str,
    in_flight: &Arc<Mutex<HashSet<String>>>,
    tally: &Arc<Mutex<NodeTally>>,
) {
    // Every pod in the cluster passes through here now (not just
    // unscheduled ones) so NodeTally can track already-bound pods'
    // resource usage. Must run unconditionally, before the
    // needs_scheduling early-return below, so a later event in this
    // same stream never reads a tally missing an earlier one.
    //
    // `ready_deferred_binds` are preemption plans (see
    // `preempt_and_pick_node`/`NodeTally::register_preemption_waiter`) whose
    // LAST awaited victim this exact event just confirmed physically gone —
    // attempt each one's bind now instead of waiting for the next resync.
    let ready_deferred_binds = tally
        .lock()
        .expect("tally lock poisoned")
        .apply_event(&event);
    for (pending, node_name) in ready_deferred_binds {
        let connector_clone = connector.clone();
        let server_clone = server.to_string();
        let tally_clone = tally.clone();
        let in_flight_clone = in_flight.clone();
        tokio::spawn(async move {
            attempt_deferred_bind(
                &connector_clone,
                &server_clone,
                &tally_clone,
                &in_flight_clone,
                pending,
                node_name,
            )
            .await;
        });
    }

    // A gated pod never enters the scheduling cycle below (needs_scheduling
    // returns None for it) — without this, its PodScheduled condition never
    // gets touched at all, and WaitForPodsSchedulingGated (which polls for
    // {type: PodScheduled, reason: SchedulingGated}, not just "unscheduled")
    // times out even though the pod correctly stays Pending.
    if let Some(gated) = scheduling_gate_status_patch(&event) {
        let connector_clone = connector.clone();
        let server_clone = server.to_string();
        tokio::spawn(async move {
            if let Err(e) = patch_pod_status(
                &connector_clone,
                &server_clone,
                &gated.namespace,
                &gated.pod_name,
                &gated.patch,
            )
            .await
            {
                error!(
                    "failed to set SchedulingGated status for {}/{}: {e}",
                    gated.namespace, gated.pod_name
                );
            }
        });
    }
    // Computed from this same event, before the pod potentially gets bound
    // below — cleared once bound (needs_scheduling's already_scheduled check
    // has no bearing here since this reads the same event, not a later one).
    let stale_gate_reset = scheduling_gate_status_reset(&event);

    let Some(pending) = needs_scheduling(&event) else {
        return;
    };

    let key = format!("{}/{}", pending.namespace, pending.pod_name);

    // Dedup: skip if a bind task for this pod is already in flight.
    {
        let mut guard = in_flight.lock().expect("in_flight lock poisoned");
        if !should_schedule(&guard, &key) {
            info!("skipping duplicate scheduling request for {key}");
            return;
        }
        guard.insert(key.clone());
    }

    info!(
        "unscheduled pod detected: {}/{}",
        pending.namespace, pending.pod_name
    );

    // Schedule asynchronously — spawn a task so we don't block the stream.
    let connector_clone = connector.clone();
    let server_clone = server.to_string();
    let in_flight_clone = in_flight.clone();
    let tally_clone = tally.clone();
    tokio::spawn(async move {
        let mut pending = pending;
        let namespace = pending.namespace.clone();
        let pod_name = pending.pod_name.clone();
        // Best-effort: clear the stale SchedulingGated reason before attempting
        // to schedule below. Not folded into `outcome` via `?` — a transient
        // failure here must not block the actual scheduling attempt that
        // follows, since getting the pod running matters more than tidying up
        // a status message.
        if let Some(reset) = stale_gate_reset {
            if let Err(e) = patch_pod_status(
                &connector_clone,
                &server_clone,
                &namespace,
                &pod_name,
                &reset,
            )
            .await
            {
                error!(
                    "failed to clear stale SchedulingGated status for {namespace}/{pod_name}: {e}"
                );
            }
        }
        // Resolve every already-bound PVC's PV nodeAffinity BEFORE the first
        // pick_node attempt below, so node_qualifies_for_pod can reject a
        // node that cannot actually mount the volume — without this, an
        // Immediate-mode (the StorageClass default) PVC's topology
        // constraint is never enforced, and the kubelet blocks forever on
        // `MountVolume.NodeAffinity check failed` once the scheduler commits
        // a bad bind. A lookup failure here is treated exactly like
        // pick_node's own GET /api/v1/nodes failure below: leave the pod
        // Pending for the next watch tick rather than schedule it as if the
        // bound PV had no topology constraint at all.
        if !pending.pvc_names.is_empty() {
            match fetch_bound_pv_node_affinities(
                &connector_clone,
                &server_clone,
                &namespace,
                &pending.pvc_names,
            )
            .await
            {
                Ok(affinities) => pending.pv_node_affinities = affinities,
                Err(e) => {
                    error!(
                        "could not resolve bound PVC node affinity while scheduling {namespace}/{pod_name}: {e} — retrying on next watch tick"
                    );
                    in_flight_clone
                        .lock()
                        .expect("in_flight lock poisoned")
                        .remove(&key);
                    return;
                }
            }
            // Same reasoning as the PV nodeAffinity resolution above, for the
            // CSILimits/NodeVolumeLimits predicate: without this, a pod whose
            // PVCs already resolve to a CSI driver never gets its per-driver
            // volume count populated, so `csi_volume_limits_fit` always sees
            // an empty want-set and the pod is bound even past the node's
            // advertised attach limit.
            match fetch_csi_volume_counts(
                &connector_clone,
                &server_clone,
                &namespace,
                &pending.pvc_names,
            )
            .await
            {
                Ok(counts) => pending.csi_volume_counts = counts,
                Err(e) => {
                    error!(
                        "could not resolve CSI volume counts while scheduling {namespace}/{pod_name}: {e} — retrying on next watch tick"
                    );
                    in_flight_clone
                        .lock()
                        .expect("in_flight lock poisoned")
                        .remove(&key);
                    return;
                }
            }
            // Same reasoning again, for the VolumeRestrictions/
            // ReadWriteOncePod predicate: without this, a pod's PVCs never
            // get checked for the ReadWriteOncePod access mode, so
            // `read_write_once_pod_conflict_free` always sees an empty
            // want-set and two pods can be bound onto the same node sharing
            // a volume Kubernetes guarantees at most one pod may use at a time.
            match fetch_read_write_once_pod_pvc_names(
                &connector_clone,
                &server_clone,
                &namespace,
                &pending.pvc_names,
            )
            .await
            {
                Ok(names) => pending.read_write_once_pod_pvcs = names,
                Err(e) => {
                    error!(
                        "could not resolve ReadWriteOncePod PVCs while scheduling {namespace}/{pod_name}: {e} — retrying on next watch tick"
                    );
                    in_flight_clone
                        .lock()
                        .expect("in_flight lock poisoned")
                        .remove(&key);
                    return;
                }
            }
            // Same reasoning again, for the CSI topology Filter: without
            // this, a pod's own unbound CSI-backed PVCs never get their
            // driver resolved, so `csi_topology_fit` always sees an empty
            // want-set and the scheduler can bind the pod to a node the
            // driver never registered — the AnyVolumeDataSource populate-pod
            // hang this predicate exists to close (see
            // `fetch_unbound_csi_pvc_drivers`'s doc comment).
            match fetch_unbound_csi_pvc_drivers(
                &connector_clone,
                &server_clone,
                &namespace,
                &pending.pvc_names,
            )
            .await
            {
                Ok(drivers) => pending.unbound_csi_pvc_drivers = drivers,
                Err(e) => {
                    error!(
                        "could not resolve unbound CSI PVC drivers while scheduling {namespace}/{pod_name}: {e} — retrying on next watch tick"
                    );
                    in_flight_clone
                        .lock()
                        .expect("in_flight lock poisoned")
                        .remove(&key);
                    return;
                }
            }
        }
        // Ok(node_name) on a successful bind, Err on any failure to schedule
        // (no node fits, even after preemption) or to bind. Distinguishing
        // the two lets us emit the matching Event below — without it,
        // `kubectl describe pod` and the SchedulerPredicates e2e suite's
        // observeEventAfterAction watch never see a Scheduled/FailedScheduling
        // event and the watch times out.
        let first_pick = pick_node(&pending, &tally_clone);
        if let Err(e) = &first_pick {
            if should_retry_without_preempting(e) {
                // A GET /api/v1/nodes failure (or an unparseable
                // response) says nothing about whether the cluster
                // actually has room — unlike a genuine NoCapacity,
                // treating it as one would run preemption (evicting
                // real lower-priority pods) or mark this pod
                // FailedScheduling off a transient infra hiccup.
                // Leave the pod Pending: the watch redelivers a
                // MODIFIED event for it, so pick_node simply runs
                // again on the next tick.
                error!(
                    "pick_node could not reach the API server while scheduling {key}: {e} — retrying on next watch tick"
                );
                in_flight_clone
                    .lock()
                    .expect("in_flight lock poisoned")
                    .remove(&key);
                return;
            }
        }
        // See `SchedulingOutcome` for why `Deferred` must NOT release `key`
        // from `in_flight` the way `Skipped`/`Done` do.
        let outcome: SchedulingOutcome = async {
            let node = match first_pick {
                Ok(node) => node,
                Err(no_capacity_err) => {
                    // No node has a free slot — try preemption before giving
                    // up: evict lower-priority pods to make room rather than
                    // leaving a higher-priority pod Pending forever.
                    match preempt_and_pick_node(
                        &connector_clone,
                        &server_clone,
                        &pending,
                        &tally_clone,
                        &namespace,
                        &pod_name,
                    )
                    .await
                    {
                        Ok(()) => {
                            // Victims evicted; the bind itself is deferred
                            // until `apply_event`'s DELETED-branch hook
                            // confirms they're actually gone (see
                            // `preempt_and_pick_node`'s doc comment and
                            // `attempt_deferred_bind`). Nothing to report
                            // yet — no Scheduled/FailedScheduling event, and
                            // `key` stays IN `in_flight`: `attempt_deferred_bind`
                            // is what releases it, once this deferred bind
                            // actually resolves.
                            return SchedulingOutcome::Deferred;
                        }
                        Err(PreemptionFailure::Skip(e)) => {
                            error!(
                                "find_preemption_plan could not reach the API server while scheduling {key}: {e} — retrying on next watch tick"
                            );
                            return SchedulingOutcome::Skipped;
                        }
                        Err(PreemptionFailure::Fail(preemption_err)) => {
                            // `find_preemption_plan`'s own failure text ("no
                            // node still fits after preemption...") says
                            // nothing about WHY no node worked in the first
                            // place — reporting the ORIGINAL `pick_node`
                            // failure instead preserves a predicate-specific
                            // reason (e.g. CSILimits' "node(s) exceed max
                            // volume count") that a conformance test's
                            // PodScheduled condition message may depend on,
                            // and is more actionable either way. Logged (not
                            // dropped) so the preemption-specific detail
                            // isn't lost entirely.
                            error!(
                                "preemption also failed while scheduling {key}: {preemption_err}"
                            );
                            return SchedulingOutcome::Done(Err(no_capacity_err.into()));
                        }
                    }
                }
            };
            match bind_reserved_node(&connector_clone, &server_clone, &tally_clone, &pending, &node)
                .await
            {
                Ok(()) => SchedulingOutcome::Done(Ok(node)),
                Err(e) if is_bind_already_assigned(&e) => {
                    // The apiserver rejected this bind because the pod is
                    // ALREADY correctly bound (an earlier bind of this exact
                    // pod already succeeded) — a benign no-op, not a
                    // scheduling failure. Do not patch PodScheduled=False or
                    // emit FailedScheduling onto a pod that is actually
                    // running fine, and do not roll back its tally
                    // reservation (see `bind_reserved_node`'s doc comment).
                    info!(
                        "bind for {key} rejected as already-assigned: {e} — pod is already \
                         correctly bound from an earlier bind; treating as a no-op, not a \
                         scheduling failure"
                    );
                    SchedulingOutcome::Skipped
                }
                Err(e) => SchedulingOutcome::Done(Err(e.into())),
            }
        }
        .await;

        let outcome = match outcome {
            // `key` stays in `in_flight` — `attempt_deferred_bind` releases
            // it once the deferred bind this pod is now waiting on resolves.
            SchedulingOutcome::Deferred => return,
            SchedulingOutcome::Skipped => {
                in_flight_clone
                    .lock()
                    .expect("in_flight lock poisoned")
                    .remove(&key);
                return;
            }
            SchedulingOutcome::Done(outcome) => {
                in_flight_clone
                    .lock()
                    .expect("in_flight lock poisoned")
                    .remove(&key);
                outcome
            }
        };

        let (reason, message, event_type) = match &outcome {
            Ok(node) => (
                "Scheduled",
                format!("Successfully assigned {namespace}/{pod_name} to {node}"),
                "Normal",
            ),
            Err(e) => {
                error!("scheduling error for {key}: {e}");
                let message = format!("{e}");
                // Best-effort, mirrors the DisruptionTarget/SchedulingGated
                // patches elsewhere in this file: the FailedScheduling Event
                // below is not enough on its own — upstream kube-scheduler
                // also patches the pod's own PodScheduled condition on every
                // failed cycle, which is what conformance waits actually poll.
                // None when the condition already reads this exact message
                // (see failed_scheduling_status_patch's doc comment) — a
                // pod that keeps failing identically must NOT keep
                // self-retriggering via its own PATCH's watch echo.
                if let Some(patch) = failed_scheduling_status_patch(&event, &message) {
                    if let Err(patch_err) = patch_pod_status(
                        &connector_clone,
                        &server_clone,
                        &namespace,
                        &pod_name,
                        &patch,
                    )
                    .await
                    {
                        error!("failed to set PodScheduled=False status for {key}: {patch_err}");
                    }
                }
                ("FailedScheduling", message, "Warning")
            }
        };
        if let Err(e) = emit_scheduling_event(
            &connector_clone,
            &server_clone,
            &namespace,
            &pod_name,
            reason,
            &message,
            event_type,
        )
        .await
        {
            error!("failed to emit {reason} event for {key}: {e}");
        }
    });
}

/// Run the scheduler's watch/schedule loop until the process is killed — this call never
/// returns `Ok`, only `Err` on a setup failure before the loop starts (a malformed
/// kubeconfig or a TLS connector that can't be built). Shared by `u7s-scheduler`'s own
/// `main()` and `u7s-apiserver`'s `--embedded-scheduler` task: both dial out over TLS to
/// `kubeconfig_path`'s server exactly the same way, rather than the apiserver wiring in
/// an in-process client — see the PR description for why that's the proportionate choice.
///
/// `server_override`, when set, replaces the server address `kubeconfig_path` itself
/// names (mirrors `u7s-scheduler --server`).
pub async fn run_scheduler(
    kubeconfig_path: &str,
    server_override: Option<&str>,
) -> anyhow::Result<()> {
    let mut creds = parse_kubeconfig(kubeconfig_path)?;
    if let Some(server_override) = server_override {
        info!("API server overridden to {server_override}");
        creds.server = server_override.to_string();
    }

    let server = creds.server.clone();
    info!("connecting to API server at {server}");

    let connector = build_tls_connector(&creds)?;

    // in_flight tracks pod keys ("namespace/name") for which a bind task is already
    // running. Two rapid ADDED/MODIFIED events for the same pod must not spawn two
    // concurrent bind_pod calls — the second would receive 409 Conflict from the API
    // server. The key is inserted before spawn and removed when the task finishes.
    let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    // The in-memory per-node resource tally pick_node/find_preemption_plan read
    // instead of a live GET fan-out (see NodeTally in lib.rs). Rebuilt from
    // scratch on every watch (re)connect below, since a fresh connect always
    // replays the full history the store still holds.
    let tally: Arc<Mutex<NodeTally>> = Arc::new(Mutex::new(NodeTally::default()));

    // `node_cache_synced` is the node watch's readiness barrier — see the
    // primary pod watch's own await on it further down for the full story on
    // why a scheduling decision must never be served before this fires. A
    // `watch` channel, not a `Notify`: both the resync loop below and that
    // later await are independent consumers of the same one-time transition
    // to "synced", and a `Notify::notify_one()` wakes at most one of them —
    // whichever happened to be waiting first would starve the other forever.
    // `watch` instead retains the current value, so each consumer's own
    // cloned receiver observes it correctly regardless of arrival order.
    let (node_cache_synced_tx, mut node_cache_synced_rx) = tokio::sync::watch::channel(false);

    // Periodic re-sync, independent of the watch stream below — see
    // `run_resync_loop`'s doc comment for what it does and why it is gated
    // on `node_cache_synced_rx` the same way the primary pod watch is.
    tokio::spawn(run_resync_loop(
        connector.clone(),
        server.clone(),
        in_flight.clone(),
        tally.clone(),
        node_cache_synced_rx.clone(),
        RESYNC_INTERVAL,
    ));

    // Secondary caches NodeTally maintains alongside the primary pod tally —
    // CSI-driver resolution (PVC/PV/StorageClass/CSINode) plus the node
    // informer cache pick_node/find_preemption_plan/fetch_node read instead
    // of a live GET /api/v1/nodes (see `run_cache_watch_loop`'s doc comment)
    // — each watched independently so one's reconnect never blocks the
    // others or the primary pod watch.
    //
    // `node_cache_synced_tx` (declared above, alongside the resync loop that
    // shares it) is notified below once, on the node watch's first
    // sendInitialEvents relist.
    for (path, apply, clear, ready) in [
        (
            PVC_WATCH_PATH,
            NodeTally::apply_pvc_event as fn(&mut NodeTally, &serde_json::Value),
            NodeTally::clear_pvc_cache as fn(&mut NodeTally),
            None,
        ),
        (
            PV_WATCH_PATH,
            NodeTally::apply_pv_event as fn(&mut NodeTally, &serde_json::Value),
            NodeTally::clear_pv_cache as fn(&mut NodeTally),
            None,
        ),
        (
            STORAGE_CLASS_WATCH_PATH,
            NodeTally::apply_storage_class_event as fn(&mut NodeTally, &serde_json::Value),
            NodeTally::clear_storage_class_cache as fn(&mut NodeTally),
            None,
        ),
        (
            CSI_NODE_WATCH_PATH,
            NodeTally::apply_csi_node_event as fn(&mut NodeTally, &serde_json::Value),
            NodeTally::clear_csi_node_cache as fn(&mut NodeTally),
            None,
        ),
        (
            NODE_WATCH_PATH,
            NodeTally::apply_node_event as fn(&mut NodeTally, &serde_json::Value),
            NodeTally::clear_node_cache as fn(&mut NodeTally),
            Some(node_cache_synced_tx.clone()),
        ),
    ] {
        tokio::spawn(run_cache_watch_loop(
            connector.clone(),
            server.clone(),
            tally.clone(),
            path,
            apply,
            clear,
            ready,
        ));
    }

    // Readiness barrier: block starting the pod watch (and therefore every
    // scheduling decision) until the node cache's initial sendInitialEvents
    // relist has landed. Without this, a scheduler restart with a pending-pod
    // backlog sees an empty node cache and pick_node fail-safes EVERY
    // decision — no wrong bind, but no progress either — until the node
    // watch's own reconnect loop eventually lands the list or the 30s
    // RESYNC_INTERVAL retries, whichever comes first. This wait is normally a
    // single network round-trip, not an indefinite stall: on any watch error
    // before the bookmark arrives, run_cache_watch_loop's own 5s-backoff
    // reconnect keeps retrying underneath it.
    info!("waiting for node cache initial sync before serving scheduling decisions");
    if !*node_cache_synced_rx.borrow() {
        let _ = node_cache_synced_rx.changed().await;
    }
    info!("node cache synced — starting pod watch");

    // Watch loop — reconnect on error with a short backoff.
    loop {
        info!("starting pod watch on {POD_WATCH_PATH}");
        let path = POD_WATCH_PATH;
        // Any preemption plan still waiting on a victim's real removal is
        // abandoned by this clear — release `in_flight` for each one too, or
        // a pod whose deferred bind can now never resolve (see
        // `attempt_deferred_bind`) would stay wrongly deduped forever instead
        // of being re-planned by the next watch tick or resync.
        let abandoned_deferred_binds = tally.lock().expect("tally lock poisoned").clear();
        if !abandoned_deferred_binds.is_empty() {
            let mut guard = in_flight.lock().expect("in_flight lock poisoned");
            for key in &abandoned_deferred_binds {
                info!(
                    "watch reconnect: releasing in_flight for {key} — its deferred \
                     preemption bind was abandoned; the fresh watch replay or periodic \
                     resync will re-plan it from scratch"
                );
                guard.remove(key);
            }
        }

        // Collect events; for each ADDED/MODIFIED pod with empty nodeName, schedule it.
        // We clone connector per loop iteration (cheap Arc clone inside).
        let connector_ref = &connector;
        let server_ref = &server;
        let in_flight_ref = &in_flight;
        let tally_ref = &tally;

        let result = stream_watch_events(connector_ref, server_ref, path, |event| {
            handle_pod_event(event, connector_ref, server_ref, in_flight_ref, tally_ref);
        })
        .await;

        if let Err(e) = result {
            error!("watch error: {e} — reconnecting in 5s");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResourceRequests;
    use serde_json::json;

    #[test]
    fn resync_pods_path_has_no_field_selector() {
        // A `fieldSelector=spec.nodeName=` here would ask the store to match
        // pods whose nodeName is SQL-equal to the empty string — but a real
        // unscheduled pod's nodeName key is entirely ABSENT (Option<String>
        // + skip_serializing_if), which the store's json_extract path reads
        // back as SQL NULL, never equal to anything. That selector matched
        // zero real pods, silently disabling this resync's stranded-pod
        // safety net. Every pod must be listed here and filtered in-process
        // instead (see `pods_needing_resync`).
        assert!(
            !RESYNC_PODS_PATH.contains("fieldSelector"),
            "resync must list the full pod collection, not filter server-side \
             on a selector the store cannot match against an absent field; \
             got: {RESYNC_PODS_PATH}"
        );
    }

    #[test]
    fn pod_watch_path_requests_allow_watch_bookmarks() {
        // Without allowWatchBookmarks=true, the apiserver never sends the 60s
        // bookmark heartbeat, so an idle-but-healthy cluster would trip
        // watch_stream's 5-min idle timeout and force a spurious reconnect
        // every 5 minutes. Losing this param would reintroduce that churn.
        assert!(
            POD_WATCH_PATH.contains("allowWatchBookmarks=true"),
            "pod watch path must request allowWatchBookmarks=true to avoid \
             spurious idle-timeout reconnects on a quiet cluster; got: {POD_WATCH_PATH}"
        );
    }

    #[test]
    fn pod_watch_path_requests_send_initial_events() {
        // This watch never carries a resourceVersion, so without
        // sendInitialEvents=true the apiserver's from_revision=0 default replays
        // raw ring-buffer write history on every (re)connect — including the one
        // the apiserver forces on every long-lived watch roughly every 30
        // minutes. That history includes each pod's ORIGINAL creation event
        // (spec.nodeName still empty at that point), which needs_scheduling
        // cannot tell apart from a genuinely new unscheduled pod: in production
        // this manifested as the scheduler re-issuing POST .../binding for
        // EVERY pod it had ever bound, roughly every 30 minutes, for the life
        // of the process — wasted apiserver load and confusing log noise on a
        // live cluster. sendInitialEvents=true makes a (re)connect relist
        // CURRENT pod state (one ADDED per pod, from a LIST) instead, so an
        // already-bound pod's ADDED event carries its real spec.nodeName and
        // needs_scheduling correctly skips it, the same as it does on the live
        // tail.
        assert!(
            POD_WATCH_PATH.contains("sendInitialEvents=true"),
            "pod watch path must request sendInitialEvents=true so a watch \
             reconnect relists CURRENT pod state instead of replaying stale \
             historical ADDED events for pods already bound; got: {POD_WATCH_PATH}"
        );
    }

    /// The 5 secondary cache-maintenance watch paths (PVC/PV/StorageClass/
    /// CSINode/Node) need the exact same two query params as
    /// `POD_WATCH_PATH`, for the exact same reasons (see its own two tests
    /// above): `allowWatchBookmarks=true` avoids a spurious reconnect every 5
    /// min on an idle cluster, and `sendInitialEvents=true` makes every
    /// (re)connect relist CURRENT state instead of replaying stale
    /// ring-buffer history — without it, `NodeTally::apply_pvc_event`/etc.
    /// would see each PVC/PV/StorageClass/CSINode/Node's original creation
    /// event on every ~30-min forced reconnect, which is harmless here
    /// (these events are idempotent upserts, unlike the pod watch's
    /// bind-reissue bug) but still wastes apiserver load for no reason.
    #[test]
    fn secondary_cache_watch_paths_request_bookmarks_and_initial_events() {
        for path in [
            PVC_WATCH_PATH,
            PV_WATCH_PATH,
            STORAGE_CLASS_WATCH_PATH,
            CSI_NODE_WATCH_PATH,
            NODE_WATCH_PATH,
        ] {
            assert!(
                path.contains("allowWatchBookmarks=true"),
                "cache watch path must request allowWatchBookmarks=true to \
                 avoid spurious idle-timeout reconnects on a quiet cluster; \
                 got: {path}"
            );
            assert!(
                path.contains("sendInitialEvents=true"),
                "cache watch path must request sendInitialEvents=true so a \
                 reconnect relists CURRENT state instead of replaying stale \
                 historical events; got: {path}"
            );
        }
    }

    /// Poll `cond` up to a 2s budget, yielding to the runtime between checks
    /// so the spawned tasks `handle_pod_event` fires off actually get to run
    /// on this test's single-threaded executor. Panics with `what` if the
    /// budget is exhausted — a hang here means the scheduling task this test
    /// is waiting on never made the progress it should have.
    async fn wait_until(mut cond: impl FnMut() -> bool, what: &str) {
        for _ in 0..400 {
            if cond() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    /// Regression for the node-cache readiness barrier in `run_scheduler`:
    /// without it, the pod watch loop starts in parallel with the node
    /// watch's own initial `sendInitialEvents=true` relist, so a restart
    /// with a pending-pod backlog can see the pod watch's ADDED events
    /// before a single node is cached — `pick_node` then fail-safes every
    /// one of them (no wrong bind, but no progress either) until the node
    /// watch's own reconnect eventually lands the list or the 30s
    /// RESYNC_INTERVAL retries. This test withholds the node watch's
    /// initial-events-end BOOKMARK (the sync signal) past when the pod
    /// watch would otherwise already be connected, and asserts the pod
    /// watch endpoint is never even DIALED until that BOOKMARK is released.
    /// Revert the `node_cache_synced.notified().await` barrier in
    /// `run_scheduler` and this test fails: the pod watch connects
    /// immediately, well before the release.
    #[tokio::test]
    async fn run_scheduler_defers_pod_watch_until_node_cache_initial_sync() {
        use rcgen::{CertificateParams, KeyPair, SanType};
        use rustls::pki_types::PrivateKeyDer;
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::sync::Notify;
        use tokio_rustls::TlsAcceptor;

        fn pem_encode(label: &str, der: &[u8]) -> String {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(der);
            let mut out = format!("-----BEGIN {label}-----\n");
            for chunk in b64.as_bytes().chunks(64) {
                out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
                out.push('\n');
            }
            out.push_str(&format!("-----END {label}-----\n"));
            out
        }

        fn initial_events_end_bookmark(kind: &str) -> serde_json::Value {
            json!({
                "type": "BOOKMARK",
                "object": {
                    "apiVersion": "v1",
                    "kind": kind,
                    "metadata": {
                        "resourceVersion": "1",
                        "annotations": {"k8s.io/initial-events-end": "true"}
                    }
                }
            })
        }

        async fn send_chunk(
            tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
            event: &serde_json::Value,
        ) {
            let mut line = event.to_string();
            line.push('\n');
            let chunk = format!("{:x}\r\n{line}\r\n", line.len());
            let _ = tls.write_all(chunk.as_bytes()).await;
            let _ = tls.flush().await;
        }

        // Server identity: self-signed, added directly to the client's trust
        // root below (mirroring every other mock server in this file) — no
        // separate CA needed since nothing here validates a chain, just this
        // exact leaf.
        let server_key = KeyPair::generate().expect("generate server key");
        let mut server_params = CertificateParams::default();
        server_params.subject_alt_names =
            vec![SanType::IpAddress("127.0.0.1".parse().expect("parse IP"))];
        let server_cert = server_params
            .self_signed(&server_key)
            .expect("self-sign server cert");
        let server_cert_der = server_cert.der().clone();
        let server_key_der = PrivateKeyDer::Pkcs8(server_key.serialize_der().into());

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert_der.clone()], server_key_der)
            .expect("server TLS config");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let port = listener.local_addr().unwrap().port();

        // build_tls_connector requires SOME client cert/key (mTLS), even
        // though the server above never asks for one (with_no_client_auth) —
        // any self-signed pair satisfies rustls's config builder.
        let client_key = KeyPair::generate().expect("generate client key");
        let client_cert = CertificateParams::default()
            .self_signed(&client_key)
            .expect("self-sign client cert");

        let kubeconfig_yaml = format!(
            "apiVersion: v1\n\
             kind: Config\n\
             clusters:\n\
             - cluster:\n\
             \x20   server: https://127.0.0.1:{port}\n\
             \x20   certificate-authority-data: {}\n\
             \x20 name: u7s\n\
             users:\n\
             - name: admin\n\
             \x20 user:\n\
             \x20   client-certificate-data: {}\n\
             \x20   client-key-data: {}\n",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                pem_encode("CERTIFICATE", &server_cert_der)
            ),
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                pem_encode("CERTIFICATE", client_cert.der())
            ),
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                client_key.serialize_pem()
            ),
        );
        let kubeconfig_path = std::env::temp_dir().join(format!(
            "u7s-scheduler-readiness-barrier-test-{}.yaml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&kubeconfig_path, &kubeconfig_yaml).expect("write temp kubeconfig");

        let pod_watch_connected = Arc::new(AtomicBool::new(false));
        let release_node_bookmark = Arc::new(Notify::new());

        {
            let pod_watch_connected = pod_watch_connected.clone();
            let release_node_bookmark = release_node_bookmark.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    let pod_watch_connected = pod_watch_connected.clone();
                    let release_node_bookmark = release_node_bookmark.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let mut buf = vec![0u8; 8192];
                        let mut total = 0usize;
                        loop {
                            let n = tls.read(&mut buf[total..]).await.unwrap_or(0);
                            if n == 0 {
                                return;
                            }
                            total += n;
                            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        let request = String::from_utf8_lossy(&buf[..total]);
                        let request_line = request.lines().next().unwrap_or("");
                        let path = request_line.split_whitespace().nth(1).unwrap_or("");

                        // Watch responses are unbounded streams — chunked
                        // transfer-encoding, exactly as the real apiserver's
                        // own hyper server picks for a body of unknown
                        // length (see crates/apiserver/src/handlers/watch.rs).
                        let _ = tls
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
                            )
                            .await;
                        let _ = tls.flush().await;

                        if path == POD_WATCH_PATH {
                            // Set BEFORE writing anything further: the
                            // property under test is whether this endpoint
                            // was ever dialed at all, not whether its relist
                            // round-trip completed.
                            pod_watch_connected.store(true, Ordering::SeqCst);
                            send_chunk(&mut tls, &initial_events_end_bookmark("Pod")).await;
                        } else if path == NODE_WATCH_PATH {
                            // Held back until the test releases it — this is
                            // what the readiness barrier is waiting on.
                            release_node_bookmark.notified().await;
                            send_chunk(&mut tls, &initial_events_end_bookmark("Node")).await;
                        } else {
                            // PVC/PV/StorageClass/CSINode: irrelevant to this
                            // test, synced immediately so their loops don't
                            // spam reconnects for the test's duration.
                            send_chunk(&mut tls, &initial_events_end_bookmark("Unrelated")).await;
                        }
                    });
                }
            });
        }

        let kubeconfig_path_string = kubeconfig_path.to_string_lossy().into_owned();
        tokio::spawn(async move {
            let _ = run_scheduler(&kubeconfig_path_string, None).await;
        });

        // Give every watch loop ample time to dial in and, for the four
        // paths that sync immediately, complete their relist — if the
        // barrier were missing, the pod watch would already be among them.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !pod_watch_connected.load(Ordering::SeqCst),
            "the pod watch must not connect before the node cache's initial sync completes — \
             connecting this early means a restart's pending-pod backlog can be fail-safed by \
             pick_node for lack of any cached node, exactly the regression this barrier exists \
             to prevent"
        );

        release_node_bookmark.notify_one();

        wait_until(
            || pod_watch_connected.load(Ordering::SeqCst),
            "the pod watch to connect promptly once the node cache's initial sync completes",
        )
        .await;

        let _ = std::fs::remove_file(&kubeconfig_path);
    }

    /// Regression for the resync loop's OWN readiness gate (see
    /// `run_resync_loop`'s doc comment): a revert that removed the gate from
    /// just this call site — while leaving the primary pod watch's identical
    /// barrier above untouched — would pass every test of the primary watch
    /// alone, so this drives `run_resync_loop` directly against a
    /// `watch::Receiver` this test controls, without the rest of
    /// `run_scheduler`'s watches involved at all.
    ///
    /// Runs with a millisecond-scale `interval` (see `run_resync_loop`'s
    /// `interval` parameter) instead of the real 30s `RESYNC_INTERVAL`, so a
    /// reverted (ungated) loop would fire several ticks — and dial the mock
    /// listener — well within this test's short real-time budget, instead of
    /// needing a genuine 30-second wait to prove the difference.
    #[tokio::test]
    async fn resync_loop_gates_on_node_cache_synced() {
        use rcgen::{CertificateParams, KeyPair};
        use rustls::pki_types::PrivateKeyDer;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let connect_count = Arc::new(AtomicUsize::new(0));
        {
            let connect_count = connect_count.clone();
            tokio::spawn(async move {
                // Each accepted connection is dropped immediately (out of
                // scope at the end of this block) — run_resync_loop's
                // http_get will fail the TLS handshake and log+continue,
                // exactly like any other transient resync error. All this
                // test needs is proof a connection was ever attempted.
                while let Ok((_tcp, _)) = listener.accept().await {
                    connect_count.fetch_add(1, Ordering::SeqCst);
                }
            });
        }

        // build_tls_connector requires SOME client cert/key (mTLS) and CA
        // cert, even though nothing here ever completes a handshake — any
        // self-signed pair satisfies rustls's config builder.
        let key = KeyPair::generate().expect("generate key");
        let cert = CertificateParams::default()
            .self_signed(&key)
            .expect("self-sign cert");
        let creds = u7s_kubeconfig::ClientCreds {
            server: format!("https://{addr}"),
            ca_cert: cert.der().clone(),
            client_cert: cert.der().clone(),
            client_key: PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        };
        let connector = build_tls_connector(&creds).expect("build connector");

        let (node_cache_synced_tx, node_cache_synced_rx) = tokio::sync::watch::channel(false);
        let in_flight = Arc::new(Mutex::new(HashSet::new()));
        let tally = Arc::new(Mutex::new(NodeTally::default()));
        tokio::spawn(run_resync_loop(
            connector,
            creds.server,
            in_flight,
            tally,
            node_cache_synced_rx,
            std::time::Duration::from_millis(10),
        ));

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            connect_count.load(Ordering::SeqCst),
            0,
            "the resync loop must not attempt its GET before the node cache's \
             initial sync completes — with a 10ms tick interval, 200ms is ample \
             time for a reverted (ungated) loop to have dialed out already; this \
             is the same fail-safe-every-decision gap the primary pod watch's \
             barrier closes, just reached via this independent timer instead of \
             a fresh connect"
        );

        node_cache_synced_tx
            .send(true)
            .expect("receiver still alive");
        wait_until(
            || connect_count.load(Ordering::SeqCst) > 0,
            "the resync loop to attempt its GET promptly once the node cache's \
             initial sync completes",
        )
        .await;
    }

    /// Regression for the exact race live-reproduced against
    /// `validates basic preemption works`/`validates lower priority pod
    /// preemption by critical pod`: `handle_pod_event` used to release a
    /// pod's `in_flight` key the instant `preempt_and_pick_node` returned
    /// `Ok(())` — the moment its victim's graceful DELETE was ISSUED, not the
    /// moment the pod actually got bound (which waits for the victim's real,
    /// kubelet-confirmed removal via `PreemptionWaiters`). A second,
    /// independent "unscheduled pod detected" tick for the SAME still-Pending
    /// pod arriving in that window used to sail straight past the dedup
    /// check, run its own preemption cycle, evict a completely unrelated
    /// bystander pod on a DIFFERENT node, and eventually double-bind the pod
    /// once both deferred binds resolved.
    ///
    /// Drives `handle_pod_event` itself (not a reimplementation of its
    /// logic) against a real in-process TLS mock server, exactly mirroring
    /// the production sequence: first tick evicts the legitimate victim and
    /// defers the bind; a second tick for the same pod arrives before that
    /// bind resolves; only then are both victims' real removals confirmed
    /// (as a live kubelet's DELETED watch events would). If the fix
    /// regresses, the second tick evicts the bystander and both deferred
    /// binds go on to succeed, corrupting two nodes' capacity accounting
    /// instead of one.
    #[tokio::test]
    async fn second_scheduling_attempt_for_same_pod_is_deduped_while_first_deferred_bind_pending() {
        use rcgen::{CertificateParams, KeyPair, SanType};
        use rustls::pki_types::PrivateKeyDer;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let key = KeyPair::generate().expect("generate key");
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().expect("parse IP"))];
        let cert = params.self_signed(&key).expect("self-sign cert");
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(key.serialize_der().into());

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server TLS config");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let port = listener.local_addr().unwrap().port();

        // Two single-victim-capacity nodes: "worker-0" hosts the legitimate
        // preemption victim, "worker-1" hosts an unrelated bystander that
        // must NEVER be touched if the second tick is correctly deduped.
        let delete_victim_count = Arc::new(AtomicUsize::new(0));
        let delete_bystander_count = Arc::new(AtomicUsize::new(0));
        let bind_count = Arc::new(AtomicUsize::new(0));
        let delete_victim_count_srv = delete_victim_count.clone();
        let delete_bystander_count_srv = delete_bystander_count.clone();
        let bind_count_srv = bind_count.clone();

        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let delete_victim_count = delete_victim_count_srv.clone();
                let delete_bystander_count = delete_bystander_count_srv.clone();
                let bind_count = bind_count_srv.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = vec![0u8; 8192];
                    let mut total = 0usize;
                    loop {
                        let n = tls.read(&mut buf[total..]).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        total += n;
                        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request = String::from_utf8_lossy(&buf[..total]);
                    let request_line = request.lines().next().unwrap_or("");
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or("");
                    let path = parts.next().unwrap_or("");

                    let body = r#"{"kind":"Status","status":"Success"}"#.to_owned();
                    if method == "DELETE" && path == "/api/v1/namespaces/default/pods/victim" {
                        delete_victim_count.fetch_add(1, Ordering::SeqCst);
                    } else if method == "DELETE"
                        && path == "/api/v1/namespaces/default/pods/bystander"
                    {
                        delete_bystander_count.fetch_add(1, Ordering::SeqCst);
                    } else if method == "POST" && path.ends_with("/binding") {
                        bind_count.fetch_add(1, Ordering::SeqCst);
                    }

                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.flush().await;
                });
            }
        });

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der).expect("add cert to root store");
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server = format!("https://127.0.0.1:{port}");

        let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let tally: Arc<Mutex<NodeTally>> = Arc::new(Mutex::new(NodeTally::default()));
        {
            let mut guard = tally.lock().expect("tally lock poisoned");
            // pick_node/find_preemption_plan read the node cache, not a live
            // GET — the mock server above serves no /api/v1/nodes route, so
            // seed it directly the way the node watch would.
            guard.apply_node_event(&json!({
                "type": "ADDED",
                "object": {"metadata": {"name": "worker-0"}, "status": {"allocatable": {"cpu": "1000m"}}}
            }));
            guard.apply_node_event(&json!({
                "type": "ADDED",
                "object": {"metadata": {"name": "worker-1"}, "status": {"allocatable": {"cpu": "1000m"}}}
            }));
            guard.assume(
                "default",
                "victim",
                "worker-0",
                0,
                ResourceRequests {
                    cpu_milli: 1000,
                    ..Default::default()
                },
                Vec::new(),
                std::collections::HashMap::new(),
                Vec::new(),
            );
            guard.assume(
                "default",
                "bystander",
                "worker-1",
                0,
                ResourceRequests {
                    cpu_milli: 1000,
                    ..Default::default()
                },
                Vec::new(),
                std::collections::HashMap::new(),
                Vec::new(),
            );
        }

        let pod_added_event = json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "preemptor", "namespace": "default"},
                "spec": {
                    "priority": 1000,
                    "containers": [{"resources": {"requests": {"cpu": "1000m"}}}]
                },
                "status": {}
            }
        });
        let deleted_event = |name: &str| {
            json!({
                "type": "DELETED",
                "object": {"metadata": {"name": name, "namespace": "default"}}
            })
        };

        // First tick: pick_node finds no room on either node, so this falls
        // to preemption, which evicts "victim" on worker-0 and defers the
        // bind. Wait for that eviction to actually land — this is the exact
        // "victims evicted, bind not yet attempted" window the race lived in.
        handle_pod_event(
            pod_added_event.clone(),
            &connector,
            &server,
            &in_flight,
            &tally,
        );
        wait_until(
            || delete_victim_count.load(Ordering::SeqCst) >= 1,
            "the first attempt's preemption to evict the legitimate victim",
        )
        .await;
        // Let the first attempt's task fully settle into its post-eviction
        // state (waiter registered, `in_flight` decision made) before racing
        // it — on real loopback this is comfortably sub-millisecond, so this
        // is generous, and it mirrors production's much larger real window.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // THE RACE: a second, independent watch tick for the SAME
        // still-unscheduled pod (spec.nodeName is still empty — the deferred
        // bind from the first tick has not landed yet). With the fix, `key`
        // is still in `in_flight` and this is deduped synchronously, right
        // here, before any network call. Without the fix, this spawns its
        // own preempt_and_pick_node cycle.
        handle_pod_event(pod_added_event, &connector, &server, &in_flight, &tally);

        // Give a would-be second preemption cycle (the bug) time to run to
        // completion against the in-process mock server — everything here is
        // loopback TLS with an instant response, so this is generous.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // Now confirm each victim's real removal, exactly as a live
        // kubelet's own DELETED watch event would — this is what resolves
        // whichever `PreemptionWaiters` plan(s) are actually outstanding.
        handle_pod_event(
            deleted_event("victim"),
            &connector,
            &server,
            &in_flight,
            &tally,
        );
        handle_pod_event(
            deleted_event("bystander"),
            &connector,
            &server,
            &in_flight,
            &tally,
        );
        wait_until(
            || bind_count.load(Ordering::SeqCst) >= 1,
            "the deferred bind to actually complete",
        )
        .await;
        // Drain a second, spurious deferred bind if the fix regressed.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        assert_eq!(
            delete_bystander_count.load(Ordering::SeqCst),
            0,
            "a second, undeduped scheduling attempt for the same still-Pending pod must never \
             run its own preemption cycle while the first attempt's deferred bind is \
             outstanding — evicting this innocent bystander pod is exactly the collateral \
             damage the race caused live"
        );
        assert_eq!(
            bind_count.load(Ordering::SeqCst),
            1,
            "the pod must be bound exactly once — a second successful bind means it was \
             double-scheduled onto two different nodes, corrupting both nodes' capacity \
             accounting"
        );
    }

    // bind-outcome classification tests — before `BindError::AlreadyAssigned`
    // existed, a bind rejected because the pod was ALREADY correctly bound
    // (e.g. by a stray duplicate bind attempt for a pod whose earlier bind
    // already succeeded) was folded into the exact same FailedScheduling
    // path as a genuine bind failure: `handle_pod_event` patched
    // PodScheduled=False, emitted FailedScheduling, and `bind_reserved_node`
    // rolled back the tally reservation that was still correctly counting
    // that pod's real usage — corrupting the status of a pod that was
    // actually running fine. Both tests below drive `handle_pod_event`
    // itself (not a reimplementation of its bind-outcome handling) against a
    // real in-process TLS mock server, exactly as
    // `second_scheduling_attempt_for_same_pod_is_deduped_while_first_deferred_bind_pending`
    // above does.

    /// How many times each side effect `handle_pod_event`'s bind-outcome
    /// handling must (or must not) trigger was recorded by
    /// `spawn_bind_outcome_mock_server` against.
    #[derive(Default)]
    struct BindOutcomeCounts {
        bind: std::sync::atomic::AtomicUsize,
        patch_status: std::sync::atomic::AtomicUsize,
        event: std::sync::atomic::AtomicUsize,
    }

    /// Spin up an in-process TLS mock server for the two bind-outcome tests
    /// below: answers every `POST .../binding` with `(bind_status,
    /// bind_body)`, and answers every other request with a bare 200 OK —
    /// while recording how many `POST .../binding`, `PATCH .../status`, and
    /// `POST .../events` calls it saw in the returned `BindOutcomeCounts`,
    /// which is what each test asserts on. Node candidates come from the
    /// caller seeding `NodeTally` directly (`pick_node` reads the node
    /// cache, not a live GET), not from anything this server serves.
    async fn spawn_bind_outcome_mock_server(
        bind_status: u16,
        bind_body: &'static str,
    ) -> (TlsConnector, String, Arc<BindOutcomeCounts>) {
        use rcgen::{CertificateParams, KeyPair, SanType};
        use rustls::pki_types::PrivateKeyDer;
        use std::sync::atomic::Ordering;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let key = KeyPair::generate().expect("generate key");
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().expect("parse IP"))];
        let cert = params.self_signed(&key).expect("self-sign cert");
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(key.serialize_der().into());

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server TLS config");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let port = listener.local_addr().unwrap().port();

        let counts = Arc::new(BindOutcomeCounts::default());
        let counts_srv = counts.clone();

        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let counts = counts_srv.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = vec![0u8; 8192];
                    let mut total = 0usize;
                    loop {
                        let n = tls.read(&mut buf[total..]).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        total += n;
                        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request = String::from_utf8_lossy(&buf[..total]);
                    let request_line = request.lines().next().unwrap_or("");
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or("");
                    let path = parts.next().unwrap_or("");

                    let (status_line, body): (String, String) =
                        if method == "POST" && path.ends_with("/binding") {
                            counts.bind.fetch_add(1, Ordering::SeqCst);
                            (format!("{bind_status} bind-response"), bind_body.to_owned())
                        } else if method == "PATCH" && path.ends_with("/status") {
                            counts.patch_status.fetch_add(1, Ordering::SeqCst);
                            (
                                "200 OK".to_owned(),
                                r#"{"kind":"Status","status":"Success"}"#.to_owned(),
                            )
                        } else if method == "POST" && path.ends_with("/events") {
                            counts.event.fetch_add(1, Ordering::SeqCst);
                            ("201 Created".to_owned(), r#"{"kind":"Event"}"#.to_owned())
                        } else {
                            (
                                "200 OK".to_owned(),
                                r#"{"kind":"Status","status":"Success"}"#.to_owned(),
                            )
                        };

                    let resp = format!(
                        "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.flush().await;
                });
            }
        });

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der).expect("add cert to root store");
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server = format!("https://127.0.0.1:{port}");

        (connector, server, counts)
    }

    /// One unscheduled pod, shared by both bind-outcome tests: no
    /// schedulingGates and no existing conditions, so `pick_node` reserves
    /// it on `worker-0` without any preemption or gating detour, isolating
    /// the test to the bind-outcome classification itself.
    fn bind_outcome_test_pod_event() -> serde_json::Value {
        json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "web-0", "namespace": "default"},
                "spec": {
                    "containers": [{"resources": {"requests": {"cpu": "100m"}}}]
                },
                "status": {}
            }
        })
    }

    #[tokio::test]
    async fn bind_rejected_as_already_assigned_is_treated_as_a_benign_no_op() {
        use std::sync::atomic::Ordering;

        // The exact 409 body the apiserver's own binding handler returns
        // when `spec.nodeName` is already set — see
        // `crates/apiserver/src/handlers/pods.rs`'s `bind_pod`.
        let (connector, server, counts) = spawn_bind_outcome_mock_server(
            409,
            r#"{"kind":"Status","status":"Failure","message":"Pod \"web-0\" is already assigned to node \"worker-0\"","reason":"Conflict","code":409}"#,
        )
        .await;

        let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let tally: Arc<Mutex<NodeTally>> = Arc::new(Mutex::new(NodeTally::default()));
        // pick_node reads the node cache, not a live GET — seed it directly
        // with a single node, or pick_node would see zero candidates and
        // never even attempt the bind this test means to exercise.
        tally
            .lock()
            .expect("tally lock poisoned")
            .apply_node_event(&json!({
                "type": "ADDED",
                "object": {"metadata": {"name": "worker-0"}, "status": {"allocatable": {"cpu": "1000m"}}}
            }));

        handle_pod_event(
            bind_outcome_test_pod_event(),
            &connector,
            &server,
            &in_flight,
            &tally,
        );
        wait_until(
            || counts.bind.load(Ordering::SeqCst) >= 1,
            "the bind attempt to reach the mock server",
        )
        .await;
        // Give a would-be PodScheduled patch or FailedScheduling event (the
        // bug this test guards against) time to fire against the mock
        // server before asserting they never did.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        assert_eq!(
            counts.patch_status.load(Ordering::SeqCst),
            0,
            "a bind rejected because the pod is ALREADY correctly bound elsewhere must never \
             patch PodScheduled=False — the pod's containers are actually running fine, and \
             this exact patch is what corrupted a live conformance run's PodScheduled status"
        );
        assert_eq!(
            counts.event.load(Ordering::SeqCst),
            0,
            "a bind rejected as already-assigned must never emit a FailedScheduling (or any \
             other) event — nothing about this pod's scheduling actually failed"
        );
        assert_eq!(
            tally
                .lock()
                .expect("tally lock poisoned")
                .pods_on("worker-0")
                .len(),
            1,
            "the tally reservation pick_node made for this pod must survive an \
             already-assigned bind rejection — it is already correctly counting this pod's \
             real usage from the earlier, successful bind, so removing it here would \
             under-count worker-0's real usage"
        );
    }

    #[tokio::test]
    async fn bind_rejected_for_another_reason_still_reports_failed_scheduling() {
        use std::sync::atomic::Ordering;

        // Regression guard for the SAME classification: a bind rejected for
        // any OTHER reason (here, a plain 500, not the "already assigned to
        // node" 409) must still be a genuine scheduling failure, exactly as
        // before `BindError::AlreadyAssigned` existed. Without this test, an
        // over-broadened classification could silently swallow a real
        // scheduling failure too.
        let (connector, server, counts) = spawn_bind_outcome_mock_server(
            500,
            r#"{"kind":"Status","status":"Failure","message":"internal error","reason":"InternalError","code":500}"#,
        )
        .await;

        let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let tally: Arc<Mutex<NodeTally>> = Arc::new(Mutex::new(NodeTally::default()));
        // pick_node reads the node cache, not a live GET — seed it directly
        // with a single node, or pick_node would see zero candidates and
        // never even attempt the bind this test means to exercise.
        tally
            .lock()
            .expect("tally lock poisoned")
            .apply_node_event(&json!({
                "type": "ADDED",
                "object": {"metadata": {"name": "worker-0"}, "status": {"allocatable": {"cpu": "1000m"}}}
            }));

        handle_pod_event(
            bind_outcome_test_pod_event(),
            &connector,
            &server,
            &in_flight,
            &tally,
        );
        wait_until(
            || counts.event.load(Ordering::SeqCst) >= 1,
            "the FailedScheduling event for a genuine bind failure",
        )
        .await;

        assert_eq!(
            counts.patch_status.load(Ordering::SeqCst),
            1,
            "a bind rejected for a genuine (non-already-assigned) reason must still patch \
             PodScheduled=False exactly as before — weakening this path for every OTHER bind \
             failure, not just the already-assigned no-op, would leave a truly unschedulable \
             pod's status stuck Pending forever"
        );
        assert_eq!(
            tally
                .lock()
                .expect("tally lock poisoned")
                .pods_on("worker-0")
                .len(),
            0,
            "a genuine bind failure must still roll back its tally reservation exactly as \
             before — otherwise worker-0's capacity accounting would overcount a pod that was \
             never actually bound"
        );
    }

    // stamp_selected_node_for_pvcs wiring — before this fix, u7s's scheduler
    // never stamped volume.kubernetes.io/selected-node on a pod's unbound
    // WaitForFirstConsumer PVCs at bind time, so external-provisioner (which
    // watches exactly that annotation to learn which node to provision a
    // topology-aware volume on) never saw any signal at all: the PVC stayed
    // Pending forever and the pod never left ContainerCreating. Drives
    // `handle_pod_event` itself (not a reimplementation of the bind-path
    // wiring) against a real in-process TLS mock server that also serves
    // PVC/StorageClass GETs, mirroring the bind-outcome tests above.

    /// What `spawn_volume_binding_mock_server` recorded: every PATCH's
    /// (path, body), and how many binds it saw — what the test below
    /// asserts on.
    #[derive(Default)]
    struct VolumeBindingRecorder {
        patches: std::sync::Mutex<Vec<(String, String)>>,
        bind_count: std::sync::atomic::AtomicUsize,
    }

    /// Spin up an in-process TLS mock server serving: two unbound PVCs,
    /// `data-pvc` (StorageClass `wfc-class`, WaitForFirstConsumer) and
    /// `cache-pvc` (StorageClass `immediate-class`, Immediate); those two
    /// StorageClasses' `volumeBindingMode`; and `POST .../binding` (counted,
    /// always 201 Created). Every PATCH is recorded (path + body) into the
    /// returned `VolumeBindingRecorder` rather than reasoned about here —
    /// the test itself decides which PATCHes should or should not exist.
    /// Node candidates come from the caller seeding `NodeTally` directly
    /// (`pick_node` reads the node cache, not a live GET), not from anything
    /// this server serves.
    async fn spawn_volume_binding_mock_server() -> (TlsConnector, String, Arc<VolumeBindingRecorder>)
    {
        use rcgen::{CertificateParams, KeyPair, SanType};
        use rustls::pki_types::PrivateKeyDer;
        use std::sync::atomic::Ordering;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let key = KeyPair::generate().expect("generate key");
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().expect("parse IP"))];
        let cert = params.self_signed(&key).expect("self-sign cert");
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(key.serialize_der().into());

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server TLS config");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let port = listener.local_addr().unwrap().port();

        let recorder = Arc::new(VolumeBindingRecorder::default());
        let recorder_srv = recorder.clone();

        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let recorder = recorder_srv.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = vec![0u8; 8192];
                    let mut total = 0usize;
                    let header_end = loop {
                        let n = tls.read(&mut buf[total..]).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        total += n;
                        if let Some(pos) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let request_line = head.lines().next().unwrap_or("");
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_owned();
                    let path = parts.next().unwrap_or("").to_owned();
                    // Needed to read the full PATCH body below — the initial
                    // read above may have captured only the headers if the
                    // body arrived in a later TCP segment.
                    let content_length: usize = head
                        .lines()
                        .find_map(|l| {
                            let (name, value) = l.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    while total < header_end + content_length {
                        let n = tls.read(&mut buf[total..]).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        total += n;
                    }
                    let body_end = (header_end + content_length).min(total);
                    let request_body =
                        String::from_utf8_lossy(&buf[header_end..body_end]).to_string();

                    let (status_line, resp_body): (String, String) = if method == "GET"
                        && path == "/api/v1/namespaces/default/persistentvolumeclaims/data-pvc"
                    {
                        (
                            "200 OK".to_owned(),
                            json!({"metadata": {"annotations": {}}, "spec": {"storageClassName": "wfc-class"}})
                                .to_string(),
                        )
                    } else if method == "GET"
                        && path == "/api/v1/namespaces/default/persistentvolumeclaims/cache-pvc"
                    {
                        (
                            "200 OK".to_owned(),
                            json!({"metadata": {"annotations": {}}, "spec": {"storageClassName": "immediate-class"}})
                                .to_string(),
                        )
                    } else if method == "GET"
                        && path == "/apis/storage.k8s.io/v1/storageclasses/wfc-class"
                    {
                        (
                            "200 OK".to_owned(),
                            json!({"volumeBindingMode": "WaitForFirstConsumer"}).to_string(),
                        )
                    } else if method == "GET"
                        && path == "/apis/storage.k8s.io/v1/storageclasses/immediate-class"
                    {
                        (
                            "200 OK".to_owned(),
                            json!({"volumeBindingMode": "Immediate"}).to_string(),
                        )
                    } else if method == "PATCH" {
                        recorder
                            .patches
                            .lock()
                            .expect("recorder lock poisoned")
                            .push((path.clone(), request_body));
                        (
                            "200 OK".to_owned(),
                            r#"{"kind":"PersistentVolumeClaim"}"#.to_owned(),
                        )
                    } else if method == "POST" && path.ends_with("/binding") {
                        recorder.bind_count.fetch_add(1, Ordering::SeqCst);
                        ("201 Created".to_owned(), r#"{"kind":"Binding"}"#.to_owned())
                    } else {
                        (
                            "200 OK".to_owned(),
                            r#"{"kind":"Status","status":"Success"}"#.to_owned(),
                        )
                    };

                    let resp = format!(
                        "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.flush().await;
                });
            }
        });

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der).expect("add cert to root store");
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server = format!("https://127.0.0.1:{port}");

        (connector, server, recorder)
    }

    #[tokio::test]
    async fn bind_stamps_selected_node_on_unbound_wait_for_first_consumer_pvc_only() {
        use std::sync::atomic::Ordering;

        let (connector, server, recorder) = spawn_volume_binding_mock_server().await;

        let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let tally: Arc<Mutex<NodeTally>> = Arc::new(Mutex::new(NodeTally::default()));
        // pick_node reads the node cache, not a live GET — seed it directly
        // with a single node, or pick_node would see zero candidates and
        // never bind this pod at all.
        tally
            .lock()
            .expect("tally lock poisoned")
            .apply_node_event(&json!({
                "type": "ADDED",
                "object": {"metadata": {"name": "worker-0"}, "status": {"allocatable": {"cpu": "1000m"}}}
            }));

        // web-0 references two PVCs directly: one whose StorageClass is
        // WaitForFirstConsumer (must be stamped once bound to worker-0), one
        // whose StorageClass is Immediate (must never be touched).
        let pod_event = json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "web-0", "namespace": "default"},
                "spec": {
                    "containers": [{"resources": {"requests": {"cpu": "100m"}}}],
                    "volumes": [
                        {"name": "data", "persistentVolumeClaim": {"claimName": "data-pvc"}},
                        {"name": "cache", "persistentVolumeClaim": {"claimName": "cache-pvc"}}
                    ]
                },
                "status": {}
            }
        });

        handle_pod_event(pod_event, &connector, &server, &in_flight, &tally);
        wait_until(
            || recorder.bind_count.load(Ordering::SeqCst) >= 1,
            "the pod bind to actually complete",
        )
        .await;
        // Give a spurious cache-pvc PATCH (the bug this test guards against)
        // time to land before asserting it never did.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let patches = recorder.patches.lock().expect("recorder lock poisoned");
        let data_pvc_patches: Vec<&(String, String)> = patches
            .iter()
            .filter(|(path, _)| path.ends_with("/persistentvolumeclaims/data-pvc"))
            .collect();
        let cache_pvc_patches: Vec<&(String, String)> = patches
            .iter()
            .filter(|(path, _)| path.ends_with("/persistentvolumeclaims/cache-pvc"))
            .collect();

        assert_eq!(
            data_pvc_patches.len(),
            1,
            "an unbound PVC whose StorageClass is WaitForFirstConsumer must be PATCHed exactly \
             once with the selected-node annotation at bind time — without this, \
             external-provisioner never learns which node to provision the volume on and the \
             PVC stays Pending forever"
        );
        assert!(
            data_pvc_patches[0]
                .1
                .contains(r#""volume.kubernetes.io/selected-node":"worker-0""#),
            "the PATCH body must set volume.kubernetes.io/selected-node to the bound node's \
             name; got {:?}",
            data_pvc_patches[0].1
        );
        assert!(
            cache_pvc_patches.is_empty(),
            "a PVC whose StorageClass is Immediate must never be stamped — it already has its \
             own non-topology-gated provisioning path, and stamping it anyway would just be a \
             dead write nothing ever reads"
        );
    }
}
