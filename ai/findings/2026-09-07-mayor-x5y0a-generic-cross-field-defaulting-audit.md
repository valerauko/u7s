Bead: mayor-x5y0a
Verdict: 3 confirmed gaps (2 HIGH, 1 MED) in a light scan of Pod/RC/LimitRange/Service — the
generic cross-field defaulting pattern is real beyond the two already-shipped instances, but it
is not yet dense enough (found in every checked type but only 1-2 per type) to declare a fully
systemic all-groups sweep mandatory right now. Recommend the two HIGH follow-ons land first;
defer a broader per-type audit unless a third HIGH-severity instance turns up outside core v1.

## Method

Fetched `pkg/apis/core/v1/defaults.go` at release-1.36 via `gh api` into
`temp/research/defaults.go` (not committed — scratch). Enumerated every `SetDefaults_*` rule that
reads one field to set another, then checked each against u7s's `apply_pod_spec_defaults`
(`crates/apiserver/src/handlers/pods.rs:5073`), `crates/apiserver/src/handlers/defaults.rs`, and
`crates/apiserver/src/limit_range.rs` via grep + Read (no LSP needed — plain-JSON admission code,
not a typed API most gaps sit in).

## Excluded (already shipped / in flight)

- `serviceAccountName <- serviceAccount` alias (pods.rs:5161-5177) — mayor-gktrw, shipped.
- Container `requests <- limits` per key (`SetDefaults_Pod`, defaults.go:164-192) — mayor-5igaz,
  in flight on a separate branch. Not touched or re-flagged here.

## Confirmed gaps

### 1. HIGH — hostNetwork pods never backfill `containerPort` into `hostPort`
`crates/apiserver/src/handlers/pods.rs` (`apply_pod_spec_defaults`, no hostPort assignment
anywhere in the function). Upstream rule: `SetDefaults_Pod` calls `defaultHostNetworkPorts()`
unconditionally when `spec.hostNetwork==true` (defaults.go:206-209, 397-406), copying each
container/init-container port's `containerPort` into `hostPort` wherever `hostPort==0`.

Confirmed downstream consequence, not just a hypothesis: the scheduler's NodePorts predicate
(`crates/scheduler/src/lib.rs`, `container_host_ports` ~line 281, test at ~line 9597-9617,
"a containerPort with no hostPort must not produce a hostPort claim") derives conflict claims
from `hostPort` only and does not special-case `hostNetwork`. Two `hostNetwork:true` pods with
the same `containerPort` and no explicit `hostPort` are therefore never detected as conflicting
and can be co-scheduled onto the same node — one fails at container start with "address already
in use". Follow-on: **mayor-v0kxc**.

### 2. HIGH — LimitRangeItem `default`/`defaultRequest` never backfilled from `max`/`min`
`crates/apiserver/src/limit_range.rs`: `parse_container_limit_items` (~line 128-148) reads
`item["default"]`/`item["defaultRequest"]`/`item["min"]`/`item["max"]` verbatim from the stored
LimitRange JSON with no chaining; `inject_defaults` (~line 161-227) only injects from
`item.default_limit`/`item.default_request`, never falling back to max/min. No LimitRange
create/update defaulting function exists anywhere in `crates/apiserver/src` (grepped `defaults.rs`
and the whole crate). Upstream `SetDefaults_LimitRangeItem` (defaults.go:360-390) chains three
per-key defaults on every stored Container-type LimitRangeItem: `default <- max` (if unset),
then `defaultRequest <- default` (post max-fill, if unset), then `defaultRequest <- min` (if still
unset).

Effect: a LimitRange specifying only `max` (a common minimal-governance pattern — cap cpu without
restating a default) injects nothing into pods that omit resources, where upstream would inject
`limit=max` (and a chained request). A LimitRange specifying only `min` silently loses the
`defaultRequest<-min` backfill too. This defeats operator intent without any error. Follow-on:
**mayor-7n1b4**.

### 3. MED — ReplicationController `metadata.labels` never backfilled from template labels
`crates/apiserver/src/handlers/defaults.rs` (`default_replicationcontroller`, ~line 387-408)
implements only the `spec.selector <- template.metadata.labels` half of upstream
`SetDefaults_ReplicationController` (defaults.go:50-65); the second half —
`obj.Labels <- labels` when the RC's own top-level labels are empty — has no equivalent (no
`obj["metadata"]["labels"]` write in the function). Lower severity than #1/#2: it affects
introspection (`kubectl get rc --show-labels`, a Service/NetworkPolicy selecting by the RC's own
labels) rather than pod scheduling/matching — the load-bearing selector half is already correct.
Follow-on: **mayor-elasq**.

## Checked, no gap found

- Container `imagePullPolicy <- image tag` (`SetDefaults_Container`) — implemented, pods.rs:5287-5295.
- Service `ports[].targetPort <- port` (`SetDefaults_Service`) — implemented, defaults.rs:3802-3863.
- Service `sessionAffinityConfig` timeout default on ClientIP — implemented, defaults.rs:506-530.
- ReplicaSet/StatefulSet/Deployment `spec.selector <- template.metadata.labels` — implemented
  (defaults.rs:1058-1247), same pattern as RC's selector half.
- PersistentVolume/PersistentVolumeClaim `SetDefaults_*` — no cross-field rules exist upstream
  (VolumeMode default is a fixed constant, not derived from another field).

## Deferred (not filed as follow-ons — noted for future reference only)

- `Volume.image.pullPolicy <- image tag` (`SetDefaults_Volume`) — gated behind the alpha
  `ImageVolume` feature; low usage, defer until that feature is otherwise prioritized.
- `NodeStatus.allocatable <- capacity` (`SetDefaults_NodeStatus`) — in practice the kubelet always
  sets both fields together on every status PUT, so this upstream fallback is rarely exercised;
  low risk without a concrete failure path.
- Pod-level `defaultHugePagePodLimits`/`defaultPodRequests` (`PodLevelResources` feature,
  defaults.go:423-527) — alpha-gated pod-level `spec.resources` aggregation from containers; would
  need its own scoping pass to confirm whether `spec.resources` is even modeled in u7s's `types.rs`
  before this is actionable.

## Follow-on beads

- mayor-v0kxc — hostNetwork hostPort backfill (HIGH)
- mayor-7n1b4 — LimitRangeItem default/defaultRequest chain (HIGH)
- mayor-elasq — RC metadata.labels backfill (MED)
