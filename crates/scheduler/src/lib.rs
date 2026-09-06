/// u7s-scheduler library — all non-main scheduling logic.
///
/// Extracted from main.rs so that pure functions can be unit-tested without
/// standing up an API server.
use anyhow::{bail, Context};
use hyper::{Method, StatusCode, Uri};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info};
use u7s_kubeconfig::HyperApiClient;

mod run;
/// The scheduler's watch/schedule loop as a callable library function — see
/// `run.rs` for why (`u7s-apiserver`'s `--embedded-scheduler` task calls this
/// directly).
pub use run::run_scheduler;

// ---------------------------------------------------------------------------
// HTTP helpers — delegates to HyperApiClient in kubeconfig.
// ---------------------------------------------------------------------------

/// Parse `base` + `path` into (host, port, "host:port") for TCP connect.
///
/// Pure function extracted so URI-parsing logic can be unit-tested without
/// network access.
pub fn parse_uri_parts(base: &str, path: &str) -> anyhow::Result<(String, u16, String)> {
    let uri: Uri = format!("{base}{path}").parse().context("parse URI")?;
    let host = uri.host().context("URI missing host")?.to_owned();
    let port = uri.port_u16().unwrap_or(443);
    let addr = format!("{host}:{port}");
    Ok((host, port, addr))
}

pub async fn http_get(
    connector: &TlsConnector,
    base: &str,
    path: &str,
) -> anyhow::Result<(StatusCode, String)> {
    let client = HyperApiClient {
        server: base.to_owned(),
        connector: connector.clone(),
        bearer: None,
    };
    client.request(Method::GET, path, None).await
}

pub async fn http_post_json(
    connector: &TlsConnector,
    base: &str,
    path: &str,
    payload: &Value,
) -> anyhow::Result<(StatusCode, String)> {
    let client = HyperApiClient {
        server: base.to_owned(),
        connector: connector.clone(),
        bearer: None,
    };
    let body_str = serde_json::to_string(payload)?;
    client.request(Method::POST, path, Some(body_str)).await
}

pub async fn http_delete(
    connector: &TlsConnector,
    base: &str,
    path: &str,
) -> anyhow::Result<(StatusCode, String)> {
    let client = HyperApiClient {
        server: base.to_owned(),
        connector: connector.clone(),
        bearer: None,
    };
    client.request(Method::DELETE, path, None).await
}

/// PATCH with `application/strategic-merge-patch+json`, the content type
/// status-subresource endpoints require (the apiserver's
/// `accepts_patch_content_type` rejects the plain `application/json` that
/// [`http_post_json`]/[`request`] send, with 415).
pub async fn http_patch_status(
    connector: &TlsConnector,
    base: &str,
    path: &str,
    payload: &Value,
) -> anyhow::Result<(StatusCode, String)> {
    let client = HyperApiClient {
        server: base.to_owned(),
        connector: connector.clone(),
        bearer: None,
    };
    let body_str = serde_json::to_string(payload)?;
    client
        .request_with_content_type(
            Method::PATCH,
            path,
            Some(body_str),
            "application/strategic-merge-patch+json",
        )
        .await
}

// ---------------------------------------------------------------------------
// Watch streaming — reads newline-delimited JSON from a watch endpoint
// ---------------------------------------------------------------------------

// Re-export drain_watch_buffer from kubeconfig so that:
// 1. The canonical implementation lives alongside watch_stream (which calls it).
// 2. Scheduler-level unit tests exercise the same function used in production,
//    not a separate copy.
pub use u7s_kubeconfig::drain_watch_buffer;

pub async fn stream_watch_events(
    connector: &TlsConnector,
    base: &str,
    path: &str,
    handler: impl FnMut(Value),
) -> anyhow::Result<()> {
    let client = HyperApiClient {
        server: base.to_owned(),
        connector: connector.clone(),
        bearer: None,
    };
    client.watch_stream(path, handler).await
}

// ---------------------------------------------------------------------------
// Scheduling logic
// ---------------------------------------------------------------------------

/// Typed envelope for a Kubernetes watch event.
///
/// Using a struct rather than raw `event["type"]` / `event["object"][...]`
/// indexing means a missing or mistyped field is a deserialization error,
/// not a silent empty string that causes pods to be skipped forever.
#[derive(Debug, Deserialize)]
struct WatchEvent<T> {
    #[serde(rename = "type")]
    event_type: String,
    object: T,
}

/// Local typed view of the fields in a Pod's `spec` that the scheduler reads.
/// Parsing at the boundary means a typo in `nodeName` is a compile error,
/// not a silent None that leaves pods unscheduled forever.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodSpec {
    node_name: Option<String>,
    node_selector: Option<std::collections::HashMap<String, String>>,
    /// Scheduling priority. Absent means the apiserver never resolved a
    /// priorityClassName to a value (or none was set) — treated as 0, the
    /// lowest rung, by `needs_scheduling`.
    priority: Option<i32>,
    /// Non-empty scheduling gates ("spec.schedulingGates") mean the pod is not
    /// yet ready to be considered for scheduling at all — a signal distinct
    /// from a predicate failure, managed by external controllers that PATCH
    /// gates away when the pod is ready. Only presence matters here; gate
    /// names are opaque to the scheduler.
    scheduling_gates: Option<Vec<Value>>,
    /// The pod's tolerations, gating which tainted nodes it may be bound to.
    tolerations: Option<Vec<Toleration>>,
    affinity: Option<Affinity>,
    /// The pod's containers, whose `resources.requests` are summed for the
    /// NodeResourcesFit predicate. Reused as-is by `PodListItem` (a pod
    /// already bound to a node) and `PreemptionPodListItem`.
    #[serde(default)]
    containers: Vec<ContainerSpec>,
    /// The pod's volumes — read for `referenced_pvc_names`'s selected-node
    /// stamping. `Option<Vec<_>>`, not a bare `Vec`, for the same reason as
    /// `ContainerSpec::ports`: a real apiserver response serializes an unset
    /// `volumes` as literal JSON `null`.
    #[serde(default)]
    volumes: Option<Vec<PodVolume>>,
    /// The pod's `spec.topologySpreadConstraints` — see `TopologySpreadConstraint`.
    #[serde(default)]
    topology_spread_constraints: Vec<TopologySpreadConstraint>,
    /// The pod's `spec.overhead` — cpu/memory/ephemeral-storage (plus any
    /// extended resource) that the apiserver's RuntimeClass admission plugin
    /// copies in from `RuntimeClass.overhead.podFixed` when the pod names a
    /// sandboxed runtime (e.g. gVisor/Kata). Added on top of
    /// `sum_container_requests` by `pod_total_requests` — without it, a
    /// sandboxed pod's true footprint is undercounted and its node can be
    /// over-subscribed.
    #[serde(default)]
    overhead: std::collections::HashMap<String, String>,
}

/// One `spec.volumes[]` entry — only the two sources that reference a PVC
/// (directly, or via an ephemeral volumeClaimTemplate) matter to
/// `referenced_pvc_names`; every other volume source is irrelevant to
/// selected-node stamping.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodVolume {
    name: String,
    #[serde(default)]
    persistent_volume_claim: Option<PersistentVolumeClaimVolumeSource>,
    /// Only presence is checked — an ephemeral volume's derived PVC name
    /// comes from `name` (see `referenced_pvc_names`), not from any field
    /// inside this value.
    #[serde(default)]
    ephemeral: Option<Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistentVolumeClaimVolumeSource {
    claim_name: String,
}

/// Minimal typed view of a container's `resources.requests` — cpu/memory/
/// ephemeral-storage quantity strings, as needed by NodeResourcesFit — plus
/// `ports`, as needed by the NodePorts predicate.
#[derive(Debug, Default, Deserialize)]
struct ContainerSpec {
    #[serde(default)]
    resources: ContainerResources,
    /// `containerPort` entries; only those with a nonzero `hostPort` are ever
    /// turned into a `HostPortClaim` by `container_host_ports` — a plain
    /// `containerPort` binds nothing on the node's own network namespace and
    /// can never conflict with another pod.
    ///
    /// `Option`, not a bare `Vec` with `#[serde(default)]`: a real apiserver
    /// response serializes an unset `ports` as literal JSON `null`, not an
    /// absent key, and `#[serde(default)]` only covers the latter — a bare
    /// `Vec<ContainerPortSpec>` here fails to deserialize `null` and (via
    /// `needs_scheduling`'s deserialize-error fallback) silently drops every
    /// such pod from the scheduling cycle, live-reproduced against a real
    /// conformance stack where sonobuoy's own pod (no `ports` set) never got
    /// scheduled at all. Mirrors `PodSpec`'s existing `tolerations`/
    /// `scheduling_gates`/`node_selector` fields, which use the same
    /// `Option<Vec<_>>` shape for exactly this reason.
    #[serde(default)]
    ports: Option<Vec<ContainerPortSpec>>,
}

#[derive(Debug, Default, Deserialize)]
struct ContainerResources {
    #[serde(default)]
    requests: std::collections::HashMap<String, String>,
}

/// One `container.ports[]` entry — only the fields the NodePorts predicate
/// needs (`containerPort`/`name` are irrelevant to host conflict detection).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContainerPortSpec {
    host_port: Option<i32>,
    /// `v1.ContainerPort`'s JSON field is the irregularly-cased `hostIP`
    /// (capital IP), not the `hostIp` that `rename_all = "camelCase"` would
    /// derive from `host_ip` — an explicit rename is required or this field
    /// silently never deserializes and every hostPort claim looks wildcard.
    #[serde(default, rename = "hostIP")]
    host_ip: String,
    protocol: Option<String>,
}

/// One `hostPort` claim derived from a pod's container ports — the
/// (hostPort, hostIP, protocol) tuple the NodePorts predicate conflicts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPortClaim {
    pub host_port: u16,
    /// Empty string is the wildcard, matching upstream's `v1.ContainerPort`
    /// default: it means "every interface on the host", and conflicts with
    /// ANY other hostIP claiming the same hostPort+protocol — see
    /// `host_ports_conflict`. Literal `"0.0.0.0"` means the same thing (the
    /// exact scenario the NodePorts conformance test exercises: one pod
    /// leaves hostIP empty, the other sets it to the node's real IP, and
    /// they must still be treated as conflicting).
    pub host_ip: String,
    /// Always upper-cased ("TCP"/"UDP"/"SCTP") — defaults to "TCP" to match
    /// `v1.ContainerPort`'s own default when `protocol` is omitted.
    pub protocol: String,
}

/// Extract every `hostPort`-claiming port across `containers` — ports with no
/// `hostPort`, or `hostPort <= 0`, bind nothing on the host and are skipped
/// (mirrors upstream `pkg/scheduler/util.GetHostPorts`'s `HostPort > 0` gate).
/// Init containers are not accounted for, matching `sum_container_requests`'s
/// existing MVP scope decision to sum only steady-state (regular) containers.
fn container_host_ports(containers: &[ContainerSpec]) -> Vec<HostPortClaim> {
    containers
        .iter()
        .filter_map(|c| c.ports.as_ref())
        .flatten()
        .filter(|p| p.host_port.is_some_and(|hp| hp > 0))
        .map(|p| HostPortClaim {
            host_port: p.host_port.unwrap_or(0) as u16,
            host_ip: p.host_ip.clone(),
            protocol: p.protocol.as_deref().unwrap_or("TCP").to_ascii_uppercase(),
        })
        .collect()
}

/// A pod's `spec.affinity`. `preferredDuringSchedulingIgnoredDuringExecution`
/// on `podAffinity`/`podAntiAffinity` is not modeled — it is a soft signal
/// upstream only weighs during scoring, and this scheduler does no scoring
/// (same reasoning `NodeAffinity` already documents for its own `preferred`
/// term).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Affinity {
    node_affinity: Option<NodeAffinity>,
    pod_affinity: Option<PodAffinity>,
    pod_anti_affinity: Option<PodAntiAffinity>,
}

/// A pod's `spec.affinity.nodeAffinity`. Only the `required` term is modeled —
/// `preferredDuringSchedulingIgnoredDuringExecution` is a soft signal upstream
/// only weighs during scoring, and this scheduler does no scoring.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeAffinity {
    pub required_during_scheduling_ignored_during_execution: Option<NodeSelectorSpec>,
}

/// The `nodeSelectorTerms` list inside a `requiredDuringSchedulingIgnoredDuringExecution`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSelectorSpec {
    #[serde(default)]
    pub node_selector_terms: Vec<NodeSelectorTerm>,
}

/// One term of a `NodeSelector`: its `matchExpressions` and `matchFields` are
/// ANDed together.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSelectorTerm {
    #[serde(default)]
    pub match_expressions: Vec<NodeSelectorRequirement>,
    /// Kubernetes only ever populates this with `metadata.name` — it's how the
    /// DaemonSet controller pins each per-node pod to a specific node while
    /// leaving `spec.nodeName` empty for the scheduler to fill in.
    #[serde(default)]
    pub match_fields: Vec<NodeSelectorRequirement>,
}

/// A single `matchExpressions[]` entry: `key <operator> values`.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeSelectorRequirement {
    pub key: String,
    pub operator: String,
    #[serde(default)]
    pub values: Vec<String>,
}

/// A `metav1.LabelSelector` (`podAffinityTerm.labelSelector`). `matchLabels`
/// and `matchExpressions` are ANDed together, and — matching real Kubernetes
/// semantics — a `None` selector matches NO pods (upstream's
/// `LabelSelectorAsSelector` turns a nil selector into `labels.Nothing()`),
/// while `Some` with both empty (an explicit `{}`) matches every pod.
///
/// `matchExpressions` reuses `NodeSelectorRequirement` rather than a new
/// near-identical type: `metav1.LabelSelectorRequirement` and
/// `v1.NodeSelectorRequirement` are wire-identical (`key`/`operator`/
/// `values`), and `node_selector_requirement_matches` already treats the
/// operators a label selector can legally use (`In`/`NotIn`/`Exists`/
/// `DoesNotExist`) correctly — label selectors never use `Gt`/`Lt`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelectorSpec {
    #[serde(default)]
    pub match_labels: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub match_expressions: Vec<NodeSelectorRequirement>,
}

/// One `requiredDuringSchedulingIgnoredDuringExecution[]` entry of a
/// `podAffinity`/`podAntiAffinity`. `namespaceSelector`/`matchLabelKeys`/
/// `mismatchLabelKeys` are not modeled — narrow refinements of which
/// namespaces/pods a term matches that the SchedulerPredicates gap this
/// closes does not exercise. A term relying ONLY on one of them (no
/// `namespaces`/`labelSelector` doing any of the real work) degrades to
/// never matching any pod rather than silently matching every pod, the same
/// fail-closed convention `node_selector_requirement_matches` uses for
/// `Gt`/`Lt`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodAffinityTerm {
    pub label_selector: Option<LabelSelectorSpec>,
    /// Namespace names this term applies to. Empty means "this pod's own
    /// namespace" — matches upstream's `PodAffinityTerm.Namespaces` default.
    #[serde(default)]
    pub namespaces: Vec<String>,
    #[serde(default)]
    pub topology_key: String,
}

/// A pod's `spec.affinity.podAffinity`. Only the `required` term list is
/// modeled — see `Affinity`'s doc comment for why `preferred` is out of
/// scope.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodAffinity {
    #[serde(default)]
    pub required_during_scheduling_ignored_during_execution: Vec<PodAffinityTerm>,
}

/// A pod's `spec.affinity.podAntiAffinity`. Only the `required` term list is
/// modeled — see `Affinity`'s doc comment for why `preferred` is out of
/// scope.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodAntiAffinity {
    #[serde(default)]
    pub required_during_scheduling_ignored_during_execution: Vec<PodAffinityTerm>,
}

/// One `spec.topologySpreadConstraints[]` entry: at most `maxSkew` pods may
/// separate the topology domain (grouped by `topologyKey`, e.g. a zone or
/// hostname) with the FEWEST pods matching `labelSelector` from the one with
/// the most — see `TopologySpreadContext` for the actual skew computation.
///
/// `minDomains`, `nodeAffinityPolicy`, `nodeTaintsPolicy`, and
/// `matchLabelKeys` are not modeled — newer, finer-grained knobs upstream
/// only uses to narrow which topology domains/pods take part in the spread
/// calculation at all. Omitting them defaults to upstream's own defaults
/// for each (`minDomains: 1`, `nodeAffinityPolicy: Honor`,
/// `nodeTaintsPolicy: Ignore` — i.e. every domain and every node counts,
/// matching this MVP's existing choice not to model node-inclusion policies
/// for inter-pod affinity either), not to "ignore the field silently
/// diverges from upstream's actual behavior" — the one exception being
/// `matchLabelKeys`, whose absence just means `labelSelector` alone decides
/// matching, exactly as if it were never set.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopologySpreadConstraint {
    #[serde(default)]
    pub max_skew: i32,
    #[serde(default)]
    pub topology_key: String,
    /// Upstream's Filter plugin only ever enforces `DoNotSchedule` terms —
    /// `ScheduleAnyway` terms feed its Score plugin instead, purely a
    /// placement PREFERENCE. This scheduler has no Score phase yet (mirrors
    /// `Affinity`'s doc comment for `preferred` affinity terms), so a
    /// `ScheduleAnyway` constraint is parsed but never filters a node — see
    /// `TopologySpreadContext::build`.
    #[serde(default)]
    pub when_unsatisfiable: String,
    pub label_selector: Option<LabelSelectorSpec>,
}

/// A pod's `spec.tolerations[]` entry.
///
/// `key: None` (with `operator: "Exists"`) tolerates every taint regardless of
/// key — the "tolerate everything" wildcard. `effect: None` tolerates a
/// matching key/value taint of any effect. Mirrors the upstream
/// `v1.Toleration` shape exactly so a typo in a JSON field is a deserialization
/// gap, not a silent always-false match.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Toleration {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub effect: Option<String>,
}

/// Minimal typed view of a Pod's metadata needed by the scheduler.
///
/// `labels` is shared by both consumers of this type: `PodObject` (a pod
/// being considered for scheduling — its own labels feed the inter-pod
/// affinity self-match bootstrap case, see `pod_affinity_satisfied`) and
/// `PreemptionPodListItem` (an already-bound pod `NodeTally` tracks — its
/// labels are what OTHER pending pods' podAffinity/podAntiAffinity terms
/// match against).
#[derive(Debug, Default, Deserialize)]
struct PodMetadata {
    name: Option<String>,
    namespace: Option<String>,
    #[serde(default)]
    labels: std::collections::HashMap<String, String>,
}

/// A single `status.conditions[]` entry, as needed to read back whatever
/// PodScheduled condition is currently stored — used by the SchedulingGated
/// status-patch bookkeeping (`scheduling_gate_status_patch` /
/// `scheduling_gate_status_reset`) and by `failed_scheduling_status_patch`
/// to decide whether a PATCH is still needed. `Option` (not `String` with
/// `#[serde(default)]`) because a condition field can be present-but-`null`,
/// not just absent — see `merge_conditions` in the apiserver, which can
/// persist a literal `null` reason on first write.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodConditionView {
    #[serde(rename = "type")]
    condition_type: Option<String>,
    status: Option<String>,
    reason: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PodStatusView {
    #[serde(default)]
    conditions: Vec<PodConditionView>,
}

/// Minimal typed view of a Pod object in a watch event.
#[derive(Debug, Default, Deserialize)]
struct PodObject {
    metadata: PodMetadata,
    spec: PodSpec,
    #[serde(default)]
    status: PodStatusView,
}

/// A pod discovered by `needs_scheduling` as ready to enter the scheduling
/// cycle, carrying every placement input the predicates need to gate node
/// selection. A struct (not a growing tuple) so each new predicate this
/// scheduler learns to enforce is a named field, not another `_` in a
/// destructure at every call site.
#[derive(Debug, Clone)]
pub struct PendingPod {
    pub namespace: String,
    pub pod_name: String,
    /// The pod's `spec.nodeSelector` map (empty if absent).
    pub node_selector: std::collections::HashMap<String, String>,
    /// The pod's `spec.priority`, defaulting to 0 (the lowest rung) when
    /// absent, so preemption has a value to compare even for pods that never
    /// had a priority resolved.
    pub priority: i32,
    /// The pod's `spec.tolerations` (empty if absent) — gates which tainted
    /// nodes it may be bound to.
    pub tolerations: Vec<Toleration>,
    /// The pod's `spec.affinity.nodeAffinity`, if any — gates which nodes it
    /// may be bound to by label, in addition to `node_selector`.
    pub node_affinity: Option<NodeAffinity>,
    /// The pod's own `metadata.labels` — read by inter-pod affinity's
    /// self-match bootstrap case (see `pod_affinity_satisfied`), which lets
    /// the very first replica of a self-referencing podAffinity workload
    /// (e.g. a StatefulSet whose pods affine to their own selector) actually
    /// get scheduled instead of waiting forever for a matching pod that can
    /// never exist until this one is placed.
    pub labels: std::collections::HashMap<String, String>,
    /// The pod's `spec.affinity.podAffinity.requiredDuringSchedulingIgnoredDuringExecution`
    /// terms (empty if absent) — every term must be satisfied by at least
    /// one already-tallied pod sharing the term's topology domain, see
    /// `pod_affinity_satisfied`.
    pub pod_affinity_terms: Vec<PodAffinityTerm>,
    /// The pod's `spec.affinity.podAntiAffinity.requiredDuringSchedulingIgnoredDuringExecution`
    /// terms (empty if absent) — a node is rejected if ANY already-tallied
    /// pod matching a term shares that term's topology domain with it, see
    /// `pod_anti_affinity_satisfied`.
    pub pod_anti_affinity_terms: Vec<PodAffinityTerm>,
    /// Summed `resources.requests.{cpu,memory,ephemeral-storage}` across the
    /// pod's containers — the NodeResourcesFit predicate's resource dimension.
    pub requests: ResourceRequests,
    /// Every `hostPort`-claiming container port across the pod's containers —
    /// the NodePorts predicate's conflict-detection dimension.
    pub host_ports: Vec<HostPortClaim>,
    /// PVC names this pod's volumes reference (direct or ephemeral-derived)
    /// — see `referenced_pvc_names`. Each is a candidate for
    /// `stamp_selected_node_for_pvcs`'s selected-node annotation once this
    /// pod is bound to a node.
    pub pvc_names: Vec<String>,
    /// The resolved `spec.nodeAffinity.required` selector of every PV already
    /// bound (Immediate-mode `spec.volumeName` set) to one of `pvc_names` —
    /// see `fetch_bound_pv_node_affinities`. Unlike every other field here,
    /// this is never populated by `needs_scheduling` itself (that runs
    /// synchronously off a single watch event, but resolving a bound PVC's PV
    /// needs its own GETs) — the caller fetches it once and fills it in right
    /// before the first `pick_node` attempt. Empty for a pod with no bound
    /// PVCs or whose bound PVs carry no `nodeAffinity`, which
    /// `node_qualifies_for_pod` then treats as "nothing to restrict on",
    /// exactly like an absent pod-level `nodeAffinity`.
    pub pv_node_affinities: Vec<NodeSelectorSpec>,
    /// The pod's `spec.topologySpreadConstraints` (empty if absent) — each
    /// `whenUnsatisfiable: DoNotSchedule` entry rejects a candidate node that
    /// would push its topology domain's skew beyond `maxSkew`, see
    /// `TopologySpreadContext`.
    pub topology_spread_constraints: Vec<TopologySpreadConstraint>,
    /// New CSI volumes this pod needs, grouped by driver name — the
    /// CSILimits/NodeVolumeLimits predicate's per-driver volume count. Like
    /// `pv_node_affinities`, never populated by `needs_scheduling` itself
    /// (resolving a PVC's driver via its bound PV or StorageClass needs its
    /// own GETs) — the caller fetches it once via `fetch_csi_volume_counts`
    /// and fills it in right before the first `pick_node` attempt. Empty for
    /// a pod with no PVC-backed volumes, or whose PVCs resolve to no CSI
    /// driver at all, which `csi_volume_limits_fit` then treats as "nothing
    /// to check" — the same convention `pv_node_affinities` uses.
    pub csi_volume_counts: std::collections::BTreeMap<String, i64>,
    /// Names of this pod's `pvc_names` that carry the `ReadWriteOncePod`
    /// access mode — the VolumeRestrictions predicate's exclusivity
    /// dimension: at most one pod cluster-wide may use such a PVC at a time.
    /// Like `pv_node_affinities`/`csi_volume_counts`, never populated by
    /// `needs_scheduling` itself (needs a PVC GET) — the caller fetches it
    /// once via `fetch_read_write_once_pod_pvc_names` and fills it in right
    /// before the first `pick_node` attempt. Empty for a pod with no RWOP
    /// PVCs, which `read_write_once_pod_conflict` then treats as "nothing to
    /// check".
    pub read_write_once_pod_pvcs: Vec<String>,
    /// CSI driver names this pod's OWN unbound PVCs still need
    /// dynamically provisioned — see `fetch_unbound_csi_pvc_drivers`.
    /// Like `pv_node_affinities`/`csi_volume_counts`/
    /// `read_write_once_pod_pvcs`, never populated by `needs_scheduling`
    /// itself (needs a PVC/StorageClass GET) — the caller fetches it once
    /// via `fetch_unbound_csi_pvc_drivers` and fills it in right before the
    /// first `pick_node` attempt. Empty for a pod with no unbound
    /// CSI-backed PVCs, which `csi_topology_fit` then treats as "nothing to
    /// check".
    pub unbound_csi_pvc_drivers: Vec<String>,
}

/// Determine whether a watch event represents a pod that needs scheduling.
///
/// Returns `Some(PendingPod)` when the event is an ADDED or MODIFIED pod with
/// an empty `spec.nodeName` and no non-empty `spec.schedulingGates`; `None`
/// otherwise. A non-empty `schedulingGates` list means the pod is not yet
/// ready to be considered for scheduling at all — it must never enter the
/// scheduling cycle, distinct from a predicate failure.
///
/// Extracted as a pure function so the decision can be unit-tested without
/// standing up an API server.
pub fn needs_scheduling(event: &Value) -> Option<PendingPod> {
    let event_type = event.get("type").and_then(Value::as_str).unwrap_or("");
    if event_type != "ADDED" && event_type != "MODIFIED" {
        return None;
    }
    needs_scheduling_pod(event.get("object")?)
}

/// The pod-level half of `needs_scheduling`'s decision, taking the pod object
/// itself rather than a `{"type": ..., "object": ...}` watch-event envelope.
///
/// Split out so `pods_needing_resync` can run this exact check against each
/// raw `/api/v1/pods` list item directly — without first paying to fabricate
/// a synthetic envelope Value around it just to satisfy `needs_scheduling`'s
/// signature. That fabrication is a full recursive clone of the pod (`json!`
/// wrapping a `Value` reference always deep-copies), so doing it for every
/// listed pod before deciding which ones even need it was the resync loop's
/// dominant allocation cost. Delegating both callers to this one function
/// keeps the live-watch and resync paths from ever diverging on what "needs
/// scheduling" means.
fn needs_scheduling_pod(pod: &Value) -> Option<PendingPod> {
    let object: PodObject = PodObject::deserialize(pod).unwrap_or_default();
    let pod_name = object.metadata.name.as_deref().unwrap_or("");
    if pod_name.is_empty() {
        return None;
    }
    let already_scheduled = object
        .spec
        .node_name
        .as_deref()
        .is_some_and(|n| !n.is_empty());
    if already_scheduled {
        return None;
    }
    let has_scheduling_gates = object
        .spec
        .scheduling_gates
        .as_ref()
        .is_some_and(|gates| !gates.is_empty());
    if has_scheduling_gates {
        // Gated pods must never enter the scheduling cycle — this is not a
        // predicate failure (no FailedScheduling event), it's "not ready yet".
        return None;
    }
    let namespace = object
        .metadata
        .namespace
        .unwrap_or_else(|| "default".to_owned());
    let labels = object.metadata.labels;
    let requests = pod_total_requests(&object.spec);
    let node_selector = object.spec.node_selector.unwrap_or_default();
    let priority = object.spec.priority.unwrap_or(0);
    let tolerations = object.spec.tolerations.unwrap_or_default();
    let affinity = object.spec.affinity;
    let pod_affinity_terms = affinity
        .as_ref()
        .and_then(|a| a.pod_affinity.as_ref())
        .map(|pa| {
            pa.required_during_scheduling_ignored_during_execution
                .clone()
        })
        .unwrap_or_default();
    let pod_anti_affinity_terms = affinity
        .as_ref()
        .and_then(|a| a.pod_anti_affinity.as_ref())
        .map(|paa| {
            paa.required_during_scheduling_ignored_during_execution
                .clone()
        })
        .unwrap_or_default();
    let node_affinity = affinity.and_then(|a| a.node_affinity);
    let host_ports = container_host_ports(&object.spec.containers);
    let pvc_names = referenced_pvc_names(pod_name, object.spec.volumes.as_deref().unwrap_or(&[]));
    let topology_spread_constraints = object.spec.topology_spread_constraints;
    Some(PendingPod {
        namespace,
        pod_name: pod_name.to_owned(),
        node_selector,
        priority,
        tolerations,
        node_affinity,
        labels,
        pod_affinity_terms,
        pod_anti_affinity_terms,
        requests,
        host_ports,
        pvc_names,
        pv_node_affinities: Vec::new(),
        topology_spread_constraints,
        csi_volume_counts: std::collections::BTreeMap::new(),
        read_write_once_pod_pvcs: Vec::new(),
        unbound_csi_pvc_drivers: Vec::new(),
    })
}

/// Every PVC name `pod_name`'s volumes reference — direct
/// (`persistentVolumeClaim.claimName`) or ephemeral-derived. Upstream's
/// ephemeral-volume controller always names an ephemeral volume's PVC
/// `<pod-name>-<volume-name>` (`pkg/controller/volume/ephemeral/controller.go`),
/// so that name can be derived here without ever reading the PVC itself.
fn referenced_pvc_names(pod_name: &str, volumes: &[PodVolume]) -> Vec<String> {
    volumes
        .iter()
        .filter_map(|v| {
            if let Some(pvc) = &v.persistent_volume_claim {
                Some(pvc.claim_name.clone())
            } else if v.ephemeral.is_some() {
                Some(format!("{pod_name}-{}", v.name))
            } else {
                None
            }
        })
        .collect()
}

/// Namespace-qualify a bare PVC name into the key `NodeTally`'s cross-pod,
/// cross-namespace aggregates (`TalliedPod`/`NodeUsage`/`NodePod`'s
/// `pvc_names`) use. A PVC name is only unique within its own namespace —
/// two unrelated PVCs in different namespaces may share a name — so any
/// collection that tallies PVC references across MULTIPLE pods (which may
/// span multiple namespaces) must key on this, not the bare name, or a
/// same-named PVC elsewhere in the cluster gets treated as the same volume.
fn pvc_key(namespace: &str, pvc_name: &str) -> String {
    format!("{namespace}/{pvc_name}")
}

/// The `PodScheduled` condition type name — matches `v1.PodScheduled`.
const POD_SCHEDULED: &str = "PodScheduled";
/// The reason upstream's real scheduler stamps on a gated pod — matches
/// `v1.PodReasonSchedulingGated`. `WaitForPodsSchedulingGated`
/// (k8s.io/kubernetes/test/e2e/framework/pod/wait.go) polls for exactly this
/// type/reason pair.
const SCHEDULING_GATED_REASON: &str = "SchedulingGated";
const SCHEDULING_GATED_MESSAGE: &str = "Scheduling is blocked due to non-empty scheduling gates";
/// The reason/message the apiserver stamps on every new pod's initial
/// PodScheduled=False condition (see `apply_pod_create_defaults`). Used to
/// reset a stale SchedulingGated reason back to the same "don't know why yet"
/// default the pod would have carried had it never been gated.
const UNSCHEDULABLE_REASON: &str = "Unschedulable";
const UNSCHEDULABLE_MESSAGE: &str = "pod not yet scheduled";

/// A pending PATCH to a gated pod's `status.conditions`, identifying the pod
/// and carrying the merge-patch body to send.
#[derive(Debug, PartialEq)]
pub struct GatedStatusPatch {
    pub namespace: String,
    pub pod_name: String,
    pub patch: Value,
}

/// Determine whether a watch event's pod needs its `PodScheduled` condition
/// set to `False`/`SchedulingGated`.
///
/// Mirrors the condition upstream's real kube-scheduler stamps on a gated pod
/// (see `v1.PodReasonSchedulingGated`) so `WaitForPodsSchedulingGated` — which
/// polls `status.conditions` for exactly `{type: PodScheduled, reason:
/// SchedulingGated}`, not just "is the pod unscheduled" — can tell "blocked on
/// gates" apart from a genuine predicate failure. `needs_scheduling` keeps
/// gated pods out of the scheduling cycle entirely, so nothing else ever
/// writes this condition for them.
///
/// Returns `None` (nothing to do) when: the pod has no non-empty
/// `schedulingGates` (ungated pods take the normal scheduling path instead);
/// the pod is already bound (`spec.nodeName` set — never touch a pod's
/// `PodScheduled` condition once binding may have flipped it to `True`); or
/// the condition already reads `False`/`SchedulingGated` (idempotent — avoids
/// re-PATCHing on every reconcile tick, including the tick triggered by this
/// function's own prior PATCH echoing back through the watch).
pub fn scheduling_gate_status_patch(event: &Value) -> Option<GatedStatusPatch> {
    let watch_event: WatchEvent<PodObject> = WatchEvent::<PodObject>::deserialize(event).ok()?;
    if watch_event.event_type != "ADDED" && watch_event.event_type != "MODIFIED" {
        return None;
    }
    let pod_name = watch_event.object.metadata.name.clone().unwrap_or_default();
    if pod_name.is_empty() {
        return None;
    }
    let already_scheduled = watch_event
        .object
        .spec
        .node_name
        .as_deref()
        .is_some_and(|n| !n.is_empty());
    if already_scheduled {
        return None;
    }
    let has_gates = watch_event
        .object
        .spec
        .scheduling_gates
        .as_ref()
        .is_some_and(|gates| !gates.is_empty());
    if !has_gates {
        return None;
    }
    let already_marked = watch_event.object.status.conditions.iter().any(|c| {
        c.condition_type.as_deref() == Some(POD_SCHEDULED)
            && c.status.as_deref() == Some("False")
            && c.reason.as_deref() == Some(SCHEDULING_GATED_REASON)
    });
    if already_marked {
        return None;
    }
    let namespace = watch_event
        .object
        .metadata
        .namespace
        .unwrap_or_else(|| "default".to_owned());
    let patch = serde_json::json!({
        "status": {
            "conditions": [{
                "type": POD_SCHEDULED,
                "status": "False",
                "reason": SCHEDULING_GATED_REASON,
                "message": SCHEDULING_GATED_MESSAGE,
            }]
        }
    });
    Some(GatedStatusPatch {
        namespace,
        pod_name,
        patch,
    })
}

/// Determine whether a watch event's pod needs its stale `SchedulingGated`
/// reason cleared now that every gate has been removed.
///
/// `spec.schedulingGates` can be removed one at a time (a ReplicaSet's pods
/// each carrying `[foo, bar]` may see `bar` removed first, leaving `[bar]`
/// still non-empty) — this must only fire once the list is fully empty, not
/// on every reduction. Once it does fire, the condition must not keep saying
/// "blocked on scheduling gates" once that's no longer true, or `kubectl
/// describe pod` lies about why the pod is still Pending.
///
/// Returns `None` when: any gate remains; the pod is already bound (never
/// touch a bound pod's condition); or the condition doesn't currently say
/// `SchedulingGated` (nothing stale to clear).
///
/// The returned patch deliberately omits `status`: a concurrent successful
/// bind (`bind_pod` in the apiserver) flips `PodScheduled` to `True` in the
/// same atomic write as `spec.nodeName`, and this reset runs concurrently
/// with that scheduling attempt (see caller). Sending `status: "False"` here
/// could race a fresh `True` and clobber it back to `False`; omitting the key
/// entirely means this patch can only ever touch `reason`/`message`, never
/// `status`, so it can never contradict a real bind outcome.
pub fn scheduling_gate_status_reset(event: &Value) -> Option<Value> {
    let watch_event: WatchEvent<PodObject> = WatchEvent::<PodObject>::deserialize(event).ok()?;
    if watch_event.event_type != "ADDED" && watch_event.event_type != "MODIFIED" {
        return None;
    }
    let already_scheduled = watch_event
        .object
        .spec
        .node_name
        .as_deref()
        .is_some_and(|n| !n.is_empty());
    if already_scheduled {
        return None;
    }
    let has_gates = watch_event
        .object
        .spec
        .scheduling_gates
        .as_ref()
        .is_some_and(|gates| !gates.is_empty());
    if has_gates {
        return None;
    }
    let still_marked_gated = watch_event.object.status.conditions.iter().any(|c| {
        c.condition_type.as_deref() == Some(POD_SCHEDULED)
            && c.reason.as_deref() == Some(SCHEDULING_GATED_REASON)
    });
    if !still_marked_gated {
        return None;
    }
    Some(serde_json::json!({
        "status": {
            "conditions": [{
                "type": POD_SCHEDULED,
                "reason": UNSCHEDULABLE_REASON,
                "message": UNSCHEDULABLE_MESSAGE,
            }]
        }
    }))
}

/// Build the `status.conditions` PATCH for a pod that just failed a
/// scheduling attempt (no node fit, even after preemption, or the bind
/// itself failed) — `None` when `event` (the watch event that triggered
/// this scheduling attempt) already shows this exact
/// False/Unschedulable/`message` condition.
///
/// Mirrors upstream kube-scheduler, which patches `PodScheduled=False` with
/// reason `Unschedulable` on EVERY failed scheduling cycle, not just the
/// FailedScheduling Event `main.rs` already emits. Without this, a pod's
/// `status.conditions` stays frozen at the pod-creation-time default
/// forever, so anything polling for `{type: PodScheduled, reason:
/// Unschedulable}` (some conformance waits do exactly this) can never
/// observe the failure.
///
/// The idempotency check is load-bearing, not cosmetic: a status PATCH
/// echoes back through the watch as a fresh MODIFIED event for the same
/// still-unscheduled pod, which re-enters `needs_scheduling` and retries
/// scheduling immediately — repeating this PATCH unconditionally on a pod
/// that keeps failing with the SAME message every attempt (e.g. a
/// permanently-unsatisfiable nodeSelector) would fire a tight, unbounded
/// self-retrigger loop hammering the apiserver, rather than settling once
/// the message stops changing. Mirrors `scheduling_gate_status_patch`'s
/// identical guard for the identical reason.
pub fn failed_scheduling_status_patch(event: &Value, message: &str) -> Option<Value> {
    if let Ok(watch_event) = WatchEvent::<PodObject>::deserialize(event) {
        let already_marked = watch_event.object.status.conditions.iter().any(|c| {
            c.condition_type.as_deref() == Some(POD_SCHEDULED)
                && c.status.as_deref() == Some("False")
                && c.reason.as_deref() == Some(UNSCHEDULABLE_REASON)
                && c.message.as_deref() == Some(message)
        });
        if already_marked {
            return None;
        }
    }
    Some(serde_json::json!({
        "status": {
            "conditions": [{
                "type": POD_SCHEDULED,
                "status": "False",
                "reason": UNSCHEDULABLE_REASON,
                "message": message,
            }]
        }
    }))
}

/// Return `true` if a spawn for `key` ("namespace/name") should proceed.
///
/// `key` must be absent from `in_flight` — the set of pod keys currently being
/// scheduled. The caller is responsible for inserting the key before spawning and
/// removing it when the task completes (success or error).
///
/// Pure function so the dedup decision can be unit-tested without a runtime.
/// The guard prevents two rapid ADDED/MODIFIED events for the same pod from
/// spawning two concurrent bind_pod tasks; the second bind would receive a 409
/// Conflict, which (after bead 2) is now a logged Err rather than silent Ok.
pub fn should_schedule(in_flight: &std::collections::HashSet<String>, key: &str) -> bool {
    !in_flight.contains(key)
}

/// Response body of `GET /api/v1/pods` — a full pod list, not a watch event.
/// Items are kept as raw `Value` (not deserialized into a `PodObject` up
/// front) so `pods_needing_resync` can wrap each one into the exact same
/// `{"type": "MODIFIED", "object": ...}` envelope `needs_scheduling` already
/// parses from a live watch event, without a second, parallel Pod type.
#[derive(Deserialize)]
pub struct PodList {
    pub items: Vec<Value>,
}

/// From a raw `/api/v1/pods` list's items, build the synthetic
/// `{"type": "MODIFIED", "object": <pod>}` watch events the periodic resync
/// loop should feed through the same per-event handler the live watch uses.
///
/// A pod that fails a scheduling attempt (e.g. exhausts preemption retries)
/// is otherwise stranded: `needs_scheduling` only fires on an ADDED/MODIFIED
/// event for the pod itself, a failed attempt never patches the pod's own
/// status, and the apiserver's watch replay is a bounded ring buffer that
/// can rotate past a stale pod's last event under unrelated churn long
/// before the next forced reconnect. The periodic resync exists to
/// manufacture that missing event from a fresh list, on a timer, independent
/// of whatever the watch stream has or hasn't delivered.
///
/// Delegates to `needs_scheduling_pod`/`should_schedule` — the same pod-level
/// check `needs_scheduling` uses for a live watch event — so this can never
/// diverge from what a real watch event for the same pod would decide, and a
/// pod already in `in_flight` (a bind already running, from the watch or an
/// earlier resync tick) is excluded here exactly as it would be there. Pure
/// so the resync's core decision — which stranded pods get retried this tick
/// — is unit-testable without a live apiserver GET.
///
/// Filters each raw `item` BEFORE wrapping it into the envelope, not after:
/// wrapping is the expensive step (a full recursive clone of the pod), and
/// most cluster pods are already scheduled, so wrapping every item first and
/// filtering second — the reverse order — would pay that clone for pods this
/// function is about to discard anyway.
pub fn pods_needing_resync(
    items: &[Value],
    in_flight: &std::collections::HashSet<String>,
) -> Vec<Value> {
    items
        .iter()
        .filter(|item| {
            needs_scheduling_pod(item).is_some_and(|pending| {
                let key = format!("{}/{}", pending.namespace, pending.pod_name);
                should_schedule(in_flight, &key)
            })
        })
        .map(|item| serde_json::json!({"type": "MODIFIED", "object": item}))
        .collect()
}

#[derive(Deserialize)]
pub struct NodeList {
    pub items: Vec<NodeItem>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeItem {
    pub metadata: NodeMetadata,
    #[serde(default)]
    pub spec: NodeSpec,
    #[serde(default)]
    pub status: NodeStatus,
    /// Remaining CSI attach capacity per driver — `CSINode.spec.drivers[].allocatable.count`
    /// minus how many volumes of that driver are already attached to this node, for every
    /// driver the node advertises a limit for. Never present in the raw `/api/v1/nodes` JSON
    /// (hence `skip_deserializing`) — `pick_node` fills this in from a separate CSINode GET
    /// plus a cluster-wide pod scan, only when the pending pod itself needs CSI volumes, right
    /// before calling `select_and_reserve_node`. A driver absent here has no advertised limit
    /// (or the pod needs none of it) — see `csi_volume_limits_fit`.
    #[serde(default, skip_deserializing)]
    pub csi_driver_headroom: std::collections::BTreeMap<String, i64>,
    /// CSI driver names this node's CSINode currently registers. Never
    /// present in the raw `/api/v1/nodes` JSON (hence `skip_deserializing`)
    /// — `select_and_reserve_node` fills this in from `NodeTally`'s
    /// watch-maintained CSINode cache, only when the pending pod itself has
    /// an unbound CSI-backed PVC (`PendingPod::unbound_csi_pvc_drivers`),
    /// exactly like `csi_driver_headroom`. See `csi_topology_fit`.
    #[serde(default, skip_deserializing)]
    pub csi_registered_drivers: std::collections::HashSet<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NodeSpec {
    #[serde(default)]
    pub taints: Vec<Taint>,
    /// `spec.unschedulable` — set by `kubectl cordon` (a PATCH) or present on
    /// a node object from creation (e.g. upstream e2e's fake unschedulable
    /// node). `None`/`Some(false)` behave identically; `Some(true)` blocks
    /// scheduling in `node_qualifies_for_pod` unless the pod carries the
    /// override toleration, mirroring upstream's always-on
    /// `NodeUnschedulable` default Filter plugin.
    #[serde(default)]
    pub unschedulable: Option<bool>,
}

/// A node taint (`spec.taints[]`). Only `NoSchedule`/`NoExecute` effects block
/// scheduling in this MVP — `PreferNoSchedule` is a soft signal upstream only
/// weighs during scoring, and this scheduler does no scoring, so it is treated
/// as always tolerated.
#[derive(Debug, Clone, Deserialize)]
pub struct Taint {
    pub key: String,
    #[serde(default)]
    pub value: String,
    pub effect: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NodeStatus {
    #[serde(default)]
    pub allocatable: NodeAllocatable,
    #[serde(default)]
    pub capacity: NodeAllocatable,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NodeAllocatable {
    /// Maximum pods the node will accept (quantity string, e.g. "110").
    /// Zero means the field was absent — treat as unlimited for safety (no cap check).
    #[serde(default)]
    pub pods: String,
    /// CPU quantity string (e.g. "4", "500m"). Empty/unparseable means unknown
    /// — that dimension of NodeResourcesFit is not checked (see `resource_fits`).
    #[serde(default)]
    pub cpu: String,
    /// Memory quantity string (e.g. "8Gi"). Same "unknown → skip" convention as `cpu`.
    #[serde(default)]
    pub memory: String,
    /// Ephemeral-storage quantity string (e.g. "20Gi"). Same convention as `cpu`.
    #[serde(default, rename = "ephemeral-storage")]
    pub ephemeral_storage: String,
    /// Every other `status.allocatable`/`status.capacity` entry, keyed by
    /// resource name to its raw quantity string — extended resources (e.g.
    /// `scheduling.k8s.io/foo`, `nvidia.com/gpu`) and hugepages. The scheduler
    /// has no fixed list of extended-resource names (they are cluster-defined
    /// via `AddExtendedResource`-style PATCHes), so anything not already named
    /// above is captured here rather than silently dropped. Without this,
    /// `resource_fits`/preemption can never see that a node has (or lacks)
    /// capacity for a resource beyond cpu/memory/ephemeral-storage/pod-count,
    /// so a pod that only requests an extended resource always looks like it
    /// fits — the exact gap that leaves the SchedulerPreemption conformance
    /// suite's synthetic-resource tests unable to trigger eviction.
    #[serde(flatten)]
    pub extended: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeMetadata {
    pub name: String,
    #[serde(default)]
    pub labels: std::collections::HashMap<String, String>,
}

/// Parse a Kubernetes quantity string for pod count (e.g. "110") into u32.
///
/// Returns 0 when the field is absent or unparseable, which the capacity check
/// treats as "unknown capacity — skip capping".  Pod counts are always small
/// non-negative integers so u32 is more than sufficient.
pub fn parse_pod_capacity(s: &str) -> u32 {
    s.trim().parse::<u32>().unwrap_or(0)
}

/// A pod's (or a node's allocatable) cpu/memory/ephemeral-storage, all in
/// milli-units — see `parse_quantity_milli`. Working in milli-units
/// throughout means comparisons never need to convert back to a display unit.
///
/// `extended` carries every OTHER requested resource (name -> milli-units),
/// e.g. `scheduling.k8s.io/foo` or `nvidia.com/gpu` — resource names the
/// scheduler has no fixed list for, so they cannot be dedicated struct fields
/// like cpu/memory. Without this, a pod requesting only an extended resource
/// always looks like it requests nothing, and can never be blocked (or
/// trigger preemption) by that resource being exhausted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ResourceRequests {
    pub cpu_milli: i64,
    pub memory_milli: i64,
    pub ephemeral_storage_milli: i64,
    pub extended: std::collections::BTreeMap<String, i64>,
}

impl std::ops::Add for ResourceRequests {
    type Output = Self;
    fn add(mut self, other: Self) -> Self {
        self.cpu_milli += other.cpu_milli;
        self.memory_milli += other.memory_milli;
        self.ephemeral_storage_milli += other.ephemeral_storage_milli;
        for (name, amount) in other.extended {
            *self.extended.entry(name).or_insert(0) += amount;
        }
        self
    }
}

/// Subtract `victim`'s requests out of `total` in place — the inverse of
/// `Add`, used by `select_preemption_victims` to track how much of each
/// dimension remains committed as candidate victims are evicted one at a
/// time. Not a `Sub`/`SubAssign` impl: this is the only call site, and an
/// operator overload would need to decide what negative remainders mean
/// (they cannot occur here — a node's used total is always >= any single
/// pod's request already counted in it).
fn subtract_requests(total: &mut ResourceRequests, victim: &ResourceRequests) {
    total.cpu_milli -= victim.cpu_milli;
    total.memory_milli -= victim.memory_milli;
    total.ephemeral_storage_milli -= victim.ephemeral_storage_milli;
    for (name, amount) in &victim.extended {
        if let Some(remaining) = total.extended.get_mut(name) {
            *remaining -= amount;
        }
    }
}

/// Parse the numeric portion of a quantity (everything before the unit suffix) scaled by
/// `mult`, into a milli-unit integer. Mirrors `crates/apiserver/src/quota.rs`'s
/// `parse_number_milli` (kept separate — no shared types crate today), adapted to this
/// crate's "0 means unparseable" convention instead of `Option`.
///
/// Whole-number input is parsed as `i64` and multiplied exactly — the original, unchanged
/// path, so large magnitudes (e.g. multi-exabyte quantities) stay precise. Only input with a
/// fractional component (e.g. "1.5") falls back to `f64`, and the milli-unit result is
/// rounded to the nearest integer since milli is this representation's finest granularity —
/// a deliberate, explicit choice rather than the silent truncation-to-zero that `i64` parsing
/// alone would produce. `NaN`/`inf` are rejected: `f64::from_str` accepts them, but they are
/// not valid Kubernetes quantity values. The scaled (post-`mult`) value is also range-checked
/// against `i64` before the final cast: `f64 as i64` SATURATES to `i64::MAX`/`i64::MIN` on
/// overflow rather than signaling failure, so without this check a monster fractional
/// quantity (e.g. "1e19") would be silently accepted as the saturated max/min instead of
/// treated as unparseable (0).
fn parse_number_milli(s: &str, mult: i64) -> i64 {
    if let Ok(n) = s.parse::<i64>() {
        return n.checked_mul(mult).unwrap_or(0);
    }
    let f: f64 = match s.parse() {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let scaled = f * mult as f64;
    // `i64::MAX` (2^63 - 1) needs 63 bits and isn't exactly representable in f64's 53-bit
    // mantissa, so `i64::MAX as f64` rounds UP to 2^63. A strict `>` would let `scaled ==
    // 2^63.0` through the guard, then saturate to `i64::MAX` on the cast below — so the
    // upper bound must be `>=`, not `>`. `i64::MIN` (-2^63) is a power of two and IS exact,
    // so `<` is correct there.
    if !scaled.is_finite() || scaled < i64::MIN as f64 || scaled >= i64::MAX as f64 {
        return 0;
    }
    scaled.round() as i64
}

/// Parse a Kubernetes resource quantity string into milli-units: for CPU,
/// "500m" -> 500, "1" -> 1000, "1.5" -> 1500; for memory/ephemeral-storage, "128Mi" ->
/// 128*1024*1024*1000. Fractional quantities (e.g. "1.5", "1.5Gi") are rounded to the
/// nearest milli-unit — see `parse_number_milli` for why rounding was chosen over rejection.
/// Mirrors the arithmetic in `crates/apiserver/src/quota.rs`'s `parse_quantity_milli` (kept
/// separate here — the scheduler and apiserver are independent binaries with no shared types
/// crate today).
///
/// Returns 0 for an absent/unparseable string. Callers must treat 0 as "no
/// value was set" — for a pod's own request that means "this container
/// declared no request for that resource" (contributes 0 to the sum, matching
/// Kubernetes' best-effort semantics); for a node's allocatable it means
/// "capacity unknown" (that dimension is not checked), the same convention
/// `parse_pod_capacity` already uses for `status.allocatable.pods`.
fn parse_quantity_milli(s: &str) -> i64 {
    if s.is_empty() {
        return 0;
    }
    if let Some(rest) = s.strip_suffix('m') {
        return parse_number_milli(rest, 1);
    }
    let binary_suffixes = [
        ("Ki", 1024i64),
        ("Mi", 1024 * 1024),
        ("Gi", 1024 * 1024 * 1024),
        ("Ti", 1024 * 1024 * 1024 * 1024),
        ("Pi", 1024 * 1024 * 1024 * 1024 * 1024),
        ("Ei", 1024 * 1024 * 1024 * 1024 * 1024 * 1024),
    ];
    for (suf, mult) in &binary_suffixes {
        if let Some(rest) = s.strip_suffix(suf) {
            return parse_number_milli(rest, mult * 1000);
        }
    }
    let decimal_suffixes = [
        ("k", 1_000i64),
        ("M", 1_000_000),
        ("G", 1_000_000_000),
        ("T", 1_000_000_000_000),
        ("P", 1_000_000_000_000_000),
        ("E", 1_000_000_000_000_000_000),
    ];
    for (suf, mult) in &decimal_suffixes {
        if let Some(rest) = s.strip_suffix(suf) {
            return parse_number_milli(rest, mult * 1000);
        }
    }
    parse_number_milli(s, 1000)
}

/// Add one `(resourceName, quantityString)` pair into `total` — shared by
/// `sum_container_requests` (container `resources.requests`) and
/// `pod_total_requests` (pod `spec.overhead`): cpu/memory/ephemeral-storage
/// get dedicated fields, everything else falls into `extended`.
fn accumulate_request(total: &mut ResourceRequests, name: &str, quantity: &str) {
    let milli = parse_quantity_milli(quantity);
    match name {
        "cpu" => total.cpu_milli += milli,
        "memory" => total.memory_milli += milli,
        "ephemeral-storage" => total.ephemeral_storage_milli += milli,
        _ => *total.extended.entry(name.to_owned()).or_insert(0) += milli,
    }
}

/// Sum `resources.requests.{cpu,memory,ephemeral-storage}` plus every other
/// (extended) resource key across a pod's containers. Init containers are not
/// accounted for — this MVP sums the steady-state (regular) containers only,
/// matching what the conformance suite's saturate-then-overflow tests
/// actually create.
fn sum_container_requests(containers: &[ContainerSpec]) -> ResourceRequests {
    let mut total = ResourceRequests::default();
    for c in containers {
        for (name, quantity) in &c.resources.requests {
            accumulate_request(&mut total, name, quantity);
        }
    }
    total
}

/// A pod's total resource footprint for the NodeResourcesFit predicate:
/// `sum_container_requests` plus `spec.overhead`. Mirrors upstream's
/// `noderesources.computePodResourceRequest`, which adds `pod.Spec.Overhead`
/// on top of the container sum rather than folding it into any one
/// container — `spec.overhead` is the RuntimeClass admission plugin's
/// per-pod sandboxing tax (e.g. gVisor/Kata), not a per-container cost.
/// Without this, a sandboxed pod's true footprint is undercounted and its
/// node can be over-subscribed.
fn pod_total_requests(spec: &PodSpec) -> ResourceRequests {
    let mut total = sum_container_requests(&spec.containers);
    for (name, quantity) in &spec.overhead {
        accumulate_request(&mut total, name, quantity);
    }
    total
}

#[derive(Deserialize, Default)]
struct PodListItemStatus {
    #[serde(default)]
    phase: String,
}

/// A node's already-committed usage from its non-terminated pods: the pod
/// count (against `status.allocatable.pods`), summed cpu/memory/
/// ephemeral-storage requests (against `status.allocatable.{cpu,memory,ephemeral-storage}`),
/// every hostPort already claimed by those pods (the NodePorts predicate's
/// conflict-detection dimension), every PVC `pvc_key(namespace, name)`
/// key they reference (the VolumeRestrictions/ReadWriteOncePod predicate's
/// exclusivity dimension) — namespace-qualified because these pods may span
/// multiple namespaces, and a bare name can collide with an unrelated PVC
/// elsewhere in the cluster — and their already-attached CSI volumes per
/// driver (the CSILimits predicate's dimension), resolved from assumed AND
/// bound pods alike via `NodeTally`'s watch-maintained PVC/PV/StorageClass
/// caches — see `csi_attached_counts`'s own doc comment for why this must
/// come from the tally, not a live GET. Computed by `NodeTally::usage_by_node`.
#[derive(Debug, Default, Clone)]
pub struct NodeUsage {
    pub pod_count: u32,
    pub requests: ResourceRequests,
    pub host_ports: Vec<HostPortClaim>,
    pub pvc_names: Vec<String>,
    pub csi_attached_counts: std::collections::BTreeMap<String, i64>,
}

/// A pod already on a node, as needed by preemption victim selection: its
/// "namespace/name" key (to DELETE it), its scheduling priority (to decide
/// whether it is a legal victim for a given pending pod), its own resource
/// requests (how much pod-count/cpu/memory/ephemeral-storage/extended-resource
/// capacity evicting it would actually free), and the `pvc_key(namespace,
/// name)`-qualified PVC keys it references (whether evicting it would also
/// resolve a ReadWriteOncePod conflict — see `NodeUsage`'s doc comment for
/// why this must be namespace-qualified, not a bare name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePod {
    pub key: String,
    pub priority: i32,
    pub requests: ResourceRequests,
    pub pvc_names: Vec<String>,
}

/// Minimal typed view of a pod watch event's object needed to maintain
/// `NodeTally`: identity (to key the tally), phase (to exclude terminated
/// pods), `spec.nodeName` (which node, if any, it occupies a slot on), and
/// its containers' resource requests.
#[derive(Deserialize)]
struct PreemptionPodListItem {
    metadata: PodMetadata,
    #[serde(default)]
    spec: PodSpec,
    #[serde(default)]
    status: PodListItemStatus,
}

/// One pod's contribution to `NodeTally`: which node it currently occupies a
/// slot on, its namespace/labels (what an inter-pod affinity/anti-affinity
/// term matches against), its priority (preemption eligibility), its
/// resource requests, its hostPort claims, and the `pvc_key`-qualified PVC
/// keys its volumes reference (the ReadWriteOncePod exclusivity predicate's
/// conflict-detection dimension — see `referenced_pvc_names`/`pvc_key`;
/// namespace-qualified, not bare `referenced_pvc_names` output, so a
/// same-named PVC in another namespace is never conflated with this one).
///
/// Populated both by `apply_event` (a real watch event carries the pod's full
/// `metadata`/`spec.containers`/`spec.volumes`) and by `assume`'s fast path
/// (the pending pod's own already-computed `labels`/`host_ports`/`pvc_names`)
/// — see `NodeTally::assume`'s doc comment for why the latter matters.
#[derive(Debug, Clone)]
struct TalliedPod {
    node_name: String,
    namespace: String,
    labels: std::collections::HashMap<String, String>,
    priority: i32,
    /// `referenced_pvc_names`'s BARE output (unlike `pvc_names` below, never
    /// `pvc_key`-qualified) — `NodeTally::csi_volume_counts_for` resolves
    /// these against its watch-maintained PVC cache to compute this pod's
    /// CSI-driver volume counts fresh, at read time, mirroring upstream's
    /// CSILimits Filter resolving live from listers rather than baking a
    /// resolved count in at event-ingestion time (see that method's doc
    /// comment for why: resolution must tolerate the PVC/PV cache converging
    /// after this pod's own ADDED event already landed).
    bare_pvc_names: Vec<String>,
    requests: ResourceRequests,
    host_ports: Vec<HostPortClaim>,
    pvc_names: Vec<String>,
}

/// A preemption plan whose victims have all had their graceful DELETE issued
/// (see `delete_pod`'s doc comment) but not yet confirmed PHYSICALLY gone by
/// a real watch event from the kubelet actually running them.
#[derive(Debug)]
struct WaitingPlan {
    pod: PendingPod,
    node_name: String,
    /// Victim keys ("namespace/name") not yet confirmed gone. Shrinks as
    /// `PreemptionWaiters::resolve` observes each one's real removal; once
    /// empty, the plan is ready for `main.rs`'s deferred bind.
    remaining_victims: std::collections::HashSet<String>,
}

/// Preemption plans deferred by `main.rs`'s `preempt_and_pick_node` between
/// "victims evicted" (a soft, graceful DELETE acknowledged by the apiserver)
/// and "victims actually gone" (a real DELETED/terminal-phase watch event
/// from the kubelet that was running them) — see `NodeTally::apply_event`'s
/// DELETED-branch hook, which drains a plan here the instant its last
/// awaited victim is confirmed.
///
/// CACHE ONLY, NEVER A DECISION RECORD: the durable correctness backstop for
/// every pod tracked here is `pods_needing_resync`'s unconditional retry of
/// any pod still `spec.nodeName`-empty (see its doc comment) — that resync
/// loop must keep retrying a pod with `nominatedNodeName` set exactly as it
/// would any other stranded pod. Losing this map entirely (process restart,
/// or the `clear()` a watch reconnect triggers) costs at most
/// `RESYNC_INTERVAL` of extra latency for the waiting pod, never a
/// stuck-forever pod — nothing here is any pod's ONLY path to getting bound.
/// Conversely, a plan resolving here is only ever a cue to RE-TRY the bind,
/// never a license to skip re-verifying fit first (see
/// `preemption_reservation_still_fits`): the reservation this plan made when
/// it committed can go stale while this plan sits here waiting (e.g. a watch
/// reconnect wipes `NodeTally.pods` — including this plan's own `assume`d
/// reservation — well before the victim's real DELETE lands).
#[derive(Debug, Default)]
struct PreemptionWaiters {
    plans: Vec<WaitingPlan>,
}

impl PreemptionWaiters {
    fn register(&mut self, pod: PendingPod, node_name: String, victims: &[String]) {
        self.plans.push(WaitingPlan {
            pod,
            node_name,
            remaining_victims: victims.iter().cloned().collect(),
        });
    }

    /// `victim_key` was just observed as truly, physically gone. Returns
    /// every plan for which this was the LAST still-awaited victim, each as
    /// `(pod, node_name)` — ready for the caller to attempt the deferred
    /// bind for (after re-verifying fit; see this struct's doc comment).
    fn resolve(&mut self, victim_key: &str) -> Vec<(PendingPod, String)> {
        for plan in &mut self.plans {
            plan.remaining_victims.remove(victim_key);
        }
        let mut ready = Vec::new();
        let mut i = 0;
        while i < self.plans.len() {
            if self.plans[i].remaining_victims.is_empty() {
                let plan = self.plans.remove(i);
                ready.push((plan.pod, plan.node_name));
            } else {
                i += 1;
            }
        }
        ready
    }

    /// Drop every waiting plan, returning each abandoned plan's pod key
    /// ("namespace/name") so the caller (`NodeTally::clear`, then `main.rs`)
    /// can release it from `in_flight` too — a plan dropped here can never
    /// resolve via `resolve` any more, so nothing else would ever clear that
    /// pod's dedup entry, permanently stranding it as "already being
    /// scheduled" even though nothing is scheduling it any more.
    fn clear(&mut self) -> Vec<String> {
        self.plans
            .drain(..)
            .map(|p| format!("{}/{}", p.pod.namespace, p.pod.pod_name))
            .collect()
    }
}

/// An in-memory, watch-maintained running tally of every bound, non-terminal
/// pod's resource requests, keyed by "namespace/name".
///
/// Replaces a design where `pick_node`/`find_preemption_plan` issued a live
/// GET /api/v1/pods?fieldSelector=spec.nodeName=<node> per candidate node on
/// every scheduling decision. Besides being O(qualifying nodes) HTTP+DB round
/// trips per pod scheduled, that GET raced the scheduler's own writes: under
/// concurrent scheduling load, a just-committed bind's resource request was
/// not always visible to the very next GET (a read-after-write race between
/// the bind and the immediately-following capacity check), so a node could
/// look emptier than it really was and receive a second pod it did not
/// actually have room for — the kubelet then rejected it with OutOfcpu.
///
/// `main.rs` keeps this current two ways: (1) every pod watch event is fed
/// through `apply_event`, so the tally converges to cluster state the same
/// way a real kube-scheduler's informer cache does; (2) the scheduler's own
/// `assume`/`remove` calls update it immediately when it decides to bind or
/// evict a pod, before the HTTP call that makes the change durable even
/// completes — so a scheduling decision (possibly running concurrently, in a
/// different spawned task) can never read a snapshot older than the most
/// recent decision this process itself already made.
#[derive(Debug, Default)]
pub struct NodeTally {
    pods: std::collections::HashMap<String, TalliedPod>,
    /// Node name -> "namespace/name" keys of every pod in `pods` currently on
    /// that node — the secondary index `pods_on`/`csi_attached_counts` use in
    /// place of a full scan of `pods`. Mirrors `node_authz`'s
    /// `NodeGraphInner::by_node` shape. Maintained ONLY through
    /// `insert_pod`/`remove_pod`/`clear` below; every other method must go
    /// through those instead of touching `pods` directly, or this index can
    /// diverge from `pods` — which silently mis-counts a node's capacity
    /// (a phantom entry lets `pods_on` return a pod `usage_by_node` no
    /// longer sees, or a missing entry hides one it still does) rather than
    /// failing loudly.
    by_node: std::collections::HashMap<String, std::collections::HashSet<String>>,
    /// "namespace/name" keys of pods already named as victims by a reserved-
    /// but-not-yet-evicted preemption plan — see `claim_victims`.
    reserved_victims: std::collections::HashSet<String>,
    /// Preemption plans deferred until their victims are confirmed
    /// physically gone — see `PreemptionWaiters`.
    waiters: PreemptionWaiters,
    /// "namespace/name" -> (bound PV name, StorageClass name) — watch-
    /// maintained by `apply_pvc_event`, mirroring upstream's PVC lister.
    pvcs: std::collections::HashMap<String, PvcVolumeInfo>,
    /// PV name -> CSI driver (`spec.csi.driver`) — watch-maintained by
    /// `apply_pv_event`, mirroring upstream's PV lister.
    pv_csi_drivers: std::collections::HashMap<String, String>,
    /// StorageClass name -> provisioner — watch-maintained by
    /// `apply_storage_class_event`, mirroring upstream's StorageClass lister.
    sc_provisioners: std::collections::HashMap<String, String>,
    /// Node name -> per-driver `CSINode.spec.drivers[].allocatable.count` —
    /// watch-maintained by `apply_csi_node_event`, mirroring upstream's
    /// CSINode lister.
    csi_node_limits: std::collections::HashMap<String, std::collections::BTreeMap<String, i64>>,
    /// Node name -> every CSI driver name registered in that node's CSINode
    /// (`CSINode.spec.drivers[].name`), regardless of whether the driver
    /// advertises an attach-count limit — watch-maintained by
    /// `apply_csi_node_event` alongside `csi_node_limits`. A separate cache
    /// (not derived from `csi_node_limits`'s keys) because many real CSI
    /// drivers, csi-hostpath included, never set `allocatable.count`, so
    /// `csi_node_limits` alone cannot answer "is this driver registered
    /// here" — only "does it have this limit". This is `csi_topology_fit`'s
    /// per-node input.
    csi_node_drivers: std::collections::HashMap<String, std::collections::HashSet<String>>,
    /// Node name -> node object, watch-maintained by `apply_node_event` —
    /// `pick_node`/`fetch_node`/`find_preemption_plan` read this instead of a
    /// live GET /api/v1/nodes per scheduling decision, mirroring the pod
    /// watch's own informer-cache trade-off: a cordon/taint/capacity change
    /// lags by one watch round-trip, exactly like a pod change does before
    /// landing in `pods`. A `BTreeMap` (not `HashMap`) so `node_list`'s
    /// iteration order is deterministic and, since node keys sort the same
    /// way the store's own `ORDER BY key ASC` list scan does, matches what a
    /// live GET would have returned — preserving `select_node_with_capacity`'s
    /// list-order tie-break for nodes that score identically.
    nodes: std::collections::BTreeMap<String, NodeItem>,
}

/// A PVC's fields needed to resolve its backing CSI driver — see
/// `NodeTally::resolve_csi_driver`.
#[derive(Debug, Clone, Default)]
struct PvcVolumeInfo {
    volume_name: String,
    storage_class_name: Option<String>,
}

impl NodeTally {
    /// Insert/overwrite `key`'s entry in `pods`, keeping `by_node` in lockstep.
    /// The only path that may write into `pods`'s map slot for `key` — every
    /// caller (`apply_event`, `assume`) must go through this rather than
    /// calling `self.pods.insert` directly, or `by_node` silently falls out
    /// of sync with `pods` (see `by_node`'s doc comment for the fallout).
    ///
    /// A real Pod's `spec.nodeName` never changes once set, so the
    /// old-node/new-node mismatch branch below should never fire in
    /// practice — handled anyway so the index cannot corrupt itself even if
    /// that assumption is ever wrong.
    fn insert_pod(&mut self, key: String, pod: TalliedPod) {
        let node_name = pod.node_name.clone();
        if let Some(old) = self.pods.insert(key.clone(), pod) {
            if old.node_name != node_name {
                if let Some(set) = self.by_node.get_mut(&old.node_name) {
                    set.remove(&key);
                }
            }
        }
        self.by_node.entry(node_name).or_default().insert(key);
    }

    /// Remove `key`'s entry from `pods`, keeping `by_node` in lockstep — the
    /// only path that may remove from `pods`'s map slot for `key` (see
    /// `insert_pod`'s doc comment for why direct `self.pods.remove` calls
    /// elsewhere are forbidden).
    ///
    /// Prunes the outer `by_node` entry once its pod set empties — otherwise
    /// every distinct node name ever observed for the life of the process
    /// leaves behind an empty `HashSet`, growing `by_node` unbounded across
    /// node churn (e.g. autoscaling nodes coming and going) even though the
    /// last pod on that node is long gone.
    fn remove_pod(&mut self, key: &str) -> Option<TalliedPod> {
        let removed = self.pods.remove(key)?;
        if let Some(set) = self.by_node.get_mut(&removed.node_name) {
            set.remove(key);
            if set.is_empty() {
                self.by_node.remove(&removed.node_name);
            }
        }
        Some(removed)
    }

    /// Update the tally from one raw pod watch event.
    ///
    /// A DELETED event, or an ADDED/MODIFIED event for a pod that is unbound
    /// (`spec.nodeName` empty) or in a terminal phase (Succeeded/Failed —
    /// mirrors the NodeResourcesFit predicate: a completed pod is not
    /// occupying a slot), removes any prior entry for that pod. Any other
    /// ADDED/MODIFIED event overwrites (never adds to) the entry, so
    /// replaying the same event twice — e.g. after a watch reconnect —
    /// is idempotent.
    ///
    /// Returns every deferred preemption plan (see `PreemptionWaiters`,
    /// `register_preemption_waiter`) for which this event was the LAST
    /// still-awaited victim's real removal — `(pending pod, node name)`
    /// pairs the caller (`main.rs`'s `handle_pod_event`) should now attempt
    /// the deferred bind for. Empty for the overwhelming majority of events,
    /// which never touch a tracked victim at all.
    pub fn apply_event(&mut self, event: &Value) -> Vec<(PendingPod, String)> {
        let Ok(watch_event) = WatchEvent::<PreemptionPodListItem>::deserialize(event) else {
            return Vec::new();
        };
        let name = watch_event.object.metadata.name.unwrap_or_default();
        if name.is_empty() {
            return Vec::new();
        }
        let namespace = watch_event
            .object
            .metadata
            .namespace
            .unwrap_or_else(|| "default".to_owned());
        let labels = watch_event.object.metadata.labels;
        let key = format!("{namespace}/{name}");

        if watch_event.event_type != "ADDED" && watch_event.event_type != "MODIFIED" {
            self.remove_pod(&key);
            return self.waiters.resolve(&key);
        }
        let terminal = matches!(
            watch_event.object.status.phase.as_str(),
            "Succeeded" | "Failed"
        );
        let priority = watch_event.object.spec.priority.unwrap_or(0);
        let requests = pod_total_requests(&watch_event.object.spec);
        let host_ports = container_host_ports(&watch_event.object.spec.containers);
        let bare_pvc_names = referenced_pvc_names(
            &name,
            watch_event.object.spec.volumes.as_deref().unwrap_or(&[]),
        );
        let pvc_names: Vec<String> = bare_pvc_names
            .iter()
            .map(|n| pvc_key(&namespace, n))
            .collect();
        let node_name = watch_event.object.spec.node_name.filter(|n| !n.is_empty());
        match node_name {
            Some(node_name) if !terminal => {
                self.insert_pod(
                    key,
                    TalliedPod {
                        node_name,
                        namespace,
                        labels,
                        priority,
                        bare_pvc_names,
                        requests,
                        host_ports,
                        pvc_names,
                    },
                );
                Vec::new()
            }
            Some(_) => {
                // Bound but now terminal (Succeeded/Failed) — free its slot.
                // A terminal phase is as strong a "physically gone" signal as
                // a real DELETE: the kubelet only reports it once the
                // container(s) it was running have actually stopped, so a
                // preemption victim that completes this way (rather than
                // being hard-deleted first) must resolve waiters too.
                self.remove_pod(&key);
                self.waiters.resolve(&key)
            }
            None => {
                // Still unbound: do NOT remove any existing entry. Live-
                // reproduced: main.rs's best-effort `nominatedNodeName`
                // status PATCH on a pod this scheduler just `assume`d (but
                // has not yet bound — bind is what actually sets
                // `spec.nodeName`) echoes back through this SAME watch
                // stream with `spec.nodeName` still empty. Removing here
                // erased that concurrently-committed reservation well before
                // the real bind landed, letting a THIRD pod's capacity check
                // see phantom free room and get force-bound onto a node that
                // was, in physical reality, already full — the kubelet then
                // rejected it OutOfResource. A pod that was never bound was
                // never in `pods` to begin with, so this is a genuine no-op
                // for the ordinary (not-yet-scheduled) case.
                Vec::new()
            }
        }
    }

    /// Record that `namespace/pod_name` now occupies a slot on `node_name` —
    /// called the instant the scheduler decides to bind, before the bind's
    /// HTTP call even completes. `remove` undoes this if the bind then fails.
    ///
    /// `host_ports`/`labels`/`pvc_names` — like `requests` — are the pending
    /// pod's own already-computed values at decision time, not something read
    /// back from a watch event: without them, a hostPort a scheduling
    /// decision just reserved on `node_name` would stay invisible to
    /// `usage_by_node`/the NodePorts filter, this pod's labels would stay
    /// invisible to inter-pod affinity/anti-affinity, and this pod's PVCs
    /// would stay invisible to the ReadWriteOncePod exclusivity filter, for
    /// every OTHER concurrent decision until the real bind's watch event
    /// round-tripped through `apply_event` — the same read-after-write race
    /// `requests` already closes for cpu/memory (see this struct's doc
    /// comment).
    ///
    /// `pvc_names` is BARE names (`PendingPod::pvc_names`'s own convention) —
    /// this qualifies each into `pvc_key(namespace, ..)` before storing, the
    /// same convention `apply_event` uses, so `usage_by_node`/`pods_on` never
    /// see an unqualified name that could collide with a same-named PVC in a
    /// different namespace.
    #[allow(clippy::too_many_arguments)]
    pub fn assume(
        &mut self,
        namespace: &str,
        pod_name: &str,
        node_name: &str,
        priority: i32,
        requests: ResourceRequests,
        host_ports: Vec<HostPortClaim>,
        labels: std::collections::HashMap<String, String>,
        pvc_names: Vec<String>,
    ) {
        let bare_pvc_names = pvc_names.clone();
        let pvc_names = pvc_names
            .into_iter()
            .map(|n| pvc_key(namespace, &n))
            .collect();
        self.insert_pod(
            format!("{namespace}/{pod_name}"),
            TalliedPod {
                node_name: node_name.to_owned(),
                namespace: namespace.to_owned(),
                labels,
                priority,
                bare_pvc_names,
                requests,
                host_ports,
                pvc_names,
            },
        );
    }

    /// Remove `namespace/pod_name` from the tally — called immediately after
    /// a preemption eviction succeeds (freeing its resources for the re-fit
    /// check that follows), or to roll back an `assume` when the bind it
    /// anticipated does not actually go through.
    pub fn remove(&mut self, namespace: &str, pod_name: &str) {
        self.remove_pod(&format!("{namespace}/{pod_name}"));
    }

    /// Drop all tallied state. Called on watch reconnect: `POD_WATCH_PATH`'s
    /// `sendInitialEvents=true` makes every reconnect relist current pod
    /// state as ADDED events from scratch, and without clearing first, a pod
    /// deleted while disconnected (and so absent from that fresh relist)
    /// would leave a phantom entry this tally could never otherwise correct.
    ///
    /// Also drops every deferred preemption plan (`waiters`): a reconnect
    /// wipes `pods`, which is where each plan's own `assume`d reservation
    /// lived, so a plan surviving this call would be waiting to bind a
    /// reservation that no longer exists. This is safe to drop unconditionally
    /// — see `PreemptionWaiters`'s doc comment for why losing it costs only
    /// latency (the periodic resync re-plans the still-Pending pod from
    /// scratch), never correctness.
    ///
    /// Returns the "namespace/name" key of each abandoned plan's pod —
    /// `main.rs` holds that key in `in_flight` for the plan's entire
    /// preempt-then-wait lifetime (see `attempt_deferred_bind`), and since a
    /// dropped plan can never reach that function's own release point any
    /// more, the caller here must release it instead, or the pod would stay
    /// wrongly deduped forever.
    #[must_use]
    pub fn clear(&mut self) -> Vec<String> {
        self.pods.clear();
        self.by_node.clear();
        self.reserved_victims.clear();
        self.waiters.clear()
    }

    /// Defer `pod`'s bind to `node_name` until every one of `victims` has a
    /// real (not just this scheduler's own soft-delete bookkeeping) removal
    /// observed via `apply_event` — see `PreemptionWaiters`. Called by
    /// `main.rs`'s `preempt_and_pick_node` immediately after `evict_victims`
    /// issues each victim's graceful DELETE, in place of binding right away.
    pub fn register_preemption_waiter(
        &mut self,
        pod: PendingPod,
        node_name: String,
        victims: &[String],
    ) {
        self.waiters.register(pod, node_name, victims);
    }

    /// Mark every pod in `victims` ("namespace/name" keys) as claimed by an
    /// in-flight (reserved-but-not-yet-evicted) preemption plan.
    ///
    /// Called by `verify_and_reserve_preemption` under the same lock
    /// acquisition as its `assume` call, so the claim becomes visible to
    /// every other decision at the exact instant the plan is committed.
    /// `pods_on` then hides these keys from every OTHER concurrent plan's
    /// candidate search until `release_victims` undoes this — without it,
    /// two concurrent equal-priority preemptors independently re-derive the
    /// same "cheapest victim" every time, since neither plan's search has
    /// any way to know the other has already committed to evicting it (live
    /// reproduced: 3 concurrent equal-priority preemptors all targeted the
    /// same single victim, leaving 2 of them force-bound onto a node that
    /// never actually had room, which the kubelet then rejected).
    pub fn claim_victims(&mut self, victims: &[String]) {
        self.reserved_victims.extend(victims.iter().cloned());
    }

    /// Undo `claim_victims` once a plan's eviction sequence finishes,
    /// whether every victim was actually evicted (the ordinary case; a
    /// no-op for those keys, since `remove` already dropped them from
    /// `pods` by then) or the plan was abandoned partway through eviction —
    /// the case that matters: an un-evicted victim must become visible to
    /// `pods_on` again, or it would stay excluded from every future
    /// preemption plan forever even though it is still really there.
    pub fn release_victims(&mut self, victims: &[String]) {
        for v in victims {
            self.reserved_victims.remove(v);
        }
    }

    /// Non-terminal pod count, summed resource requests, claimed hostPorts,
    /// referenced PVC names, and already-attached CSI volume counts per
    /// node — the shape `select_node_with_capacity` consumes in place of a
    /// live GET.
    pub fn usage_by_node(&self) -> std::collections::HashMap<String, NodeUsage> {
        let mut usage: std::collections::HashMap<String, NodeUsage> =
            std::collections::HashMap::new();
        for pod in self.pods.values() {
            let entry = usage.entry(pod.node_name.clone()).or_default();
            entry.pod_count += 1;
            entry.requests = entry.requests.clone() + pod.requests.clone();
            entry.host_ports.extend(pod.host_ports.iter().cloned());
            entry.pvc_names.extend(pod.pvc_names.iter().cloned());
            for (driver, count) in self.csi_volume_counts_for(&pod.namespace, &pod.bare_pvc_names) {
                *entry.csi_attached_counts.entry(driver).or_insert(0) += count;
            }
        }
        usage
    }

    /// Resolve the CSI driver backing `pvc_name` (in `namespace`) from the
    /// watch-maintained PVC/PV/StorageClass caches: prefer its already-bound
    /// PV's `spec.csi.driver`, falling back to its StorageClass's
    /// `provisioner` when unbound — mirrors the async `resolve_csi_driver`
    /// this replaced, but zero I/O, so it is safe to call while holding
    /// `NodeTally`'s own lock. A PVC absent from the cache (not yet
    /// observed by `apply_pvc_event`, or genuinely gone) resolves to `None`
    /// exactly like a 404 did for the old live-GET version — such a volume
    /// is simply not counted, never fail-closed.
    fn resolve_csi_driver(&self, namespace: &str, pvc_name: &str) -> Option<String> {
        let pvc = self.pvcs.get(&pvc_key(namespace, pvc_name))?;
        if !pvc.volume_name.is_empty() {
            if let Some(driver) = self.pv_csi_drivers.get(&pvc.volume_name) {
                return Some(driver.clone());
            }
        }
        let sc_name = pvc.storage_class_name.as_deref()?;
        self.sc_provisioners.get(sc_name).cloned()
    }

    /// Count how many CSI volumes `pvc_names` (deduplicated — the same PVC
    /// mounted twice by one pod is one volume) resolve to, grouped by driver
    /// name — the CSILimits predicate's per-driver volume count, resolved
    /// fresh from the watch-maintained caches every call (mirroring
    /// upstream's CSILimits Filter resolving live from listers at filter
    /// time, rather than baking a resolved count into `TalliedPod` at
    /// event-ingestion time — the PVC/PV cache may still converge after a
    /// referencing pod's own ADDED event lands, and re-resolving here means
    /// that catches up automatically instead of leaving a permanent
    /// undercount). Called both by `usage_by_node` (already-attached counts,
    /// assumed AND bound pods alike) and by `main.rs`'s scheduling flow (the
    /// PENDING pod's own counts, via `csi_volume_counts_for`'s `pub`
    /// re-export below).
    fn count_csi_volumes(
        &self,
        namespace: &str,
        pvc_names: &[String],
    ) -> std::collections::BTreeMap<String, i64> {
        let mut counts = std::collections::BTreeMap::new();
        let mut seen = std::collections::HashSet::new();
        for pvc_name in pvc_names {
            if !seen.insert(pvc_name.clone()) {
                continue;
            }
            if let Some(driver) = self.resolve_csi_driver(namespace, pvc_name) {
                *counts.entry(driver).or_insert(0) += 1;
            }
        }
        counts
    }

    /// `count_csi_volumes`, `pub` so `main.rs` can resolve a PENDING pod's
    /// own CSI volume counts (`PendingPod::csi_volume_counts`) the same way
    /// `usage_by_node` resolves already-attached ones — see that function's
    /// doc comment for why both must share one resolution path instead of
    /// this one reading the watch cache and another still issuing a live
    /// PVC/PV/StorageClass GET chain.
    pub fn csi_volume_counts_for(
        &self,
        namespace: &str,
        pvc_names: &[String],
    ) -> std::collections::BTreeMap<String, i64> {
        self.count_csi_volumes(namespace, pvc_names)
    }

    /// Already-attached CSI volume counts per driver for every tallied
    /// (assumed AND bound) pod on `node_name` — `find_preemption_candidate`'s
    /// and `verify_and_reserve_preemption`'s counterpart to `usage_by_node`'s
    /// per-node fold (see `fresh_csi_headroom_for_node`), needed separately
    /// because both read `pods_on` per node under their own lock rather than
    /// a single upfront `usage_by_node` snapshot.
    pub fn csi_attached_counts(&self, node_name: &str) -> std::collections::BTreeMap<String, i64> {
        let mut counts = std::collections::BTreeMap::new();
        let Some(keys) = self.by_node.get(node_name) else {
            return counts;
        };
        for pod in keys.iter().filter_map(|key| self.pods.get(key)) {
            for (driver, count) in self.count_csi_volumes(&pod.namespace, &pod.bare_pvc_names) {
                *counts.entry(driver).or_insert(0) += count;
            }
        }
        counts
    }

    /// Every node's advertised per-driver CSI attach limit
    /// (`CSINode.spec.drivers[].allocatable.count`), watch-maintained by
    /// `apply_csi_node_event` — the static half of the CSILimits fit check;
    /// `select_and_reserve_node` nets this against `usage_by_node`'s
    /// per-node `csi_attached_counts`, and `find_preemption_candidate`/
    /// `verify_and_reserve_preemption` net it against `csi_attached_counts`
    /// directly (see `fresh_csi_headroom_for_node`) — always under the SAME
    /// lock acquisition that goes on to `assume()`, closing the
    /// read-after-write race a separate pre-lock live GET (or a separate
    /// pre-lock snapshot of this very method) reopened (see this struct's
    /// own doc comment).
    pub fn csi_driver_limits_by_node(
        &self,
    ) -> std::collections::HashMap<String, std::collections::BTreeMap<String, i64>> {
        self.csi_node_limits.clone()
    }

    /// Every node's CSINode-registered CSI driver names — see
    /// `csi_node_drivers`'s doc comment. `csi_topology_fit`'s per-node
    /// input; read under the same lock discipline as
    /// `csi_driver_limits_by_node` for consistency, even though a driver's
    /// CSINode registration changes far less often than attach counts do.
    pub fn csi_driver_names_by_node(
        &self,
    ) -> std::collections::HashMap<String, std::collections::HashSet<String>> {
        self.csi_node_drivers.clone()
    }

    /// Update the PVC cache from one raw PVC watch event — see `pvcs`'s doc
    /// comment. A malformed event, or one with no name, is silently ignored
    /// exactly like `apply_event`'s pod handling (a bookmark event has no
    /// usable object, not a real change to react to).
    pub fn apply_pvc_event(&mut self, event: &Value) {
        let Ok(watch_event) = WatchEvent::<PvcObject>::deserialize(event) else {
            return;
        };
        let name = watch_event.object.metadata.name.clone().unwrap_or_default();
        if name.is_empty() {
            return;
        }
        let namespace = watch_event
            .object
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| "default".to_owned());
        let key = pvc_key(&namespace, &name);
        if watch_event.event_type != "ADDED" && watch_event.event_type != "MODIFIED" {
            self.pvcs.remove(&key);
            return;
        }
        self.pvcs.insert(
            key,
            PvcVolumeInfo {
                volume_name: watch_event.object.spec.volume_name,
                storage_class_name: watch_event.object.spec.storage_class_name,
            },
        );
    }

    /// Update the PV cache from one raw PersistentVolume watch event — see
    /// `pv_csi_drivers`'s doc comment.
    pub fn apply_pv_event(&mut self, event: &Value) {
        let Ok(watch_event) = WatchEvent::<PvObject>::deserialize(event) else {
            return;
        };
        let name = watch_event.object.metadata.name.unwrap_or_default();
        if name.is_empty() {
            return;
        }
        if watch_event.event_type != "ADDED" && watch_event.event_type != "MODIFIED" {
            self.pv_csi_drivers.remove(&name);
            return;
        }
        match watch_event
            .object
            .spec
            .csi
            .map(|c| c.driver)
            .filter(|d| !d.is_empty())
        {
            Some(driver) => {
                self.pv_csi_drivers.insert(name, driver);
            }
            None => {
                self.pv_csi_drivers.remove(&name);
            }
        }
    }

    /// Update the StorageClass cache from one raw StorageClass watch event —
    /// see `sc_provisioners`'s doc comment.
    pub fn apply_storage_class_event(&mut self, event: &Value) {
        let Ok(watch_event) = WatchEvent::<StorageClassObject>::deserialize(event) else {
            return;
        };
        let name = watch_event.object.metadata.name.unwrap_or_default();
        if name.is_empty() {
            return;
        }
        if watch_event.event_type != "ADDED" && watch_event.event_type != "MODIFIED" {
            self.sc_provisioners.remove(&name);
            return;
        }
        if watch_event.object.provisioner.is_empty() {
            self.sc_provisioners.remove(&name);
        } else {
            self.sc_provisioners
                .insert(name, watch_event.object.provisioner);
        }
    }

    /// Update the CSINode cache from one raw CSINode watch event — see
    /// `csi_node_limits`'s doc comment.
    pub fn apply_csi_node_event(&mut self, event: &Value) {
        let Ok(watch_event) = WatchEvent::<CsiNodeItem>::deserialize(event) else {
            return;
        };
        let name = watch_event.object.metadata.name;
        if name.is_empty() {
            return;
        }
        if watch_event.event_type != "ADDED" && watch_event.event_type != "MODIFIED" {
            self.csi_node_limits.remove(&name);
            self.csi_node_drivers.remove(&name);
            return;
        }
        let limits: std::collections::BTreeMap<String, i64> = watch_event
            .object
            .spec
            .drivers
            .iter()
            .filter_map(|d| {
                d.allocatable
                    .as_ref()
                    .and_then(|a| a.count)
                    .map(|c| (d.name.clone(), c))
            })
            .collect();
        let names: std::collections::HashSet<String> = watch_event
            .object
            .spec
            .drivers
            .iter()
            .map(|d| d.name.clone())
            .collect();
        self.csi_node_limits.insert(name.clone(), limits);
        self.csi_node_drivers.insert(name, names);
    }

    /// Drop the PVC cache — called on that watch's own reconnect, for the
    /// same reason `clear` drops `pods` on the pod watch's reconnect: a PVC
    /// deleted while this watch was disconnected would otherwise leave a
    /// phantom entry the fresh `sendInitialEvents=true` relist never
    /// corrects (it only re-adds what still exists). Scoped to just this
    /// cache — a PVC watch reconnect says nothing about whether the PV/
    /// StorageClass/CSINode watches (independent connections) also dropped.
    pub fn clear_pvc_cache(&mut self) {
        self.pvcs.clear();
    }

    /// Drop the PV cache — see `clear_pvc_cache`'s doc comment.
    pub fn clear_pv_cache(&mut self) {
        self.pv_csi_drivers.clear();
    }

    /// Drop the StorageClass cache — see `clear_pvc_cache`'s doc comment.
    pub fn clear_storage_class_cache(&mut self) {
        self.sc_provisioners.clear();
    }

    /// Drop the CSINode cache — see `clear_pvc_cache`'s doc comment.
    pub fn clear_csi_node_cache(&mut self) {
        self.csi_node_limits.clear();
        self.csi_node_drivers.clear();
    }

    /// Update the node cache from one raw Node watch event — see `nodes`'s
    /// doc comment.
    pub fn apply_node_event(&mut self, event: &Value) {
        let Ok(watch_event) = WatchEvent::<NodeItem>::deserialize(event) else {
            return;
        };
        let name = watch_event.object.metadata.name.clone();
        if name.is_empty() {
            return;
        }
        if watch_event.event_type != "ADDED" && watch_event.event_type != "MODIFIED" {
            self.nodes.remove(&name);
            return;
        }
        self.nodes.insert(name, watch_event.object);
    }

    /// Drop the node cache — see `clear_pvc_cache`'s doc comment.
    pub fn clear_node_cache(&mut self) {
        self.nodes.clear();
    }

    /// One cached node by name — `fetch_node`'s direct O(1) lookup in place
    /// of fetching every node just to find one by name.
    pub fn node(&self, node_name: &str) -> Option<NodeItem> {
        self.nodes.get(node_name).cloned()
    }

    /// Every cached node, as the same typed `NodeList` projection
    /// `pick_node`/`find_preemption_plan` used to GET fresh per decision —
    /// now served from this watch-maintained cache instead. Iteration order
    /// matches `nodes`'s doc comment: same order a live GET would return.
    pub fn node_list(&self) -> NodeList {
        NodeList {
            items: self.nodes.values().cloned().collect(),
        }
    }

    /// Every tallied pod currently on `node_name`, for preemption victim
    /// selection — in place of a live GET.
    ///
    /// Excludes any pod already claimed by another in-flight preemption plan
    /// (see `claim_victims`). Such a pod is still physically on the node, so
    /// `usage_by_node` — the path ordinary direct scheduling reads — must
    /// keep counting it; but for preemption planning it is already spoken
    /// for, since the plan that claimed it has already folded the capacity
    /// its eviction will free into its own `assume` reservation. Continuing
    /// to offer it here as a candidate/occupant to every OTHER concurrent
    /// plan is exactly what let equal-priority preemptors independently
    /// converge on the same victim.
    pub fn pods_on(&self, node_name: &str) -> Vec<NodePod> {
        let Some(keys) = self.by_node.get(node_name) else {
            return Vec::new();
        };
        keys.iter()
            .filter(|key| !self.reserved_victims.contains(key.as_str()))
            .filter_map(|key| {
                self.pods.get(key).map(|p| NodePod {
                    key: key.clone(),
                    priority: p.priority,
                    requests: p.requests.clone(),
                    pvc_names: p.pvc_names.clone(),
                })
            })
            .collect()
    }

    /// Namespace/labels/node of every tallied pod, cluster-wide — the input
    /// `pod_affinity_satisfied`/`pod_anti_affinity_satisfied` need to check a
    /// pending pod's required podAffinity/podAntiAffinity terms against pods
    /// scheduled ANYWHERE in the cluster, not just on one candidate node,
    /// since a term's topology domain can span multiple nodes (e.g. every
    /// node in a zone).
    ///
    /// Unlike `pods_on`, does NOT exclude pods claimed by an in-flight
    /// preemption plan (`reserved_victims`): such a pod is still physically
    /// running until its eviction is actually confirmed, so it must keep
    /// counting for affinity/anti-affinity purposes exactly like
    /// `usage_by_node` keeps counting it for resource capacity — only the
    /// preemption search itself (`pods_on`) needs to hide it from other
    /// concurrent plans.
    pub fn tallied_pod_labels(&self) -> Vec<TalliedPodLabels> {
        self.pods
            .iter()
            .map(|(key, p)| TalliedPodLabels {
                key: key.clone(),
                node_name: p.node_name.clone(),
                namespace: p.namespace.clone(),
                labels: p.labels.clone(),
            })
            .collect()
    }
}

/// One tallied pod's namespace/labels, keyed by which node it occupies — see
/// `NodeTally::tallied_pod_labels`. `key` ("namespace/name", matching
/// `PreemptionPlan.victims`' entries) lets `find_preemption_candidate` pick
/// out which of these belong to a candidate node's own selected preemption
/// victims, so their contribution to topology-spread/inter-pod-affinity
/// counts can be discounted before judging that node's qualification — see
/// `TopologySpreadContext::node_qualifies_excluding_victims`.
#[derive(Debug, Clone)]
pub struct TalliedPodLabels {
    pub key: String,
    pub node_name: String,
    pub namespace: String,
    pub labels: std::collections::HashMap<String, String>,
}

/// Return true when `node` is eligible to host `pod` at all, independent of
/// capacity: its labels satisfy the pod's `nodeSelector` AND (if present)
/// required `nodeAffinity`, AND every scheduling-blocking taint on the node
/// is tolerated, AND (if `spec.unschedulable` is set, e.g. by `kubectl
/// cordon`) the pod carries the override toleration, AND its labels satisfy
/// every already-bound PVC's PV `spec.nodeAffinity`.
///
/// That last conjunct matters for any Immediate-mode (the StorageClass
/// default) PVC, whose PV is already bound by the time the pod is scheduled —
/// unlike an unbound WaitForFirstConsumer PVC (see `selected_node_patches`,
/// which is scoped to exactly that other case), there is no later
/// provisioning step to steer onto a compatible node, so this Filter is the
/// only place topology-aware binding (e.g. every topology-aware CSI driver)
/// ever gets enforced. Skipping it lets the scheduler bind a pod onto a node
/// that cannot actually mount the volume; the kubelet then retries
/// `MountVolume.NodeAffinity check failed` forever with no recourse, since
/// the binding already committed.
///
/// Shared by `select_node_with_capacity` (direct scheduling) and
/// `find_preemption_plan`, so preemption never evicts pods on a node the
/// pending pod could not use anyway even after the eviction.
fn node_qualifies_for_pod(node: &NodeItem, pod: &PendingPod) -> bool {
    node_selector_matches(&node.metadata.labels, &pod.node_selector)
        && node_affinity_matches(
            &node.metadata.labels,
            &node.metadata.name,
            pod.node_affinity.as_ref(),
        )
        && node_taints_tolerated(&node.spec.taints, &pod.tolerations)
        // Mirrors upstream's `NodeUnschedulable` default Filter plugin: a
        // cordoned node (`spec.unschedulable=true`) is rejected unless the
        // pod tolerates the well-known `node.kubernetes.io/unschedulable`
        // NoSchedule taint (reusing the same toleration-matching logic
        // `node_taints_tolerated` uses for real taints).
        && (node.spec.unschedulable != Some(true)
            || pod.tolerations.iter().any(|tol| {
                toleration_matches_taint(
                    tol,
                    &Taint {
                        key: "node.kubernetes.io/unschedulable".to_owned(),
                        value: String::new(),
                        effect: "NoSchedule".to_owned(),
                    },
                )
            }))
        // Every bound PVC's PV nodeAffinity is ANDed in, not ORed: a pod
        // with two bound PVCs pinned to different nodes has nowhere it can
        // actually run, and a node satisfying only one of them still cannot
        // mount both — mirrors upstream's VolumeBinding Filter plugin,
        // which rejects a node the instant any one bound volume's PV
        // nodeAffinity fails.
        && pod
            .pv_node_affinities
            .iter()
            .all(|selector| node_selector_spec_matches(&node.metadata.labels, &node.metadata.name, Some(selector)))
}

/// Return true when adding `requested` to a node's already-committed `used`
/// requests would not exceed `allocatable`, independently for each of
/// cpu/memory/ephemeral-storage/extended resources. An allocatable value of 0
/// (field absent or unparseable — see `parse_quantity_milli`) means that
/// cpu/memory/ephemeral-storage dimension is unknown and is not checked,
/// mirroring `parse_pod_capacity`'s existing convention for
/// `status.allocatable.pods`.
///
/// Extended resources are NOT given this "unknown means unlimited" treatment:
/// a node that does not advertise a given extended resource at all has none
/// of it to give, so requesting it must fail-closed, not be silently ignored
/// — otherwise a pod requesting a GPU (say) could be bound to a node with no
/// GPU, which the kubelet would then reject anyway (as the SchedulerPreemption
/// conformance suite's synthetic `scheduling.k8s.io/foo` resource does today).
///
/// `pub` (not module-private) so `benches/predicates.rs` can call it directly
/// — a criterion bench is a separate crate that only ever sees this crate's
/// public API.
pub fn resource_fits(
    allocatable: &NodeAllocatable,
    used: &ResourceRequests,
    requested: &ResourceRequests,
) -> bool {
    let cpu_cap = parse_quantity_milli(&allocatable.cpu);
    let mem_cap = parse_quantity_milli(&allocatable.memory);
    let eph_cap = parse_quantity_milli(&allocatable.ephemeral_storage);
    (cpu_cap == 0 || used.cpu_milli + requested.cpu_milli <= cpu_cap)
        && (mem_cap == 0 || used.memory_milli + requested.memory_milli <= mem_cap)
        && (eph_cap == 0
            || used.ephemeral_storage_milli + requested.ephemeral_storage_milli <= eph_cap)
        && requested.extended.iter().all(|(name, &want)| {
            if want == 0 {
                return true;
            }
            let cap = allocatable
                .extended
                .get(name)
                .map(|s| parse_quantity_milli(s))
                .unwrap_or(0);
            let have = used.extended.get(name).copied().unwrap_or(0);
            have + want <= cap
        })
}

/// Return true when `ip` is the wildcard hostIP — "every interface on the
/// host" — matching upstream's `HostPortInfo.sanitize`/`DefaultBindAllHostIP`:
/// an absent `hostIP` (empty string, the field's own zero value) and the
/// literal `"0.0.0.0"` are the same thing, not two different addresses.
fn is_wildcard_host_ip(ip: &str) -> bool {
    ip.is_empty() || ip == "0.0.0.0"
}

/// Return true when two hostPort claims conflict: same hostPort, same
/// protocol, and a hostIP that is identical OR where either side is the
/// wildcard (0.0.0.0/empty) — the exact semantics of upstream's NodePorts
/// predicate (`HostPortInfo.CheckConflict`). Without the wildcard half of
/// this check, a pod that leaves `hostIP` empty (binding all interfaces)
/// would NOT be seen as conflicting with a second pod that pins the node's
/// real IP on the same hostPort+protocol, even though both pods are
/// fighting over the same physical socket and the kubelet can only start one
/// of them.
fn host_ports_conflict(a: &HostPortClaim, b: &HostPortClaim) -> bool {
    a.host_port == b.host_port
        && a.protocol == b.protocol
        && (a.host_ip == b.host_ip
            || is_wildcard_host_ip(&a.host_ip)
            || is_wildcard_host_ip(&b.host_ip))
}

/// The NodePorts predicate: true when none of `pod_ports` conflicts with any
/// hostPort already claimed by pods tallied on the candidate node
/// (`node_ports`) — see `host_ports_conflict` for the exact conflict rule.
///
/// `pub` (not module-private) for the same reason `resource_fits` is: a
/// criterion bench in `benches/predicates.rs` may exercise it directly.
pub fn host_ports_fit(node_ports: &[HostPortClaim], pod_ports: &[HostPortClaim]) -> bool {
    !pod_ports.iter().any(|want| {
        node_ports
            .iter()
            .any(|have| host_ports_conflict(have, want))
    })
}

/// Among every node in `list` that qualifies for `pod` (see
/// `node_qualifies_for_pod`) AND satisfies `pod`'s required podAffinity/
/// podAntiAffinity terms against `tallied_pods` (see
/// `InterPodAffinityContext`) AND satisfies every hard
/// (`whenUnsatisfiable: DoNotSchedule`) `topologySpreadConstraints` entry
/// against `tallied_pods` (see `TopologySpreadContext`) AND has at least one
/// free pod slot AND enough uncommitted cpu/memory/ephemeral-storage/extended
/// resources to fit `pod.requests` (NodeResourcesFit) AND has no hostPort
/// conflict with `pod.host_ports` (NodePorts — see `host_ports_fit`), select
/// the LEAST LOADED one.
///
/// "Least loaded" ranks primarily by tallied pod count, then (as a tie-break
/// only) by tallied cpu/memory/ephemeral-storage requests. Pod count must lead
/// the ranking, not requests alone: BestEffort pods (the overwhelming
/// majority of e2e/conformance test workloads) request nothing, so a
/// requests-only comparison sees every qualifying node tied at zero and can
/// never break the tie. Before this ranking existed, `find` just returned the
/// first qualifying node, so every request-less pod deterministically piled
/// onto whichever node sorted first in `list` — confirmed live in a 2-node
/// conformance run where the second node carried exactly one pod (a mandatory
/// per-node system daemon) for the run's entire duration while the first
/// carried the whole test fleet, eventually OOM-killing it. Ranking by pod
/// count directly spreads that BestEffort majority; the request-based
/// tie-break still matters for nodes with equal pod counts but different
/// committed load.
///
/// `node_usage` maps node name → current non-terminated pod count and summed
/// resource requests, as computed by `NodeTally::usage_by_node`.  If a node's
/// name is absent from `node_usage`, its usage is treated as zero
/// (conservative: schedule).
///
/// Pod-count capacity is read from `status.allocatable.pods`, falling back to
/// `status.capacity.pods`.  A capacity of 0 (field absent / unparseable) means
/// the limit is unknown; such nodes are NOT skipped (the old safe behaviour) —
/// the same convention applies to each resource dimension (see `resource_fits`).
///
/// Returns `Err` when no node qualifies with free capacity, so the caller can
/// leave the pod Pending instead of binding to a full or unusable node.
///
/// Pure function so the capacity-gate logic can be unit-tested without a network.
pub fn select_node_with_capacity(
    list: NodeList,
    pod: &PendingPod,
    node_usage: &std::collections::HashMap<String, NodeUsage>,
    tallied_pods: &[TalliedPodLabels],
) -> anyhow::Result<String> {
    // Built once, up front, from the full node list — `list.items` is
    // consumed piecemeal by the `.into_iter().filter(...)` below, so every
    // OTHER node's labels (needed to resolve a tallied pod's topology
    // domain) must be captured before that starts.
    let node_labels_by_name: std::collections::HashMap<
        String,
        std::collections::HashMap<String, String>,
    > = list
        .items
        .iter()
        .map(|n| (n.metadata.name.clone(), n.metadata.labels.clone()))
        .collect();
    let affinity_ctx = InterPodAffinityContext::build(pod, tallied_pods, &node_labels_by_name);
    let topology_ctx = TopologySpreadContext::build(pod, tallied_pods, &node_labels_by_name);
    let usage_of = |name: &str| node_usage.get(name).cloned().unwrap_or_default();
    // `NodeUsage::pvc_names` is namespace-qualified (see its doc comment) —
    // qualify `pod`'s own RWOP PVCs the same way before comparing, or a
    // same-named PVC in a DIFFERENT namespace would be treated as the same
    // volume as `pod`'s own.
    let rwop_pvcs: Vec<String> = pod
        .read_write_once_pod_pvcs
        .iter()
        .map(|n| pvc_key(&pod.namespace, n))
        .collect();
    // Set when some node satisfies every OTHER conjunct below and is
    // rejected ONLY by `csi_volume_limits_fit` — lets the final error below
    // report the CSILimits-specific reason (matching upstream's own
    // `ErrReasonMaxVolumeCountExceeded`) instead of the generic
    // NodeResourcesFit message, which the volumeLimits conformance test's
    // `PodScheduled=False` condition message must match via a
    // `max.+volume.+count` regex.
    //
    // Imprecise across MULTIPLE rejected nodes: once any node's sole failure
    // is CSI, this stays `true` even if a LATER node in the same call also
    // fails for a resource reason — so the final error can name "max volume
    // count" when a different node was actually blocked by cpu/memory. Only
    // cosmetic (the pod correctly stays unscheduled either way) — scoping
    // this per-node needs the filter to record more than a single failure
    // reason per candidate, which no caller currently needs.
    let mut csi_limit_was_the_only_blocker = false;
    let candidates: Vec<NodeItem> = list
        .items
        .into_iter()
        .filter(|n| {
            if !node_qualifies_for_pod(n, pod) {
                return false;
            }
            if !affinity_ctx.node_qualifies(&n.metadata.labels) {
                return false;
            }
            if !topology_ctx.node_qualifies(&n.metadata.labels) {
                return false;
            }
            let usage = usage_of(&n.metadata.name);
            // Resolve pod-count capacity: prefer allocatable, fall back to capacity.
            let cap_str = if !n.status.allocatable.pods.is_empty() {
                &n.status.allocatable.pods
            } else {
                &n.status.capacity.pods
            };
            let cap = parse_pod_capacity(cap_str);
            if cap != 0 && usage.pod_count >= cap {
                return false;
            }
            if !resource_fits(&n.status.allocatable, &usage.requests, &pod.requests)
                || !host_ports_fit(&usage.host_ports, &pod.host_ports)
            {
                return false;
            }
            if !read_write_once_pod_conflict_free(&usage.pvc_names, &rwop_pvcs) {
                return false;
            }
            if !csi_volume_limits_fit(&n.csi_driver_headroom, &pod.csi_volume_counts) {
                csi_limit_was_the_only_blocker = true;
                return false;
            }
            if !csi_topology_fit(&n.csi_registered_drivers, &pod.unbound_csi_pvc_drivers) {
                return false;
            }
            true
        })
        .collect();
    // `min_by_key` returns the FIRST minimal element on a tie, preserving
    // `list`'s original order as the final tie-break — the same order the old
    // first-fit `.find()` used, so a single qualifying node (or several tied
    // on both pod count and requests) behaves exactly as before.
    let found = candidates.into_iter().min_by_key(|n| {
        let usage = usage_of(&n.metadata.name);
        (
            usage.pod_count,
            usage.requests.cpu_milli,
            usage.requests.memory_milli,
            usage.requests.ephemeral_storage_milli,
        )
    });
    found.map(|n| n.metadata.name).ok_or_else(|| {
        if csi_limit_was_the_only_blocker {
            anyhow::anyhow!("node(s) exceed max volume count")
        } else {
            anyhow::anyhow!(
                "no node satisfies the pod's nodeSelector/tolerations with free pod/resource capacity (NodeResourcesFit)"
            )
        }
    })
}

/// Select the pods to evict from one node so that a pending pod at
/// `pending_priority` requesting `pending_requests` fits, given the node's
/// pod-count `pod_count_capacity` and resource `allocatable` — the same
/// dimensions `resource_fits`/`select_node_with_capacity` check at bind time.
///
/// Generalizes the original pod-count-only MVP: a pending pod can be blocked
/// by pod-count OR by any resource dimension `select_node_with_capacity`
/// would reject it for — most notably an extended resource (e.g. a GPU, or
/// the SchedulerPreemption conformance suite's synthetic
/// `scheduling.k8s.io/foo`). Without accounting for resources here too, a
/// higher-priority pod whose only contention is an extended resource can
/// never trigger eviction — `pick_node` already returns `Ok` for such a node
/// (cpu/memory/pod-count all look free), so this function never even runs,
/// and the pending pod is bound onto a node the kubelet then rejects it from,
/// with no recourse.
///
/// Only pods with priority STRICTLY LOWER than `pending_priority` are eligible
/// victims: kube-scheduler never preempts equal-or-higher-priority pods, and
/// neither must u7s — otherwise same-priority pods could evict each other in a
/// cycle and scheduling would never stabilize. Eligible victims are evicted
/// lowest-priority-first (cheapest disruption), accumulating freed pod-count
/// and resource capacity one victim at a time, until the pending pod fits
/// every dimension — never evicting more than necessary.
///
/// Returns an empty `Vec` — meaning "do not evict anything" — when the pod
/// already fits (preemption must never run when there was room, or it would
/// kill a workload for no reason), or when evicting every eligible
/// lower-priority pod still would not free enough of some dimension — the
/// pending pod would not fit even after the disruption, so evicting anyone
/// would be pointless.
pub fn select_preemption_victims(
    pending_priority: i32,
    pending_requests: &ResourceRequests,
    node_pods: &[NodePod],
    pod_count_capacity: u32,
    allocatable: &NodeAllocatable,
) -> Vec<String> {
    let fits = |pod_count: u32, requests: &ResourceRequests| {
        (pod_count_capacity == 0 || pod_count < pod_count_capacity)
            && resource_fits(allocatable, requests, pending_requests)
    };

    let total_pod_count = node_pods.len() as u32;
    let total_requests = node_pods
        .iter()
        .fold(ResourceRequests::default(), |acc, p| {
            acc + p.requests.clone()
        });

    // Pod-count is a candidate-independent dimension: if it is short, EVERY
    // pod helps (each occupies exactly one slot). A resource dimension is
    // different: a pod that requests none of a specific short resource frees
    // none of it by being evicted, no matter how low its priority — e.g. on a
    // node short on the SchedulerPreemption suite's synthetic
    // `scheduling.k8s.io/foo`, evicting coredns (which requests none of it)
    // is pure collateral damage that helps nobody — reproduced live: before
    // this filter, u7s evicted kube-system/coredns and
    // kube-system/konnectivity-agent instead of the pod actually holding the
    // contended resource, because they happened to have lower/no priority.
    let pod_count_short = pod_count_capacity != 0 && total_pod_count >= pod_count_capacity;
    let mut candidates: Vec<&NodePod> = node_pods
        .iter()
        .filter(|p| p.priority < pending_priority)
        .filter(|p| {
            pod_count_short
                || resource_deficiency_relevant(
                    allocatable,
                    &total_requests,
                    pending_requests,
                    &p.requests,
                )
        })
        .collect();
    candidates.sort_by_key(|p| p.priority);

    let mut remaining_pod_count = total_pod_count;
    let mut remaining_requests = total_requests;
    let mut victims = Vec::new();
    for candidate in candidates {
        if fits(remaining_pod_count, &remaining_requests) {
            break;
        }
        remaining_pod_count -= 1;
        subtract_requests(&mut remaining_requests, &candidate.requests);
        victims.push(candidate.key.clone());
    }

    if fits(remaining_pod_count, &remaining_requests) {
        victims
    } else {
        Vec::new()
    }
}

/// Return true when evicting a pod requesting `candidate` could plausibly
/// help admit `pending` — i.e. some resource dimension is both short (adding
/// `pending`'s request to the node's `total_used` would exceed `allocatable`)
/// AND `candidate` itself requests a nonzero amount of that SAME dimension.
/// A pod holding none of the scarce resource cannot free any of it by being
/// evicted, however low its priority (see `select_preemption_victims`).
fn resource_deficiency_relevant(
    allocatable: &NodeAllocatable,
    total_used: &ResourceRequests,
    pending: &ResourceRequests,
    candidate: &ResourceRequests,
) -> bool {
    let short = |cap: i64, used: i64, want: i64| cap != 0 && used + want > cap;
    if short(
        parse_quantity_milli(&allocatable.cpu),
        total_used.cpu_milli,
        pending.cpu_milli,
    ) && candidate.cpu_milli > 0
    {
        return true;
    }
    if short(
        parse_quantity_milli(&allocatable.memory),
        total_used.memory_milli,
        pending.memory_milli,
    ) && candidate.memory_milli > 0
    {
        return true;
    }
    if short(
        parse_quantity_milli(&allocatable.ephemeral_storage),
        total_used.ephemeral_storage_milli,
        pending.ephemeral_storage_milli,
    ) && candidate.ephemeral_storage_milli > 0
    {
        return true;
    }
    pending.extended.iter().any(|(name, &want)| {
        if want == 0 {
            return false;
        }
        // Unlike cpu/memory/ephemeral-storage, a missing/0 capacity for an
        // extended resource is a real (exhausted) limit, not "unknown, don't
        // check" — matches resource_fits's fail-closed convention. So this
        // branch, unlike the three above, does NOT gate on `cap != 0`.
        let cap = allocatable
            .extended
            .get(name)
            .map(|s| parse_quantity_milli(s))
            .unwrap_or(0);
        let used = total_used.extended.get(name).copied().unwrap_or(0);
        let candidate_has = candidate.extended.get(name).copied().unwrap_or(0);
        used + want > cap && candidate_has > 0
    })
}

/// The VolumeRestrictions/ReadWriteOncePod predicate: true when none of
/// `rwop_pvcs` (the pending pod's ReadWriteOncePod PVC names) is already
/// referenced by a pod tallied on this node (`node_pvc_names`). A PVC with
/// the ReadWriteOncePod access mode may be mounted by at most one pod at a
/// time — Kubernetes' strictest access mode, stricter than ReadWriteOnce's
/// "one node" — so a second pod wanting the same PVC must never be bound
/// alongside the first, on any node.
///
/// `pub` (not module-private) so `benches/predicates.rs` can call it
/// directly, for the same reason `resource_fits`/`host_ports_fit` are.
pub fn read_write_once_pod_conflict_free(node_pvc_names: &[String], rwop_pvcs: &[String]) -> bool {
    !rwop_pvcs.iter().any(|pvc| node_pvc_names.contains(pvc))
}

/// Every tallied pod on this candidate node that already references one of
/// `pod`'s ReadWriteOncePod PVCs, as MANDATORY preemption victims: unlike
/// `select_preemption_victims`'s resource-dimension candidates (evicted only
/// if doing so helps the pending pod fit), evicting an RWOP conflict holder
/// is not optional — no amount of free cpu/memory/pod-count capacity lets
/// this node admit `pod` while that holder is still there.
///
/// Returns `None` — meaning this node can NEVER become viable via preemption
/// — when any conflicting pod's priority is not strictly lower than
/// `pending_priority`: kube-scheduler (and this scheduler, see
/// `select_preemption_victims`) never preempts an equal-or-higher-priority
/// pod, so such a conflict can never be resolved by eviction. Returns
/// `Some(&[])` when `pod` has no ReadWriteOncePod PVCs at all, or none of
/// them conflict with anything on this node — nothing extra to preempt here.
fn read_write_once_pod_preemption_victims(
    node_pods: &[NodePod],
    rwop_pvcs: &[String],
    pending_priority: i32,
) -> Option<Vec<String>> {
    if rwop_pvcs.is_empty() {
        return Some(Vec::new());
    }
    let conflicting: Vec<&NodePod> = node_pods
        .iter()
        .filter(|p| p.pvc_names.iter().any(|name| rwop_pvcs.contains(name)))
        .collect();
    if conflicting.iter().any(|p| p.priority >= pending_priority) {
        return None;
    }
    Some(conflicting.into_iter().map(|p| p.key.clone()).collect())
}

/// Return true when all entries in `selector` are satisfied by `labels`.
///
/// An empty selector matches any node (standard Kubernetes semantics).
/// Extracted as a pure function so the matching logic can be unit-tested
/// without network access.
pub fn node_selector_matches(
    labels: &std::collections::HashMap<String, String>,
    selector: &std::collections::HashMap<String, String>,
) -> bool {
    selector
        .iter()
        .all(|(k, v)| labels.get(k).map(|s| s == v).unwrap_or(false))
}

/// Evaluate one `matchExpressions[]` requirement against a node's labels.
///
/// `Gt`/`Lt` (numeric comparison operators) are not implemented by this MVP —
/// they never match. The SchedulerPredicates conformance suite only exercises
/// `In`/`NotIn`, and silently treating an unrecognized/unsupported operator as
/// an automatic pass would let a pod bypass an affinity rule it doesn't
/// actually satisfy.
fn node_selector_requirement_matches(
    labels: &std::collections::HashMap<String, String>,
    req: &NodeSelectorRequirement,
) -> bool {
    match req.operator.as_str() {
        "In" => labels.get(&req.key).is_some_and(|v| req.values.contains(v)),
        "NotIn" => !labels.get(&req.key).is_some_and(|v| req.values.contains(v)),
        "Exists" => labels.contains_key(&req.key),
        "DoesNotExist" => !labels.contains_key(&req.key),
        _ => false,
    }
}

/// Return true when `labels`/`node_name` satisfy `selector`.
///
/// `nodeSelectorTerms` are ORed together (any one term matching is enough);
/// within a single term, every `matchExpressions` requirement AND every
/// `matchFields` requirement must hold — mirroring Kubernetes' `NodeSelector`
/// semantics. `matchFields` is evaluated against a synthetic one-entry
/// `{"metadata.name": node_name}` map — the only field Kubernetes ever
/// populates `matchFields` with (it's how the DaemonSet controller pins each
/// per-node pod). `None`, or an empty term list, matches any node — there is
/// nothing to restrict on.
///
/// Shared by `node_affinity_matches` (a pod's own required `nodeAffinity`)
/// and `node_qualifies_for_pod`'s `pv_node_affinities` conjunct (a bound
/// PVC's PV `spec.nodeAffinity`) — both reduce to the exact same "OR of
/// terms, AND of expressions/fields within a term" evaluation over a
/// `NodeSelectorSpec`, just sourced from a different part of the API.
fn node_selector_spec_matches(
    labels: &std::collections::HashMap<String, String>,
    node_name: &str,
    selector: Option<&NodeSelectorSpec>,
) -> bool {
    let Some(selector) = selector else {
        return true;
    };
    if selector.node_selector_terms.is_empty() {
        return true;
    }
    let field_values: std::collections::HashMap<String, String> =
        [("metadata.name".to_owned(), node_name.to_owned())].into();
    selector.node_selector_terms.iter().any(|term| {
        term.match_expressions
            .iter()
            .all(|req| node_selector_requirement_matches(labels, req))
            && term
                .match_fields
                .iter()
                .all(|req| node_selector_requirement_matches(&field_values, req))
    })
}

/// Return true when `labels`/`node_name` satisfy a required `nodeAffinity`.
///
/// `None` (no nodeAffinity, or no
/// `requiredDuringSchedulingIgnoredDuringExecution`) matches any node — there
/// is nothing to restrict on. See `node_selector_spec_matches` for the actual
/// term-matching semantics.
///
/// Extracted as a pure function so the predicate can be unit-tested without
/// network access — mirrors `node_selector_matches`.
pub fn node_affinity_matches(
    labels: &std::collections::HashMap<String, String>,
    node_name: &str,
    affinity: Option<&NodeAffinity>,
) -> bool {
    node_selector_spec_matches(
        labels,
        node_name,
        affinity.and_then(|a| {
            a.required_during_scheduling_ignored_during_execution
                .as_ref()
        }),
    )
}

/// Return true when `labels` satisfies `selector`. Mirrors upstream's
/// `metav1.LabelSelectorAsSelector`: a `None` selector matches NOTHING (the
/// "nil labelSelector" case), while `Some` with both `matchLabels` and
/// `matchExpressions` empty matches EVERYTHING — these are opposite
/// defaults, so they cannot be collapsed into one "empty means match-all"
/// rule the way `node_selector_matches`'s bare map can.
fn label_selector_matches(
    labels: &std::collections::HashMap<String, String>,
    selector: Option<&LabelSelectorSpec>,
) -> bool {
    let Some(selector) = selector else {
        return false;
    };
    selector
        .match_labels
        .iter()
        .all(|(k, v)| labels.get(k) == Some(v))
        && selector
            .match_expressions
            .iter()
            .all(|req| node_selector_requirement_matches(labels, req))
}

/// Return true when `candidate_namespace` is one of the namespaces
/// `term_namespaces` applies to. An empty `term_namespaces` means "this
/// pod's own namespace" (`pod_namespace`) — matches upstream's
/// `PodAffinityTerm.Namespaces` default.
fn term_namespace_matches(
    term_namespaces: &[String],
    pod_namespace: &str,
    candidate_namespace: &str,
) -> bool {
    if term_namespaces.is_empty() {
        candidate_namespace == pod_namespace
    } else {
        term_namespaces.iter().any(|n| n == candidate_namespace)
    }
}

/// Return true when a pod with `candidate_namespace`/`candidate_labels`
/// satisfies `term`, evaluated relative to `pod_namespace` (the pending
/// pod's own namespace — what an empty `term.namespaces` falls back to).
/// Shared by `topology_pairs_matched_by_terms` (checking already-tallied
/// pods) and the self-match bootstrap case in `pod_affinity_satisfied`
/// (checking the pending pod against its own terms).
fn pod_matches_affinity_term(
    term: &PodAffinityTerm,
    pod_namespace: &str,
    candidate_namespace: &str,
    candidate_labels: &std::collections::HashMap<String, String>,
) -> bool {
    term_namespace_matches(&term.namespaces, pod_namespace, candidate_namespace)
        && label_selector_matches(candidate_labels, term.label_selector.as_ref())
}

/// For each `(topologyKey, topologyValue)` pair some node currently carries,
/// how many pods in `tallied` — anywhere in the cluster, not just on that
/// node — match one of `terms` AND occupy a node with that pair. Built once
/// per scheduling decision (the pending pod's own required terms and the
/// current tally do not change while candidate nodes are being evaluated for
/// THIS pod), not once per candidate node — mirrors upstream's
/// PreFilter-computed `topologyToMatchedTermCount`, just recomputed fresh
/// each time instead of incrementally maintained across a whole Filter pass.
///
/// A per-pair COUNT, not just a boolean "has a match" — rather than a plain
/// `HashSet` — so `InterPodAffinityContext::node_qualifies_excluding_victims`
/// can discount a candidate node's own about-to-be-evicted victims from a
/// pair's count without losing track of whether some OTHER pod (on a
/// different node sharing the same topology value) still legitimately
/// matches there too.
fn topology_pairs_matched_by_terms(
    terms: &[PodAffinityTerm],
    pod_namespace: &str,
    tallied: &[TalliedPodLabels],
    node_labels_by_name: &std::collections::HashMap<
        String,
        std::collections::HashMap<String, String>,
    >,
) -> std::collections::HashMap<(String, String), i32> {
    let mut matched = std::collections::HashMap::new();
    for term in terms {
        if term.topology_key.is_empty() {
            continue;
        }
        for p in tallied {
            if !pod_matches_affinity_term(term, pod_namespace, &p.namespace, &p.labels) {
                continue;
            }
            if let Some(value) = node_labels_by_name
                .get(&p.node_name)
                .and_then(|labels| labels.get(&term.topology_key))
            {
                *matched
                    .entry((term.topology_key.clone(), value.clone()))
                    .or_insert(0) += 1;
            }
        }
    }
    matched
}

/// Return true when `node_labels` satisfies every one of `pod`'s required
/// podAffinity terms — each term requires that, within the topology domain
/// (the set of nodes sharing `term.topologyKey`'s value) `node_labels`
/// belongs to, `matched` records at least one already-tallied pod matching
/// the term. A node missing `term.topologyKey` entirely fails the term
/// outright (mirrors upstream: "all topology labels must exist on the
/// node" — there is no domain to test membership in).
///
/// The self-match rescue mirrors upstream's `satisfyPodAffinity`: if
/// LITERALLY NO pod anywhere in the cluster matches any of `pod`'s terms
/// (`matched` empty overall, not just empty for this node's domain) AND
/// `pod`'s own labels/namespace would satisfy every one of its own terms,
/// every node carrying the required topology labels is admitted. Without
/// this, the very first replica of a self-referencing podAffinity workload
/// (e.g. a StatefulSet whose pods affine to their own selector) could never
/// be scheduled — no other matching pod can ever exist until this one is
/// placed somewhere.
fn pod_affinity_satisfied(
    pod: &PendingPod,
    node_labels: &std::collections::HashMap<String, String>,
    matched: &std::collections::HashMap<(String, String), i32>,
) -> bool {
    if pod.pod_affinity_terms.is_empty() {
        return true;
    }
    let mut all_terms_have_a_match = true;
    for term in &pod.pod_affinity_terms {
        let Some(value) = node_labels.get(&term.topology_key) else {
            return false;
        };
        let has_match = matched
            .get(&(term.topology_key.clone(), value.clone()))
            .is_some_and(|count| *count > 0);
        if !has_match {
            all_terms_have_a_match = false;
        }
    }
    if all_terms_have_a_match {
        return true;
    }
    matched.is_empty()
        && pod.pod_affinity_terms.iter().all(|term| {
            pod_matches_affinity_term(term, &pod.namespace, &pod.namespace, &pod.labels)
        })
}

/// Return true when `node_labels` satisfies every one of `pod`'s required
/// podAntiAffinity terms — a term is violated (node rejected) when `matched`
/// records an already-tallied pod sharing `node_labels`'s value for
/// `term.topologyKey`. Unlike `pod_affinity_satisfied`, a node missing
/// `term.topologyKey` entirely satisfies that term (no domain, so nothing to
/// conflict with) rather than failing it — mirrors upstream's
/// `satisfyPodAntiAffinity`, which only checks a term when the node actually
/// carries the topology label.
fn pod_anti_affinity_satisfied(
    pod: &PendingPod,
    node_labels: &std::collections::HashMap<String, String>,
    matched: &std::collections::HashMap<(String, String), i32>,
) -> bool {
    pod.pod_anti_affinity_terms.iter().all(|term| {
        node_labels.get(&term.topology_key).is_none_or(|value| {
            matched
                .get(&(term.topology_key.clone(), value.clone()))
                .is_none_or(|count| *count <= 0)
        })
    })
}

/// Cluster-wide state for evaluating one pending pod's required podAffinity/
/// podAntiAffinity terms against every candidate node in a single scheduling
/// decision, built ONCE (not once per candidate node) via `build` — see
/// `topology_pairs_matched_by_terms`'s doc comment for why that's safe.
///
/// Deliberately does NOT implement upstream's "existing pod's own
/// anti-affinity blocks the incoming pod" (symmetric) direction —
/// `ErrReasonExistingAntiAffinityRulesNotMatch` in upstream's
/// `interpodaffinity/filtering.go` — which would require tallying every
/// scheduled pod's OWN required anti-affinity terms, not just its labels.
/// Only the incoming pod's own terms, matched against already-tallied pods,
/// are enforced.
struct InterPodAffinityContext<'a> {
    pod: &'a PendingPod,
    affinity_matched: std::collections::HashMap<(String, String), i32>,
    anti_affinity_matched: std::collections::HashMap<(String, String), i32>,
}

impl<'a> InterPodAffinityContext<'a> {
    fn build(
        pod: &'a PendingPod,
        tallied: &[TalliedPodLabels],
        node_labels_by_name: &std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        >,
    ) -> Self {
        Self {
            pod,
            affinity_matched: topology_pairs_matched_by_terms(
                &pod.pod_affinity_terms,
                &pod.namespace,
                tallied,
                node_labels_by_name,
            ),
            anti_affinity_matched: topology_pairs_matched_by_terms(
                &pod.pod_anti_affinity_terms,
                &pod.namespace,
                tallied,
                node_labels_by_name,
            ),
        }
    }

    fn node_qualifies(&self, node_labels: &std::collections::HashMap<String, String>) -> bool {
        self.node_qualifies_excluding_victims(node_labels, &[])
    }

    /// Same judgment as `node_qualifies`, but as if every pod in `victims` —
    /// this candidate node's own about-to-be-evicted preemption victims,
    /// always physically located on this SAME node (see
    /// `find_preemption_candidate`) — had already been removed. Mirrors
    /// upstream's `selectVictimsOnNode` calling `RemovePod` on the
    /// InterPodAffinity plugin's cycle state for each selected victim before
    /// re-checking the node: a node whose only affinity/anti-affinity
    /// violation is a pod about to be evicted from IT is still a valid
    /// preemption target.
    ///
    /// Skips the discount entirely (and so allocates nothing) when
    /// `victims` is empty — `node_qualifies`'s common, non-preemption-plan
    /// case.
    fn node_qualifies_excluding_victims(
        &self,
        node_labels: &std::collections::HashMap<String, String>,
        victims: &[&TalliedPodLabels],
    ) -> bool {
        if victims.is_empty() {
            return pod_affinity_satisfied(self.pod, node_labels, &self.affinity_matched)
                && pod_anti_affinity_satisfied(self.pod, node_labels, &self.anti_affinity_matched);
        }
        let affinity_matched = discount_matched_pairs(
            &self.pod.pod_affinity_terms,
            &self.pod.namespace,
            &self.affinity_matched,
            node_labels,
            victims,
        );
        let anti_affinity_matched = discount_matched_pairs(
            &self.pod.pod_anti_affinity_terms,
            &self.pod.namespace,
            &self.anti_affinity_matched,
            node_labels,
            victims,
        );
        pod_affinity_satisfied(self.pod, node_labels, &affinity_matched)
            && pod_anti_affinity_satisfied(self.pod, node_labels, &anti_affinity_matched)
    }
}

/// Build a copy of `matched`'s per-`(topologyKey, value)` pair counts (see
/// `topology_pairs_matched_by_terms`) with each of `terms`'s contribution
/// from `victims` subtracted out — the `InterPodAffinityContext` counterpart
/// to `TopologySpreadContext::node_qualifies_excluding_victims`'s inline
/// discount, extracted here (rather than inlined the same way) because a
/// pod's required affinity/anti-affinity terms can each carry a DIFFERENT
/// `topologyKey` — unlike `TopologySpreadConstraint`, where the discount is
/// computed once per constraint — so `pod_affinity_satisfied`/
/// `pod_anti_affinity_satisfied` need the discount already folded into the
/// map before they iterate `pod`'s terms themselves.
///
/// `victims` are only ever on this one candidate node (see
/// `find_preemption_candidate`), so — exactly like the topology-spread
/// case — only the ONE domain value `node_labels` itself carries for each
/// term's `topologyKey` is ever discounted; a match contributed by some
/// OTHER node sharing that same topology value is untouched.
fn discount_matched_pairs(
    terms: &[PodAffinityTerm],
    pod_namespace: &str,
    matched: &std::collections::HashMap<(String, String), i32>,
    node_labels: &std::collections::HashMap<String, String>,
    victims: &[&TalliedPodLabels],
) -> std::collections::HashMap<(String, String), i32> {
    let mut discounted = matched.clone();
    for term in terms {
        let Some(value) = node_labels.get(&term.topology_key) else {
            continue;
        };
        let discount = victims
            .iter()
            .filter(|v| pod_matches_affinity_term(term, pod_namespace, &v.namespace, &v.labels))
            .count() as i32;
        if discount > 0 {
            if let Some(count) = discounted.get_mut(&(term.topology_key.clone(), value.clone())) {
                *count -= discount;
            }
        }
    }
    discounted
}

/// For one topology-spread `constraint`, every topology-domain VALUE some
/// node currently carries under `constraint.topologyKey`, mapped to how many
/// already-tallied pods matching `constraint.labelSelector` occupy that
/// domain.
///
/// Every domain value observed among `node_labels_by_name` is seeded at 0
/// FIRST, even if no matching pod occupies it — mirroring upstream's
/// `calPreFilterState`, whose `s.TpValueToMatchNum[i][value] += count` map
/// insertion has the side effect of creating a zero entry for every domain a
/// node exists in, regardless of whether any pod matches there. Without this,
/// a domain with truly nothing on it would be ABSENT from the map rather than
/// present at 0, and `TopologySpreadContext::build`'s `.values().min()` would
/// then only ever see domains that already have at least one match — putting
/// a floor under the computed minimum that lets a heavily loaded cluster's
/// skew look smaller than it really is.
///
/// Only pods in `pod_namespace` (the pending pod's own namespace) count —
/// mirrors upstream's `countPodsMatchSelector`, which explicitly skips pods
/// in a different namespace: a spread constraint only ever balances sibling
/// replicas of the SAME namespaced workload, not every pod in the cluster
/// that happens to share a label.
fn topology_domain_counts(
    constraint: &TopologySpreadConstraint,
    pod_namespace: &str,
    tallied: &[TalliedPodLabels],
    node_labels_by_name: &std::collections::HashMap<
        String,
        std::collections::HashMap<String, String>,
    >,
) -> std::collections::HashMap<String, i32> {
    let mut counts: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
    for node_labels in node_labels_by_name.values() {
        if let Some(value) = node_labels.get(&constraint.topology_key) {
            counts.entry(value.clone()).or_insert(0);
        }
    }
    for p in tallied {
        if p.namespace != pod_namespace {
            continue;
        }
        if !label_selector_matches(&p.labels, constraint.label_selector.as_ref()) {
            continue;
        }
        if let Some(value) = node_labels_by_name
            .get(&p.node_name)
            .and_then(|labels| labels.get(&constraint.topology_key))
        {
            *counts.entry(value.clone()).or_insert(0) += 1;
        }
    }
    counts
}

/// One hard (`whenUnsatisfiable: DoNotSchedule`) topology-spread constraint's
/// pre-computed skew inputs: the domain->matchCount map (see
/// `topology_domain_counts`) and its global minimum across every domain —
/// upstream's `minMatchNum`, computed once (not once per candidate node) by
/// `TopologySpreadContext::build`.
struct TopologySpreadTerm<'a> {
    constraint: &'a TopologySpreadConstraint,
    counts: std::collections::HashMap<String, i32>,
    min_match_num: i32,
}

/// Cluster-wide state for evaluating one pending pod's hard
/// (`whenUnsatisfiable: DoNotSchedule`) `topologySpreadConstraints` against
/// every candidate node in a single scheduling decision, built ONCE via
/// `build` — mirrors `InterPodAffinityContext`.
///
/// `ScheduleAnyway` constraints are dropped entirely at `build` time: they
/// are upstream's soft, Score-phase-only preference (see
/// `TopologySpreadConstraint`'s doc comment), and this scheduler has no Score
/// phase, so keeping them here would only cost cycles for no effect.
struct TopologySpreadContext<'a> {
    pod: &'a PendingPod,
    terms: Vec<TopologySpreadTerm<'a>>,
}

impl<'a> TopologySpreadContext<'a> {
    fn build(
        pod: &'a PendingPod,
        tallied: &[TalliedPodLabels],
        node_labels_by_name: &std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        >,
    ) -> Self {
        let terms = pod
            .topology_spread_constraints
            .iter()
            .filter(|c| c.when_unsatisfiable == "DoNotSchedule" && !c.topology_key.is_empty())
            .map(|constraint| {
                let counts = topology_domain_counts(
                    constraint,
                    &pod.namespace,
                    tallied,
                    node_labels_by_name,
                );
                let min_match_num = counts.values().min().copied().unwrap_or(0);
                TopologySpreadTerm {
                    constraint,
                    counts,
                    min_match_num,
                }
            })
            .collect();
        Self { pod, terms }
    }

    /// Return true when `node_labels` violates none of this pod's hard
    /// spread constraints. A node missing a constraint's `topologyKey`
    /// entirely is rejected outright — mirrors upstream's
    /// `ErrReasonNodeLabelNotMatch`: there is no domain to test skew against.
    ///
    /// Otherwise, mirrors upstream's exact judging criterion: `existing
    /// matching count in this node's domain` + `1 if this pod's own labels
    /// would themselves match the constraint's selector, else 0` -
    /// `the global minimum matching count across every domain` must not
    /// exceed `maxSkew`. The self-match term matters even for a pod with no
    /// tallied siblings anywhere yet — without it, the very first replica of
    /// a spread-constrained workload would see skew 0 everywhere and never
    /// actually reserve the "slot" its own placement is about to fill,
    /// letting a second replica land in the very same domain a moment later.
    fn node_qualifies(&self, node_labels: &std::collections::HashMap<String, String>) -> bool {
        self.node_qualifies_excluding_victims(node_labels, &[])
    }

    /// Same judgment as `node_qualifies`, but as if every pod in `victims` —
    /// this candidate node's own about-to-be-evicted preemption victims,
    /// always physically located on this SAME node (see
    /// `find_preemption_candidate`) — had already been removed. Mirrors
    /// upstream's `selectVictimsOnNode` calling `RemovePod` on the
    /// PodTopologySpread plugin's cycle state for each selected victim
    /// before re-checking the node: a node whose only skew violation is
    /// caused by a pod about to be evicted from IT is still a valid
    /// preemption target, not falsely rejected as if that pod would keep
    /// occupying its domain forever.
    ///
    /// `victims` are only ever on this one node, so only the ONE domain
    /// value THIS node itself carries for a constraint's `topologyKey` is
    /// ever discounted — every other domain's count is untouched, and
    /// `term.min_match_num` (the precomputed, common case) is reused as-is
    /// whenever there is nothing to discount for this term.
    fn node_qualifies_excluding_victims(
        &self,
        node_labels: &std::collections::HashMap<String, String>,
        victims: &[&TalliedPodLabels],
    ) -> bool {
        self.terms.iter().all(|term| {
            let Some(value) = node_labels.get(&term.constraint.topology_key) else {
                return false;
            };
            let discount = victims
                .iter()
                .filter(|v| {
                    v.namespace == self.pod.namespace
                        && label_selector_matches(
                            &v.labels,
                            term.constraint.label_selector.as_ref(),
                        )
                })
                .count() as i32;
            let match_num = term.counts.get(value).copied().unwrap_or(0) - discount;
            let self_match_num = i32::from(label_selector_matches(
                &self.pod.labels,
                term.constraint.label_selector.as_ref(),
            ));
            let min_match_num = if discount == 0 {
                term.min_match_num
            } else {
                term.counts
                    .iter()
                    .map(|(v, c)| if v == value { c - discount } else { *c })
                    .min()
                    .unwrap_or(term.min_match_num)
            };
            let skew = match_num + self_match_num - min_match_num;
            skew <= term.constraint.max_skew
        })
    }
}

/// Return true when `toleration` tolerates `taint`, mirroring Kubernetes'
/// `Toleration.ToleratesTaint`: an empty `key` only ever matches when paired
/// with `operator: Exists` (the "tolerate everything" wildcard); otherwise the
/// key must match exactly, and — unless `operator: Exists` — the value must
/// match exactly too (operator `Equal`, the default when absent). A
/// toleration with a set `effect` only tolerates a taint of that same effect.
fn toleration_matches_taint(toleration: &Toleration, taint: &Taint) -> bool {
    if let Some(t_effect) = &toleration.effect {
        if t_effect != &taint.effect {
            return false;
        }
    }
    match &toleration.key {
        None => toleration.operator.as_deref() == Some("Exists"),
        Some(key) => {
            key == &taint.key
                && (toleration.operator.as_deref() == Some("Exists")
                    || toleration.value.as_deref().unwrap_or("") == taint.value)
        }
    }
}

/// Return true when every scheduling-blocking taint on the node (`NoSchedule`
/// or `NoExecute`) is tolerated by at least one of the pod's tolerations.
///
/// A node with no such taints trivially satisfies this (nothing to tolerate).
/// Extracted as a pure function so the taint/toleration predicate can be
/// unit-tested without network access — mirrors `node_selector_matches`.
pub fn node_taints_tolerated(taints: &[Taint], tolerations: &[Toleration]) -> bool {
    taints
        .iter()
        .filter(|t| t.effect == "NoSchedule" || t.effect == "NoExecute")
        .all(|t| {
            tolerations
                .iter()
                .any(|tol| toleration_matches_taint(tol, t))
        })
}

/// Select the first node from `list` whose labels satisfy `selector`.
///
/// An empty `selector` matches any node (standard Kubernetes semantics).
/// Returns `Err` when no node satisfies the selector (pod must stay Pending).
///
/// Extracted as a pure function so the selection logic can be unit-tested
/// without network access. Replaces the former `select_first_node` which
/// ignored nodeSelector entirely, causing pods with non-matching selectors
/// to be incorrectly bound to any available node.
pub fn select_node_for_pod(
    list: NodeList,
    selector: &std::collections::HashMap<String, String>,
) -> anyhow::Result<String> {
    list.items
        .into_iter()
        .find(|n| node_selector_matches(&n.metadata.labels, selector))
        .map(|n| n.metadata.name)
        .context("no node satisfies the pod's nodeSelector")
}

/// Select the first node name from a `NodeList` (no selector filtering).
///
/// Retained for callers that have already confirmed the pod has no nodeSelector.
/// Returns an error when the list is empty.
pub fn select_first_node(list: NodeList) -> anyhow::Result<String> {
    list.items
        .into_iter()
        .next()
        .map(|n| n.metadata.name)
        .context("no nodes available")
}

/// Why `pick_node` failed to find a node for a pending pod.
///
/// The caller must treat these two causes very differently. `NoCapacity`
/// means every qualifying node was actually checked and none had room — a
/// legitimate reason to fall back to preemption (see `find_preemption_plan`).
/// `ApiError` means the GET /api/v1/nodes call itself failed, or its body
/// could not be parsed — no node was actually checked, so this says nothing
/// about real capacity. Collapsing `ApiError` into `NoCapacity` (the bug this
/// type replaces) would run preemption — evicting real lower-priority pods —
/// or mark the pod FailedScheduling, off a transient infra hiccup that the
/// next watch tick would otherwise have retried cleanly.
#[derive(Debug, thiserror::Error)]
pub enum PickNodeError {
    /// Carries `select_node_with_capacity`'s own specific reason (e.g. the
    /// generic NodeResourcesFit message, or CSILimits' "node(s) exceed max
    /// volume count") rather than a single fixed string — `handle_pod_event`
    /// reuses this text as the eventual `FailedScheduling`/`PodScheduled=False`
    /// message when a subsequent preemption attempt ALSO fails, since
    /// `find_preemption_plan`'s own failure text is generic and would
    /// otherwise overwrite a predicate-specific reason a conformance test's
    /// condition-message check relies on (see the volumeLimits e2e test).
    #[error("{0}")]
    NoCapacity(String),
    #[error(transparent)]
    ApiError(#[from] anyhow::Error),
}

/// Return the name of the least-loaded node that qualifies for `pod`
/// (see `select_node_with_capacity`): it must qualify (`node_qualifies_for_pod`),
/// have at least one free pod slot, and have enough uncommitted
/// cpu/memory/ephemeral-storage for `pod.requests` (NodeResourcesFit
/// predicate). On success, atomically reserves `pod` on
/// the chosen node in `tally` (see `NodeTally::assume`) before returning it.
///
/// Reads the node list from `tally`'s watch-maintained node cache (see
/// `NodeTally::node_list`) rather than a live GET — mirroring how per-node
/// usage already comes from `tally` instead of a live GET fan-out. A prior
/// version issued a GET /api/v1/pods?fieldSelector=spec.nodeName%3D<node> per
/// qualifying candidate node on every scheduling decision; besides being
/// O(qualifying nodes) per decision, that GET could read a just-committed
/// bind's resource request as stale (a read-after-write race under
/// concurrent scheduling load), letting a pod be bound onto a node that was
/// actually already full. `tally` cannot observe that race: the scheduler
/// updates it synchronously the moment it decides to bind, before the bind's
/// HTTP call even completes. The node cache accepts the same staleness
/// trade-off the pod tally already does — a cordon/taint/capacity change
/// lags by one watch round-trip — since nothing here ever writes a node
/// object, so there is no analogous read-after-write race to close for it.
///
/// The reservation happens under the SAME lock acquisition as the fit check,
/// not in a later, separate lock taken by the caller: two pods racing for the
/// same just-freed slot (e.g. a preemptor's post-eviction re-check racing a
/// controller's replacement pod for the capacity a preemption just freed —
/// reproduced live against the PreemptionExecutionPath conformance scenario)
/// could otherwise both read the slot as free before either reserved it, and
/// both bind — the kubelet then rejects whichever container it admits
/// second. Splitting the check and the reservation across two lock
/// acquisitions (as a prior version did, calling `NodeTally::assume`
/// separately after `pick_node` returned) reopens exactly the read-after-write
/// race this tally exists to close, just between two scheduling decisions
/// instead of between a GET and a bind. Reading the node list itself is a
/// separate, earlier lock acquisition (see `NodeTally::node_list`'s doc
/// comment) — safe, because nothing about node identity/spec/labels is part
/// of that race.
///
/// A node at or above its `status.allocatable.pods` limit, or that cannot fit
/// `pod.requests` alongside what's already tallied, is skipped. Returns
/// `Err(PickNodeError::NoCapacity)` when no suitable node exists so the
/// caller can skip binding and leave the pod Pending (without
/// this check, pods are bound to full nodes and the kubelet fails them
/// OutOfpods/OutOfcpu/OutOfephemeral-storage).
pub fn pick_node(
    pod: &PendingPod,
    tally: &std::sync::Mutex<NodeTally>,
) -> Result<String, PickNodeError> {
    let list = tally.lock().expect("tally lock poisoned").node_list();
    select_and_reserve_node(list, pod, tally)
}

/// Look up a single node by name, for `main.rs`'s `attempt_deferred_bind` to
/// re-verify fit against right before a deferred preemption bind. Reads
/// `tally`'s node cache directly by key (`NodeTally::node`) rather than
/// fetching every node just to find one by name. `None` means the node is
/// not (or no longer) in the cache — e.g. removed from the cluster while a
/// bind was deferred, or not yet observed by the node watch — the caller
/// must treat that as "cannot bind here any more".
pub fn fetch_node(tally: &std::sync::Mutex<NodeTally>, node_name: &str) -> Option<NodeItem> {
    tally.lock().expect("tally lock poisoned").node(node_name)
}

/// The synchronous fit-check-and-reserve step behind `pick_node`, split out
/// so its atomicity (one `tally` lock acquisition covers both the check and
/// the reservation) can be exercised under real concurrent access in a unit
/// test, without a live API server — `pick_node` itself cannot be unit
/// tested that way since it needs a network round trip for the node list.
///
/// Nets every candidate's CSI attach headroom (`net_csi_headroom`) fresh,
/// from THIS SAME `tally_guard`'s `usage_by_node()` snapshot, right here —
/// not via a separate, earlier lock acquisition (a prior version populated
/// `NodeItem::csi_driver_headroom` before this function's own lock, which a
/// concurrent decision's `assume()` could land in between, reopening the
/// exact read-after-write race `assume()` closes for cpu/mem/hostPorts/
/// pvc_names). Skipped entirely when `pod` needs no CSI volumes, mirroring
/// upstream's own PreFilter skip for the CSILimits plugin.
fn select_and_reserve_node(
    mut list: NodeList,
    pod: &PendingPod,
    tally: &std::sync::Mutex<NodeTally>,
) -> Result<String, PickNodeError> {
    let candidates = list.items.len();
    let mut tally_guard = tally.lock().expect("tally lock poisoned");
    let usage = tally_guard.usage_by_node();
    if !pod.csi_volume_counts.is_empty() {
        let limits_by_node = tally_guard.csi_driver_limits_by_node();
        for node in &mut list.items {
            let Some(limits) = limits_by_node.get(&node.metadata.name) else {
                continue;
            };
            let attached = usage
                .get(&node.metadata.name)
                .map(|u| u.csi_attached_counts.clone())
                .unwrap_or_default();
            node.csi_driver_headroom = net_csi_headroom(limits, &attached);
        }
    }
    if !pod.unbound_csi_pvc_drivers.is_empty() {
        let drivers_by_node = tally_guard.csi_driver_names_by_node();
        for node in &mut list.items {
            if let Some(drivers) = drivers_by_node.get(&node.metadata.name) {
                node.csi_registered_drivers = drivers.clone();
            }
        }
    }
    let node = select_node_with_capacity(list, pod, &usage, &tally_guard.tallied_pod_labels())
        .map_err(|e| {
            debug!(pod = %pod.pod_name, candidates, "pick_node: no node had capacity");
            PickNodeError::NoCapacity(e.to_string())
        })?;
    tally_guard.assume(
        &pod.namespace,
        &pod.pod_name,
        &node,
        pod.priority,
        pod.requests.clone(),
        pod.host_ports.clone(),
        pod.labels.clone(),
        pod.pvc_names.clone(),
    );
    Ok(node)
}

/// Whether a `pick_node` failure should be treated as "leave this pod
/// Pending and let the watch retry" instead of falling through to
/// preemption.
///
/// Pure predicate over the typed error — no networking — so the exact
/// branch that was bugged before `PickNodeError` existed (every `pick_node`
/// failure fell through to preemption, so a transient GET failure could
/// evict real lower-priority pods, or mark an otherwise-healthy pod
/// FailedScheduling, for no actual capacity reason) can be unit-tested
/// without a fake API server — `main.rs`'s tokio::spawn body that acts on
/// this isn't otherwise reachable from a unit test.
pub fn should_retry_without_preempting(err: &PickNodeError) -> bool {
    matches!(err, PickNodeError::ApiError(_))
}

/// A viable preemption outcome: the node to bind the pending pod to, and the
/// "namespace/name" keys of the pods that must be evicted first to free a slot.
#[derive(Debug, PartialEq)]
pub struct PreemptionPlan {
    pub node_name: String,
    pub victims: Vec<String>,
}

/// Search every node that qualifies for `pod` (see `node_qualifies_for_pod`)
/// for a viable preemption target: a node where evicting some lower-priority
/// pods would free a slot for `pod`. On success, atomically reserves `pod`
/// on the chosen node in `tally` (see `NodeTally::assume`) — BEFORE any of
/// `victims` is actually evicted — so the caller can safely evict them and
/// bind without a second fit check.
///
/// Intended to run only after `pick_node` has already failed for the same pod —
/// this is the fallback that stops a higher-priority pod from staying Pending
/// forever just because lower-priority pods claimed every slot first.
///
/// Per-node pod identity/priority/requests come from `tally` (see
/// `NodeTally`), not a live GET — see `pick_node`'s doc comment for why.
/// Reserving `pod` before eviction, rather than checking fit again after it,
/// is deliberate: a live repro against the PreemptionExecutionPath
/// conformance scenario showed that evicting victims first and only then
/// re-checking leaves a window where a THIRD, concurrently-scheduled pod
/// (there, a ReplicaSet controller's replacement for a pod just evicted)
/// can repeatedly claim each freed slot before the actual preemptor's
/// re-check runs — fast enough that even a several-attempt bounded retry of
/// "evict, then re-check" never won. Reserving first means the tally already
/// shows the node as occupied by `pod` — on top of the not-yet-evicted
/// victims — for the entire eviction sequence, so no other scheduling
/// decision ever observes a free slot to steal.
///
/// The reservation happens under a single, fresh lock acquisition that also
/// re-verifies the plan against the CURRENT tally (not the possibly-stale
/// per-node snapshots the search loop below used): if some other reservation
/// has already consumed the room this plan counted on, this returns `Err` so
/// the caller can re-plan from scratch, instead of reserving `pod` onto a
/// node that a fresher read shows no longer fits.
///
/// Why `find_preemption_plan` failed to find a preemption plan for a pending
/// pod.
///
/// Same distinction `PickNodeError` draws for `pick_node`, and for the same
/// reason (see its doc comment): `NoViablePlan` means every qualifying node
/// was actually checked and even preempting its lower-priority pods
/// wouldn't free enough room — a genuine "this pod cannot be scheduled"
/// outcome that stays that way until the cluster changes. `ApiError` means
/// the GET /api/v1/nodes call itself failed, or its body could not be
/// parsed — no node was actually checked, so it says nothing about whether
/// preemption would have worked. Collapsing `ApiError` into `NoViablePlan`
/// would mark a possibly-schedulable pod `FailedScheduling` off a transient
/// infra hiccup that the next watch tick would otherwise have retried
/// cleanly — the same bug `PickNodeError` fixed for `pick_node`.
#[derive(Debug, thiserror::Error)]
pub enum FindPreemptionPlanError {
    #[error("no node can fit the pending pod even after preempting lower-priority pods")]
    NoViablePlan,
    #[error(transparent)]
    ApiError(#[from] anyhow::Error),
}

/// Whether a `find_preemption_plan` failure should be treated as "leave this
/// pod Pending and let the watch retry" instead of a genuine scheduling
/// failure worth a `FailedScheduling` event.
///
/// Pure predicate over the typed error — no networking — so it can be unit
/// tested without a fake API server, mirroring
/// `should_retry_without_preempting`'s relationship to `pick_node`.
pub fn should_retry_after_preemption_plan_error(err: &FindPreemptionPlanError) -> bool {
    matches!(err, FindPreemptionPlanError::ApiError(_))
}

/// Among nodes where preemption would work, the node requiring the FEWEST
/// victims is chosen (cheapest disruption); ties keep `tally`'s node-list
/// order (see `NodeTally::node_list`'s doc comment for why that matches what
/// a live GET would have returned). Returns
/// `Err(FindPreemptionPlanError::NoViablePlan)` when no candidate node — even
/// after preempting every eligible lower-priority pod on it — could fit the
/// pending pod.
pub fn find_preemption_plan(
    pod: &PendingPod,
    tally: &std::sync::Mutex<NodeTally>,
) -> Result<PreemptionPlan, FindPreemptionPlanError> {
    let list = tally.lock().expect("tally lock poisoned").node_list();
    let node_labels_by_name: std::collections::HashMap<
        String,
        std::collections::HashMap<String, String>,
    > = list
        .items
        .iter()
        .map(|n| (n.metadata.name.clone(), n.metadata.labels.clone()))
        .collect();
    let tallied_pods = tally
        .lock()
        .expect("tally lock poisoned")
        .tallied_pod_labels();

    let (index, plan) =
        find_preemption_candidate(&list, pod, &tallied_pods, &node_labels_by_name, tally)
            .ok_or(FindPreemptionPlanError::NoViablePlan)?;
    verify_and_reserve_preemption(pod, &list.items[index], &plan, tally)
        .map_err(|_| FindPreemptionPlanError::NoViablePlan)?;

    Ok(plan)
}

/// The synchronous candidate-search step behind `find_preemption_plan`, split
/// out so its filtering logic can be exercised in a unit test without a live
/// API server — mirrors `select_and_reserve_node`'s relationship to
/// `pick_node`, for the same reason.
///
/// Considers every node that qualifies for `pod` (`node_qualifies_for_pod`)
/// AND, once that node's own preemption victims (`select_preemption_victims`)
/// have been selected and virtually removed, satisfies its required
/// podAffinity/podAntiAffinity terms (`InterPodAffinityContext`) AND every
/// hard (`whenUnsatisfiable: DoNotSchedule`) `topologySpreadConstraints`
/// entry (`TopologySpreadContext`) — the same two contexts, and the same
/// `node_qualifies` conjuncts, `select_node_with_capacity` applies for direct
/// scheduling, evaluated here via each context's `_excluding_victims`
/// counterpart. Without the `TopologySpreadContext` conjunct, a topology-
/// constrained pod could still trigger preemption onto a node that violates
/// its own `maxSkew` — the exact placement the direct-scheduling path
/// already refuses. And without discounting the node's own victims first, a
/// node whose ONLY topology/affinity violation is a pod already about to be
/// evicted from it would be rejected outright — mirrors upstream's
/// `selectVictimsOnNode`, which calls `RemovePod` on every plugin's cycle
/// state as each victim is chosen, so PodTopologySpread/InterPodAffinity are
/// re-checked with victims already discounted.
///
/// Victims are therefore selected BEFORE the affinity/topology check here,
/// the reverse of `select_node_with_capacity`'s ordering — which pods would
/// even be evicted depends on capacity fit, so that has to run first.
///
/// Among qualifying nodes, returns the cheapest (fewest-victims) viable
/// `(node index, PreemptionPlan)` — a node with at least one lower-priority
/// pod whose eviction would free enough room (`select_preemption_victims`).
/// `None` when no such node exists.
fn find_preemption_candidate(
    list: &NodeList,
    pod: &PendingPod,
    tallied_pods: &[TalliedPodLabels],
    node_labels_by_name: &std::collections::HashMap<
        String,
        std::collections::HashMap<String, String>,
    >,
    tally: &std::sync::Mutex<NodeTally>,
) -> Option<(usize, PreemptionPlan)> {
    let affinity_ctx = InterPodAffinityContext::build(pod, tallied_pods, node_labels_by_name);
    let topology_ctx = TopologySpreadContext::build(pod, tallied_pods, node_labels_by_name);
    // `NodePod::pvc_names` is namespace-qualified (see its doc comment) —
    // qualify `pod`'s own RWOP PVCs the same way before comparing, exactly
    // like `select_node_with_capacity` does, or a same-named PVC in a
    // DIFFERENT namespace would be picked as a mandatory victim here for no
    // real conflict.
    let rwop_pvcs: Vec<String> = pod
        .read_write_once_pod_pvcs
        .iter()
        .map(|n| pvc_key(&pod.namespace, n))
        .collect();

    let mut best: Option<(usize, PreemptionPlan)> = None;
    for (index, node) in list.items.iter().enumerate() {
        if !node_qualifies_for_pod(node, pod) {
            continue;
        }
        let capacity = pod_count_capacity(node);
        let node_name = &node.metadata.name;
        let tally_guard = tally.lock().expect("tally lock poisoned");
        let node_pods = tally_guard.pods_on(node_name);
        // Unlike RWOP's exact PVC-name match, there is no per-pod CSI-driver
        // attach-count tracked in `NodePod` to name a specific mandatory
        // victim from — the node-wide headroom, netted fresh right here
        // under the SAME lock as `pods_on` above (not a separate, earlier
        // lock acquisition — see `net_csi_headroom`'s doc comment for why
        // that would reopen the read-after-write race this closes), is the
        // only signal available. So an unresolved CSI-limit conflict makes
        // this node NON-VIABLE outright, the same fail-closed outcome RWOP
        // reaches for a conflict against an equal-or-higher-priority holder —
        // never silently treated as "no limit" (an empty headroom map
        // already means that via `csi_volume_limits_fit`'s own convention,
        // so this is safe for pods that need no CSI volumes).
        let csi_fits = pod.csi_volume_counts.is_empty()
            || csi_volume_limits_fit(
                &fresh_csi_headroom_for_node(&tally_guard, node_name),
                &pod.csi_volume_counts,
            );
        // Same reasoning as `csi_fits` above, for the topology gate: a node
        // whose CSINode does not register `pod`'s unbound PVC's driver
        // cannot serve it no matter which lower-priority pods get evicted,
        // so it must never be chosen as a preemption target — see
        // `csi_topology_fit`'s own doc comment.
        let topology_fits = pod.unbound_csi_pvc_drivers.is_empty()
            || csi_topology_fit(
                &fresh_csi_registered_drivers_for_node(&tally_guard, node_name),
                &pod.unbound_csi_pvc_drivers,
            );
        drop(tally_guard);
        if !csi_fits || !topology_fits {
            continue;
        }

        let mut victims = select_preemption_victims(
            pod.priority,
            &pod.requests,
            &node_pods,
            capacity,
            &node.status.allocatable,
        );
        // A ReadWriteOncePod PVC conflict is never a resource-dimension
        // problem `select_preemption_victims` can see — the node may have
        // plenty of free cpu/memory/pod-count and still be unusable because
        // another pod on it already holds the exclusive volume `pod` needs.
        // Such a holder is a MANDATORY victim (not a cost/benefit choice like
        // a resource-short candidate): evicting it is the only way this
        // node's RWOP conflict resolves, no matter how much capacity is
        // otherwise free. `None` means some conflicting pod's priority is
        // not strictly lower than `pod`'s own — kube-scheduler never
        // preempts an equal-or-higher-priority pod, so this node can never
        // become viable via preemption at all and must be skipped outright.
        let Some(rwop_victims) =
            read_write_once_pod_preemption_victims(&node_pods, &rwop_pvcs, pod.priority)
        else {
            continue;
        };
        for victim in rwop_victims {
            if !victims.contains(&victim) {
                victims.push(victim);
            }
        }
        if victims.is_empty() {
            continue;
        }
        // Every victim is, by construction, one of `node_pods` — i.e.
        // physically on THIS candidate node — so this is exactly the set
        // `node_qualifies_excluding_victims` needs to discount.
        let victim_pods: Vec<&TalliedPodLabels> = tallied_pods
            .iter()
            .filter(|p| victims.iter().any(|v| v == &p.key))
            .collect();
        if !affinity_ctx.node_qualifies_excluding_victims(&node.metadata.labels, &victim_pods) {
            continue;
        }
        if !topology_ctx.node_qualifies_excluding_victims(&node.metadata.labels, &victim_pods) {
            continue;
        }
        debug!(
            pod = %pod.pod_name,
            node = %node_name,
            victims = victims.len(),
            "find_preemption_plan: candidate evaluated"
        );
        let is_cheaper = best
            .as_ref()
            .is_none_or(|(_, b)| victims.len() < b.victims.len());
        if is_cheaper {
            best = Some((
                index,
                PreemptionPlan {
                    node_name: node_name.clone(),
                    victims,
                },
            ));
        }
    }
    best
}

/// Resolve a node's pod-count capacity, preferring `status.allocatable.pods`
/// and falling back to `status.capacity.pods` — shared by
/// `select_node_with_capacity` and `find_preemption_plan` so both agree on
/// which field wins when both are present.
fn pod_count_capacity(node: &NodeItem) -> u32 {
    let cap_str = if !node.status.allocatable.pods.is_empty() {
        &node.status.allocatable.pods
    } else {
        &node.status.capacity.pods
    };
    parse_pod_capacity(cap_str)
}

/// The synchronous re-verify-and-reserve step behind `find_preemption_plan`,
/// split out so its atomicity (one `tally` lock acquisition covers both the
/// fresh fit re-check and the reservation) can be exercised under real
/// concurrent access in a unit test — mirrors `select_and_reserve_node`'s
/// relationship to `pick_node`, for the same reason (see `find_preemption_plan`'s
/// doc comment).
///
/// Re-derives remaining pod-count and resource usage on `node` from a FRESH
/// `tally` read with `plan.victims`' contributions subtracted out (rather
/// than trusting the possibly-stale snapshot the search loop in
/// `find_preemption_plan` used), so a reservation some other decision made in
/// the meantime is never missed.
fn verify_and_reserve_preemption(
    pod: &PendingPod,
    node: &NodeItem,
    plan: &PreemptionPlan,
    tally: &std::sync::Mutex<NodeTally>,
) -> anyhow::Result<()> {
    let capacity = pod_count_capacity(node);
    let mut tally_guard = tally.lock().expect("tally lock poisoned");
    let current_pods = tally_guard.pods_on(&plan.node_name);
    let mut remaining_pod_count = current_pods.len() as u32;
    let mut remaining_requests = current_pods
        .iter()
        .fold(ResourceRequests::default(), |acc, p| {
            acc + p.requests.clone()
        });
    for victim in &plan.victims {
        // A victim already absent from the fresh read — because some other
        // actor deleted it independently, or because a fresher concurrent
        // plan already claimed it (see `NodeTally::pods_on`) — contributes
        // nothing to subtract — its capacity is already accounted for as
        // free, which only helps this check succeed.
        if let Some(p) = current_pods.iter().find(|p| &p.key == victim) {
            remaining_pod_count -= 1;
            subtract_requests(&mut remaining_requests, &p.requests);
        }
    }
    let still_fits = (capacity == 0 || remaining_pod_count < capacity)
        && resource_fits(&node.status.allocatable, &remaining_requests, &pod.requests);
    if !still_fits {
        debug!(
            node = %plan.node_name,
            "find_preemption_plan: re-verification failed, capacity claimed concurrently"
        );
        bail!(
            "no node still fits after preemption \
             (capacity may have been claimed concurrently)"
        );
    }
    // CSI attach limits aren't freed by evicting `plan.victims` (no per-pod
    // CSI attach-count is tracked to credit a specific victim — see
    // `find_preemption_candidate`'s own doc comment), so this re-checks the
    // node-wide headroom exactly as-is, fresh under this SAME lock, right
    // before `assume()` — closing the identical read-after-write race the
    // cpu/mem re-check above closes: two concurrent preemption plans for the
    // same CSI driver's last attach slot could otherwise both pass
    // `find_preemption_candidate`'s now-stale-by-then search-time check and
    // both `assume()`.
    if !pod.csi_volume_counts.is_empty() {
        let csi_headroom = fresh_csi_headroom_for_node(&tally_guard, &plan.node_name);
        if !csi_volume_limits_fit(&csi_headroom, &pod.csi_volume_counts) {
            debug!(
                node = %plan.node_name,
                "find_preemption_plan: re-verification failed, CSI attach limit claimed concurrently"
            );
            bail!(
                "no node still fits after preemption \
                 (CSI attach limit may have been claimed concurrently)"
            );
        }
    }
    tally_guard.assume(
        &pod.namespace,
        &pod.pod_name,
        &plan.node_name,
        pod.priority,
        pod.requests.clone(),
        pod.host_ports.clone(),
        pod.labels.clone(),
        pod.pvc_names.clone(),
    );
    // Claim the victims under this SAME lock acquisition, not a later one —
    // otherwise a fresher concurrent plan's search could still see them as
    // available in the gap between this commit and a separate claim call.
    tally_guard.claim_victims(&plan.victims);
    Ok(())
}

/// Re-check, under the CURRENT tally, that `pod`'s already-`assume`d
/// preemption reservation on `node` still holds — `main.rs`'s
/// `attempt_deferred_bind` must call this before every deferred bind, never
/// bind purely because `PreemptionWaiters` says a plan's victims are gone.
///
/// The fast-path counterpart to `verify_and_reserve_preemption`'s re-check,
/// called just before a DEFERRED bind instead of just before the ORIGINAL
/// reservation commits. Unlike that function, no victims need subtracting
/// here: by the time a deferred bind is attempted, every one of the plan's
/// victims has already been removed from `tally` (both by `evict_victims`'s
/// eager `tally.remove` and by the real watch event that triggered this
/// recheck), so none of them appear in `pods_on` any more. `pod`'s own
/// reservation IS excluded from "what else occupies this node" — it's the
/// thing being verified, not a competing occupant.
///
/// This is what a stale reservation looks like in practice: a watch
/// reconnect (`NodeTally::clear`) wipes `pod`'s `assume`d slot entirely,
/// after which some other, unrelated scheduling decision can legitimately
/// claim the same node capacity while this plan sits in `PreemptionWaiters`
/// waiting for its victims. Returning `false` here is what makes that safe —
/// the caller falls back to leaving `pod` Pending for the same 30s resync
/// backstop that already covers a pod stranded any other way (see
/// `PreemptionWaiters`'s doc comment), instead of double-booking the node.
pub fn preemption_reservation_still_fits(
    pod: &PendingPod,
    node: &NodeItem,
    tally: &std::sync::Mutex<NodeTally>,
) -> bool {
    let capacity = pod_count_capacity(node);
    let self_key = format!("{}/{}", pod.namespace, pod.pod_name);
    let current_pods = tally
        .lock()
        .expect("tally lock poisoned")
        .pods_on(&node.metadata.name);
    let mut remaining_pod_count = 0u32;
    let mut remaining_requests = ResourceRequests::default();
    for p in current_pods.iter().filter(|p| p.key != self_key) {
        remaining_pod_count += 1;
        remaining_requests = remaining_requests + p.requests.clone();
    }
    (capacity == 0 || remaining_pod_count < capacity)
        && resource_fits(&node.status.allocatable, &remaining_requests, &pod.requests)
}

/// The target of a Binding — identifies the node to bind to.
#[derive(Serialize)]
struct BindingTarget<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    name: &'a str,
}

/// Full Binding object body as posted to the API server.
#[derive(Serialize)]
struct Binding<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    metadata: BindingMeta<'a>,
    target: BindingTarget<'a>,
}

#[derive(Serialize)]
struct BindingMeta<'a> {
    name: &'a str,
    namespace: &'a str,
}

/// Build the binding path for a pod in a given namespace.
///
/// Pure function extracted so callers can test path construction without
/// network access.
pub fn binding_path(namespace: &str, pod_name: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/pods/{pod_name}/binding")
}

/// Build the JSON payload for a pod binding.
///
/// Pure function so the payload shape can be verified in tests.
/// Uses typed structs so field renames are compile errors, not silent bugs.
pub fn binding_payload(namespace: &str, pod_name: &str, node_name: &str) -> Value {
    let binding = Binding {
        api_version: "v1",
        kind: "Binding",
        metadata: BindingMeta {
            name: pod_name,
            namespace,
        },
        target: BindingTarget {
            api_version: "v1",
            kind: "Node",
            name: node_name,
        },
    };
    serde_json::to_value(binding).expect("Binding is always serializable")
}

/// Why a bind attempt (`bind_pod`'s `POST .../binding`) failed.
///
/// The caller must treat these very differently, mirroring
/// `PickNodeError`'s `NoCapacity`/`ApiError` split. `AlreadyAssigned` means
/// the apiserver's own binding handler rejected this bind with 409 Conflict
/// specifically because `spec.nodeName` was already non-empty — this exact
/// pod was already bound by an EARLIER, successful bind (typically a stray
/// duplicate bind attempt for a pod that is already running fine), so it is
/// a benign no-op: the caller must not patch `PodScheduled=False`, must not
/// emit a `FailedScheduling` event, and must not roll back the tally
/// reservation the original successful bind already earned — collapsing
/// this into a genuine failure (the bug this type replaces) corrupts the
/// status and capacity accounting of a pod that never actually had a
/// scheduling problem. `Other` covers every other bind failure (network
/// error, apiserver down, or a bind rejected for a genuinely different
/// reason) and must still be treated as a real scheduling failure, exactly
/// as before this distinction existed.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error("{0}")]
    AlreadyAssigned(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// True when `err` is a bind rejected because the pod was already assigned
/// to a node — see `BindError::AlreadyAssigned`. Extracted as a pure
/// predicate (mirroring `should_retry_without_preempting`) so the "this
/// specific outcome is a benign no-op, not a failure" classification can be
/// unit-tested without spinning up `handle_pod_event`'s full async task.
pub fn is_bind_already_assigned(err: &BindError) -> bool {
    matches!(err, BindError::AlreadyAssigned(_))
}

/// Classify a bind response status code and body, returning Err on non-2xx.
///
/// Extracted as a pure function so the classification logic can be
/// unit-tested without network access. A non-2xx response must surface as
/// Err so the caller can log and retry; silently returning Ok on 409
/// Conflict (duplicate bind) or 404 (pod gone) masks real scheduling
/// failures. `AlreadyAssigned` requires BOTH a 409 status AND the "already
/// assigned to node" message the apiserver's own binding handler uses for
/// this exact rejection (see `crates/apiserver/src/handlers/pods.rs`'s
/// `bind_pod`) — any OTHER 409 (or any other status) must still classify as
/// `Other`, a genuine scheduling failure worth reporting.
pub fn check_bind_response(status: u16, body: &str) -> Result<(), BindError> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    if status == 409 && body.contains("already assigned to node") {
        return Err(BindError::AlreadyAssigned(format!(
            "bind rejected with HTTP 409 (pod already assigned elsewhere): {body}"
        )));
    }
    Err(BindError::Other(anyhow::anyhow!(
        "bind failed with HTTP {status}: {body}"
    )))
}

// ---------------------------------------------------------------------------
// VolumeBinding — stamps volume.kubernetes.io/selected-node on unbound
// WaitForFirstConsumer PVCs at bind time, mirroring upstream kube-scheduler's
// VolumeBinding plugin (pkg/scheduler/framework/plugins/volumebinding).
// External-provisioner sidecars watch this annotation as their sole signal
// for which node to provision a topology-aware volume on — without it, a
// WaitForFirstConsumer PVC stays Pending forever and its pod never leaves
// ContainerCreating.
// ---------------------------------------------------------------------------

const SELECTED_NODE_ANNOTATION: &str = "volume.kubernetes.io/selected-node";

/// Build the path for a namespaced PVC.
fn pvc_path(namespace: &str, name: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/persistentvolumeclaims/{name}")
}

/// Build the path for a (cluster-scoped) StorageClass.
fn storage_class_path(name: &str) -> String {
    format!("/apis/storage.k8s.io/v1/storageclasses/{name}")
}

#[derive(Debug, Default, Deserialize)]
struct PvcObject {
    #[serde(default)]
    metadata: PvcMetadata,
    #[serde(default)]
    spec: PvcSpecView,
}

#[derive(Debug, Default, Deserialize)]
struct PvcMetadata {
    /// Only populated when this struct backs a watch event (`WatchEvent<PvcObject>`
    /// in `NodeTally::apply_pvc_event`) — a single-PVC-by-name GET already
    /// knows its own name/namespace from the request URL, so those call
    /// sites never read these two fields.
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    annotations: std::collections::HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PvcSpecView {
    #[serde(default)]
    volume_name: String,
    storage_class_name: Option<String>,
    #[serde(default)]
    access_modes: Vec<String>,
}

/// `volumeBindingMode`/`provisioner` sit directly on a StorageClass object,
/// not under a `.spec` wrapper — mirrors `apiserver::types::StorageClassFields`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StorageClassObject {
    /// See `PvObject::metadata`'s doc comment — same reuse, same reason.
    #[serde(default)]
    metadata: ClusterScopedMetadata,
    volume_binding_mode: Option<String>,
    #[serde(default)]
    provisioner: String,
}

/// The subset of a PVC's state `selected_node_patches` needs to decide
/// whether it needs stamping.
#[derive(Debug, Clone, Default, PartialEq)]
struct PvcBindingInfo {
    /// `spec.volumeName` — non-empty means the PVC is already bound to a PV
    /// and must never be re-stamped.
    volume_name: String,
    storage_class_name: Option<String>,
    /// The PVC's current `volume.kubernetes.io/selected-node` annotation
    /// value, if any — read back so an already-correct stamp is not
    /// needlessly re-PATCHed.
    selected_node: Option<String>,
    /// `spec.accessModes` — read by `fetch_read_write_once_pod_pvc_names` to
    /// find which of a pod's PVCs carry `ReadWriteOncePod`, the
    /// VolumeRestrictions predicate's exclusivity dimension.
    access_modes: Vec<String>,
}

/// One intended selected-node PATCH: which PVC to stamp, and the node name
/// to stamp it with.
#[derive(Debug, Clone, PartialEq)]
struct SelectedNodePatch {
    pvc_name: String,
    node_name: String,
}

/// Decide which of `pvc_names` need `volume.kubernetes.io/selected-node`
/// stamped for `node_name`.
///
/// Pure decision function: `pvc_lookup`/`sc_lookup` supply the PVC's current
/// state and its StorageClass's `volumeBindingMode` respectively, so this can
/// be unit-tested with hand-constructed inputs, without a live API server.
/// `stamp_selected_node_for_pvcs` (the only real caller) is what actually
/// performs the GETs these closures wrap.
///
/// A PVC is stamped only when it is unbound (`volume_name` empty) AND its
/// StorageClass's `volumeBindingMode` is exactly `"WaitForFirstConsumer"` —
/// an `Immediate` (or unset/unknown) StorageClass already has its own
/// provisioning path and must never be touched here, matching upstream's
/// VolumeBinding plugin (`BindPodVolumes` only acts on
/// `PodHasUnboundImmediateVolumes`-excluded PVCs).
fn selected_node_patches(
    pvc_names: &[String],
    node_name: &str,
    pvc_lookup: impl Fn(&str) -> Option<PvcBindingInfo>,
    sc_lookup: impl Fn(&str) -> Option<String>,
) -> Vec<SelectedNodePatch> {
    let mut patches = Vec::new();
    for pvc_name in pvc_names {
        let Some(info) = pvc_lookup(pvc_name) else {
            continue;
        };
        if !info.volume_name.is_empty() {
            continue;
        }
        let Some(sc_name) = info.storage_class_name.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };
        let Some(mode) = sc_lookup(sc_name) else {
            continue;
        };
        if mode != "WaitForFirstConsumer" {
            continue;
        }
        if info.selected_node.as_deref() == Some(node_name) {
            continue;
        }
        patches.push(SelectedNodePatch {
            pvc_name: pvc_name.clone(),
            node_name: node_name.to_owned(),
        });
    }
    patches
}

/// Build the merge-patch body that stamps `volume.kubernetes.io/selected-node`
/// on a PVC.
fn selected_node_annotation_patch(node_name: &str) -> Value {
    serde_json::json!({
        "metadata": {
            "annotations": {
                "volume.kubernetes.io/selected-node": node_name
            }
        }
    })
}

async fn fetch_pvc_binding_info(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    name: &str,
) -> anyhow::Result<Option<PvcBindingInfo>> {
    let path = pvc_path(namespace, name);
    let (status, body) = http_get(connector, server, &path).await?;
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        bail!("GET {path} returned {status}: {body}");
    }
    let obj: PvcObject = serde_json::from_str(&body).context("parse PersistentVolumeClaim")?;
    Ok(Some(PvcBindingInfo {
        volume_name: obj.spec.volume_name,
        storage_class_name: obj.spec.storage_class_name,
        selected_node: obj
            .metadata
            .annotations
            .get(SELECTED_NODE_ANNOTATION)
            .cloned(),
        access_modes: obj.spec.access_modes,
    }))
}

/// Resolve which of `pvc_names` (in `namespace`) carry the
/// `ReadWriteOncePod` access mode — the VolumeRestrictions predicate's
/// exclusivity dimension. The caller (`main.rs`'s `handle_pod_event`)
/// fetches this once and fills it into `PendingPod::read_write_once_pod_pvcs`
/// right before the first `pick_node` attempt, exactly like
/// `fetch_bound_pv_node_affinities`/`fetch_csi_volume_counts`. A PVC that no
/// longer exists (404) contributes nothing — mirrors
/// `fetch_bound_pv_node_affinities`'s own convention for a gone PVC.
pub async fn fetch_read_write_once_pod_pvc_names(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pvc_names: &[String],
) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    for pvc_name in pvc_names {
        let Some(info) = fetch_pvc_binding_info(connector, server, namespace, pvc_name).await?
        else {
            continue;
        };
        if info.access_modes.iter().any(|m| m == "ReadWriteOncePod") {
            names.push(pvc_name.clone());
        }
    }
    Ok(names)
}

async fn fetch_storage_class_binding_mode(
    connector: &TlsConnector,
    server: &str,
    name: &str,
) -> anyhow::Result<Option<String>> {
    let path = storage_class_path(name);
    let (status, body) = http_get(connector, server, &path).await?;
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        bail!("GET {path} returned {status}: {body}");
    }
    let obj: StorageClassObject = serde_json::from_str(&body).context("parse StorageClass")?;
    Ok(obj.volume_binding_mode)
}

/// The CSI driver name a StorageClass provisions through — its `provisioner`
/// field — for `resolve_csi_driver`'s unbound-PVC fallback. A separate GET
/// from `fetch_storage_class_binding_mode` (rather than widening its return
/// type): the two are independent call sites (selected-node stamping vs. the
/// CSILimits predicate) that happen to read the same object.
async fn fetch_storage_class_provisioner(
    connector: &TlsConnector,
    server: &str,
    name: &str,
) -> anyhow::Result<Option<String>> {
    let path = storage_class_path(name);
    let (status, body) = http_get(connector, server, &path).await?;
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        bail!("GET {path} returned {status}: {body}");
    }
    let obj: StorageClassObject = serde_json::from_str(&body).context("parse StorageClass")?;
    Ok(Some(obj.provisioner).filter(|p| !p.is_empty()))
}

/// Stamp `volume.kubernetes.io/selected-node` on every one of `pvc_names`
/// (in `namespace`) that is unbound and whose StorageClass has
/// `volumeBindingMode: WaitForFirstConsumer` — see this module's doc comment
/// for why external-provisioner needs this signal.
///
/// Called from `bind_reserved_node` (main.rs) BEFORE `bind_pod`'s own POST,
/// so external-provisioner sees the node choice the moment the pod is bound,
/// not after. Best-effort: a lookup or PATCH failure here is logged and
/// skipped rather than surfaced to the caller — the pod's node reservation
/// already succeeded, and refusing to bind a schedulable pod over an
/// unrelated PVC's stamping failure would strand it for no reason. A PVC
/// that misses its stamp this way simply stays Pending for the PVC's own
/// controller resync, or a future re-bind of this pod, to retry.
pub async fn stamp_selected_node_for_pvcs(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pvc_names: &[String],
    node_name: &str,
) {
    if pvc_names.is_empty() {
        return;
    }
    let mut pvc_info = std::collections::HashMap::new();
    for name in pvc_names {
        match fetch_pvc_binding_info(connector, server, namespace, name).await {
            Ok(Some(info)) => {
                pvc_info.insert(name.clone(), info);
            }
            Ok(None) => {}
            Err(e) => {
                error!("failed to fetch PVC {namespace}/{name} for selected-node stamping: {e}");
            }
        }
    }
    let mut sc_mode: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for info in pvc_info.values() {
        let Some(sc_name) = info.storage_class_name.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };
        if sc_mode.contains_key(sc_name) {
            continue;
        }
        match fetch_storage_class_binding_mode(connector, server, sc_name).await {
            Ok(Some(mode)) => {
                sc_mode.insert(sc_name.to_owned(), mode);
            }
            Ok(None) => {}
            Err(e) => {
                error!("failed to fetch StorageClass {sc_name} for selected-node stamping: {e}");
            }
        }
    }
    let patches = selected_node_patches(
        pvc_names,
        node_name,
        |name| pvc_info.get(name).cloned(),
        |sc_name| sc_mode.get(sc_name).cloned(),
    );
    for patch in patches {
        let path = pvc_path(namespace, &patch.pvc_name);
        let payload = selected_node_annotation_patch(&patch.node_name);
        match http_patch_status(connector, server, &path, &payload).await {
            Ok((status, _)) if status.is_success() => {
                info!(
                    pvc = %patch.pvc_name, node = %patch.node_name,
                    "stamped volume.kubernetes.io/selected-node"
                );
            }
            Ok((status, body)) => {
                error!("PATCH {path} returned {status}: {body}");
            }
            Err(e) => {
                error!(
                    "failed to PATCH selected-node annotation on PVC {namespace}/{}: {e}",
                    patch.pvc_name
                );
            }
        }
    }
}

/// Build the path for a (cluster-scoped) PersistentVolume.
fn pv_path(name: &str) -> String {
    format!("/api/v1/persistentvolumes/{name}")
}

#[derive(Debug, Default, Deserialize)]
struct PvObject {
    /// Only populated when this struct backs a watch event
    /// (`WatchEvent<PvObject>` in `NodeTally::apply_pv_event`) — a
    /// single-PV-by-name GET already knows its own name from the request
    /// URL and never reads this.
    #[serde(default)]
    metadata: ClusterScopedMetadata,
    #[serde(default)]
    spec: PvSpecView,
}

/// A cluster-scoped object's name, as carried by a watch event's `object`
/// (a single-object-by-name GET already knows the name from its own request
/// URL) — shared by `PvObject` and `StorageClassObject`, both cluster-scoped
/// resources `NodeTally` watches for CSI-driver resolution.
#[derive(Debug, Default, Deserialize)]
struct ClusterScopedMetadata {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PvSpecView {
    #[serde(default)]
    node_affinity: Option<PvNodeAffinity>,
    #[serde(default)]
    csi: Option<PvCsiSource>,
}

/// A PV's `spec.csi` — only `driver` matters here, for the CSILimits/
/// NodeVolumeLimits predicate's per-driver volume count.
#[derive(Debug, Default, Deserialize)]
struct PvCsiSource {
    driver: String,
}

/// A PV's `spec.nodeAffinity`. Unlike a pod's `nodeAffinity`, this wraps its
/// `NodeSelector` directly under `required` — a PV's topology constraint is
/// not a "soft during scheduling, hard during execution" preference, so there
/// is no `requiredDuringSchedulingIgnoredDuringExecution` qualifier to peel
/// off, matching upstream's `v1.VolumeNodeAffinity` shape.
#[derive(Debug, Default, Deserialize)]
struct PvNodeAffinity {
    #[serde(default)]
    required: Option<NodeSelectorSpec>,
}

async fn fetch_pv_node_affinity(
    connector: &TlsConnector,
    server: &str,
    name: &str,
) -> anyhow::Result<Option<NodeSelectorSpec>> {
    let path = pv_path(name);
    let (status, body) = http_get(connector, server, &path).await?;
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        bail!("GET {path} returned {status}: {body}");
    }
    let obj: PvObject = serde_json::from_str(&body).context("parse PersistentVolume")?;
    Ok(obj.spec.node_affinity.and_then(|a| a.required))
}

/// The CSI driver name backing PV `name` — `spec.csi.driver` — for
/// `resolve_csi_driver`'s bound-PVC path. `None` when the PV is gone, or has
/// no `spec.csi` source at all (an in-tree, non-CSI volume type this MVP does
/// not model) — `resolve_csi_driver` then falls back to the PVC's
/// StorageClass, matching upstream's own in-tree-to-CSI fallback shape
/// (without the migration machinery this scheduler has no need for).
async fn fetch_pv_csi_driver(
    connector: &TlsConnector,
    server: &str,
    name: &str,
) -> anyhow::Result<Option<String>> {
    let path = pv_path(name);
    let (status, body) = http_get(connector, server, &path).await?;
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        bail!("GET {path} returned {status}: {body}");
    }
    let obj: PvObject = serde_json::from_str(&body).context("parse PersistentVolume")?;
    Ok(obj.spec.csi.map(|c| c.driver).filter(|d| !d.is_empty()))
}

/// Resolve the `spec.nodeAffinity.required` selector of every PV already
/// bound (`spec.volumeName` non-empty) to one of `pvc_names` — the
/// Immediate-mode-binding case `selected_node_patches` deliberately does not
/// cover (see its doc comment: that function only ever stamps an UNBOUND
/// WaitForFirstConsumer PVC). The result feeds `PendingPod::pv_node_affinities`,
/// which `node_qualifies_for_pod` then treats as one more mandatory (ANDed)
/// filter, mirroring upstream's VolumeBinding Filter plugin evaluating one
/// bound volume's topology constraint at a time.
///
/// A PVC or PV that no longer exists (404) contributes no constraint — that
/// PVC simply isn't backed by a real, already-provisioned volume yet. A GET
/// actually FAILING (network error, non-2xx, unparseable body) is propagated
/// instead of swallowed: unlike `stamp_selected_node_for_pvcs`'s best-effort
/// annotation PATCH (whose failure only delays an unrelated controller's
/// resync), silently treating a failed lookup as "no constraint" here would
/// let the scheduler bind the pod onto a node that cannot actually mount the
/// volume — exactly the bug this function exists to close.
pub async fn fetch_bound_pv_node_affinities(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pvc_names: &[String],
) -> anyhow::Result<Vec<NodeSelectorSpec>> {
    let mut affinities = Vec::new();
    for pvc_name in pvc_names {
        let Some(info) = fetch_pvc_binding_info(connector, server, namespace, pvc_name).await?
        else {
            continue;
        };
        if info.volume_name.is_empty() {
            continue;
        }
        if let Some(selector) = fetch_pv_node_affinity(connector, server, &info.volume_name).await?
        {
            affinities.push(selector);
        }
    }
    Ok(affinities)
}

const NO_PROVISIONER: &str = "kubernetes.io/no-provisioner";

/// Resolve the CSI driver name for every one of `pvc_names` that is
/// currently UNBOUND (`spec.volumeName` empty) and backed by a
/// StorageClass with a real provisioner — the provisioning-time
/// counterpart to `fetch_bound_pv_node_affinities`'s already-bound case.
/// Feeds `PendingPod::unbound_csi_pvc_drivers`, which `csi_topology_fit`
/// then treats as one more mandatory (ANDed) filter: a node whose CSINode
/// does not register this driver cannot serve whatever volume
/// csi-provisioner is about to create for it — see `csi_topology_fit`'s own
/// doc comment for the AnyVolumeDataSource hang this closes.
///
/// `kubernetes.io/no-provisioner` is excluded even though it IS a
/// StorageClass provisioner string: it is the well-known sentinel for "PVs
/// are created out-of-band, bind to an existing one" (local /
/// pre-provisioned-volume workflows) — no CSI driver, and therefore no
/// CSINode entry, will ever exist for it, so gating on CSINode presence
/// would wedge those PVCs Pending forever instead of letting the ordinary
/// PV-matching bind proceed.
///
/// A GET failure is propagated, not swallowed, for the same reason
/// `fetch_bound_pv_node_affinities` propagates its own: silently treating
/// it as "no driver" here would let the scheduler bind the pod onto a node
/// the eventual volume cannot be mounted on.
pub async fn fetch_unbound_csi_pvc_drivers(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pvc_names: &[String],
) -> anyhow::Result<Vec<String>> {
    let mut drivers = Vec::new();
    for pvc_name in pvc_names {
        let Some(info) = fetch_pvc_binding_info(connector, server, namespace, pvc_name).await?
        else {
            continue;
        };
        if !info.volume_name.is_empty() {
            continue;
        }
        let Some(sc_name) = info.storage_class_name.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };
        if let Some(provisioner) =
            fetch_storage_class_provisioner(connector, server, sc_name).await?
        {
            if provisioner != NO_PROVISIONER {
                drivers.push(provisioner);
            }
        }
    }
    Ok(drivers)
}

/// Resolve the CSI driver backing `pvc_name` (in `namespace`): prefer its
/// already-bound PV's `spec.csi.driver`; fall back to its StorageClass's
/// `provisioner` when unbound, or when the bound PV resolves to no CSI
/// driver at all — mirrors upstream's `getCSIDriverInfo`/
/// `getCSIDriverInfoFromSC` two-step fallback (minus the in-tree migration
/// machinery this scheduler has no need for). `None` when neither resolves
/// (PVC/PV gone, or the PVC has no StorageClass) — such a volume is simply
/// not counted, matching upstream's own no-op for a non-CSI-backed volume.
async fn resolve_csi_driver(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pvc_name: &str,
) -> anyhow::Result<Option<String>> {
    let Some(info) = fetch_pvc_binding_info(connector, server, namespace, pvc_name).await? else {
        return Ok(None);
    };
    if !info.volume_name.is_empty() {
        if let Some(driver) = fetch_pv_csi_driver(connector, server, &info.volume_name).await? {
            return Ok(Some(driver));
        }
    }
    let Some(sc_name) = info.storage_class_name.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    fetch_storage_class_provisioner(connector, server, sc_name).await
}

/// Count how many CSI volumes `pvc_names` (deduplicated — the same PVC
/// mounted twice by one pod is one volume) resolve to, grouped by driver
/// name — the CSILimits/NodeVolumeLimits predicate's per-driver volume
/// count. `cache` (keyed by "namespace/pvcName") is shared across every call
/// within one scheduling decision, so a PVC referenced by more than one pod
/// — or checked again while tallying a second node — is only ever resolved
/// once.
async fn count_csi_volumes_by_driver(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pvc_names: &[String],
    cache: &mut std::collections::HashMap<String, Option<String>>,
) -> anyhow::Result<std::collections::BTreeMap<String, i64>> {
    let mut counts = std::collections::BTreeMap::new();
    let mut seen = std::collections::HashSet::new();
    for pvc_name in pvc_names {
        if !seen.insert(pvc_name.clone()) {
            continue;
        }
        let cache_key = format!("{namespace}/{pvc_name}");
        let driver = if let Some(cached) = cache.get(&cache_key) {
            cached.clone()
        } else {
            let resolved = resolve_csi_driver(connector, server, namespace, pvc_name).await?;
            cache.insert(cache_key, resolved.clone());
            resolved
        };
        if let Some(driver) = driver {
            *counts.entry(driver).or_insert(0) += 1;
        }
    }
    Ok(counts)
}

/// Resolve `pvc_names`' CSI driver volume counts for the PENDING pod — see
/// `count_csi_volumes_by_driver`. The caller (`main.rs`'s `handle_pod_event`)
/// fetches this once and fills it into `PendingPod::csi_volume_counts` right
/// before the first `pick_node` attempt, exactly like
/// `fetch_bound_pv_node_affinities`.
pub async fn fetch_csi_volume_counts(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pvc_names: &[String],
) -> anyhow::Result<std::collections::BTreeMap<String, i64>> {
    let mut cache = std::collections::HashMap::new();
    count_csi_volumes_by_driver(connector, server, namespace, pvc_names, &mut cache).await
}

#[derive(Debug, Default, Deserialize)]
struct CsiNodeItem {
    #[serde(default)]
    metadata: CsiNodeMetadata,
    #[serde(default)]
    spec: CsiNodeSpecView,
}

#[derive(Debug, Default, Deserialize)]
struct CsiNodeMetadata {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CsiNodeSpecView {
    #[serde(default)]
    drivers: Vec<CsiNodeDriverView>,
}

#[derive(Debug, Default, Deserialize)]
struct CsiNodeDriverView {
    name: String,
    #[serde(default)]
    allocatable: Option<CsiNodeAllocatable>,
}

#[derive(Debug, Default, Deserialize)]
struct CsiNodeAllocatable {
    #[serde(default)]
    count: Option<i64>,
}

/// Net a node's advertised per-driver CSI attach limit
/// (`CSINode.spec.drivers[].allocatable.count`) against its current
/// per-driver attached-volume count into the CSILimits predicate's headroom
/// map. Pure arithmetic — callers are responsible for reading BOTH maps
/// fresh, under the SAME `NodeTally` lock acquisition that goes on to
/// `assume()`/reserve the pending pod, or this reopens the exact
/// read-after-write race it exists to close (see `NodeTally`'s own doc
/// comment): a separate, earlier lock acquisition can snapshot headroom
/// before a concurrently-decided pod's `assume()` lands, so a second
/// decision reading that stale snapshot never sees the first's reservation.
fn net_csi_headroom(
    limits: &std::collections::BTreeMap<String, i64>,
    attached: &std::collections::BTreeMap<String, i64>,
) -> std::collections::BTreeMap<String, i64> {
    limits
        .iter()
        .map(|(driver, &limit)| {
            let used = attached.get(driver).copied().unwrap_or(0);
            (driver.clone(), limit - used)
        })
        .collect()
}

/// `net_csi_headroom`, reading both inputs itself from `tally` for a SINGLE
/// node — for `find_preemption_candidate`'s per-candidate search loop and
/// `verify_and_reserve_preemption`'s final re-check, both of which already
/// hold their own lock per node (`pods_on`) rather than one upfront
/// `usage_by_node()` snapshot for the whole list (that shape is
/// `select_and_reserve_node`'s, which nets directly from its own
/// already-fetched `usage_by_node()` instead of calling this). Reads
/// `csi_driver_limits_by_node()`'s whole map just for one node's entry —
/// clarity over the extra clone, matching this module's existing
/// correctness-over-micro-perf convention for these small, rarely-hit maps.
fn fresh_csi_headroom_for_node(
    tally: &NodeTally,
    node_name: &str,
) -> std::collections::BTreeMap<String, i64> {
    let Some(limits) = tally.csi_driver_limits_by_node().remove(node_name) else {
        return std::collections::BTreeMap::new();
    };
    net_csi_headroom(&limits, &tally.csi_attached_counts(node_name))
}

/// The CSILimits/NodeVolumeLimits predicate: true when adding `pod`'s new
/// CSI volumes would not push any driver past this node's advertised
/// per-driver attach limit. A driver `pod` needs but that is absent from
/// `csi_driver_headroom` has no limit advertised on this node (or the node
/// has no CSINode entry at all) — not checked, mirroring `resource_fits`'s
/// "unknown means unlimited" convention for missing allocatable fields.
///
/// `pub` (not module-private) so `benches/predicates.rs` can call it
/// directly, for the same reason `resource_fits`/`host_ports_fit` are.
pub fn csi_volume_limits_fit(
    csi_driver_headroom: &std::collections::BTreeMap<String, i64>,
    csi_volume_counts: &std::collections::BTreeMap<String, i64>,
) -> bool {
    csi_volume_counts.iter().all(|(driver, &want)| {
        csi_driver_headroom
            .get(driver)
            .is_none_or(|&headroom| want <= headroom)
    })
}

/// `csi_driver_names_by_node`, reading it fresh from `tally` for a SINGLE
/// node — `find_preemption_candidate`'s per-candidate counterpart to
/// `fresh_csi_headroom_for_node`, same reasoning: it already holds its own
/// lock per node (`pods_on`) rather than the one upfront enrichment
/// `select_and_reserve_node` does on `NodeItem::csi_registered_drivers`.
fn fresh_csi_registered_drivers_for_node(
    tally: &NodeTally,
    node_name: &str,
) -> std::collections::HashSet<String> {
    tally
        .csi_driver_names_by_node()
        .remove(node_name)
        .unwrap_or_default()
}

/// The VolumeBinding-provisioning-topology Filter: true when every CSI
/// driver `pod`'s own UNBOUND PVCs still need provisioned
/// (`unbound_csi_pvc_drivers`) is registered in this node's CSINode
/// (`node_registered_drivers`) — mirrors upstream's VolumeBinding Filter
/// plugin rejecting a node that cannot possibly serve a provisioning
/// claim's topology.
///
/// Unlike `csi_volume_limits_fit`'s "unknown means unlimited" convention, a
/// driver absent from `node_registered_drivers` on EVERY node (an empty
/// candidate set) is NOT permissive here: it correctly rejects every node,
/// leaving the pod Pending until the driver's own CSINode registration
/// lands. Treating "driver location unknown" as "any node will do" is
/// exactly the bug this predicate exists to close — the csi-hostpath CSI
/// driver runs as a single-replica StatefulSet, so a node picked without
/// checking CSINode is very likely the wrong one: its PV then carries a
/// `nodeAffinity` pinning it to the driver's real node, and a pod bound to
/// any other node fails `MountVolume.NodeAffinity check failed` forever
/// (the AnyVolumeDataSource conformance hang this predicate fixes).
///
/// `pub` (not module-private) for the same reason `csi_volume_limits_fit`
/// is: a criterion bench may exercise it directly.
pub fn csi_topology_fit(
    node_registered_drivers: &std::collections::HashSet<String>,
    unbound_csi_pvc_drivers: &[String],
) -> bool {
    unbound_csi_pvc_drivers
        .iter()
        .all(|driver| node_registered_drivers.contains(driver))
}

/// Bind a pod to a node via POST .../pods/:name/binding.
pub async fn bind_pod(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pod_name: &str,
    node_name: &str,
) -> Result<(), BindError> {
    let path = binding_path(namespace, pod_name);
    let payload = binding_payload(namespace, pod_name, node_name);

    let start = std::time::Instant::now();
    let (status, body) = http_post_json(connector, server, &path, &payload).await?;
    let elapsed_ms = start.elapsed().as_millis() as u64;
    debug!(pod = %pod_name, node = %node_name, elapsed_ms, "bind_pod: POST completed");
    check_bind_response(status.as_u16(), &body)?;
    info!("bound pod {namespace}/{pod_name} → node {node_name}");
    Ok(())
}

/// Build the DELETE path for a pod in a given namespace.
///
/// Pure function extracted so callers can test path construction without
/// network access — mirrors `binding_path`.
pub fn delete_pod_path(namespace: &str, pod_name: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/pods/{pod_name}")
}

/// Check a pod-eviction DELETE response status, returning Err on failures other
/// than "already gone" or "already changing".
///
/// A 404 means the pod was already removed — by a previous retry of this same
/// eviction, or another actor — which is the outcome preemption wants, so it
/// must be treated as success rather than aborting the eviction loop.
///
/// A 409 means the eviction's soft-delete PUT lost an optimistic-concurrency
/// race against a concurrent write to the same victim (e.g. the kubelet's
/// routine status sync while the pod is being torn down, or another scheduling
/// attempt evicting the same victim). Either way the pod is already moving
/// toward deletion, so a 409 here is not a real eviction failure. Treating it
/// as fatal would abort the whole preemption cycle via `?` and leave the
/// preemptor pod stuck Pending.
pub fn check_delete_response(status: u16) -> anyhow::Result<()> {
    if (200..300).contains(&status) || status == 404 || status == 409 {
        return Ok(());
    }
    bail!("evict failed with HTTP {status}")
}

// ---------------------------------------------------------------------------
// Scheduling Events — reports bind success/failure so `kubectl describe pod`
// and clients that watch Events (e.g. the SchedulerPredicates e2e suite's
// observeEventAfterAction) can see the outcome.
// ---------------------------------------------------------------------------

/// The `involvedObject` reference on a scheduling Event — always the pod.
#[derive(Serialize)]
struct EventInvolvedObject<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    namespace: &'a str,
    name: &'a str,
}

#[derive(Serialize)]
struct EventSource<'a> {
    component: &'a str,
}

#[derive(Serialize)]
struct EventMeta<'a> {
    name: &'a str,
    namespace: &'a str,
}

/// Full Event object body as posted to the API server.
#[derive(Serialize)]
struct SchedulingEvent<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    metadata: EventMeta<'a>,
    #[serde(rename = "involvedObject")]
    involved_object: EventInvolvedObject<'a>,
    reason: &'a str,
    message: &'a str,
    #[serde(rename = "type")]
    event_type: &'a str,
    count: u32,
    source: EventSource<'a>,
    #[serde(rename = "firstTimestamp")]
    first_timestamp: &'a str,
    #[serde(rename = "lastTimestamp")]
    last_timestamp: &'a str,
}

/// Build a unique Event object name for `pod_name`.
///
/// Real Kubernetes event recorders name events `<involvedObjectName>.<hex-suffix>`.
/// Upstream's e2e predicate (`scheduleFailureEvent`/`scheduleSuccessEvent` in
/// `test/e2e/scheduling/events.go`) matches on `strings.HasPrefix(e.Name, podName)`,
/// so the name MUST start with `pod_name` — any other shape makes the event
/// invisible to that check even though it was created correctly.
///
/// `nanos` is passed in (rather than read from `SystemTime::now()` here) so the
/// naming logic itself can be unit-tested without a clock dependency.
pub fn scheduling_event_name(pod_name: &str, nanos: u128) -> String {
    format!("{pod_name}.{nanos:x}")
}

/// Convert nanoseconds since the Unix epoch to an RFC3339 UTC timestamp
/// (`YYYY-MM-DDThh:mm:ssZ`) — the shape real kube-scheduler stamps on an
/// Event's `firstTimestamp`/`lastTimestamp` (`metav1.Time`, second precision).
///
/// `nanos` is passed in (same reason as `scheduling_event_name`) so the
/// conversion can be unit-tested without a clock dependency. Uses only
/// `std::time` — no chrono dependency: this crate has no dependency on the
/// apiserver crate (whose `util::secs_to_rfc3339` does the same conversion),
/// so the calendar math (Howard Hinnant's public-domain `civil_from_days`) is
/// duplicated here rather than shared.
pub fn scheduling_event_timestamp(nanos: u128) -> String {
    let secs = (nanos / 1_000_000_000) as i64;
    let secs_of_day = secs.rem_euclid(86400);
    let s = secs_of_day % 60;
    let m = (secs_of_day / 60) % 60;
    let h = (secs_of_day / 3600) % 24;
    let days = secs.div_euclid(86400);

    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Build the JSON payload for a Kubernetes Event recording a scheduling outcome
/// (bind success or failure) for a pod.
///
/// Pure function so the payload shape can be verified in tests without a network.
/// Uses typed structs so field renames are compile errors, not silent bugs —
/// mirrors `binding_payload`.
///
/// `timestamp` sets both `firstTimestamp` and `lastTimestamp` to the moment the
/// event was created — real kube-scheduler always stamps both on a newly
/// created Event (they only diverge on a later same-reason update, which this
/// scheduler doesn't do: every scheduling attempt creates a fresh Event).
/// Without it, `kubectl describe pod`'s AGE column and any conformance check
/// on Event freshness (e.g. `WaitForEvent`'s age-based staleness filter) see a
/// null timestamp instead of a real one.
pub fn scheduling_event_payload(
    namespace: &str,
    pod_name: &str,
    event_name: &str,
    reason: &str,
    message: &str,
    event_type: &str,
    timestamp: &str,
) -> Value {
    let event = SchedulingEvent {
        api_version: "v1",
        kind: "Event",
        metadata: EventMeta {
            name: event_name,
            namespace,
        },
        involved_object: EventInvolvedObject {
            api_version: "v1",
            kind: "Pod",
            namespace,
            name: pod_name,
        },
        reason,
        message,
        event_type,
        count: 1,
        source: EventSource {
            component: "u7s-scheduler",
        },
        first_timestamp: timestamp,
        last_timestamp: timestamp,
    };
    serde_json::to_value(event).expect("SchedulingEvent is always serializable")
}

/// Build the POST path for Events in a given namespace.
///
/// Pure function extracted so callers can test path construction without
/// network access — mirrors `binding_path`.
pub fn events_path(namespace: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/events")
}

/// Post a scheduling-outcome Event (`reason` "Scheduled" or "FailedScheduling")
/// for `pod_name` to the API server.
///
/// Without this, `kubectl describe pod` never shows a scheduling event, and any
/// client watching Events for a scheduling decision (e.g. the SchedulerPredicates
/// e2e suite's `observeEventAfterAction`) times out waiting for one that was never
/// created — the scheduler made the right bind/reject decision but nobody outside
/// process memory ever heard about it.
pub async fn emit_scheduling_event(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pod_name: &str,
    reason: &str,
    message: &str,
    event_type: &str,
) -> anyhow::Result<()> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let event_name = scheduling_event_name(pod_name, nanos);
    let timestamp = scheduling_event_timestamp(nanos);
    let payload = scheduling_event_payload(
        namespace,
        pod_name,
        &event_name,
        reason,
        message,
        event_type,
        &timestamp,
    );
    let path = events_path(namespace);
    let start = std::time::Instant::now();
    let (status, body) = http_post_json(connector, server, &path, &payload).await?;
    let elapsed_ms = start.elapsed().as_millis() as u64;
    debug!(pod = %pod_name, reason, elapsed_ms, "emit_scheduling_event: POST completed");
    if !status.is_success() {
        bail!("POST event failed with HTTP {status}: {body}");
    }
    Ok(())
}

/// The `DisruptionTarget` condition reason upstream's real kube-scheduler
/// stamps on a preemption victim before deleting it — matches
/// `v1.PodReasonPreemptionByScheduler` (`pkg/scheduler/framework/preemption/executor.go`).
const PREEMPTION_BY_SCHEDULER_REASON: &str = "PreemptionByScheduler";

/// Build the status-conditions PATCH that marks a preemption victim with the
/// `DisruptionTarget` condition, mirroring upstream kube-scheduler's
/// `Executor.PreemptPod`: it patches this condition onto the victim BEFORE
/// deleting it, so a client re-fetching the pod mid-termination (as the
/// `validates pod disruption condition is added to the preempted pod`
/// conformance test does) sees WHY it is being evicted, not just that it is
/// disappearing. `VerifyPodHasConditionWithType`
/// (test/e2e/framework/pod/resource.go) only checks the condition's `type`,
/// but a made-up reason would misrepresent to `kubectl describe pod` who
/// evicted the pod and why.
pub fn disruption_target_patch(pending_pod_name: &str) -> Value {
    serde_json::json!({
        "status": {
            "conditions": [{
                "type": "DisruptionTarget",
                "status": "True",
                "reason": PREEMPTION_BY_SCHEDULER_REASON,
                "message": format!(
                    "u7s-scheduler: preempting to accommodate higher priority pod {pending_pod_name}"
                ),
            }]
        }
    })
}

/// Build the status-subresource PATCH that stamps `status.nominatedNodeName`
/// on the pending pod once `find_preemption_plan`/`verify_and_reserve_preemption`
/// have committed a plan for it, mirroring upstream kube-scheduler's
/// nominate-then-evict-async ordering: the nomination must be visible to a
/// client polling the pod BEFORE any victim is evicted, not only after the
/// pod is finally bound. Without this, `SchedulerAsyncPreemption`'s e2e test
/// (`test/e2e/scheduling/preemption.go`) hangs forever on its very first wait
/// step (`highPod.Status.NominatedNodeName != ""`), at any contention level.
pub fn nominated_node_name_patch(node_name: &str) -> Value {
    serde_json::json!({
        "status": {
            "nominatedNodeName": node_name
        }
    })
}

/// Evict a pod (preemption's victim-removal step) via a single graceful
/// DELETE to .../pods/:name.
///
/// The apiserver's pod DELETE always soft-deletes on the first call (stamps
/// `deletionTimestamp`, honoring `spec.terminationGracePeriodSeconds`, so the
/// real kubelet running the victim's container can send SIGTERM, run any
/// preStop hook, and gracefully terminate) and only hard-deletes once the pod
/// is already Terminating with no finalizers. That second, hard-delete call
/// is issued by the kubelet itself once it has actually stopped the
/// container — not by this scheduler.
///
/// An earlier version of this function issued the DELETE twice back-to-back
/// to force the victim straight to hard-deleted, on the theory that the
/// freed slot needed to already be gone from the apiserver's store before
/// the caller's immediate bind attempt for the preemptor could see it. That
/// reasoning no longer holds: the scheduler's own capacity accounting lives
/// entirely in the in-memory `NodeTally`, and `evict_victims` (main.rs)
/// removes the victim from `tally` as soon as this call returns success —
/// independent of whether the pod has actually disappeared from the
/// apiserver's store. Force-double-DELETE bought nothing but a victim that
/// goes from Running to 404 in about a second, which is too fast for
/// upstream's e2e preemption test (`test/e2e/scheduling/preemption.go`,
/// 1s poll interval) to ever observe the intermediate
/// "DeletionTimestamp set, still Gettable" state it asserts on.
pub async fn delete_pod(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pod_name: &str,
) -> anyhow::Result<()> {
    let path = delete_pod_path(namespace, pod_name);
    let start = std::time::Instant::now();
    let (status, body) = http_delete(connector, server, &path).await?;
    let elapsed_ms = start.elapsed().as_millis() as u64;
    debug!(pod = %pod_name, elapsed_ms, "delete_pod: DELETE completed");
    check_delete_response(status.as_u16())
        .with_context(|| format!("evicting {namespace}/{pod_name}: {body}"))?;
    info!("evicted pod {namespace}/{pod_name} (preemption)");
    Ok(())
}

/// Build the status-subresource PATCH path for a pod.
///
/// Pure function extracted so callers can test path construction without
/// network access — mirrors `binding_path`/`delete_pod_path`.
pub fn pod_status_path(namespace: &str, pod_name: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/pods/{pod_name}/status")
}

/// Check a status-patch response status code, returning Err on non-2xx.
///
/// Extracted as a pure function so the error-returning logic can be
/// unit-tested without network access — mirrors `check_bind_response`.
pub fn check_status_patch_response(status: u16, body: &str) -> anyhow::Result<()> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    bail!("status patch failed with HTTP {status}: {body}")
}

/// PATCH a pod's `.status` via .../pods/:name/status.
///
/// Used to stamp/clear the `PodScheduled`/`SchedulingGated` condition
/// (`scheduling_gate_status_patch` / `scheduling_gate_status_reset`) — the
/// apiserver's `patch_pod_status` merges the `conditions` array by `.type`
/// (see `merge_conditions`), so `patch` only needs to carry the single
/// condition being added or changed; unrelated conditions are preserved.
pub async fn patch_pod_status(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pod_name: &str,
    patch: &Value,
) -> anyhow::Result<()> {
    let path = pod_status_path(namespace, pod_name);
    let start = std::time::Instant::now();
    let (status, body) = http_patch_status(connector, server, &path, patch).await?;
    let elapsed_ms = start.elapsed().as_millis() as u64;
    debug!(pod = %pod_name, elapsed_ms, "patch_pod_status: PATCH completed");
    check_status_patch_response(status.as_u16(), &body)
        .with_context(|| format!("patching status for {namespace}/{pod_name}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // check_bind_response tests — the error-returning logic for bind_pod.
    // Before this fix, bind_pod returned Ok(()) on any status code, including
    // 409 Conflict (duplicate bind) and 404 (pod already gone). Callers then
    // logged nothing and assumed success, silently masking scheduling failures.

    #[test]
    fn bind_pod_returns_err_on_non_2xx() {
        // 409 Conflict is what the API server returns when a pod is already bound.
        // bind_pod must surface this as Err so the caller can log and skip.
        // Reverting to Ok(()) on non-2xx would make this test fail.
        let result = check_bind_response(409, "AlreadyExists");
        assert!(
            result.is_err(),
            "409 Conflict must return Err, not Ok — duplicate binds must be surfaced"
        );
        let msg = format!("{:#}", result.err().unwrap());
        assert!(
            msg.contains("409"),
            "error must include the status code; got: {msg}"
        );
    }

    #[test]
    fn check_bind_response_ok_on_2xx() {
        // 201 Created is the success response for a new binding.
        assert!(
            check_bind_response(201, "").is_ok(),
            "201 Created must return Ok"
        );
        assert!(
            check_bind_response(200, "ok").is_ok(),
            "200 OK must return Ok"
        );
    }

    #[test]
    fn check_bind_response_err_includes_body() {
        // The error message must include the response body so operators can diagnose
        // failures without needing API server logs.
        let result = check_bind_response(422, "validation error: bad spec");
        let msg = format!("{:#}", result.err().unwrap());
        assert!(
            msg.contains("validation error"),
            "error message must include response body; got: {msg}"
        );
    }

    #[test]
    fn check_bind_response_err_on_404() {
        // 404 means the pod was deleted before binding completed — must surface as Err.
        let result = check_bind_response(404, "not found");
        assert!(result.is_err(), "404 must return Err");
    }

    #[test]
    fn check_bind_response_err_on_500() {
        // 500 Internal Server Error must not be silently swallowed.
        let result = check_bind_response(500, "internal error");
        assert!(result.is_err(), "500 must return Err");
    }

    // check_bind_response/is_bind_already_assigned tests — a 409 whose body
    // says the pod is "already assigned to node" means an EARLIER bind of
    // this exact pod already succeeded; this is a benign no-op, not a
    // scheduling failure. Before BindError existed, main.rs's caller treated
    // this identically to any other bind failure: it patched
    // PodScheduled=False and emitted FailedScheduling onto a pod whose
    // containers were actually already running fine (live-reproduced against
    // a duplicate-bind bug that periodically re-issues binds for already-
    // bound pods once the apiserver started correctly rejecting them with
    // 409 instead of silently accepting every duplicate).

    #[test]
    fn check_bind_response_classifies_409_already_assigned_message_as_already_assigned() {
        let result = check_bind_response(
            409,
            r#"{"kind":"Status","message":"Pod \"web-0\" is already assigned to node \"worker-1\""}"#,
        );
        let err = result.expect_err("a 409 must still be Err, just classified differently");
        assert!(
            is_bind_already_assigned(&err),
            "a 409 whose body says the pod is already assigned to a node must classify as \
             AlreadyAssigned, not a generic bind failure — the caller relies on this to skip \
             the PodScheduled=False patch/FailedScheduling event/tally rollback that would \
             otherwise corrupt a pod that is actually running fine"
        );
    }

    #[test]
    fn check_bind_response_does_not_classify_other_409s_as_already_assigned() {
        // A 409 for a DIFFERENT reason (not the "already assigned to node"
        // message) must still be a genuine failure — over-broadening the
        // AlreadyAssigned special case here would silently swallow other
        // conflicts the caller ought to report.
        let result = check_bind_response(409, "AlreadyExists");
        let err = result.expect_err("409 must still be Err");
        assert!(
            !is_bind_already_assigned(&err),
            "a 409 without the already-assigned-to-node message must classify as Other, \
             not AlreadyAssigned"
        );
    }

    #[test]
    fn check_bind_response_does_not_classify_non_409_as_already_assigned() {
        // Only a 409 with the specific message counts — any other status
        // (even one whose body happens to mention "already assigned to
        // node") must not take the benign no-op path.
        let result = check_bind_response(500, "Pod is already assigned to node worker-1");
        let err = result.expect_err("500 must still be Err");
        assert!(
            !is_bind_already_assigned(&err),
            "a non-409 status must never classify as AlreadyAssigned, regardless of body text"
        );
    }

    // referenced_pvc_names tests — needs_scheduling's only source of PVC
    // candidates for selected-node stamping. A pod whose volumes this
    // function fails to enumerate correctly never gets its PVC's annotation
    // stamped at all, silently reproducing the exact bug this feature fixes.

    #[test]
    fn referenced_pvc_names_includes_direct_claim_name() {
        let volumes = vec![PodVolume {
            name: "data".to_owned(),
            persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                claim_name: "data-pvc".to_owned(),
            }),
            ephemeral: None,
        }];
        assert_eq!(
            referenced_pvc_names("web-0", &volumes),
            vec!["data-pvc".to_owned()],
            "a volume with a direct persistentVolumeClaim source must contribute its \
             claimName verbatim — that PVC is what needs the selected-node stamp, not \
             some derived name"
        );
    }

    #[test]
    fn referenced_pvc_names_derives_ephemeral_pvc_name_from_pod_and_volume_name() {
        let volumes = vec![PodVolume {
            name: "scratch".to_owned(),
            persistent_volume_claim: None,
            ephemeral: Some(json!({"volumeClaimTemplate": {}})),
        }];
        assert_eq!(
            referenced_pvc_names("web-0", &volumes),
            vec!["web-0-scratch".to_owned()],
            "an ephemeral volume's PVC is created by upstream's ephemeral-volume controller \
             as <pod-name>-<volume-name> — any other derived name would look up (and stamp) \
             a PVC that doesn't exist, leaving the real one never stamped"
        );
    }

    #[test]
    fn referenced_pvc_names_ignores_volumes_with_no_pvc_source() {
        let volumes = vec![PodVolume {
            name: "config".to_owned(),
            persistent_volume_claim: None,
            ephemeral: None,
        }];
        assert!(
            referenced_pvc_names("web-0", &volumes).is_empty(),
            "a volume with neither persistentVolumeClaim nor ephemeral (e.g. configMap, \
             emptyDir) must never be treated as a PVC reference — stamping a nonexistent \
             PVC name would just be a wasted GET/PATCH cycle"
        );
    }

    // selected_node_patches tests — the pure decision behind
    // stamp_selected_node_for_pvcs. Real PVC/StorageClass lookups are network
    // calls (fetch_pvc_binding_info/fetch_storage_class_binding_mode), so the
    // WHICH-PVCs-need-stamping decision is exercised here directly, with
    // hand-constructed lookups, instead of through a mock API server.

    fn unbound_pvc(storage_class_name: &str) -> PvcBindingInfo {
        PvcBindingInfo {
            volume_name: String::new(),
            storage_class_name: Some(storage_class_name.to_owned()),
            selected_node: None,
            access_modes: Vec::new(),
        }
    }

    #[test]
    fn selected_node_patches_stamps_unbound_pvc_on_wait_for_first_consumer_class() {
        let pvcs = [("data-pvc".to_owned(), unbound_pvc("wfc-class"))]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let patches = selected_node_patches(
            &["data-pvc".to_owned()],
            "worker-0",
            |name| pvcs.get(name).cloned(),
            |_| Some("WaitForFirstConsumer".to_owned()),
        );
        assert_eq!(
            patches,
            vec![SelectedNodePatch {
                pvc_name: "data-pvc".to_owned(),
                node_name: "worker-0".to_owned(),
            }],
            "an unbound PVC on a WaitForFirstConsumer StorageClass is exactly the case \
             external-provisioner is blocked on — this must produce a stamp, or the PVC \
             (and the pod waiting on it) hangs forever"
        );
    }

    #[test]
    fn selected_node_patches_skips_immediate_storage_class() {
        let pvcs = [("cache-pvc".to_owned(), unbound_pvc("immediate-class"))]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>();
        let patches = selected_node_patches(
            &["cache-pvc".to_owned()],
            "worker-0",
            |name| pvcs.get(name).cloned(),
            |_| Some("Immediate".to_owned()),
        );
        assert!(
            patches.is_empty(),
            "an Immediate StorageClass already provisions without waiting on pod placement — \
             stamping it too would be a dead write nothing ever reads, not a harmless extra"
        );
    }

    #[test]
    fn selected_node_patches_skips_already_bound_pvc() {
        let pvcs = [(
            "data-pvc".to_owned(),
            PvcBindingInfo {
                volume_name: "pv-123".to_owned(),
                storage_class_name: Some("wfc-class".to_owned()),
                selected_node: None,
                access_modes: Vec::new(),
            },
        )]
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
        let patches = selected_node_patches(
            &["data-pvc".to_owned()],
            "worker-0",
            |name| pvcs.get(name).cloned(),
            |_| Some("WaitForFirstConsumer".to_owned()),
        );
        assert!(
            patches.is_empty(),
            "a PVC with a non-empty spec.volumeName is already bound to a real PV — \
             re-stamping it would rewrite a decision that's already been made and acted on"
        );
    }

    #[test]
    fn selected_node_patches_is_idempotent_once_already_stamped_for_this_node() {
        let pvcs = [(
            "data-pvc".to_owned(),
            PvcBindingInfo {
                volume_name: String::new(),
                storage_class_name: Some("wfc-class".to_owned()),
                selected_node: Some("worker-0".to_owned()),
                access_modes: Vec::new(),
            },
        )]
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
        let patches = selected_node_patches(
            &["data-pvc".to_owned()],
            "worker-0",
            |name| pvcs.get(name).cloned(),
            |_| Some("WaitForFirstConsumer".to_owned()),
        );
        assert!(
            patches.is_empty(),
            "a PVC already stamped with THIS node must not be re-PATCHed on every re-bind \
             (e.g. a watch replay) — repeating an already-correct write is a needless \
             apiserver round trip, not a correctness fix"
        );
    }

    #[test]
    fn selected_node_patches_re_stamps_when_selected_node_differs() {
        let pvcs = [(
            "data-pvc".to_owned(),
            PvcBindingInfo {
                volume_name: String::new(),
                storage_class_name: Some("wfc-class".to_owned()),
                selected_node: Some("worker-1".to_owned()),
                access_modes: Vec::new(),
            },
        )]
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
        let patches = selected_node_patches(
            &["data-pvc".to_owned()],
            "worker-0",
            |name| pvcs.get(name).cloned(),
            |_| Some("WaitForFirstConsumer".to_owned()),
        );
        assert_eq!(
            patches,
            vec![SelectedNodePatch {
                pvc_name: "data-pvc".to_owned(),
                node_name: "worker-0".to_owned(),
            }],
            "a stale stamp from a PREVIOUS bind attempt on a different node must be \
             overwritten to match the node this pod is actually bound to now — otherwise \
             external-provisioner would provision on the wrong node"
        );
    }

    #[test]
    fn selected_node_patches_skips_pvc_missing_from_lookup() {
        let patches = selected_node_patches(
            &["ghost-pvc".to_owned()],
            "worker-0",
            |_| None,
            |_| Some("WaitForFirstConsumer".to_owned()),
        );
        assert!(
            patches.is_empty(),
            "a PVC that GET returned 404 for (deleted between pod creation and bind, or a \
             lookup that failed) must be skipped, not panic or stamp a nonexistent object"
        );
    }

    // should_retry_without_preempting tests — before PickNodeError existed, a
    // transient GET /api/v1/nodes failure and a genuine full cluster produced
    // the same untyped Err, so main.rs treated an apiserver hiccup exactly
    // like "no capacity" and fell through to preemption: it could evict real
    // lower-priority pods, or mark the pod FailedScheduling, over a blip the
    // next watch tick would have retried cleanly.

    #[test]
    fn should_retry_without_preempting_is_false_for_no_capacity() {
        // A genuine NoCapacity means every qualifying node was actually
        // checked and none had room. If this returned true (retry instead of
        // preempt), a higher-priority pod stuck behind lower-priority ones
        // on a truly full cluster would stay Pending forever, since nothing
        // would ever try to preempt for it.
        assert!(
            !should_retry_without_preempting(&PickNodeError::NoCapacity("no room".to_owned())),
            "a real NoCapacity must fall through to preemption, not a bare retry"
        );
    }

    #[test]
    fn should_retry_without_preempting_is_true_for_api_error() {
        // The GET /api/v1/nodes call itself failed — no node was actually
        // checked, so this says nothing about real cluster capacity. If this
        // returned false (the pre-fix behavior), main.rs would preempt real
        // lower-priority pods, or mark this pod FailedScheduling, over a
        // transient apiserver hiccup instead of just retrying next tick.
        let err = PickNodeError::ApiError(anyhow::anyhow!("GET /api/v1/nodes returned 503"));
        assert!(
            should_retry_without_preempting(&err),
            "a transient API error must not trigger preemption or FailedScheduling"
        );
    }

    // should_retry_after_preemption_plan_error tests — find_preemption_plan had
    // the same untyped-Err gap pick_node did: a transient GET /api/v1/nodes
    // failure and "no node fits even after preempting" both surfaced as a bare
    // anyhow::Error, so main.rs's preemption arm treated an apiserver hiccup as
    // a genuine "this pod cannot be scheduled" outcome and marked it
    // FailedScheduling instead of leaving it Pending for the watch to retry.

    #[test]
    fn should_retry_after_preemption_plan_error_is_false_for_no_viable_plan() {
        // A genuine NoViablePlan means every qualifying node was actually
        // checked, including what preempting its lower-priority pods would
        // free. If this returned true (skip silently), a pod that truly
        // cannot fit anywhere would never get its FailedScheduling event.
        assert!(
            !should_retry_after_preemption_plan_error(&FindPreemptionPlanError::NoViablePlan),
            "a real NoViablePlan must produce a FailedScheduling event, not a silent skip"
        );
    }

    #[test]
    fn should_retry_after_preemption_plan_error_is_true_for_api_error() {
        // The GET /api/v1/nodes call itself failed — no node was actually
        // checked, so nothing here says the pod is truly unschedulable. If
        // this returned false (the pre-fix behavior), main.rs would mark the
        // pod FailedScheduling over a transient apiserver hiccup instead of
        // leaving it Pending for the next watch tick to retry.
        let err =
            FindPreemptionPlanError::ApiError(anyhow::anyhow!("GET /api/v1/nodes returned 503"));
        assert!(
            should_retry_after_preemption_plan_error(&err),
            "a transient API error during preemption planning must not be treated as \
             a genuine 'no viable plan' scheduling failure"
        );
    }

    // should_schedule tests — the dedup guard for concurrent bind_pod spawns.
    // Without this guard, two rapid ADDED/MODIFIED events for the same pod
    // would spawn two concurrent bind_pod calls; the second returns 409 Conflict
    // (now surfaced as Err after bead 2). The HashSet prevents the duplicate spawn.

    #[test]
    fn should_schedule_returns_true_for_key_not_in_flight() {
        // An empty in-flight set means no bind is running — schedule is allowed.
        // Removing the HashSet guard entirely would make this always return true,
        // which is correct here; the failure mode is in the next test.
        let in_flight = std::collections::HashSet::new();
        assert!(
            should_schedule(&in_flight, "default/my-pod"),
            "must return true when pod is not in-flight"
        );
    }

    #[test]
    fn should_schedule_returns_false_when_key_already_in_flight() {
        // A pod key present in in_flight means a bind task is already running.
        // should_schedule must return false to prevent a duplicate spawn.
        // This test fails if the HashSet guard is removed (always returns true).
        let mut in_flight = std::collections::HashSet::new();
        in_flight.insert("default/my-pod".to_owned());
        assert!(
            !should_schedule(&in_flight, "default/my-pod"),
            "must return false when pod is already in-flight"
        );
    }

    #[test]
    fn should_schedule_is_key_specific() {
        // Only the matching key must be blocked; other pods must still be schedulable.
        let mut in_flight = std::collections::HashSet::new();
        in_flight.insert("default/pod-a".to_owned());
        assert!(
            should_schedule(&in_flight, "default/pod-b"),
            "pod-b must be schedulable even when pod-a is in-flight"
        );
        assert!(
            !should_schedule(&in_flight, "default/pod-a"),
            "pod-a must not be schedulable when it is in-flight"
        );
    }

    #[test]
    fn should_schedule_key_uses_namespace_slash_name_format() {
        // The key format is "namespace/name". A key "default/pod" must not match
        // "kube-system/pod" — different namespace, different key.
        let mut in_flight = std::collections::HashSet::new();
        in_flight.insert("default/coredns".to_owned());
        assert!(
            should_schedule(&in_flight, "kube-system/coredns"),
            "same pod name in different namespace must be treated as a distinct key"
        );
    }

    // pods_needing_resync tests — the periodic resync's core decision: which
    // pods from a fresh /api/v1/pods list get a fresh scheduling attempt this
    // tick. A pod that exhausts preemption retries and goes FailedScheduling
    // never produces another watch event by itself — resync is
    // the only thing left that can ever pick it back up, so this decision
    // dropping such a pod, or ignoring in_flight, reintroduces the exact
    // stranding this fixes.

    #[test]
    fn pods_needing_resync_includes_a_still_unscheduled_pod() {
        // Mirrors a pod that lost a scheduling race (e.g. exhausted
        // preemption retries) and is still sitting Pending with no
        // nodeName — the exact shape of a pod stranded with no other watch event
        // coming. If this stopped returning such a pod, the periodic resync would never
        // re-attempt it and the stranding bug would be back.
        let items = vec![json!({
            "metadata": { "name": "stranded-pod", "namespace": "kube-system" },
            "spec": { "nodeName": "" }
        })];
        let in_flight = std::collections::HashSet::new();
        let events = pods_needing_resync(&items, &in_flight);
        assert_eq!(
            events.len(),
            1,
            "the unscheduled pod must produce exactly one synthetic event"
        );
        assert_eq!(events[0]["type"], "MODIFIED");
        assert_eq!(events[0]["object"]["metadata"]["name"], "stranded-pod");
    }

    /// Regression for the resync GET's dropped `fieldSelector=spec.nodeName=`:
    /// a real unscheduled pod never has `spec.nodeName` present-and-empty like
    /// the test above — `nodeName` is an `Option<String>` with
    /// `skip_serializing_if`, so an unscheduled pod's stored JSON has the key
    /// entirely ABSENT. A `fieldSelector=spec.nodeName=` GET compares that
    /// absence against SQL NULL, which matches nothing, so every real
    /// unscheduled pod was silently dropped before it ever reached this
    /// function — this test pins the exact on-the-wire shape that regression
    /// missed, not the empty-string shape above.
    #[test]
    fn pods_needing_resync_includes_a_pod_with_nodename_key_entirely_absent() {
        let items = vec![json!({
            "metadata": { "name": "never-scheduled-pod", "namespace": "kube-system" },
            "spec": {}
        })];
        let in_flight = std::collections::HashSet::new();
        let events = pods_needing_resync(&items, &in_flight);
        assert_eq!(
            events.len(),
            1,
            "a pod whose spec.nodeName key is entirely absent (how every real \
             unscheduled pod is actually persisted) must still be picked up by \
             resync"
        );
        assert_eq!(
            events[0]["object"]["metadata"]["name"],
            "never-scheduled-pod"
        );
    }

    #[test]
    fn pods_needing_resync_excludes_an_already_scheduled_pod() {
        // A pod that already has a nodeName is done. Resync must not keep
        // re-wrapping it as a "needs scheduling" event on every tick, or the
        // scheduler would spam pick_node calls and Scheduled/FailedScheduling
        // events for every bound pod in the cluster every 30s, forever.
        let items = vec![json!({
            "metadata": { "name": "bound-pod", "namespace": "default" },
            "spec": { "nodeName": "node-1" }
        })];
        let in_flight = std::collections::HashSet::new();
        assert!(
            pods_needing_resync(&items, &in_flight).is_empty(),
            "an already-scheduled pod must not be re-submitted for scheduling"
        );
    }

    #[test]
    fn pods_needing_resync_excludes_a_pod_already_in_flight() {
        // The watch may already have a bind task running for this exact pod
        // (e.g. it re-triggered scheduling milliseconds before this resync
        // tick fired). Without this check, resync would spawn a second,
        // concurrent bind_pod call for the same pod, racing the watch's own
        // attempt into a 409 Conflict — the exact double-schedule the
        // in_flight guard exists to prevent.
        let items = vec![json!({
            "metadata": { "name": "stranded-pod", "namespace": "kube-system" },
            "spec": { "nodeName": "" }
        })];
        let mut in_flight = std::collections::HashSet::new();
        in_flight.insert("kube-system/stranded-pod".to_owned());
        assert!(
            pods_needing_resync(&items, &in_flight).is_empty(),
            "a pod already in in_flight must be skipped by resync, not double-scheduled"
        );
    }

    /// Guardrail (restart-safety audit): a pod nominated by a deferred
    /// preemption plan (`PreemptionWaiters` in-memory only — see its doc
    /// comment) must be retried by resync exactly like any other
    /// `spec.nodeName`-empty pod, `nominatedNodeName` notwithstanding. The
    /// in-memory waiters map vanishes on process restart or a watch
    /// reconnect; the ONLY thing that makes losing it a latency regression
    /// instead of a stuck-forever pod is this resync path never special-
    /// casing (excluding) a pod just because it looks "already handled" by
    /// its `nominatedNodeName`. If a future change adds such a filter, this
    /// test catches it: the pod would silently stop being retried the moment
    /// the waiters map that was supposed to bind it disappears.
    #[test]
    fn pods_needing_resync_includes_a_pod_with_nominated_node_name_set() {
        let items = vec![json!({
            "metadata": { "name": "preemptor-pod", "namespace": "default" },
            "spec": { "nodeName": "" },
            "status": { "nominatedNodeName": "worker-0" }
        })];
        let in_flight = std::collections::HashSet::new();
        let events = pods_needing_resync(&items, &in_flight);
        assert_eq!(
            events.len(),
            1,
            "a pod with nominatedNodeName set but spec.nodeName still empty \
             must still be retried by resync — excluding it reintroduces the \
             stuck-forever failure mode the restart-safety audit flagged, \
             since the in-memory map that would otherwise finish binding it \
             does not survive a restart or a watch reconnect"
        );
        assert_eq!(events[0]["object"]["metadata"]["name"], "preemptor-pod");
    }

    /// Regression for the resync loop's map/filter reorder: `pods_needing_resync`
    /// now filters each raw list item BEFORE wrapping it into a watch-event
    /// envelope (only survivors pay that clone), instead of wrapping every
    /// item first and filtering second. A mixed batch exercising every
    /// exclusion reason side by side — already-scheduled, scheduling-gated,
    /// already in-flight — pinned against the exact set of names that must
    /// survive catches a bug the single-scenario tests above could each miss
    /// alone: a reorder that only happens to work when it's the sole
    /// candidate in the list, e.g. an off-by-one in which items the raw
    /// pre-filter inspects versus which ones get wrapped.
    #[test]
    fn pods_needing_resync_reordered_filter_matches_pre_reorder_exclusion_set() {
        let items = vec![
            json!({
                "metadata": { "name": "stranded", "namespace": "default" },
                "spec": { "nodeName": "" }
            }),
            json!({
                "metadata": { "name": "bound", "namespace": "default" },
                "spec": { "nodeName": "node-1" }
            }),
            json!({
                "metadata": { "name": "gated", "namespace": "default" },
                "spec": { "nodeName": "", "schedulingGates": [{"name": "example.com/gate"}] }
            }),
            json!({
                "metadata": { "name": "in-flight", "namespace": "default" },
                "spec": { "nodeName": "" }
            }),
        ];
        let mut in_flight = std::collections::HashSet::new();
        in_flight.insert("default/in-flight".to_owned());
        let events = pods_needing_resync(&items, &in_flight);
        let names: std::collections::BTreeSet<&str> = events
            .iter()
            .map(|e| e["object"]["metadata"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from(["stranded"]),
            "reordering the filter ahead of the wrap must not change which pods \
             get resynced — bound, gated, and in-flight pods must stay excluded \
             exactly as they were when the wrap ran first"
        );
    }

    // drain_watch_buffer is re-exported from kubeconfig where it is called by
    // watch_stream (and therefore stream_watch_events). This test confirms that
    // the function used in production handles multi-line chunks correctly.
    // If drain_watch_buffer were decoupled from watch_stream again (reverted to
    // an inline copy), this re-export would break at compile time.
    #[test]
    fn drain_watch_buffer_multi_line_chunk_parses_all_events() {
        // Simulate receiving three complete JSON watch events in a single chunk
        // (an initial ADDED burst, e.g. scheduler startup against a cluster with
        // many pre-existing pods, is exactly when several lines pile up in one
        // read). This exercises the production code path: watch_stream calls
        // drain_watch_buffer per frame, and drain_watch_buffer must consume all
        // complete lines even when several arrive in one network frame — each
        // loop iteration drains the buffer in place, so this also confirms the
        // repeated drain doesn't lose or misalign later lines.
        let mut buf = "{\"type\":\"ADDED\",\"object\":{}}\n{\"type\":\"MODIFIED\",\"object\":{}}\n{\"type\":\"DELETED\",\"object\":{}}\n"
            .to_owned();
        let mut events: Vec<Value> = Vec::new();
        drain_watch_buffer(&mut buf, &mut |v| events.push(v));
        assert_eq!(
            events.len(),
            3,
            "all three lines must be parsed from a single chunk"
        );
        assert_eq!(events[0]["type"], "ADDED");
        assert_eq!(events[1]["type"], "MODIFIED");
        assert_eq!(events[2]["type"], "DELETED");
        assert!(buf.is_empty(), "all complete lines must be consumed");
    }

    // WatchEvent deserialization — verifies that the typed envelope correctly
    // maps "type" → event_type and "object" → object. A rename or missing field
    // would cause every watch event to be silently ignored.
    #[test]
    fn watch_event_deserializes_type_and_object() {
        let json = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "my-pod", "namespace": "staging" },
                "spec": { "nodeName": "" }
            }
        });
        let we: WatchEvent<PodObject> =
            serde_json::from_value(json).expect("WatchEvent should deserialize");
        assert_eq!(we.event_type, "ADDED");
        assert_eq!(we.object.metadata.name.as_deref(), Some("my-pod"));
        assert_eq!(we.object.metadata.namespace.as_deref(), Some("staging"));
        assert_eq!(we.object.spec.node_name.as_deref(), Some(""));
    }

    // Regression test: the cluster-wide watch path must NOT be scoped to a
    // specific namespace.  If this constant ever reverts to the old
    // "namespaces/default/pods" path, cross-namespace pods (e.g. CoreDNS in
    // kube-system) will never be scheduled.
    #[test]
    fn watch_path_is_cluster_wide() {
        let path = "/api/v1/pods?watch=true&fieldSelector=spec.nodeName%3D";
        assert!(
            !path.contains("namespaces/"),
            "watch path must be cluster-wide, not namespace-scoped: {path}"
        );
        assert!(
            path.starts_with("/api/v1/pods"),
            "watch path must use /api/v1/pods, got: {path}"
        );
    }

    #[test]
    fn needs_scheduling_returns_none_for_non_pod_events() {
        let event = json!({ "type": "DELETED", "object": { "metadata": { "name": "foo", "namespace": "default" }, "spec": {} } });
        assert!(needs_scheduling(&event).is_none());
    }

    #[test]
    fn needs_scheduling_returns_none_when_already_scheduled() {
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "foo", "namespace": "kube-system" },
                "spec": { "nodeName": "node-1" }
            }
        });
        assert!(needs_scheduling(&event).is_none());
    }

    #[test]
    fn needs_scheduling_returns_namespace_from_event() {
        // Pods outside `default` (e.g. CoreDNS in kube-system) must be
        // scheduled using the namespace from the event, not a hard-coded value.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "coredns-abc", "namespace": "kube-system" },
                "spec": { "nodeName": "" }
            }
        });
        let result = needs_scheduling(&event);
        assert!(result.is_some(), "expected Some for unscheduled pod");
        let pending = result.unwrap();
        assert_eq!(
            pending.namespace, "kube-system",
            "namespace must come from event metadata"
        );
        assert_eq!(pending.pod_name, "coredns-abc");
    }

    #[test]
    fn needs_scheduling_returns_some_for_unscheduled_pod_in_default() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "my-pod", "namespace": "default" },
                "spec": {}
            }
        });
        let result = needs_scheduling(&event);
        assert!(result.is_some());
        let pending = result.unwrap();
        assert_eq!(pending.namespace, "default");
        assert_eq!(pending.pod_name, "my-pod");
    }

    #[test]
    fn needs_scheduling_returns_none_when_event_type_missing() {
        // Missing "type" field must not be treated as schedulable.
        let event = json!({
            "object": {
                "metadata": { "name": "my-pod", "namespace": "default" },
                "spec": {}
            }
        });
        assert!(needs_scheduling(&event).is_none());
    }

    #[test]
    fn needs_scheduling_returns_none_when_pod_name_empty() {
        // An event with no pod name must not produce a scheduling decision.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "", "namespace": "default" },
                "spec": {}
            }
        });
        assert!(needs_scheduling(&event).is_none());
    }

    #[test]
    fn needs_scheduling_defaults_namespace_to_default_when_absent() {
        // If the event carries no namespace field, fall back to "default".
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "no-ns-pod" },
                "spec": {}
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(pending.namespace, "default");
        assert_eq!(pending.pod_name, "no-ns-pod");
    }

    #[test]
    fn needs_scheduling_handles_modified_unscheduled_pod() {
        // MODIFIED events for unscheduled pods must also trigger scheduling
        // (e.g. when a pod is updated before being bound).
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "pending-pod", "namespace": "staging" },
                "spec": { "nodeName": null }
            }
        });
        let result = needs_scheduling(&event);
        assert!(result.is_some());
        let pending = result.unwrap();
        assert_eq!(pending.namespace, "staging");
        assert_eq!(pending.pod_name, "pending-pod");
    }

    // schedulingGates tests: a ReplicaSet's pods can carry
    // spec.schedulingGates so they stay Pending — not even considered "ready to
    // schedule" — until an external controller clears the gates. Without this
    // check the scheduler binds gated pods immediately, which is why the
    // conformance test "validates Pods with non-empty schedulingGates are
    // blocked on scheduling" saw all 3 ReplicaSet pods get bound and start
    // Running right away.

    #[test]
    fn needs_scheduling_returns_none_when_scheduling_gates_non_empty() {
        // A pod carrying schedulingGates: [foo, bar] must never enter the
        // scheduling cycle, no matter how empty spec.nodeName is.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [{"name": "foo"}, {"name": "bar"}] }
            }
        });
        assert!(
            needs_scheduling(&event).is_none(),
            "a pod with non-empty schedulingGates must stay out of the scheduling \
             cycle entirely — reverting this check would bind gated ReplicaSet pods \
             immediately, failing 'validates Pods with non-empty schedulingGates \
             are blocked on scheduling'"
        );
    }

    #[test]
    fn needs_scheduling_returns_some_when_scheduling_gates_is_empty_array() {
        // An empty gate list (all gates cleared) must behave exactly like no
        // gates at all — the pod is ready to schedule.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "ungated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [] }
            }
        });
        assert!(
            needs_scheduling(&event).is_some(),
            "an empty schedulingGates array means all gates are cleared — the pod \
             must be schedulable, not stuck forever"
        );
    }

    // scheduling_gate_status_patch / scheduling_gate_status_reset tests:
    // needs_scheduling correctly keeps gated pods out of the scheduling cycle, but
    // that alone leaves status.conditions untouched — WaitForPodsSchedulingGated
    // (upstream test/e2e/framework/pod/wait.go) polls status.conditions for
    // {type: PodScheduled, reason: SchedulingGated}, not just "is it unscheduled".
    // These tests cover the PATCH-decision logic that fills that gap.

    #[test]
    fn scheduling_gate_status_patch_sets_condition_when_absent() {
        // A freshly-created gated pod (no PodScheduled condition yet at all) must
        // get one — otherwise `kubectl describe pod` and WaitForPodsSchedulingGated
        // have nothing to read, even though the pod is correctly stuck Pending.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [{"name": "foo"}, {"name": "bar"}] }
            }
        });
        let patch = scheduling_gate_status_patch(&event)
            .expect("a newly gated pod with no condition yet must get one patched in");
        assert_eq!(patch.namespace, "default");
        assert_eq!(patch.pod_name, "gated-pod");
        let cond = &patch.patch["status"]["conditions"][0];
        assert_eq!(cond["type"], "PodScheduled");
        assert_eq!(cond["status"], "False");
        assert_eq!(
            cond["reason"], "SchedulingGated",
            "reason must exactly match v1.PodReasonSchedulingGated — \
             WaitForPodsSchedulingGated string-matches this field"
        );
    }

    #[test]
    fn scheduling_gate_status_patch_sets_condition_over_create_time_default() {
        // apply_pod_create_defaults (apiserver) stamps every new pod with
        // PodScheduled=False/reason=Unschedulable at creation, including gated
        // ones — this is the REAL starting state a gated ReplicaSet pod has, not
        // "no condition at all". The gated reason must still get applied over it.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [{"name": "foo"}] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "Unschedulable", "message": "pod not yet scheduled"}
                    ]
                }
            }
        });
        let patch = scheduling_gate_status_patch(&event).expect(
            "a gated pod still carrying the generic Unschedulable default must be \
             re-patched to the specific SchedulingGated reason",
        );
        assert_eq!(
            patch.patch["status"]["conditions"][0]["reason"],
            "SchedulingGated"
        );
    }

    #[test]
    fn scheduling_gate_status_patch_is_idempotent_once_already_marked() {
        // Every ADDED/MODIFIED event for a still-gated pod re-enters this
        // function (including the event generated by this function's own prior
        // PATCH echoing back through the watch). Once the condition already
        // reads False/SchedulingGated, re-sending the identical PATCH forever
        // would be a needless write storm — must return None instead.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [{"name": "bar"}] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "SchedulingGated", "message": "Scheduling is blocked due to non-empty scheduling gates"}
                    ]
                }
            }
        });
        assert!(
            scheduling_gate_status_patch(&event).is_none(),
            "condition already matches the target state (even with only one of \
             the original two gates remaining — gates clear one at a time) — \
             no PATCH is needed"
        );
    }

    #[test]
    fn scheduling_gate_status_patch_is_none_when_gates_empty() {
        // An ungated pod takes the normal scheduling path; this function must
        // never touch its PodScheduled condition.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "normal-pod", "namespace": "default" },
                "spec": { "schedulingGates": [] }
            }
        });
        assert!(scheduling_gate_status_patch(&event).is_none());
    }

    #[test]
    fn scheduling_gate_status_patch_is_none_when_already_scheduled() {
        // A gated pod should never reach spec.nodeName != "" (the binding
        // endpoint requires empty schedulingGates), but this must defensively
        // refuse to touch a bound pod's condition regardless — matching the
        // same non-interference guarantee needs_scheduling already provides.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "nodeName": "node-1", "schedulingGates": [{"name": "foo"}] }
            }
        });
        assert!(scheduling_gate_status_patch(&event).is_none());
    }

    #[test]
    fn scheduling_gate_status_reset_clears_stale_reason_once_gates_fully_removed() {
        // Once every gate is gone, the pod is about to proceed through normal
        // scheduling — leaving the condition saying SchedulingGated would lie
        // about why it's still Pending if scheduling doesn't succeed instantly.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "SchedulingGated", "message": "Scheduling is blocked due to non-empty scheduling gates"}
                    ]
                }
            }
        });
        let patch = scheduling_gate_status_reset(&event)
            .expect("the stale SchedulingGated reason must be cleared once all gates clear");
        assert_eq!(patch["status"]["conditions"][0]["reason"], "Unschedulable");
    }

    #[test]
    fn scheduling_gate_status_reset_is_none_while_one_gate_remains() {
        // Gates clear one at a time (predicates.go removes "foo" first, leaving
        // "bar"): with "bar" still present the pod is genuinely still blocked,
        // so the SchedulingGated reason must NOT be reset yet.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [{"name": "bar"}] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "SchedulingGated", "message": "Scheduling is blocked due to non-empty scheduling gates"}
                    ]
                }
            }
        });
        assert!(
            scheduling_gate_status_reset(&event).is_none(),
            "removing only one of two gates must not clear the condition — the \
             pod is still blocked on the remaining gate"
        );
    }

    #[test]
    fn scheduling_gate_status_reset_is_none_once_already_scheduled() {
        // If the pod was already bound (e.g. a fast scheduling attempt won the
        // race against this reset check on an earlier event), its PodScheduled
        // condition belongs to the bind outcome now — never touch it here.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "nodeName": "node-1", "schedulingGates": [] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "True", "reason": "PodScheduled", "message": ""}
                    ]
                }
            }
        });
        assert!(scheduling_gate_status_reset(&event).is_none());
    }

    #[test]
    fn scheduling_gate_status_reset_is_none_for_a_pod_that_was_never_gated() {
        // A normal pod's condition already reads Unschedulable from apiserver's
        // create-time default — there is no stale SchedulingGated reason to
        // clear, so this must not fire (and must not needlessly PATCH every pod).
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "normal-pod", "namespace": "default" },
                "spec": { "schedulingGates": [] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "Unschedulable", "message": "pod not yet scheduled"}
                    ]
                }
            }
        });
        assert!(scheduling_gate_status_reset(&event).is_none());
    }

    #[test]
    fn scheduling_gate_status_reset_patch_omits_status_field() {
        // Load-bearing for race-safety: bind_pod (apiserver) flips PodScheduled
        // to True atomically with spec.nodeName in one write, concurrently with
        // this reset. If the reset patch included "status": "False", it could
        // apply after a fresh bind and clobber True back to False. Omitting the
        // key entirely means this patch can only ever touch reason/message.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "SchedulingGated", "message": "Scheduling is blocked due to non-empty scheduling gates"}
                    ]
                }
            }
        });
        let patch =
            scheduling_gate_status_reset(&event).expect("gates cleared, reason still stale");
        assert!(
            patch["status"]["conditions"][0].get("status").is_none(),
            "the reset patch must never carry a \"status\" field — doing so risks \
             clobbering a concurrently-bound pod's True back to False"
        );
    }

    #[test]
    fn failed_scheduling_status_patch_sets_pod_scheduled_false() {
        // Without this, a pod that fails every scheduling attempt keeps
        // whatever PodScheduled condition it had at creation forever — the
        // FailedScheduling Event main.rs emits is invisible to anything that
        // polls status.conditions instead of watching Events (some
        // conformance waits do exactly that), so this must actually flip the
        // condition, not just log/emit.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "p", "namespace": "default" },
                "spec": {}
            }
        });
        let patch = failed_scheduling_status_patch(&event, "no node fits")
            .expect("a pod with no matching condition yet must get one patched in");
        let cond = &patch["status"]["conditions"][0];
        assert_eq!(cond["type"], "PodScheduled");
        assert_eq!(cond["status"], "False");
        assert_eq!(
            cond["reason"], "Unschedulable",
            "reason must match v1.PodReasonUnschedulable — upstream kube-scheduler \
             stamps this same reason on every failed scheduling cycle"
        );
        assert_eq!(cond["message"], "no node fits");
    }

    #[test]
    fn failed_scheduling_status_patch_is_none_once_already_marked_with_same_message() {
        // Load-bearing for a permanently-unschedulable pod (e.g. an
        // impossible nodeSelector): this PATCH's own write echoes back
        // through the watch as a fresh MODIFIED event, which re-enters
        // needs_scheduling and retries scheduling immediately. Reproduced
        // live: patching unconditionally on every retry fired an unbounded
        // tight self-retrigger loop (hundreds of PATCH/watch round trips per
        // second) instead of settling once the failure message stopped
        // changing — this idempotency check is what breaks that loop.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "p", "namespace": "default" },
                "spec": {},
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "Unschedulable", "message": "no node fits"}
                    ]
                }
            }
        });
        assert!(
            failed_scheduling_status_patch(&event, "no node fits").is_none(),
            "an identical repeat failure must not re-issue the PATCH, or the pod's own \
             watch echo retriggers scheduling in a tight, unbounded loop"
        );
    }

    #[test]
    fn failed_scheduling_status_patch_fires_again_when_message_changes() {
        // A pod's failure reason CAN legitimately change between attempts
        // (e.g. NoCapacity this tick, a different node's resource shortfall
        // next tick) — the idempotency guard must only suppress an EXACT
        // repeat, never mask a genuinely new failure reason from
        // kubectl describe pod.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "p", "namespace": "default" },
                "spec": {},
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "Unschedulable", "message": "old reason"}
                    ]
                }
            }
        });
        assert!(
            failed_scheduling_status_patch(&event, "new reason").is_some(),
            "a changed failure message must still be patched in, not suppressed"
        );
    }

    // pod_status_path / check_status_patch_response tests — mirror the
    // binding_path / check_bind_response coverage above for the new status
    // subresource plumbing.

    #[test]
    fn pod_status_path_produces_correct_api_path() {
        let path = pod_status_path("default", "my-pod");
        assert_eq!(path, "/api/v1/namespaces/default/pods/my-pod/status");
    }

    #[test]
    fn check_status_patch_response_ok_on_2xx() {
        assert!(check_status_patch_response(200, "").is_ok());
    }

    #[test]
    fn check_status_patch_response_err_on_415() {
        // 415 is exactly what the apiserver returns for the wrong Content-Type
        // (see accepts_patch_content_type) — must surface as Err, not be
        // silently swallowed, or a content-type regression would go unnoticed.
        let result = check_status_patch_response(415, "unsupported media type");
        assert!(result.is_err());
        let msg = format!("{:#}", result.err().unwrap());
        assert!(
            msg.contains("415"),
            "error must include the status code; got: {msg}"
        );
    }

    // binding_path tests — verify the REST path conforms to the Kubernetes API spec.
    // A wrong path silently drops the bind request (404), leaving pods unscheduled.

    #[test]
    fn binding_path_produces_correct_api_path() {
        let path = binding_path("default", "my-pod");
        assert_eq!(path, "/api/v1/namespaces/default/pods/my-pod/binding");
    }

    #[test]
    fn binding_path_uses_provided_namespace() {
        // Pods in non-default namespaces must use their actual namespace in the path.
        let path = binding_path("kube-system", "coredns-abc");
        assert_eq!(
            path,
            "/api/v1/namespaces/kube-system/pods/coredns-abc/binding"
        );
    }

    // binding_payload tests — verify the JSON body that is POSTed to the API server.
    // Kubernetes rejects bindings with incorrect apiVersion/kind/target shape.

    #[test]
    fn binding_payload_has_correct_api_version_and_kind() {
        let payload = binding_payload("default", "my-pod", "node-1");
        assert_eq!(payload["apiVersion"], "v1");
        assert_eq!(payload["kind"], "Binding");
    }

    #[test]
    fn binding_payload_target_references_correct_node() {
        let payload = binding_payload("staging", "web-pod", "worker-2");
        assert_eq!(payload["target"]["kind"], "Node");
        assert_eq!(payload["target"]["name"], "worker-2");
        assert_eq!(payload["target"]["apiVersion"], "v1");
    }

    #[test]
    fn binding_payload_metadata_matches_pod_and_namespace() {
        let payload = binding_payload("kube-system", "dns-pod", "node-0");
        assert_eq!(payload["metadata"]["name"], "dns-pod");
        assert_eq!(payload["metadata"]["namespace"], "kube-system");
    }

    // NodeList deserialization — the scheduler depends on parsing the API server's
    // node list. If the shape changes, pick_node silently returns no nodes.

    #[test]
    fn node_list_deserializes_items() {
        let json = json!({
            "items": [
                { "metadata": { "name": "node-1" } },
                { "metadata": { "name": "node-2" } }
            ]
        });
        let list: NodeList = serde_json::from_value(json).expect("should deserialize");
        assert_eq!(list.items.len(), 2);
        assert_eq!(list.items[0].metadata.name, "node-1");
        assert_eq!(list.items[1].metadata.name, "node-2");
    }

    #[test]
    fn node_list_deserializes_empty_items() {
        let json = json!({ "items": [] });
        let list: NodeList = serde_json::from_value(json).expect("should deserialize");
        assert!(list.items.is_empty());
    }

    /// A `status.allocatable` entry beyond the named cpu/memory/ephemeral-
    /// storage/pods fields (e.g. an extended resource added by
    /// `AddExtendedResource`, or hugepages) must be captured into `extended`,
    /// not silently dropped — without this, resource_fits/preemption can
    /// never see that a node has (or lacks) capacity for it.
    #[test]
    fn node_allocatable_captures_extended_resource_keys() {
        let json = json!({
            "pods": "110",
            "cpu": "4",
            "scheduling.k8s.io/foo": "5",
            "nvidia.com/gpu": "2"
        });
        let allocatable: NodeAllocatable =
            serde_json::from_value(json).expect("should deserialize");
        assert_eq!(
            allocatable.pods, "110",
            "named fields must still deserialize normally"
        );
        assert_eq!(
            allocatable.extended.get("scheduling.k8s.io/foo"),
            Some(&"5".to_owned()),
            "an extended-resource key must land in `extended`, keyed by its full name"
        );
        assert_eq!(
            allocatable.extended.get("nvidia.com/gpu"),
            Some(&"2".to_owned()),
            "every unrecognized key must be captured, not just the one the test set up first"
        );
        assert!(
            !allocatable.extended.contains_key("cpu"),
            "a named field (cpu) must not ALSO appear in `extended` — it would double-count"
        );
    }

    // parse_uri_parts tests — the URI-parsing logic is shared by send_request and
    // stream_watch_events. A wrong host/port means every request goes to the wrong
    // address silently.

    #[test]
    fn parse_uri_parts_extracts_host_and_default_port() {
        // When no explicit port is given, HTTPS defaults to 443.
        let (host, port, addr) =
            parse_uri_parts("https://api.example.com", "/api/v1/pods").expect("should parse");
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
        assert_eq!(addr, "api.example.com:443");
    }

    #[test]
    fn parse_uri_parts_uses_explicit_port() {
        // When the server URL contains an explicit port, that port must be used.
        // A common kubeconfig server address is https://host:6443.
        let (host, port, addr) =
            parse_uri_parts("https://10.0.0.1:6443", "/api/v1/nodes").expect("should parse");
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 6443);
        assert_eq!(addr, "10.0.0.1:6443");
    }

    #[test]
    fn parse_uri_parts_fails_on_missing_host() {
        // A relative URL (no scheme/host) must return an error — not silently
        // produce an empty host, which would be an undetected misconfiguration.
        let result = parse_uri_parts("", "/api/v1/pods");
        assert!(result.is_err(), "expected error for empty base URL");
    }

    // drain_watch_buffer tests — the line-parsing logic drives the watch loop.
    // Bugs here mean watch events are silently dropped or double-processed.

    #[test]
    fn drain_watch_buffer_calls_handler_for_each_complete_line() {
        // Each newline-terminated JSON object must produce exactly one handler call.
        let mut buf = "{\"type\":\"ADDED\"}\n{\"type\":\"MODIFIED\"}\n".to_owned();
        let mut events: Vec<Value> = Vec::new();
        drain_watch_buffer(&mut buf, &mut |v| events.push(v));
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["type"], "ADDED");
        assert_eq!(events[1]["type"], "MODIFIED");
        assert!(buf.is_empty(), "complete lines must be consumed from buf");
    }

    #[test]
    fn drain_watch_buffer_leaves_incomplete_line_in_buf() {
        // If the last chunk does not end with '\n', it is a partial line and must
        // be retained for the next frame — emitting it early would corrupt the JSON.
        let mut buf = "{\"type\":\"ADDED\"}\n{\"partial\":".to_owned();
        let mut events: Vec<Value> = Vec::new();
        drain_watch_buffer(&mut buf, &mut |v| events.push(v));
        assert_eq!(events.len(), 1);
        assert_eq!(buf, "{\"partial\":", "incomplete line must stay in buf");
    }

    #[test]
    fn drain_watch_buffer_skips_blank_lines() {
        // Watch streams may include keep-alive blank lines; they must not trigger
        // the handler or cause a parse error.
        let mut buf = "\n{\"type\":\"ADDED\"}\n\n".to_owned();
        let mut events: Vec<Value> = Vec::new();
        drain_watch_buffer(&mut buf, &mut |v| events.push(v));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn drain_watch_buffer_skips_invalid_json_lines() {
        // Malformed lines (e.g. partial frames from a reconnect) must be skipped,
        // not panic or corrupt subsequent good lines.
        let mut buf = "not-json\n{\"type\":\"ADDED\"}\n".to_owned();
        let mut events: Vec<Value> = Vec::new();
        drain_watch_buffer(&mut buf, &mut |v| events.push(v));
        // Only the valid line produces a handler call.
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["type"], "ADDED");
    }

    // select_first_node tests — the node-selection policy. The scheduler always
    // picks the first node in the list; if none exist, the bind must not proceed.

    #[test]
    fn select_first_node_returns_first_item_name() {
        // When multiple nodes exist, the first one must be chosen. Round-robin or
        // other strategies are not implemented; first-wins is the intended policy.
        let list = NodeList {
            items: vec![
                NodeItem {
                    metadata: NodeMetadata {
                        name: "node-a".to_owned(),
                        labels: Default::default(),
                    },
                    spec: NodeSpec::default(),
                    status: NodeStatus::default(),
                    csi_driver_headroom: Default::default(),
                    csi_registered_drivers: Default::default(),
                },
                NodeItem {
                    metadata: NodeMetadata {
                        name: "node-b".to_owned(),
                        labels: Default::default(),
                    },
                    spec: NodeSpec::default(),
                    status: NodeStatus::default(),
                    csi_driver_headroom: Default::default(),
                    csi_registered_drivers: Default::default(),
                },
            ],
        };
        let name = select_first_node(list).expect("should return a node");
        assert_eq!(name, "node-a");
    }

    #[test]
    fn select_first_node_errors_when_list_is_empty() {
        // An empty node list must produce an error so the caller can log and retry,
        // rather than silently proceeding with an empty node name.
        let list = NodeList { items: vec![] };
        let result = select_first_node(list);
        assert!(result.is_err(), "expected error for empty node list");
    }

    // ---------------------------------------------------------------------------
    // Additional coverage: branches not exercised by earlier tests.
    // ---------------------------------------------------------------------------

    // needs_scheduling with a BOOKMARKED event type — exercises the non-ADDED/MODIFIED
    // branch with a type other than DELETED. Watch streams emit BOOKMARK events
    // periodically; they must be ignored like DELETED.
    #[test]
    fn needs_scheduling_returns_none_for_bookmark_event() {
        let event = json!({
            "type": "BOOKMARK",
            "object": {
                "metadata": { "name": "some-pod", "namespace": "default" },
                "spec": {}
            }
        });
        assert!(
            needs_scheduling(&event).is_none(),
            "BOOKMARK events must not trigger scheduling"
        );
    }

    // needs_scheduling fallback: when the event JSON cannot be deserialized into
    // WatchEvent<PodObject>, the function uses a default WatchEvent with an empty
    // event_type. This covers the unwrap_or_else branch — a non-object value like
    // a JSON number triggers the fallback.
    #[test]
    fn needs_scheduling_returns_none_for_non_object_event() {
        // A JSON number is not a WatchEvent — deserialization fails, fallback to
        // empty event_type, which does not match ADDED or MODIFIED.
        let event = json!(42);
        assert!(
            needs_scheduling(&event).is_none(),
            "non-object JSON must not trigger scheduling"
        );
    }

    // needs_scheduling with an explicitly null node_name field: None from the struct
    // means unscheduled. This is distinct from absent (already covered) and from
    // empty string "".
    #[test]
    fn needs_scheduling_returns_some_when_node_name_is_null() {
        // spec.nodeName: null is a valid unscheduled state in Kubernetes.
        // The scheduler must treat it the same as absent or "".
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "null-node-pod", "namespace": "default" },
                "spec": { "nodeName": null }
            }
        });
        let result = needs_scheduling(&event);
        assert!(
            result.is_some(),
            "null nodeName must be treated as unscheduled"
        );
        let pending = result.unwrap();
        assert_eq!(pending.namespace, "default");
        assert_eq!(pending.pod_name, "null-node-pod");
    }

    // binding_path with special characters — ensures the path template doesn't
    // introduce double slashes or truncate long names.
    #[test]
    fn binding_path_does_not_double_slash() {
        let path = binding_path("default", "my-pod");
        assert!(
            !path.contains("//"),
            "binding path must not contain double slashes: {path}"
        );
    }

    // NodeList with a single item — the common production case (one worker node).
    // select_first_node must return that node's name, not an error.
    #[test]
    fn select_first_node_returns_name_for_single_item_list() {
        let list = NodeList {
            items: vec![NodeItem {
                metadata: NodeMetadata {
                    name: "worker-0".to_owned(),
                    labels: Default::default(),
                },
                spec: NodeSpec::default(),
                status: NodeStatus::default(),
                csi_driver_headroom: Default::default(),
                csi_registered_drivers: Default::default(),
            }],
        };
        let name = select_first_node(list).expect("single-item list must return Ok");
        assert_eq!(name, "worker-0");
    }

    // ---------------------------------------------------------------------------
    // nodeSelector filtering: the scheduler must respect spec.nodeSelector.
    // Before this fix, pick_node blindly returned the first node regardless of labels,
    // causing pods with non-matching selectors to be bound to the wrong node and the
    // conformance test "validates that NodeSelector is respected if not matching" to fail.
    // ---------------------------------------------------------------------------

    fn make_node(name: &str, labels: &[(&str, &str)]) -> NodeItem {
        NodeItem {
            metadata: NodeMetadata {
                name: name.to_owned(),
                labels: labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            },
            spec: NodeSpec::default(),
            status: NodeStatus::default(),
            csi_driver_headroom: Default::default(),
            csi_registered_drivers: Default::default(),
        }
    }

    /// node_selector_matches returns true when the node labels satisfy all selector entries.
    ///
    /// This is the gating condition that prevents non-matching pods from being bound.
    /// If this always returns true (or the function is removed), every pod is scheduled
    /// regardless of its nodeSelector, making the conformance test fail.
    #[test]
    fn node_selector_matches_all_required_labels() {
        let labels: std::collections::HashMap<String, String> = [
            ("kubernetes.io/hostname".to_owned(), "lima-node".to_owned()),
            ("kubernetes.io/arch".to_owned(), "arm64".to_owned()),
        ]
        .into();
        let selector: std::collections::HashMap<String, String> =
            [("kubernetes.io/hostname".to_owned(), "lima-node".to_owned())].into();
        assert!(
            node_selector_matches(&labels, &selector),
            "node with matching label must satisfy selector — reverting the check \
             would cause this to always return true, scheduling pods on mismatched nodes"
        );
    }

    /// node_selector_matches returns false when the node is missing a required label.
    ///
    /// This is the regression test: before the fix, pick_node ignored
    /// nodeSelector, so a pod requesting `scheduledOnNode=lima-node-2` would be bound
    /// to `lima-node` (the only node). The test "NodeSelector is respected if not matching"
    /// would then fail waiting for the pod to remain Pending.
    #[test]
    fn node_selector_matches_false_when_label_absent() {
        let labels: std::collections::HashMap<String, String> =
            [("kubernetes.io/hostname".to_owned(), "lima-node".to_owned())].into();
        // Selector requires a label the node does not have.
        let selector: std::collections::HashMap<String, String> =
            [("scheduledOnNode".to_owned(), "lima-node-2".to_owned())].into();
        assert!(
            !node_selector_matches(&labels, &selector),
            "node missing a required label must NOT satisfy selector — reverting \
             this to always-true causes the scheduler to bind the pod to a mismatched \
             node, breaking the NodeSelector conformance test"
        );
    }

    /// node_selector_matches returns false when a label value differs.
    #[test]
    fn node_selector_matches_false_when_label_value_wrong() {
        let labels: std::collections::HashMap<String, String> =
            [("kubernetes.io/hostname".to_owned(), "lima-node".to_owned())].into();
        let selector: std::collections::HashMap<String, String> =
            [("kubernetes.io/hostname".to_owned(), "other-node".to_owned())].into();
        assert!(
            !node_selector_matches(&labels, &selector),
            "node with wrong label value must NOT satisfy selector"
        );
    }

    /// An empty nodeSelector matches any node.
    ///
    /// Standard Kubernetes semantics: absence of nodeSelector means "any node".
    /// If this returns false, pods without a nodeSelector are never scheduled.
    #[test]
    fn node_selector_matches_empty_selector_matches_any_node() {
        let labels: std::collections::HashMap<String, String> =
            [("kubernetes.io/hostname".to_owned(), "lima-node".to_owned())].into();
        let selector: std::collections::HashMap<String, String> = Default::default();
        assert!(
            node_selector_matches(&labels, &selector),
            "empty nodeSelector must match any node — \
             removing this would break scheduling of all pods without a nodeSelector"
        );
    }

    /// select_node_for_pod returns the first matching node.
    ///
    /// When a pod has a nodeSelector that matches the node, select_node_for_pod must
    /// return that node. If the matching logic is broken, schedulable pods stay Pending.
    #[test]
    fn select_node_for_pod_returns_matching_node() {
        let list = NodeList {
            items: vec![make_node(
                "lima-node",
                &[
                    ("kubernetes.io/hostname", "lima-node"),
                    ("kubernetes.io/arch", "arm64"),
                ],
            )],
        };
        let selector: std::collections::HashMap<String, String> =
            [("kubernetes.io/hostname".to_owned(), "lima-node".to_owned())].into();
        let name = select_node_for_pod(list, &selector).expect("matching node must be found");
        assert_eq!(
            name, "lima-node",
            "select_node_for_pod must return the name of the node whose labels match the selector"
        );
    }

    /// select_node_for_pod returns Err when no node satisfies the nodeSelector.
    ///
    /// This is the regression test: before the fix, a pod with a
    /// non-matching nodeSelector would be bound to the first node anyway (via
    /// select_first_node). With the fix, select_node_for_pod returns Err so the
    /// caller skips binding and the pod stays Pending — which is the correct behavior
    /// verified by the conformance test "validates that NodeSelector is respected if
    /// not matching".
    #[test]
    fn select_node_for_pod_errors_when_no_node_matches() {
        let list = NodeList {
            items: vec![make_node(
                "lima-node",
                &[("kubernetes.io/hostname", "lima-node")],
            )],
        };
        // Pod wants a node labeled scheduledOnNode=lima-node-2, which doesn't exist.
        let selector: std::collections::HashMap<String, String> =
            [("scheduledOnNode".to_owned(), "lima-node-2".to_owned())].into();
        let result = select_node_for_pod(list, &selector);
        assert!(
            result.is_err(),
            "select_node_for_pod must return Err when no node satisfies the selector — \
             reverting to always-pick-first would pass this as Ok, causing the conformance \
             test 'validates that NodeSelector is respected if not matching' to fail because \
             the pod gets scheduled instead of staying Pending"
        );
    }

    // ---------------------------------------------------------------------------
    // taints/tolerations: the scheduler must not bind a pod to a
    // NoSchedule/NoExecute-tainted node unless the pod tolerates that taint.
    // Before this fix, crates/scheduler/ had zero taint/toleration handling —
    // pods without a matching toleration were bound to tainted nodes anyway,
    // failing "validates that taints-tolerations is respected if not matching".
    // ---------------------------------------------------------------------------

    fn taint(key: &str, value: &str, effect: &str) -> Taint {
        Taint {
            key: key.to_owned(),
            value: value.to_owned(),
            effect: effect.to_owned(),
        }
    }

    fn toleration(key: &str, value: &str, effect: &str) -> Toleration {
        Toleration {
            key: Some(key.to_owned()),
            operator: None,
            value: Some(value.to_owned()),
            effect: Some(effect.to_owned()),
        }
    }

    /// A NoSchedule taint with no matching toleration must block the node —
    /// this is the exact scenario the conformance test exercises: a pod with
    /// no tolerations must stay Pending against a NoSchedule-tainted node.
    #[test]
    fn node_taints_tolerated_false_when_no_toleration_matches() {
        let taints = vec![taint("dedicated", "gpu", "NoSchedule")];
        assert!(
            !node_taints_tolerated(&taints, &[]),
            "a NoSchedule taint with zero tolerations must block the node — \
             reverting this would bind untolerating pods to tainted nodes, \
             failing 'validates that taints-tolerations is respected if not matching'"
        );
    }

    /// A toleration matching key/value/effect exactly must tolerate the taint.
    #[test]
    fn node_taints_tolerated_true_when_toleration_matches_exactly() {
        let taints = vec![taint("dedicated", "gpu", "NoSchedule")];
        let tolerations = vec![toleration("dedicated", "gpu", "NoSchedule")];
        assert!(
            node_taints_tolerated(&taints, &tolerations),
            "an exact key/value/effect toleration must tolerate the matching taint"
        );
    }

    /// A toleration with a different value must NOT tolerate the taint —
    /// otherwise pods could bypass taints meant to reserve nodes for specific
    /// workloads.
    #[test]
    fn node_taints_tolerated_false_when_value_differs() {
        let taints = vec![taint("dedicated", "gpu", "NoSchedule")];
        let tolerations = vec![toleration("dedicated", "cpu-only", "NoSchedule")];
        assert!(
            !node_taints_tolerated(&taints, &tolerations),
            "a toleration for a different value must not tolerate the taint"
        );
    }

    /// operator: Exists tolerates any value for the matching key — this is the
    /// upstream `Toleration{Key, Operator: Exists}` shape used to tolerate a
    /// taint regardless of its value.
    #[test]
    fn node_taints_tolerated_true_with_exists_operator_ignores_value() {
        let taints = vec![taint("dedicated", "gpu", "NoSchedule")];
        let tolerations = vec![Toleration {
            key: Some("dedicated".to_owned()),
            operator: Some("Exists".to_owned()),
            value: None,
            effect: Some("NoSchedule".to_owned()),
        }];
        assert!(
            node_taints_tolerated(&taints, &tolerations),
            "operator Exists must tolerate the taint regardless of its value"
        );
    }

    /// An empty-key toleration with operator Exists tolerates every taint,
    /// regardless of key — the upstream "tolerate everything" wildcard.
    #[test]
    fn node_taints_tolerated_true_with_wildcard_toleration() {
        let taints = vec![
            taint("dedicated", "gpu", "NoSchedule"),
            taint("other", "x", "NoExecute"),
        ];
        let tolerations = vec![Toleration {
            key: None,
            operator: Some("Exists".to_owned()),
            value: None,
            effect: None,
        }];
        assert!(
            node_taints_tolerated(&taints, &tolerations),
            "a wildcard toleration (no key, operator Exists) must tolerate every taint"
        );
    }

    /// PreferNoSchedule is a soft signal this MVP scheduler (no scoring) never
    /// hard-blocks on — only NoSchedule/NoExecute gate scheduling.
    #[test]
    fn node_taints_tolerated_true_for_prefer_no_schedule_without_toleration() {
        let taints = vec![taint("dedicated", "gpu", "PreferNoSchedule")];
        assert!(
            node_taints_tolerated(&taints, &[]),
            "PreferNoSchedule must never block scheduling in a scheduler with no scoring"
        );
    }

    /// A node with no taints at all trivially qualifies regardless of tolerations.
    #[test]
    fn node_taints_tolerated_true_when_node_has_no_taints() {
        assert!(
            node_taints_tolerated(&[], &[]),
            "a node with zero taints has nothing to tolerate"
        );
    }

    // ---------------------------------------------------------------------------
    // spec.unschedulable (kubectl cordon): the scheduler must not bind an
    // untolerating pod to a cordoned node. Before this fix, NodeSpec never
    // deserialized `unschedulable` at all, so `kubectl cordon` had zero effect
    // on new scheduling decisions (see the 0806-1102 conformance
    // flake investigation for the deterministic failure this caused).
    // ---------------------------------------------------------------------------

    /// A cordoned node (`spec.unschedulable=true`) with no matching toleration
    /// must never qualify — this is exactly what `kubectl cordon` relies on to
    /// stop new pods landing on a node under maintenance.
    #[test]
    fn unschedulable_node_rejected_when_pod_has_no_toleration() {
        let mut node = make_node("cordoned-node", &[]);
        node.spec.unschedulable = Some(true);
        let pod = empty_pending_pod();
        assert!(
            !node_qualifies_for_pod(&node, &pod),
            "a cordoned node must reject a pod with no unschedulable toleration — \
             reverting this leaves `kubectl cordon` broken end-to-end, since the \
             scheduler would keep binding fresh pods onto the cordoned node"
        );
    }

    /// A pod carrying the well-known override toleration must still be
    /// schedulable onto a cordoned node — mirrors upstream's
    /// `NodeUnschedulable` Filter plugin, which lets DaemonSet-style pods
    /// (and anything else that opts in) bypass cordon.
    #[test]
    fn unschedulable_node_accepted_when_pod_tolerates() {
        let mut node = make_node("cordoned-node", &[]);
        node.spec.unschedulable = Some(true);
        let mut pod = empty_pending_pod();
        // The exact shape the DaemonSet controller injects automatically
        // (`addDefaultTolerationsForDaemonSetPod` upstream): operator Exists,
        // no value, so it matches any taint value for the key.
        pod.tolerations = vec![Toleration {
            key: Some("node.kubernetes.io/unschedulable".to_owned()),
            operator: Some("Exists".to_owned()),
            value: None,
            effect: Some("NoSchedule".to_owned()),
        }];
        assert!(
            node_qualifies_for_pod(&node, &pod),
            "a pod tolerating node.kubernetes.io/unschedulable:NoSchedule must \
             still qualify for a cordoned node, matching upstream's override semantics"
        );
    }

    /// The deterministic conformance-flake scenario: a cordoned node with zero
    /// pods is the least-loaded candidate by raw pod count, but it must never
    /// be picked over loaded, schedulable nodes. Before this fix,
    /// `select_node_with_capacity` had no way to see `spec.unschedulable` and
    /// always won ties toward the emptiest node — which is exactly how upstream's
    /// `[sig-node] Node Lifecycle` fake unschedulable node stole unconstrained
    /// pods from `[sig-network] Networking Granular Checks` in the 0806-1102 run.
    #[test]
    fn unschedulable_node_rejected_even_when_least_loaded() {
        let loaded_a = make_node_with_capacity("loaded-a", &[], "110");
        let loaded_b = make_node_with_capacity("loaded-b", &[], "110");
        let mut cordoned = make_node_with_capacity("cordoned-empty", &[], "110");
        cordoned.spec.unschedulable = Some(true);
        let list = NodeList {
            items: vec![loaded_a, loaded_b, cordoned],
        };
        let pod = empty_pending_pod();
        let counts: std::collections::HashMap<String, NodeUsage> = [
            ("loaded-a".to_owned(), usage_with_pod_count(5)),
            ("loaded-b".to_owned(), usage_with_pod_count(3)),
            // "cordoned-empty" absent from `counts` — zero pods, the
            // least-loaded candidate by pod count alone.
        ]
        .into();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert_ne!(
            result.ok(),
            Some("cordoned-empty".to_owned()),
            "the cordoned node must never be selected even though it has the \
             fewest pods — picking it here is the exact mechanism that caused \
             the 0806-1102 deterministic conformance failure"
        );
    }

    // ---------------------------------------------------------------------------
    // InterPodAffinity Filter: spec.affinity.podAffinity/podAntiAffinity's
    // requiredDuringSchedulingIgnoredDuringExecution terms. Before this fix,
    // crates/scheduler had zero matching logic for either field — a pod
    // declaring "only run me next to X" or "never run me next to Y" was
    // scheduled as if it had no affinity constraints at all, silently
    // ignoring the user's explicit co-location/anti-co-location intent.
    // ---------------------------------------------------------------------------

    /// A required podAffinity/podAntiAffinity term restricted to `topology_key`,
    /// matching any already-tallied pod whose labels satisfy `match_labels`.
    fn podaffinity_term(topology_key: &str, match_labels: &[(&str, &str)]) -> PodAffinityTerm {
        PodAffinityTerm {
            label_selector: Some(LabelSelectorSpec {
                match_labels: match_labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                match_expressions: Vec::new(),
            }),
            namespaces: Vec::new(),
            topology_key: topology_key.to_owned(),
        }
    }

    /// An already-tallied pod occupying `node_name`, for `tallied_pods`.
    /// `key` is a placeholder, never a real preemption victim's — these
    /// tests exercise `node_qualifies` (the no-discount path), not
    /// `find_preemption_candidate`'s victim discounting.
    fn tallied(node_name: &str, namespace: &str, labels: &[(&str, &str)]) -> TalliedPodLabels {
        TalliedPodLabels {
            key: format!("{namespace}/unused-{node_name}"),
            node_name: node_name.to_owned(),
            namespace: namespace.to_owned(),
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// A required podAffinity term must admit a node sharing the topology
    /// domain (here, `zone`) with an already-tallied pod matching the term,
    /// and reject a node in a DIFFERENT domain even though it is otherwise
    /// unconstrained — this is what lets a pod declare "co-locate me with
    /// the cache tier" and have it actually enforced, not just parsed.
    #[test]
    fn interpodaffinity_filter_admits_node_when_required_affinity_pod_present_because_that_is_the_placement_intent(
    ) {
        let list = NodeList {
            items: vec![
                make_node("worker-same-zone", &[("zone", "a")]),
                make_node("worker-other-zone", &[("zone", "b")]),
            ],
        };
        let mut pod = empty_pending_pod();
        pod.pod_affinity_terms = vec![podaffinity_term("zone", &[("app", "cache")])];
        let tallied_pods = [tallied("worker-same-zone", "default", &[("app", "cache")])];
        let result =
            select_node_with_capacity(list, &pod, &std::collections::HashMap::new(), &tallied_pods);
        assert_eq!(
            result.ok(),
            Some("worker-same-zone".to_owned()),
            "the only node sharing the matching pod's topology domain must be \
             selected — picking the other zone (or failing outright) means \
             podAffinity is parsed but never actually enforced"
        );
    }

    /// A required podAffinity term with no matching pod ANYWHERE in the
    /// cluster, and whose own labels do not satisfy its own term either,
    /// must reject every node — otherwise a pod that explicitly asked to be
    /// co-located with a specific workload gets bound wherever, defeating
    /// the whole point of declaring the constraint.
    #[test]
    fn interpodaffinity_filter_rejects_node_when_required_affinity_pod_absent_because_placement_intent_is_unmet(
    ) {
        let list = NodeList {
            items: vec![make_node("worker-0", &[("zone", "a")])],
        };
        let mut pod = empty_pending_pod();
        pod.pod_affinity_terms = vec![podaffinity_term("zone", &[("app", "cache")])];
        // No tallied pods anywhere, and the pod's own labels (empty) do not
        // match its own term either — so the self-match bootstrap case
        // (see `pod_affinity_satisfied`) must not rescue this node.
        let result = select_node_with_capacity(list, &pod, &std::collections::HashMap::new(), &[]);
        assert!(
            result.is_err(),
            "with no matching pod anywhere and the pod itself not matching its \
             own term, every node must be rejected — got: {:?}",
            result.ok()
        );
    }

    /// The self-match bootstrap case: when NO pod anywhere matches a
    /// required podAffinity term, but the pending pod's OWN labels satisfy
    /// its own term, every node carrying the topology label is admitted.
    /// Without this, the very first replica of a self-referencing
    /// podAffinity workload (e.g. a StatefulSet whose pods affine to their
    /// own selector) could never be scheduled — no other matching pod can
    /// ever exist until this one is placed somewhere.
    #[test]
    fn interpodaffinity_filter_admits_first_self_affinity_pod_when_no_matching_pod_exists_yet_because_the_workload_would_otherwise_never_bootstrap(
    ) {
        let list = NodeList {
            items: vec![make_node("worker-0", &[("zone", "a")])],
        };
        let mut pod = empty_pending_pod();
        pod.labels = [("app".to_owned(), "cache".to_owned())].into();
        pod.pod_affinity_terms = vec![podaffinity_term("zone", &[("app", "cache")])];
        let result = select_node_with_capacity(list, &pod, &std::collections::HashMap::new(), &[]);
        assert_eq!(
            result.ok(),
            Some("worker-0".to_owned()),
            "the first self-affinity pod must be admitted when it would satisfy \
             its own term once placed — otherwise a self-referencing workload \
             (e.g. a StatefulSet affining to its own selector) can never bootstrap"
        );
    }

    /// A required podAntiAffinity term must reject a node sharing the
    /// topology domain with an already-tallied pod matching the term — this
    /// is what lets a pod declare "never run me next to another replica of
    /// myself" and have it actually enforced.
    #[test]
    fn interpodaffinity_filter_rejects_node_when_required_antiaffinity_pod_exists_because_placement_would_violate_user_placement_rule(
    ) {
        let list = NodeList {
            items: vec![make_node("worker-0", &[("zone", "a")])],
        };
        let mut pod = empty_pending_pod();
        pod.pod_anti_affinity_terms = vec![podaffinity_term("zone", &[("app", "cache")])];
        let tallied_pods = [tallied("worker-0", "default", &[("app", "cache")])];
        let result =
            select_node_with_capacity(list, &pod, &std::collections::HashMap::new(), &tallied_pods);
        assert!(
            result.is_err(),
            "the only node shares the anti-affinity term's topology domain with \
             a matching pod, so it must be rejected — got: {:?}",
            result.ok()
        );
    }

    /// A required podAntiAffinity term with no matching pod anywhere must
    /// admit the node — the positive control proving the anti-affinity
    /// Filter does not reject every node unconditionally, only ones that
    /// actually violate the constraint.
    #[test]
    fn interpodaffinity_filter_admits_node_when_required_antiaffinity_pod_absent_because_no_placement_conflict_exists(
    ) {
        let list = NodeList {
            items: vec![make_node("worker-0", &[("zone", "a")])],
        };
        let mut pod = empty_pending_pod();
        pod.pod_anti_affinity_terms = vec![podaffinity_term("zone", &[("app", "cache")])];
        let result = select_node_with_capacity(list, &pod, &std::collections::HashMap::new(), &[]);
        assert_eq!(
            result.ok(),
            Some("worker-0".to_owned()),
            "with no matching pod anywhere, the anti-affinity term has nothing \
             to conflict with, so the node must still be admitted"
        );
    }

    // ---------------------------------------------------------------------------
    // PodTopologySpread Filter: spec.topologySpreadConstraints. Before this fix,
    // crates/scheduler had zero handling of this field — a pod asking to be
    // spread across zones/hostnames could land arbitrarily (in practice, every
    // replica piling onto whichever node `select_node_with_capacity` tried
    // first), silently defeating the availability guarantee the field exists
    // to express.
    // ---------------------------------------------------------------------------

    /// A hard (`DoNotSchedule`) `topologySpreadConstraints[]` entry spreading
    /// on `topology_key` with `max_skew`, matching already-tallied pods whose
    /// labels satisfy `match_labels`.
    fn topology_spread_constraint(
        topology_key: &str,
        max_skew: i32,
        when_unsatisfiable: &str,
        match_labels: &[(&str, &str)],
    ) -> TopologySpreadConstraint {
        TopologySpreadConstraint {
            max_skew,
            topology_key: topology_key.to_owned(),
            when_unsatisfiable: when_unsatisfiable.to_owned(),
            label_selector: Some(LabelSelectorSpec {
                match_labels: match_labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                match_expressions: Vec::new(),
            }),
        }
    }

    /// maxSkew=1 across 3 zones, 2 already-tallied matching pods piled onto
    /// zone-a and none in zone-b/zone-c: placing the pending pod (which
    /// itself matches the constraint's selector) into zone-a would make that
    /// domain's count 3 against zone-b/zone-c's 0 — a skew of 3, blowing past
    /// maxSkew=1. Reverting the Filter (or computing skew wrong) would let
    /// this pod pile onto the already-overloaded zone, exactly the pattern
    /// `topologySpreadConstraints` exists to prevent.
    #[test]
    fn select_node_with_capacity_rejects_zone_that_would_exceed_max_skew() {
        let list = NodeList {
            items: vec![
                make_node("node-a", &[("topology.kubernetes.io/zone", "zone-a")]),
                make_node("node-b", &[("topology.kubernetes.io/zone", "zone-b")]),
                make_node("node-c", &[("topology.kubernetes.io/zone", "zone-c")]),
            ],
        };
        let mut pod = empty_pending_pod();
        pod.labels = [("app".to_owned(), "web".to_owned())].into();
        pod.topology_spread_constraints = vec![topology_spread_constraint(
            "topology.kubernetes.io/zone",
            1,
            "DoNotSchedule",
            &[("app", "web")],
        )];
        let tallied_pods = [
            tallied("node-a", "default", &[("app", "web")]),
            tallied("node-a", "default", &[("app", "web")]),
        ];
        let result =
            select_node_with_capacity(list, &pod, &std::collections::HashMap::new(), &tallied_pods);
        assert_ne!(
            result.ok(),
            Some("node-a".to_owned()),
            "zone-a already carries 2 matching pods against 0 elsewhere — \
             placing a 3rd there produces skew 3 > maxSkew 1, so it must be \
             rejected in favor of an emptier zone"
        );
    }

    /// The same shape as above, but the pending pod's ONLY viable node (via
    /// `nodeSelector`) is the overloaded zone — every candidate violates the
    /// hard constraint, so scheduling must fail outright (`Err`), NOT silently
    /// fall back to binding the pod somewhere that violates its own explicit
    /// spreading requirement.
    #[test]
    fn select_node_with_capacity_returns_err_when_every_candidate_violates_hard_constraint() {
        let list = NodeList {
            items: vec![
                make_node("node-a", &[("topology.kubernetes.io/zone", "a")]),
                make_node("node-b", &[("topology.kubernetes.io/zone", "b")]),
            ],
        };
        let mut pod = empty_pending_pod();
        pod.labels = [("app".to_owned(), "web".to_owned())].into();
        // Only node-b is a real candidate; node-a exists solely to give the
        // skew computation an (empty) zone to compare against, mirroring a
        // real cluster where the emptiest zone's node is unusable for some
        // other reason (cordoned, tainted, out of capacity).
        pod.node_selector = [("topology.kubernetes.io/zone".to_owned(), "b".to_owned())].into();
        pod.topology_spread_constraints = vec![topology_spread_constraint(
            "topology.kubernetes.io/zone",
            1,
            "DoNotSchedule",
            &[("app", "web")],
        )];
        let tallied_pods = [
            tallied("node-b", "default", &[("app", "web")]),
            tallied("node-b", "default", &[("app", "web")]),
            tallied("node-b", "default", &[("app", "web")]),
        ];
        let result =
            select_node_with_capacity(list, &pod, &std::collections::HashMap::new(), &tallied_pods);
        assert!(
            result.is_err(),
            "the only nodeSelector-eligible node violates the hard spread \
             constraint (skew 4 > maxSkew 1) — the pod must stay Pending, not \
             be bound to node-a (which the nodeSelector excludes anyway) or \
             to the violating node-b — got: {:?}",
            result.ok()
        );
    }

    /// The identical shape as the rejection test above (same 2 zones, same
    /// nodeSelector pinning the only candidate to the overloaded zone, same
    /// skew 4 > maxSkew 1), except `whenUnsatisfiable: ScheduleAnyway` —
    /// upstream treats this as a Score-phase-only preference, never a Filter
    /// rejection. Since this scheduler has no Score phase, a `ScheduleAnyway`
    /// constraint must be a pure no-op: the pod schedules onto node-b anyway,
    /// even though the byte-for-byte equivalent `DoNotSchedule` constraint
    /// (see the test above) rejects it outright. Using a single-zone shape
    /// here would not catch a "treat ScheduleAnyway as hard" regression: with
    /// only one domain, that domain is always both the min and the max, so
    /// skew can never exceed a maxSkew of 1 regardless of whether the
    /// constraint is enforced — the multi-zone shape is what actually makes
    /// enforcement observable.
    #[test]
    fn select_node_with_capacity_ignores_schedule_anyway_constraint_even_when_it_would_violate_max_skew(
    ) {
        let list = NodeList {
            items: vec![
                make_node("node-a", &[("topology.kubernetes.io/zone", "a")]),
                make_node("node-b", &[("topology.kubernetes.io/zone", "b")]),
            ],
        };
        let mut pod = empty_pending_pod();
        pod.labels = [("app".to_owned(), "web".to_owned())].into();
        pod.node_selector = [("topology.kubernetes.io/zone".to_owned(), "b".to_owned())].into();
        pod.topology_spread_constraints = vec![topology_spread_constraint(
            "topology.kubernetes.io/zone",
            1,
            "ScheduleAnyway",
            &[("app", "web")],
        )];
        let tallied_pods = [
            tallied("node-b", "default", &[("app", "web")]),
            tallied("node-b", "default", &[("app", "web")]),
            tallied("node-b", "default", &[("app", "web")]),
        ];
        let result =
            select_node_with_capacity(list, &pod, &std::collections::HashMap::new(), &tallied_pods);
        assert_eq!(
            result.ok(),
            Some("node-b".to_owned()),
            "whenUnsatisfiable: ScheduleAnyway must never filter a node — this \
             scheduler has no Score phase to weigh it as a soft preference \
             instead, so treating it as hard here would wrongly block \
             scheduling entirely (the equivalent DoNotSchedule constraint \
             returns Err for this exact shape — see the test above)"
        );
    }

    /// The constraint's `labelSelector` matches none of the 3 already-tallied
    /// pods on node-a (they carry `app=web`, the selector requires
    /// `app=other`) — so node-a's matching count is 0, identical to every
    /// other domain, and the constraint has no actual restricting effect.
    /// A labelSelector that never matches an existing pod must not block
    /// scheduling, even onto a node that already hosts many (non-matching)
    /// pods.
    #[test]
    fn select_node_with_capacity_schedules_freely_when_selector_matches_no_existing_pods() {
        let list = NodeList {
            items: vec![
                make_node("node-a", &[("topology.kubernetes.io/zone", "a")]),
                make_node("node-b", &[("topology.kubernetes.io/zone", "b")]),
            ],
        };
        let mut pod = empty_pending_pod();
        pod.labels = [("app".to_owned(), "web".to_owned())].into();
        pod.topology_spread_constraints = vec![topology_spread_constraint(
            "topology.kubernetes.io/zone",
            1,
            "DoNotSchedule",
            &[("app", "other")],
        )];
        let tallied_pods = [
            tallied("node-a", "default", &[("app", "web")]),
            tallied("node-a", "default", &[("app", "web")]),
            tallied("node-a", "default", &[("app", "web")]),
        ];
        let result =
            select_node_with_capacity(list, &pod, &std::collections::HashMap::new(), &tallied_pods);
        assert_eq!(
            result.ok(),
            Some("node-a".to_owned()),
            "a labelSelector matching zero existing pods imposes no real \
             constraint — node-a must remain selectable (and, since usage is \
             otherwise tied, win the normal list-order tie-break) despite \
             already hosting 3 pods"
        );
    }

    /// A pod with NO `topologySpreadConstraints` at all must behave exactly
    /// as before this feature existed: already-tallied pods' topology domains
    /// are irrelevant to it. This is the negative control — if building a
    /// `TopologySpreadContext` from an empty constraint list ever started
    /// synthesizing a restriction (e.g. a default constraint), this pod would
    /// wrongly reject the only available node despite asking for no spreading
    /// at all.
    #[test]
    fn select_node_with_capacity_unaffected_by_topology_when_pod_has_no_spread_constraints() {
        let list = NodeList {
            items: vec![make_node("node-a", &[("topology.kubernetes.io/zone", "a")])],
        };
        let pod = empty_pending_pod();
        let tallied_pods = [
            tallied("node-a", "default", &[("app", "web")]),
            tallied("node-a", "default", &[("app", "web")]),
            tallied("node-a", "default", &[("app", "web")]),
        ];
        let result =
            select_node_with_capacity(list, &pod, &std::collections::HashMap::new(), &tallied_pods);
        assert_eq!(
            result.ok(),
            Some("node-a".to_owned()),
            "a pod with no topologySpreadConstraints must schedule normally \
             regardless of how already-tallied pods are distributed"
        );
    }

    // ---------------------------------------------------------------------------
    // Bound-PVC PV nodeAffinity (Immediate-mode binding): a topology-aware CSI
    // driver stamps spec.nodeAffinity on the PV it provisions, and by the time
    // an Immediate-mode PVC's pod is scheduled that PVC is ALREADY bound to
    // that PV — there is no later WaitForFirstConsumer-style provisioning step
    // left to steer onto a compatible node (see `selected_node_patches`, which
    // only ever handles the unbound case). Without this check the scheduler
    // can bind the pod to a node the PV cannot actually be mounted on; the
    // kubelet then retries `MountVolume.NodeAffinity check failed` forever
    // with no recourse — live-reproduced against the CSI hostpath
    // read-write-once-pod e2e test, which hung until the 622s watchdog reap.
    // ---------------------------------------------------------------------------

    fn pv_node_affinity_requiring(key: &str, value: &str) -> NodeSelectorSpec {
        NodeSelectorSpec {
            node_selector_terms: vec![NodeSelectorTerm {
                match_expressions: vec![requirement(key, "In", &[value])],
                match_fields: vec![],
            }],
        }
    }

    /// A node missing the label a bound PVC's PV `nodeAffinity` requires must
    /// be rejected outright. Reverting the `pv_node_affinities` conjunct in
    /// `node_qualifies_for_pod` flips this from `false` to `true` — proving
    /// the predicate, not some other check, is what discriminates here.
    #[test]
    fn node_qualifies_for_pod_false_when_node_lacks_label_required_by_bound_pv_node_affinity() {
        let node = make_node("lima-node-3", &[]);
        let mut pod = empty_pending_pod();
        pod.pv_node_affinities = vec![pv_node_affinity_requiring(
            "topology.hostpath.csi/node",
            "lima-node",
        )];
        assert!(
            !node_qualifies_for_pod(&node, &pod),
            "a node missing the label a bound PVC's PV nodeAffinity requires \
             must be rejected — otherwise the scheduler binds here and the \
             kubelet blocks forever on MountVolume.NodeAffinity check failed"
        );
    }

    /// The exact same node/pod shapes as the false case above, except the
    /// node now carries the required label — this must flip to `true`, or
    /// the predicate would just be rejecting every node unconditionally
    /// rather than actually discriminating on the label.
    #[test]
    fn node_qualifies_for_pod_true_when_node_has_label_required_by_bound_pv_node_affinity() {
        let node = make_node("lima-node", &[("topology.hostpath.csi/node", "lima-node")]);
        let mut pod = empty_pending_pod();
        pod.pv_node_affinities = vec![pv_node_affinity_requiring(
            "topology.hostpath.csi/node",
            "lima-node",
        )];
        assert!(
            node_qualifies_for_pod(&node, &pod),
            "a node carrying the label a bound PVC's PV nodeAffinity requires \
             must still qualify"
        );
    }

    /// Mirrors the CSI hostpath "read-write-once-pod" e2e scenario end to
    /// end: the driver's own node carries the topology label its
    /// provisioned PV's nodeAffinity requires, a second node does not — and,
    /// the trap that makes this fail-on-revert meaningful, the WRONG node is
    /// the LESS loaded one, so the ordinary least-loaded tie-break would
    /// prefer it if the pv_node_affinities conjunct did not filter it out
    /// first.
    #[test]
    fn select_node_with_capacity_binds_to_node_satisfying_bound_pv_node_affinity_over_less_loaded_node(
    ) {
        let driver_node = make_node_with_capacity(
            "lima-node",
            &[("topology.hostpath.csi/node", "lima-node")],
            "110",
        );
        let other_node = make_node_with_capacity("lima-node-3", &[], "110");
        let list = NodeList {
            items: vec![driver_node, other_node],
        };
        let mut pod = empty_pending_pod();
        pod.pv_node_affinities = vec![pv_node_affinity_requiring(
            "topology.hostpath.csi/node",
            "lima-node",
        )];
        let counts: std::collections::HashMap<String, NodeUsage> = [
            ("lima-node".to_owned(), usage_with_pod_count(5)),
            ("lima-node-3".to_owned(), usage_with_pod_count(0)),
        ]
        .into();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert_eq!(
            result.ok(),
            Some("lima-node".to_owned()),
            "must bind to the node satisfying the bound PVC's PV nodeAffinity \
             even though the other node is less loaded — reverting the \
             pv_node_affinities conjunct picks lima-node-3 by the ordinary \
             least-loaded tie-break, exactly the bug that made the CSI \
             read-write-once-pod e2e test hang for 622s on \
             MountVolume.NodeAffinity check failed"
        );
    }

    /// needs_scheduling extracts spec.tolerations from the watch event — if this
    /// is dropped, node_taints_tolerated always sees an empty toleration list and
    /// every tainted node is treated as blocked, even for pods meant to tolerate it.
    #[test]
    fn needs_scheduling_returns_tolerations_from_event() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "tolerant-pod", "namespace": "default" },
                "spec": {
                    "tolerations": [
                        { "key": "dedicated", "operator": "Equal", "value": "gpu", "effect": "NoSchedule" }
                    ]
                }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.tolerations.len(),
            1,
            "spec.tolerations must be extracted from the watch event"
        );
        assert_eq!(pending.tolerations[0].key.as_deref(), Some("dedicated"));
        assert_eq!(pending.tolerations[0].effect.as_deref(), Some("NoSchedule"));
    }

    /// A pod with no tolerations must produce an empty list, not fail deserialization.
    #[test]
    fn needs_scheduling_returns_empty_tolerations_when_absent() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "plain-pod", "namespace": "default" },
                "spec": {}
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert!(
            pending.tolerations.is_empty(),
            "a pod without tolerations must produce an empty list"
        );
    }

    /// select_node_with_capacity must skip a tainted node the pod does not
    /// tolerate, even when it has free pod capacity — capacity alone is not
    /// enough; the node must also qualify (selector + taints).
    #[test]
    fn select_node_with_capacity_skips_untolerated_tainted_node() {
        let mut node = make_node_with_capacity("tainted-node", &[], "110");
        node.spec.taints = vec![taint("dedicated", "gpu", "NoSchedule")];
        let list = NodeList { items: vec![node] };
        let pod = empty_pending_pod();
        let counts: std::collections::HashMap<String, NodeUsage> = Default::default();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert!(
            result.is_err(),
            "a NoSchedule-tainted node with no matching toleration must be skipped \
             even when it has free capacity — got: {:?}",
            result.ok()
        );
    }

    /// select_node_with_capacity must select a tainted node when the pod
    /// carries a matching toleration.
    #[test]
    fn select_node_with_capacity_selects_tainted_node_with_matching_toleration() {
        let mut node = make_node_with_capacity("tainted-node", &[], "110");
        node.spec.taints = vec![taint("dedicated", "gpu", "NoSchedule")];
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.tolerations = vec![toleration("dedicated", "gpu", "NoSchedule")];
        let counts: std::collections::HashMap<String, NodeUsage> = Default::default();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert_eq!(
            result.unwrap(),
            "tainted-node",
            "a pod tolerating the node's taint must be scheduled there"
        );
    }

    // ---------------------------------------------------------------------------
    // nodeAffinity: RequiredDuringSchedulingIgnoredDuringExecution
    // must be enforced like nodeSelector. Before this fix, crates/scheduler/ had
    // zero handling of spec.affinity.nodeAffinity anywhere — a pod whose required
    // nodeAffinity term no node satisfied was bound anyway, failing "validates
    // that NodeAffinity is respected if not matching".
    // ---------------------------------------------------------------------------

    fn requirement(key: &str, operator: &str, values: &[&str]) -> NodeSelectorRequirement {
        NodeSelectorRequirement {
            key: key.to_owned(),
            operator: operator.to_owned(),
            values: values.iter().map(|v| v.to_string()).collect(),
        }
    }

    fn required_affinity(terms: Vec<NodeSelectorTerm>) -> NodeAffinity {
        NodeAffinity {
            required_during_scheduling_ignored_during_execution: Some(NodeSelectorSpec {
                node_selector_terms: terms,
            }),
        }
    }

    /// `None` (no nodeAffinity at all) must match any node — most pods never
    /// set affinity, and this must not restrict them.
    #[test]
    fn node_affinity_matches_true_when_no_affinity_set() {
        let labels: std::collections::HashMap<String, String> = Default::default();
        assert!(
            node_affinity_matches(&labels, "node-1", None),
            "a pod with no nodeAffinity must be schedulable on any node"
        );
    }

    /// The exact scenario from the conformance test: two ORed terms, neither of
    /// which any node label satisfies — the node must be rejected.
    #[test]
    fn node_affinity_matches_false_when_no_term_satisfied() {
        let labels: std::collections::HashMap<String, String> = Default::default();
        let affinity = required_affinity(vec![
            NodeSelectorTerm {
                match_expressions: vec![requirement("foo", "In", &["bar", "value2"])],
                match_fields: vec![],
            },
            NodeSelectorTerm {
                match_expressions: vec![requirement("diffkey", "In", &["wrong", "value2"])],
                match_fields: vec![],
            },
        ]);
        assert!(
            !node_affinity_matches(&labels, "node-1", Some(&affinity)),
            "a node satisfying neither ORed nodeSelectorTerm must be rejected — \
             reverting this check binds the pod anyway, failing 'validates that \
             NodeAffinity is respected if not matching'"
        );
    }

    /// A node whose labels satisfy one of several ORed terms must be accepted —
    /// nodeSelectorTerms are ORed, not ANDed.
    #[test]
    fn node_affinity_matches_true_when_one_of_ored_terms_satisfied() {
        let labels: std::collections::HashMap<String, String> =
            [("foo".to_owned(), "bar".to_owned())].into();
        let affinity = required_affinity(vec![
            NodeSelectorTerm {
                match_expressions: vec![requirement("foo", "In", &["bar", "value2"])],
                match_fields: vec![],
            },
            NodeSelectorTerm {
                match_expressions: vec![requirement("diffkey", "In", &["wrong", "value2"])],
                match_fields: vec![],
            },
        ]);
        assert!(
            node_affinity_matches(&labels, "node-1", Some(&affinity)),
            "a node satisfying at least one ORed nodeSelectorTerm must be accepted"
        );
    }

    /// matchExpressions within a single term are ANDed — a node satisfying only
    /// one of two required expressions in the same term must be rejected.
    #[test]
    fn node_affinity_matches_false_when_only_one_of_anded_expressions_satisfied() {
        let labels: std::collections::HashMap<String, String> =
            [("foo".to_owned(), "bar".to_owned())].into();
        let affinity = required_affinity(vec![NodeSelectorTerm {
            match_expressions: vec![
                requirement("foo", "In", &["bar"]),
                requirement("other", "Exists", &[]),
            ],
            match_fields: vec![],
        }]);
        assert!(
            !node_affinity_matches(&labels, "node-1", Some(&affinity)),
            "matchExpressions in one term are ANDed — satisfying only one of two \
             must not be enough"
        );
    }

    /// NotIn excludes a node whose label value is in the forbidden set.
    #[test]
    fn node_selector_requirement_not_in_excludes_matching_value() {
        let labels: std::collections::HashMap<String, String> =
            [("zone".to_owned(), "bad".to_owned())].into();
        assert!(
            !node_selector_requirement_matches(&labels, &requirement("zone", "NotIn", &["bad"])),
            "NotIn must reject a node whose label value is in the forbidden set"
        );
    }

    /// An unsupported operator (Gt/Lt, not implemented by this MVP) must never
    /// match — treating it as an automatic pass would let a pod bypass an
    /// affinity rule it doesn't actually satisfy.
    #[test]
    fn node_selector_requirement_unsupported_operator_never_matches() {
        let labels: std::collections::HashMap<String, String> =
            [("cpus".to_owned(), "4".to_owned())].into();
        assert!(
            !node_selector_requirement_matches(&labels, &requirement("cpus", "Gt", &["2"])),
            "an unimplemented operator must never silently match"
        );
    }

    /// needs_scheduling extracts spec.affinity.nodeAffinity from the watch
    /// event — if dropped, node_affinity_matches always sees None and every
    /// pod with a NodeAffinity restriction is bound as if it had none.
    #[test]
    fn needs_scheduling_returns_node_affinity_from_event() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "restricted-pod", "namespace": "default" },
                "spec": {
                    "affinity": {
                        "nodeAffinity": {
                            "requiredDuringSchedulingIgnoredDuringExecution": {
                                "nodeSelectorTerms": [
                                    { "matchExpressions": [
                                        { "key": "foo", "operator": "In", "values": ["bar"] }
                                    ] }
                                ]
                            }
                        }
                    }
                }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        let affinity = pending
            .node_affinity
            .expect("nodeAffinity must be extracted from the watch event");
        let required = affinity
            .required_during_scheduling_ignored_during_execution
            .expect("required term must be extracted");
        assert_eq!(required.node_selector_terms.len(), 1);
        assert_eq!(
            required.node_selector_terms[0].match_expressions[0].key,
            "foo"
        );
    }

    /// A pod with no affinity set must produce `None`, not fail deserialization.
    #[test]
    fn needs_scheduling_returns_none_node_affinity_when_absent() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "plain-pod", "namespace": "default" },
                "spec": {}
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert!(
            pending.node_affinity.is_none(),
            "a pod without spec.affinity must produce node_affinity: None"
        );
    }

    /// select_node_with_capacity must skip a node that fails the pod's required
    /// nodeAffinity, even when it has free pod capacity — the exact scenario the
    /// conformance test exercises (a pod bound anyway means this predicate never ran).
    #[test]
    fn select_node_with_capacity_skips_node_failing_required_affinity() {
        let node = make_node_with_capacity("worker-0", &[], "110");
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.node_affinity = Some(required_affinity(vec![NodeSelectorTerm {
            match_expressions: vec![requirement("foo", "In", &["bar"])],
            match_fields: vec![],
        }]));
        let counts: std::collections::HashMap<String, NodeUsage> = Default::default();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert!(
            result.is_err(),
            "a node whose labels satisfy no required nodeAffinity term must be \
             skipped — got: {:?}",
            result.ok()
        );
    }

    /// select_node_with_capacity must select a node whose labels satisfy the
    /// pod's required nodeAffinity.
    #[test]
    fn select_node_with_capacity_selects_node_satisfying_required_affinity() {
        let node = make_node_with_capacity("worker-0", &[("foo", "bar")], "110");
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.node_affinity = Some(required_affinity(vec![NodeSelectorTerm {
            match_expressions: vec![requirement("foo", "In", &["bar"])],
            match_fields: vec![],
        }]));
        let counts: std::collections::HashMap<String, NodeUsage> = Default::default();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert_eq!(
            result.unwrap(),
            "worker-0",
            "a node whose labels satisfy the required nodeAffinity term must be selected"
        );
    }

    /// The exact mechanism the DaemonSet controller uses to pin each per-node
    /// pod: a matchFields-only term on metadata.name, with spec.nodeName left
    /// empty for the scheduler to fill in. Before match_fields was modeled on
    /// NodeSelectorTerm, serde silently dropped the field, match_expressions
    /// was always empty, and `.all()` over an empty iterator is vacuously
    /// true — so the pod matched every node and select_node_with_capacity
    /// always returned the first one in list order, landing every DaemonSet
    /// pod on the same node instead of one per node.
    #[test]
    fn select_node_with_capacity_selects_pinned_node_via_match_fields() {
        let node_a = make_node_with_capacity("node-a", &[], "110");
        let node_b = make_node_with_capacity("node-b", &[], "110");
        let list = NodeList {
            items: vec![node_a, node_b],
        };
        let mut pod = empty_pending_pod();
        pod.node_affinity = Some(required_affinity(vec![NodeSelectorTerm {
            match_expressions: vec![],
            match_fields: vec![requirement("metadata.name", "In", &["node-b"])],
        }]));
        let counts: std::collections::HashMap<String, NodeUsage> = Default::default();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert_eq!(
            result.unwrap(),
            "node-b",
            "a matchFields term pinning metadata.name to node-b must select node-b \
             even though it is listed after node-a — selecting node-a here means \
             matchFields was silently dropped and every node vacuously matched"
        );
    }

    /// A term with BOTH matchExpressions and matchFields must require both —
    /// matchFields is ANDed into the same per-term requirement as
    /// matchExpressions, not treated as an independent alternative that could
    /// let a node through on a name match alone (or vice versa).
    #[test]
    fn node_affinity_matches_requires_both_match_expressions_and_match_fields() {
        let labels: std::collections::HashMap<String, String> =
            [("foo".to_owned(), "bar".to_owned())].into();
        let affinity = required_affinity(vec![NodeSelectorTerm {
            match_expressions: vec![requirement("foo", "In", &["bar"])],
            match_fields: vec![requirement("metadata.name", "In", &["node-b"])],
        }]);
        assert!(
            !node_affinity_matches(&labels, "node-a", Some(&affinity)),
            "a node matching the label but not the pinned name must still fail \
             the term — matchExpressions and matchFields are ANDed, not ORed"
        );
        assert!(
            node_affinity_matches(&labels, "node-b", Some(&affinity)),
            "a node matching both the label and the pinned name must satisfy the term"
        );
    }

    // ---------------------------------------------------------------------------
    // NodeResourcesFit / pod-capacity gate
    //
    // Without this check the scheduler binds pods to nodes already at their pod
    // cap; the kubelet then fails them OutOfpods (phase=Failed) instead of leaving
    // the pod Pending where controllers can re-issue it safely.
    // ---------------------------------------------------------------------------

    fn make_node_with_capacity(name: &str, labels: &[(&str, &str)], capacity: &str) -> NodeItem {
        NodeItem {
            metadata: NodeMetadata {
                name: name.to_owned(),
                labels: labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            },
            spec: NodeSpec::default(),
            status: NodeStatus {
                allocatable: NodeAllocatable {
                    pods: capacity.to_owned(),
                    ..Default::default()
                },
                capacity: NodeAllocatable {
                    pods: capacity.to_owned(),
                    ..Default::default()
                },
            },
            csi_driver_headroom: Default::default(),
            csi_registered_drivers: Default::default(),
        }
    }

    /// A NodeUsage with only a pod count set — the shorthand tests that predate
    /// resource-request tracking use to describe "this many pods already on
    /// the node, none of them requesting any resources".
    fn usage_with_pod_count(pod_count: u32) -> NodeUsage {
        NodeUsage {
            pod_count,
            requests: ResourceRequests::default(),
            host_ports: Vec::new(),
            pvc_names: Vec::new(),
            csi_attached_counts: Default::default(),
        }
    }

    /// A minimal PendingPod for tests that only care about capacity/taint/affinity
    /// gating, not identity or priority — empty selector (matches any node), no
    /// tolerations (tolerates nothing but taint-free nodes), no nodeAffinity
    /// (matches any node), no resource requests, no hostPort claims.
    fn empty_pending_pod() -> PendingPod {
        PendingPod {
            namespace: "default".to_owned(),
            pod_name: "pod".to_owned(),
            node_selector: Default::default(),
            priority: 0,
            tolerations: Vec::new(),
            node_affinity: None,
            labels: Default::default(),
            pod_affinity_terms: Vec::new(),
            pod_anti_affinity_terms: Vec::new(),
            requests: ResourceRequests::default(),
            host_ports: Vec::new(),
            pvc_names: Vec::new(),
            pv_node_affinities: Vec::new(),
            topology_spread_constraints: Vec::new(),
            csi_volume_counts: Default::default(),
            read_write_once_pod_pvcs: Vec::new(),
            unbound_csi_pvc_drivers: Vec::new(),
        }
    }

    /// A node at pod capacity must NOT be chosen — otherwise the kubelet fails
    /// the pod with OutOfpods (phase=Failed) and controllers may recreate without
    /// bound.  Reverting `select_node_with_capacity` to ignore counts
    /// would make this test pass when it should fail: the function would return
    /// Ok("worker-0") instead of Err, so a pod would be bound to a full node.
    #[test]
    fn full_node_is_not_selected_so_pod_pends_instead_of_failing() {
        let list = NodeList {
            items: vec![make_node_with_capacity("worker-0", &[], "110")],
        };
        let pod = empty_pending_pod();
        // Node already has 110 pods — at capacity.
        let counts: std::collections::HashMap<String, NodeUsage> =
            [("worker-0".to_owned(), usage_with_pod_count(110))].into();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert!(
            result.is_err(),
            "a node at pod capacity must return Err so the pod stays Pending, \
             not be selected and cause the kubelet to fail it OutOfpods — \
             got: {:?}",
            result.ok()
        );
    }

    /// A node with one free slot must be selected — the common non-full case must
    /// still schedule.  If select_node_with_capacity always returns Err, all
    /// scheduling would stop (false positive), so we test the positive path too.
    #[test]
    fn node_with_free_slot_is_selected() {
        let list = NodeList {
            items: vec![make_node_with_capacity("worker-0", &[], "110")],
        };
        let pod = empty_pending_pod();
        // Node has 109 pods — one slot free.
        let counts: std::collections::HashMap<String, NodeUsage> =
            [("worker-0".to_owned(), usage_with_pod_count(109))].into();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert!(
            result.is_ok(),
            "a node with a free slot must be selected — if this fails, scheduling is \
             incorrectly blocked even when capacity is available"
        );
        assert_eq!(result.unwrap(), "worker-0");
    }

    /// When two nodes match the selector but one is full, the scheduler must pick
    /// the node with free capacity — not the full one and not Err.
    #[test]
    fn full_node_is_skipped_when_second_node_has_room() {
        let list = NodeList {
            items: vec![
                make_node_with_capacity("worker-full", &[], "110"),
                make_node_with_capacity("worker-free", &[], "110"),
            ],
        };
        let pod = empty_pending_pod();
        let counts: std::collections::HashMap<String, NodeUsage> = [
            ("worker-full".to_owned(), usage_with_pod_count(110)),
            ("worker-free".to_owned(), usage_with_pod_count(50)),
        ]
        .into();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert!(
            result.is_ok(),
            "must pick worker-free when worker-full is at capacity"
        );
        assert_eq!(
            result.unwrap(),
            "worker-free",
            "must skip the full node and pick the one with free capacity"
        );
    }

    /// When two nodes both qualify and both have free capacity, the LESS
    /// LOADED one (fewer tallied pods) must be picked, even though it sorts
    /// second in `list` — reverting to the old first-fit `.find()` would pick
    /// "worker-busy" here purely because it happens to come first, exactly
    /// the bug that piled every pod onto one node in a real 2-node cluster.
    #[test]
    fn select_node_with_capacity_prefers_least_loaded_node_among_qualifying_nodes() {
        let list = NodeList {
            items: vec![
                make_node_with_capacity("worker-busy", &[], "110"),
                make_node_with_capacity("worker-idle", &[], "110"),
            ],
        };
        let pod = empty_pending_pod();
        let counts: std::collections::HashMap<String, NodeUsage> = [
            ("worker-busy".to_owned(), usage_with_pod_count(5)),
            ("worker-idle".to_owned(), usage_with_pod_count(1)),
        ]
        .into();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert_eq!(
            result.unwrap(),
            "worker-idle",
            "the node with fewer tallied pods must be preferred over the one \
             listed first — otherwise a busier node keeps accumulating pods \
             just because of list order"
        );
    }

    /// The exact live-reproduced regression this scoring exists to fix: a run
    /// of BestEffort (zero-request) pods — the overwhelming majority of
    /// e2e/conformance workloads — scheduled one at a time via
    /// `select_node_with_capacity` + `NodeTally::assume`, mirroring
    /// `select_and_reserve_node`'s real call pattern. Since every pod here
    /// requests nothing, `resource_fits` is a permanent no-op (0+0 always
    /// fits) for both nodes on every iteration — pod count is the ONLY signal
    /// that can ever break the tie. Before this fix, `.find()` returned
    /// whichever node sorted first in `list` every single time, so all 10
    /// pods landed on "lima-node" and "lima-node-3" carried zero of them —
    /// the exact shape of the live 2-node conformance run where one node ran
    /// the whole test fleet (eventually OOM-killing it) while the other sat
    /// idle with only its mandatory system daemon.
    #[test]
    fn select_node_with_capacity_spreads_besteffort_pods_by_tallied_pod_count() {
        let mut tally = NodeTally::default();

        for i in 0..10 {
            let list = NodeList {
                items: vec![
                    make_node_with_capacity("lima-node", &[], "110"),
                    make_node_with_capacity("lima-node-3", &[], "110"),
                ],
            };
            let pod = empty_pending_pod(); // BestEffort: zero cpu/memory/ephemeral requests
            let usage = tally.usage_by_node();
            let chosen = select_node_with_capacity(list, &pod, &usage, &[])
                .unwrap_or_else(|e| panic!("pod {i} failed to schedule: {e}"));
            tally.assume(
                "default",
                &format!("besteffort-{i}"),
                &chosen,
                0,
                ResourceRequests::default(),
                Vec::new(),
                std::collections::HashMap::new(),
                Vec::new(),
            );
        }

        let usage = tally.usage_by_node();
        assert_eq!(
            usage.get("lima-node").map(|u| u.pod_count).unwrap_or(0),
            5,
            "10 BestEffort pods scheduled one at a time must split 5/5 across \
             two equally-qualifying nodes, not all pile onto the first"
        );
        assert_eq!(
            usage.get("lima-node-3").map(|u| u.pod_count).unwrap_or(0),
            5,
            "lima-node-3 must receive its fair share of BestEffort pods — a \
             count of 0 here reproduces the live incident where the second \
             node never got used at all"
        );
    }

    /// When ALL matching nodes are full, the pod must stay Pending (Err returned)
    /// so that no OutOfpods failure is triggered.
    #[test]
    fn all_nodes_full_returns_err_so_pod_stays_pending() {
        let list = NodeList {
            items: vec![
                make_node_with_capacity("worker-0", &[], "110"),
                make_node_with_capacity("worker-1", &[], "110"),
            ],
        };
        let pod = empty_pending_pod();
        let counts: std::collections::HashMap<String, NodeUsage> = [
            ("worker-0".to_owned(), usage_with_pod_count(110)),
            ("worker-1".to_owned(), usage_with_pod_count(110)),
        ]
        .into();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert!(
            result.is_err(),
            "all nodes full must return Err so the pod stays Pending, not be bound \
             to a full node causing OutOfpods"
        );
    }

    /// A node with unknown capacity (field absent / zero) must still be schedulable.
    /// We do not block on missing data — that would prevent scheduling entirely in
    /// clusters that don't expose allocatable.pods.
    #[test]
    fn node_with_unknown_capacity_is_not_blocked() {
        // capacity "" → parse_pod_capacity returns 0 → treated as "unknown, allow"
        let list = NodeList {
            items: vec![make_node_with_capacity("worker-0", &[], "")],
        };
        let pod = empty_pending_pod();
        let counts: std::collections::HashMap<String, NodeUsage> =
            [("worker-0".to_owned(), usage_with_pod_count(999))].into();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert!(
            result.is_ok(),
            "a node with unknown capacity (empty string) must not be blocked — \
             we don't have enough information to cap it"
        );
    }

    /// parse_pod_capacity handles the standard "110" quantity string.
    #[test]
    fn parse_pod_capacity_handles_standard_quantity() {
        assert_eq!(parse_pod_capacity("110"), 110);
        assert_eq!(parse_pod_capacity("0"), 0);
        assert_eq!(parse_pod_capacity(""), 0);
        assert_eq!(parse_pod_capacity("not-a-number"), 0);
    }

    /// A watch ADDED event for a pod bound (`spec.nodeName` set) to `node`,
    /// at `phase`, requesting `cpu` (a quantity string, or "" for none) —
    /// the shape `NodeTally::apply_event` consumes.
    fn bound_pod_added_event(name: &str, node: &str, phase: &str, cpu: &str) -> Value {
        let requests = if cpu.is_empty() {
            json!({})
        } else {
            json!({ "cpu": cpu })
        };
        json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": name, "namespace": "default" },
                "spec": {
                    "nodeName": node,
                    "containers": [{ "resources": { "requests": requests } }]
                },
                "status": { "phase": phase }
            }
        })
    }

    /// NodeTally counts pods correctly, excluding Succeeded and Failed.
    ///
    /// This is the NodeResourcesFit predicate: running/pending pods consume a slot;
    /// completed pods do not.  Reverting to count all pods would over-count and
    /// block scheduling when completed pods have not yet been GC'd.
    #[test]
    fn node_tally_excludes_terminal_phases_from_pod_count() {
        let mut tally = NodeTally::default();
        tally.apply_event(&bound_pod_added_event("a", "worker-0", "Running", ""));
        tally.apply_event(&bound_pod_added_event("b", "worker-0", "Pending", ""));
        tally.apply_event(&bound_pod_added_event("c", "worker-0", "Succeeded", ""));
        tally.apply_event(&bound_pod_added_event("d", "worker-0", "Failed", ""));
        tally.apply_event(&bound_pod_added_event("e", "worker-0", "", "")); // missing phase → not terminal → counts

        let usage = tally.usage_by_node();
        assert_eq!(
            usage["worker-0"].pod_count, 3,
            "Running + Pending + unknown-phase count as consuming a slot; \
             Succeeded and Failed do not (NodeResourcesFit predicate)"
        );
    }

    /// NodeTally also excludes terminal-phase pods' resource requests from the
    /// sum — a completed pod that requested 4 CPUs must not still count
    /// against the node's allocatable cpu, or a saturated-but-idle node would
    /// wrongly reject new pods forever.
    #[test]
    fn node_tally_excludes_terminal_phases_from_resource_sum() {
        let mut tally = NodeTally::default();
        tally.apply_event(&bound_pod_added_event(
            "running", "worker-0", "Running", "1",
        ));
        tally.apply_event(&bound_pod_added_event("done", "worker-0", "Succeeded", "4"));

        let usage = tally.usage_by_node();
        assert_eq!(
            usage["worker-0"].requests.cpu_milli, 1000,
            "a Succeeded pod's cpu request must not count against the node's usage"
        );
    }

    /// NodeTally sums cpu requests across all non-terminated pods on the same
    /// node — the exact input pick_node needs to decide whether a pending
    /// pod's own requests still fit.
    #[test]
    fn node_tally_sums_resource_requests_across_pods_on_the_same_node() {
        let mut tally = NodeTally::default();
        tally.apply_event(&bound_pod_added_event("a", "worker-0", "Running", "500m"));
        tally.apply_event(&bound_pod_added_event("b", "worker-0", "Pending", "500m"));

        let usage = tally.usage_by_node();
        assert_eq!(usage["worker-0"].pod_count, 2);
        assert_eq!(
            usage["worker-0"].requests.cpu_milli, 1000,
            "two 500m-cpu pods on the same node must sum to 1000 milli-cpu"
        );
    }

    /// The exact regression this tally exists to fix: a live
    /// per-node GET fan-out could read a just-committed bind's resource
    /// request as stale, undercounting the node's usage and letting the
    /// scheduler bind a second pod onto a node that was already full — the
    /// kubelet then rejected it with OutOfcpu. `assume` (called immediately
    /// after a bind decision, before the bind's HTTP call even completes)
    /// must make that bind visible to the very next capacity check, with no
    /// window where it can be read as stale.
    #[test]
    fn node_tally_assume_reflects_just_bound_pod_before_next_scheduling_decision() {
        let mut tally = NodeTally::default();
        // Mirrors pick_node: the tally is updated the instant a pod's node is
        // decided, not after its HTTP bind call returns.
        tally.assume(
            "default",
            "filler",
            "worker-0",
            0,
            requests(5600, 0, 0),
            Vec::new(),
            std::collections::HashMap::new(),
            Vec::new(),
        );

        let mut node = make_node_with_capacity("worker-0", &[], "110");
        node.status.allocatable.cpu = "8".to_owned(); // 8000m allocatable
        let list = NodeList { items: vec![node] };

        let mut pod = empty_pending_pod();
        pod.requests.cpu_milli = 4000; // 5600 (tallied) + 4000 > 8000 allocatable

        let usage = tally.usage_by_node();
        let result = select_node_with_capacity(list, &pod, &usage, &[]);

        assert!(
            result.is_err(),
            "a node whose tally already reflects a just-bound 5600m-cpu pod must \
             reject a second 4000m pod on an 8000m-cpu node — reading stale (zero) \
             usage here is exactly the bug that let the scheduler bind onto an \
             already-full node, which the kubelet then OutOfcpu-rejected; got: {:?}",
            result.ok()
        );
    }

    /// The exact race reproduced live against the PreemptionExecutionPath
    /// SchedulerPreemption conformance scenario: a preemption's post-eviction
    /// re-check and a concurrently-scheduled pod (there, a ReplicaSet
    /// controller's replacement for the pod preemption just evicted) run in
    /// different tokio tasks, potentially on different OS threads, and both
    /// end up calling `select_and_reserve_node` for the same just-freed slot.
    ///
    /// Before `pick_node` committed the reservation itself, the fit check
    /// (`pick_node`) and the reservation (`NodeTally::assume`, called
    /// separately by the caller after `pick_node` returned) were two
    /// independent lock acquisitions. Two callers could each acquire the
    /// tally lock for the check, both see the slot as free, and both then
    /// separately commit — the kubelet then rejects whichever container it
    /// admits second, since the node never actually had room for both. This
    /// test spawns real OS threads racing for a slot that fits exactly one of
    /// them; reverting to two separate lock acquisitions reopens the window
    /// for more than one thread to see the slot as free before any of them
    /// reserves it.
    #[test]
    fn select_and_reserve_node_never_double_books_a_single_free_slot() {
        let tally = std::sync::Arc::new(std::sync::Mutex::new(NodeTally::default()));
        const CONTENDERS: usize = 8;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(CONTENDERS));

        let handles: Vec<_> = (0..CONTENDERS)
            .map(|i| {
                let tally = std::sync::Arc::clone(&tally);
                let barrier = std::sync::Arc::clone(&barrier);
                // Room for exactly one 1000m-cpu pod on this node, not two —
                // built fresh per thread rather than shared, since NodeList
                // is not Clone.
                let mut node = make_node_with_capacity("worker-0", &[], "110");
                node.status.allocatable.cpu = "1".to_owned();
                let list = NodeList { items: vec![node] };
                let mut pod = empty_pending_pod();
                pod.pod_name = format!("pod-{i}");
                pod.requests.cpu_milli = 1000;
                std::thread::spawn(move || {
                    // Line every thread up so as many as possible call
                    // select_and_reserve_node at the same instant — this is
                    // what makes a split check/reserve likely to be caught,
                    // not just theoretically possible.
                    barrier.wait();
                    select_and_reserve_node(list, &pod, &tally)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            ok_count, 1,
            "exactly one of {CONTENDERS} pods racing for a single 1000m-cpu \
             slot must win — splitting the fit check and the reservation \
             across two lock acquisitions lets more than one thread see the \
             slot as free and bind, which the kubelet then rejects; got \
             {ok_count} winners: {results:?}"
        );

        let usage = tally.lock().expect("tally lock poisoned").usage_by_node();
        assert_eq!(
            usage["worker-0"].requests.cpu_milli, 1000,
            "the tally must reflect exactly one reservation after the race \
             settles, not zero (a lost update) or more than one (double-booked)"
        );
    }

    /// The exact race reproduced live against the PreemptionExecutionPath
    /// SchedulerPreemption conformance scenario, one level up from
    /// `select_and_reserve_node_never_double_books_a_single_free_slot`:
    /// several pending pods each independently plan to preempt the SAME two
    /// victims on the SAME node (plausible when several pods are ready to
    /// preempt around the same time — e.g. a controller recreating several
    /// replacement pods at once). Before `find_preemption_plan` reserved the
    /// pending pod itself, the caller evicted the victims and only THEN
    /// re-checked fit — leaving a window where more than one such pod could
    /// see the node as free before any of them committed. Reserving under
    /// the SAME lock acquisition that re-reads current tally state (not the
    /// stale pre-eviction snapshot) means only the first caller to reach
    /// this function can ever win the shared capacity; every other caller's
    /// fresh read already includes the winner's reservation.
    #[test]
    fn verify_and_reserve_preemption_never_double_books_shared_victims() {
        let tally = std::sync::Arc::new(std::sync::Mutex::new(NodeTally::default()));
        {
            let mut guard = tally.lock().expect("tally lock poisoned");
            guard.assume(
                "default",
                "victim-a",
                "worker-0",
                0,
                requests(1000, 0, 0),
                Vec::new(),
                std::collections::HashMap::new(),
                Vec::new(),
            );
            guard.assume(
                "default",
                "victim-b",
                "worker-0",
                0,
                requests(1000, 0, 0),
                Vec::new(),
                std::collections::HashMap::new(),
                Vec::new(),
            );
        }

        const CONTENDERS: usize = 8;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(CONTENDERS));
        let handles: Vec<_> = (0..CONTENDERS)
            .map(|i| {
                let tally = std::sync::Arc::clone(&tally);
                let barrier = std::sync::Arc::clone(&barrier);
                // Capacity for exactly one 2000m-cpu pod once BOTH 1000m
                // victims are gone — never for a victim's slot plus a new
                // pod on top, so at most one contender can ever fit.
                let mut node = make_node_with_capacity("worker-0", &[], "110");
                node.status.allocatable.cpu = "2".to_owned();
                let mut pod = empty_pending_pod();
                pod.pod_name = format!("preemptor-{i}");
                pod.requests.cpu_milli = 2000;
                let plan = PreemptionPlan {
                    node_name: "worker-0".to_owned(),
                    victims: vec!["default/victim-a".to_owned(), "default/victim-b".to_owned()],
                };
                std::thread::spawn(move || {
                    // Line every contender up so as many as possible call
                    // verify_and_reserve_preemption at the same instant.
                    barrier.wait();
                    verify_and_reserve_preemption(&pod, &node, &plan, &tally)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            ok_count, 1,
            "exactly one of {CONTENDERS} pods independently planning to \
             preempt the same two victims must win — checking fit and \
             reserving in two separate lock acquisitions lets more than one \
             thread see the (not-yet-evicted) victims' capacity as enough \
             and reserve, which strands the loser's evicted victims for \
             nothing or double-books the node; got {ok_count} winners: \
             {results:?}"
        );
    }

    /// Live-reproduced against a 3-filler/3-preemptor extended-resource
    /// scenario once the nominatedNodeName PATCH lengthened the
    /// window before eviction: unlike
    /// `verify_and_reserve_preemption_never_double_books_shared_victims`
    /// (which hands every contender the SAME pre-computed victim list), each
    /// of these threads independently SEARCHES for its own victim via
    /// `select_preemption_victims`, exactly like `find_preemption_plan`
    /// does, retrying up to `ATTEMPTS` times exactly like
    /// `preempt_and_pick_node` — a single search-then-verify attempt can
    /// still lose a race (the search itself takes no lock), so a retry is
    /// always expected; what must never happen, with or without a retry, is
    /// two DIFFERENT winning plans landing on the same victim. Before
    /// `NodeTally::pods_on` excluded already-claimed victims, equal-priority
    /// tie-breaking made every concurrent search converge on the same
    /// cheapest filler even across retries, so N concurrent preemptors only
    /// ever freed ONE filler's worth of capacity between them.
    #[test]
    fn concurrent_equal_priority_preemption_selects_disjoint_victims() {
        const N: usize = 3;
        const ATTEMPTS: u32 = 5;
        let tally = std::sync::Arc::new(std::sync::Mutex::new(NodeTally::default()));
        {
            let mut guard = tally.lock().expect("tally lock poisoned");
            for i in 0..N {
                guard.assume(
                    "default",
                    &format!("filler-{i}"),
                    "worker-0",
                    100,
                    requests(1000, 0, 0),
                    Vec::new(),
                    std::collections::HashMap::new(),
                    Vec::new(),
                );
            }
        }

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let tally = std::sync::Arc::clone(&tally);
                let barrier = std::sync::Arc::clone(&barrier);
                // Exactly saturated by the N 1000m-cpu fillers — evicting
                // any one of them frees just enough room for one 1000m
                // preemptor, never two, so at most N total can ever fit.
                let mut node = make_node_with_capacity("worker-0", &[], "110");
                node.status.allocatable.cpu = N.to_string();
                let mut pod = empty_pending_pod();
                pod.pod_name = format!("preemptor-{i}");
                pod.priority = 1000;
                pod.requests = requests(1000, 0, 0);
                std::thread::spawn(move || {
                    // Line every contender up so as many as possible search
                    // for a victim at the same instant.
                    barrier.wait();
                    for _ in 0..ATTEMPTS {
                        let node_pods = tally
                            .lock()
                            .expect("tally lock poisoned")
                            .pods_on("worker-0");
                        let victims = select_preemption_victims(
                            pod.priority,
                            &pod.requests,
                            &node_pods,
                            110,
                            &node.status.allocatable,
                        );
                        if victims.is_empty() {
                            continue;
                        }
                        let plan = PreemptionPlan {
                            node_name: "worker-0".to_owned(),
                            victims,
                        };
                        if verify_and_reserve_preemption(&pod, &node, &plan, &tally).is_ok() {
                            return Some(plan.victims);
                        }
                    }
                    None
                })
            })
            .collect();

        let results: Vec<Option<Vec<String>>> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_some()).count();
        let raw_victims: Vec<String> = results.iter().flatten().flatten().cloned().collect();
        let mut deduped_victims = raw_victims.clone();
        deduped_victims.sort();
        deduped_victims.dedup();
        assert_eq!(
            ok_count, N,
            "all {N} equal-priority preemptors must win a distinct victim in \
             this exactly-balanced scenario — got {ok_count}"
        );
        // The bug's real signature (matches the live log evidence exactly:
        // "preempting 1 pod(s)... preempting 2 pod(s)... preempting 3
        // pod(s)"): each concurrent plan's victim list is a superset of the
        // previous, so summing every plan's victim COUNT (not just
        // deduplicating the union) is what actually distinguishes N disjoint
        // singleton victims (sum == N) from N nested/overlapping plans that
        // still happen to cover every filler between them (sum > N, e.g. 6
        // for N=3's 1+2+3 pattern) — a union-only check would miss the
        // latter case entirely.
        assert_eq!(
            raw_victims.len(),
            N,
            "if this regresses, concurrent plans re-target victims another \
             plan already claimed instead of picking disjoint ones — total \
             victim mentions across all {N} winning plans should be exactly \
             {N} (one each), got {} across {:?}",
            raw_victims.len(),
            results
        );
        assert_eq!(
            deduped_victims.len(),
            N,
            "if this regresses, {N} concurrent preemptors all target the same \
             victim, freeing 1 unit of resource instead of {N}, forcing \
             kubelet OutOfResource on the {} preemptors that don't fit; \
             distinct victims actually evicted: {deduped_victims:?}",
            N - 1
        );
    }

    /// The other half of the fix `concurrent_equal_priority_preemption_selects_disjoint_victims`
    /// exercises under real thread races: a victim already claimed by a
    /// reserved-but-not-yet-evicted plan must not be offered to a second,
    /// later plan even outside of a race — deterministic, so a regression
    /// here always fails, not just probabilistically under thread timing.
    #[test]
    fn victim_claimed_by_pending_plan_is_not_selectable_by_a_later_plan() {
        let tally = std::sync::Arc::new(std::sync::Mutex::new(NodeTally::default()));
        {
            let mut guard = tally.lock().expect("tally lock poisoned");
            guard.assume(
                "default",
                "filler-a",
                "worker-0",
                100,
                requests(1000, 0, 0),
                Vec::new(),
                std::collections::HashMap::new(),
                Vec::new(),
            );
            guard.assume(
                "default",
                "filler-b",
                "worker-0",
                100,
                requests(1000, 0, 0),
                Vec::new(),
                std::collections::HashMap::new(),
                Vec::new(),
            );
        }
        // Saturated by the two fillers — the first plan needs to evict
        // exactly one of them to fit.
        let mut node = make_node_with_capacity("worker-0", &[], "110");
        node.status.allocatable.cpu = "2".to_owned();

        let mut pod1 = empty_pending_pod();
        pod1.pod_name = "preemptor-1".to_owned();
        pod1.priority = 1000;
        pod1.requests = requests(1000, 0, 0);
        let plan1 = PreemptionPlan {
            node_name: "worker-0".to_owned(),
            // Named explicitly (not searched) so this test does not depend
            // on NodeTally's HashMap iteration order to pick filler-a.
            victims: vec!["default/filler-a".to_owned()],
        };
        verify_and_reserve_preemption(&pod1, &node, &plan1, &tally)
            .expect("evicting filler-a frees exactly enough room for preemptor-1");

        // A second, later plan for a different pending pod searches while
        // filler-a is still reserved (not yet actually evicted).
        let node_pods = tally
            .lock()
            .expect("tally lock poisoned")
            .pods_on("worker-0");
        let victims2 = select_preemption_victims(
            1000,
            &requests(1000, 0, 0),
            &node_pods,
            110,
            &node.status.allocatable,
        );

        assert_eq!(
            victims2,
            vec!["default/filler-b".to_owned()],
            "filler-a is already claimed by preemptor-1's reserved-but-not-\
             yet-evicted plan, so the second plan must fall through to the \
             only other eligible candidate (filler-b), never re-select \
             filler-a — got {victims2:?}"
        );
    }

    /// `sequential_preemption_still_reuses_freed_victim_slots`: once a
    /// claimed victim is actually evicted and its claim released, a pod
    /// later recreated under that EXACT SAME "namespace/name" key (e.g. a
    /// controller re-creating a fixed-name pod, which several conformance
    /// fixtures do) must be selectable again — the only way a leaked claim
    /// entry (never released after a completed eviction) would ever become
    /// observable, since `pods_on` already excludes anything no longer in
    /// the tally regardless of claim state.
    #[test]
    fn sequential_preemption_still_reuses_freed_victim_slots() {
        let tally = std::sync::Arc::new(std::sync::Mutex::new(NodeTally::default()));
        tally.lock().expect("tally lock poisoned").assume(
            "default",
            "filler-a",
            "worker-0",
            100,
            requests(1000, 0, 0),
            Vec::new(),
            std::collections::HashMap::new(),
            Vec::new(),
        );

        let mut node = make_node_with_capacity("worker-0", &[], "110");
        node.status.allocatable.cpu = "1".to_owned();
        let mut pod1 = empty_pending_pod();
        pod1.pod_name = "preemptor-1".to_owned();
        pod1.priority = 1000;
        pod1.requests = requests(1000, 0, 0);
        let plan1 = PreemptionPlan {
            node_name: "worker-0".to_owned(),
            victims: vec!["default/filler-a".to_owned()],
        };
        verify_and_reserve_preemption(&pod1, &node, &plan1, &tally)
            .expect("evicting filler-a frees exactly enough room for preemptor-1");

        // Mirrors main.rs's evict_victims + preempt_and_pick_node: the
        // victim is actually deleted (removed from the tally), then its
        // claim is released once the eviction sequence finishes.
        {
            let mut guard = tally.lock().expect("tally lock poisoned");
            guard.remove("default", "filler-a");
            guard.release_victims(&plan1.victims);
        }

        // A controller recreates a pod under the exact same key.
        tally.lock().expect("tally lock poisoned").assume(
            "default",
            "filler-a",
            "worker-0",
            100,
            requests(1000, 0, 0),
            Vec::new(),
            std::collections::HashMap::new(),
            Vec::new(),
        );

        // Now saturated by preemptor-1 + the recreated filler-a; a second
        // preemptor needs to evict the recreated filler-a to fit.
        node.status.allocatable.cpu = "2".to_owned();
        let node_pods = tally
            .lock()
            .expect("tally lock poisoned")
            .pods_on("worker-0");
        let victims2 = select_preemption_victims(
            1000,
            &requests(1000, 0, 0),
            &node_pods,
            110,
            &node.status.allocatable,
        );

        assert_eq!(
            victims2,
            vec!["default/filler-a".to_owned()],
            "a leaked claim on 'default/filler-a' (never released after its \
             first eviction completed) would make this key permanently \
             invisible to pods_on, hiding the recreated pod's real resource \
             usage and making the node look like it already has spare \
             capacity it does not have — got {victims2:?}"
        );
    }

    // -------------------------------------------------------------------
    // find_preemption_candidate + TopologySpreadContext: the
    // Filter-phase fix taught select_node_with_capacity to
    // reject a node that would violate a pod's topologySpreadConstraints,
    // but find_preemption_plan's separate candidate search kept using only
    // node_qualifies_for_pod + InterPodAffinityContext — so a topology-
    // constrained pod could still trigger preemption onto a node its own
    // maxSkew forbids, exactly the placement direct scheduling now refuses.
    //
    // A follow-on fix then taught that same candidate search to discount a
    // node's own selected preemption victims before judging its topology/
    // affinity qualification (mirrors upstream's `selectVictimsOnNode`
    // calling `RemovePod` on each plugin's cycle state per victim) — a node
    // whose ONLY spread violation is a pod about to be evicted from it is a
    // valid target, not a false rejection.
    // -------------------------------------------------------------------

    /// `find_preemption_candidate` must target a candidate node whose only
    /// hard `topologySpreadConstraints` violation would be resolved by
    /// evicting that SAME node's own preemption victim — zone-a's only
    /// matching sibling is precisely the low-priority pod preemption would
    /// evict there, so post-eviction skew is 1 <= maxSkew 1, not the
    /// pre-eviction 2 > 1 a naive current-state check would see. Zone-b
    /// needs preemption too (so this is a genuine choice between two
    /// preemptable candidates, not a case where zone-b would already win via
    /// direct scheduling) but carries none of the pod's matching siblings,
    /// so if the fix were absent zone-b would incorrectly look like the only
    /// legal choice. Before that fix, `TopologySpreadContext`
    /// judged every candidate against the CURRENT tally — never discounting
    /// a node's own about-to-be-evicted occupant — so this exact node-a was
    /// rejected outright even though evicting its own victim makes it fully
    /// compliant, forcing preemption onto zone-b (a real disruption) when
    /// zone-a was the correct, spread-compliant target all along.
    #[test]
    fn find_preemption_candidate_targets_zone_whose_own_victim_resolves_the_spread_violation() {
        let list = NodeList {
            items: vec![
                make_node_with_capacity(
                    "node-a",
                    &[("topology.kubernetes.io/zone", "zone-a")],
                    "1",
                ),
                make_node_with_capacity(
                    "node-b",
                    &[("topology.kubernetes.io/zone", "zone-b")],
                    "1",
                ),
            ],
        };
        let node_labels_by_name: std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        > = list
            .items
            .iter()
            .map(|n| (n.metadata.name.clone(), n.metadata.labels.clone()))
            .collect();

        let tally = std::sync::Mutex::new(NodeTally::default());
        {
            let mut guard = tally.lock().expect("tally lock poisoned");
            // zone-a's only slot is occupied by a low-priority pod matching
            // the pending pod's own spread selector — it is also the ONLY
            // pod that would be preempted there, so evicting it fully
            // resolves the skew this constraint would otherwise flag.
            guard.assume(
                "default",
                "web-a",
                "node-a",
                0,
                ResourceRequests::default(),
                Vec::new(),
                [("app".to_owned(), "web".to_owned())].into(),
                Vec::new(),
            );
            // zone-b's only slot is occupied by an unrelated low-priority
            // filler, so zone-b ALSO needs preemption — this pod cannot
            // simply pick zone-b directly via select_node_with_capacity
            // without reaching this search at all.
            guard.assume(
                "default",
                "filler-b",
                "node-b",
                0,
                ResourceRequests::default(),
                Vec::new(),
                [("app".to_owned(), "other".to_owned())].into(),
                Vec::new(),
            );
        }
        let tallied_pods = tally
            .lock()
            .expect("tally lock poisoned")
            .tallied_pod_labels();

        let mut pod = empty_pending_pod();
        pod.priority = 100;
        pod.labels = [("app".to_owned(), "web".to_owned())].into();
        pod.topology_spread_constraints = vec![topology_spread_constraint(
            "topology.kubernetes.io/zone",
            1,
            "DoNotSchedule",
            &[("app", "web")],
        )];

        let best =
            find_preemption_candidate(&list, &pod, &tallied_pods, &node_labels_by_name, &tally);
        assert_eq!(
            best.map(|(_, plan)| plan.node_name),
            Some("node-a".to_owned()),
            "zone-a's only matching sibling is exactly the pod its own \
             preemption plan would evict — post-eviction skew is 1 <= \
             maxSkew 1, so zone-a must win, not be rejected as if that \
             sibling would keep occupying its domain forever"
        );
    }

    /// The fix above must not become a blanket "ignore this node's zone"
    /// pass: discounting must ONLY ever remove a candidate's own selected
    /// victims, never a matching sibling parked on a DIFFERENT node that
    /// merely shares the same zone. zone-a here spans two nodes: node-a1
    /// hosts the pending pod's own low-priority victim (would be evicted),
    /// but node-a2 hosts a SEPARATE, higher-priority sibling that is never a
    /// candidate for eviction and so must keep counting against zone-a's
    /// skew. Evicting node-a1's own victim alone therefore does NOT resolve
    /// the violation (zone-a still carries one real matching sibling via
    /// node-a2) — node-a1 must still be rejected, and preemption must fall
    /// through to zone-b. If discounting ever subtracted more than a
    /// candidate's OWN victims — e.g. by naively re-deriving `min_match_num`
    /// from a zeroed-out zone-a instead of only node-a1's own contribution —
    /// this would wrongly let node-a1 win, piling a second replica onto a
    /// zone that already holds one via node-a2.
    #[test]
    fn find_preemption_candidate_still_rejects_zone_whose_violation_survives_its_own_eviction() {
        let list = NodeList {
            items: vec![
                make_node_with_capacity(
                    "node-a1",
                    &[("topology.kubernetes.io/zone", "zone-a")],
                    "1",
                ),
                make_node_with_capacity(
                    "node-a2",
                    &[("topology.kubernetes.io/zone", "zone-a")],
                    "1",
                ),
                make_node_with_capacity(
                    "node-b",
                    &[("topology.kubernetes.io/zone", "zone-b")],
                    "1",
                ),
            ],
        };
        let node_labels_by_name: std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        > = list
            .items
            .iter()
            .map(|n| (n.metadata.name.clone(), n.metadata.labels.clone()))
            .collect();

        let tally = std::sync::Mutex::new(NodeTally::default());
        {
            let mut guard = tally.lock().expect("tally lock poisoned");
            // node-a1's only occupant is a low-priority matching sibling —
            // this IS the pod preemption would evict there.
            guard.assume(
                "default",
                "web-a1",
                "node-a1",
                0,
                ResourceRequests::default(),
                Vec::new(),
                [("app".to_owned(), "web".to_owned())].into(),
                Vec::new(),
            );
            // node-a2's occupant is ALSO a matching sibling, but too
            // high-priority to ever be selected as a victim — it must
            // still count against zone-a's skew no matter what happens on
            // node-a1.
            guard.assume(
                "default",
                "web-a2",
                "node-a2",
                1000,
                ResourceRequests::default(),
                Vec::new(),
                [("app".to_owned(), "web".to_owned())].into(),
                Vec::new(),
            );
            // zone-b's only slot is an unrelated low-priority filler, so
            // zone-b needs preemption too but carries no matching sibling.
            guard.assume(
                "default",
                "filler-b",
                "node-b",
                0,
                ResourceRequests::default(),
                Vec::new(),
                [("app".to_owned(), "other".to_owned())].into(),
                Vec::new(),
            );
        }
        let tallied_pods = tally
            .lock()
            .expect("tally lock poisoned")
            .tallied_pod_labels();

        let mut pod = empty_pending_pod();
        pod.priority = 100;
        pod.labels = [("app".to_owned(), "web".to_owned())].into();
        pod.topology_spread_constraints = vec![topology_spread_constraint(
            "topology.kubernetes.io/zone",
            1,
            "DoNotSchedule",
            &[("app", "web")],
        )];

        let best =
            find_preemption_candidate(&list, &pod, &tallied_pods, &node_labels_by_name, &tally);
        assert_eq!(
            best.map(|(_, plan)| plan.node_name),
            Some("node-b".to_owned()),
            "node-a2's higher-priority matching sibling is untouched by \
             node-a1's own eviction, so zone-a still carries a real match — \
             node-a1 must stay rejected and preemption must fall through to \
             zone-b, proving the victim discount never reaches beyond a \
             candidate's OWN selected victims"
        );
    }

    /// The negative control for the fix above: a pod with NO
    /// `topologySpreadConstraints` must see `find_preemption_candidate`
    /// behave exactly as before the fix — the empty `TopologySpreadContext`
    /// built from an empty constraint list must impose no restriction at
    /// all, so the normal list-order tie-break (both candidates need exactly
    /// one eviction) still picks node-a. If building a `TopologySpreadContext`
    /// ever started synthesizing a restriction for a pod that asked for none,
    /// this would wrongly reject node-a and over-filter preemption targets
    /// that have nothing to do with topology spreading.
    #[test]
    fn find_preemption_candidate_unaffected_by_topology_when_pod_has_no_spread_constraints() {
        let list = NodeList {
            items: vec![
                make_node_with_capacity(
                    "node-a",
                    &[("topology.kubernetes.io/zone", "zone-a")],
                    "1",
                ),
                make_node_with_capacity(
                    "node-b",
                    &[("topology.kubernetes.io/zone", "zone-b")],
                    "1",
                ),
            ],
        };
        let node_labels_by_name: std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        > = list
            .items
            .iter()
            .map(|n| (n.metadata.name.clone(), n.metadata.labels.clone()))
            .collect();

        let tally = std::sync::Mutex::new(NodeTally::default());
        {
            let mut guard = tally.lock().expect("tally lock poisoned");
            guard.assume(
                "default",
                "web-a",
                "node-a",
                0,
                ResourceRequests::default(),
                Vec::new(),
                [("app".to_owned(), "web".to_owned())].into(),
                Vec::new(),
            );
            guard.assume(
                "default",
                "filler-b",
                "node-b",
                0,
                ResourceRequests::default(),
                Vec::new(),
                [("app".to_owned(), "other".to_owned())].into(),
                Vec::new(),
            );
        }
        let tallied_pods = tally
            .lock()
            .expect("tally lock poisoned")
            .tallied_pod_labels();

        let mut pod = empty_pending_pod();
        pod.priority = 100;
        pod.labels = [("app".to_owned(), "web".to_owned())].into();
        // No topology_spread_constraints set at all.

        let best =
            find_preemption_candidate(&list, &pod, &tallied_pods, &node_labels_by_name, &tally);
        assert_eq!(
            best.map(|(_, plan)| plan.node_name),
            Some("node-a".to_owned()),
            "a pod with no topologySpreadConstraints must be unaffected by \
             TopologySpreadContext — both candidates need exactly one \
             eviction, so the ordinary list-order tie-break must still pick \
             node-a"
        );
    }

    /// `remove` must actually free the capacity it removes — used both to
    /// roll back a failed bind's `assume` and to account for a preemption
    /// eviction. If a removal were silently dropped, the tally would
    /// permanently overcount that node and leave pods Pending that could
    /// legitimately fit.
    #[test]
    fn node_tally_remove_frees_capacity_for_the_next_decision() {
        let mut tally = NodeTally::default();
        tally.assume(
            "default",
            "filler",
            "worker-0",
            0,
            requests(8000, 0, 0),
            Vec::new(),
            std::collections::HashMap::new(),
            Vec::new(),
        );
        tally.remove("default", "filler");

        let mut node = make_node_with_capacity("worker-0", &[], "110");
        node.status.allocatable.cpu = "8".to_owned();
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.requests.cpu_milli = 4000;

        let usage = tally.usage_by_node();
        let result = select_node_with_capacity(list, &pod, &usage, &[]);
        assert!(
            result.is_ok(),
            "removing the filler pod's reservation must free its 8000m cpu — \
             a leaked reservation would leave this node wrongly looking full forever"
        );
    }

    /// Every key tallied under a node in `by_node` must resolve in `pods` to
    /// that SAME node, and vice versa — used by
    /// `node_tally_by_node_index_never_diverges_from_the_pods_map` after
    /// every mutation, since a divergence here does not panic anywhere else:
    /// it silently mis-counts one node's capacity instead.
    fn assert_by_node_index_matches_pods(tally: &NodeTally) {
        for (key, pod) in &tally.pods {
            assert!(
                tally
                    .by_node
                    .get(&pod.node_name)
                    .is_some_and(|set| set.contains(key)),
                "pods[{key}] is tallied on node {} but by_node has no matching \
                 entry — pods_on/csi_attached_counts would silently miss this \
                 pod and undercount that node's real occupancy",
                pod.node_name
            );
        }
        for (node_name, keys) in &tally.by_node {
            for key in keys {
                assert!(
                    tally
                        .pods
                        .get(key)
                        .is_some_and(|p| &p.node_name == node_name),
                    "by_node[{node_name}] lists {key} but pods disagrees — \
                     pods_on/csi_attached_counts would return a phantom pod \
                     that isn't really occupying a slot on that node any more"
                );
            }
        }
    }

    /// The `by_node` secondary index (added so `pods_on`/`csi_attached_counts`
    /// need not scan every tallied pod cluster-wide) must never disagree with
    /// the primary `pods` map, across every mutation path: `apply_event`'s
    /// ADDED/MODIFIED/DELETED/terminal-phase branches, `assume`, `remove`,
    /// and `clear`. A stale index here does not fail loudly — it silently
    /// mis-counts a node's capacity (a phantom `by_node` entry offers up a
    /// pod that `usage_by_node` no longer counts; a missing one hides a pod
    /// `usage_by_node` still does), which is exactly the shape of bug that
    /// lets the scheduler bind a pod onto a node with no real room left, or
    /// wrongly reject one that would actually fit.
    #[test]
    fn node_tally_by_node_index_never_diverges_from_the_pods_map() {
        let mut tally = NodeTally::default();

        tally.apply_event(&bound_pod_added_event("a", "worker-0", "Running", "1"));
        assert_by_node_index_matches_pods(&tally);

        tally.apply_event(&bound_pod_added_event("b", "worker-1", "Running", "1"));
        assert_by_node_index_matches_pods(&tally);

        tally.assume(
            "default",
            "c",
            "worker-0",
            0,
            requests(500, 0, 0),
            Vec::new(),
            std::collections::HashMap::new(),
            Vec::new(),
        );
        assert_by_node_index_matches_pods(&tally);

        // MODIFIED overwrite of an existing entry on the SAME node.
        tally.apply_event(&bound_pod_added_event("a", "worker-0", "Pending", "1"));
        assert_by_node_index_matches_pods(&tally);

        // A real Pod's spec.nodeName never changes once bound, but the index
        // must not corrupt itself even if it ever did — same key, new node.
        tally.apply_event(&bound_pod_added_event("a", "worker-2", "Running", "1"));
        assert_by_node_index_matches_pods(&tally);
        assert!(
            tally
                .pods_on("worker-0")
                .iter()
                .all(|p| p.key != "default/a"),
            "a's index entry must move with it — leaving its key behind under \
             the OLD node would make pods_on(\"worker-0\") offer up a phantom \
             preemption victim that isn't actually there any more"
        );

        // remove() rollback of an assume.
        tally.remove("default", "c");
        assert_by_node_index_matches_pods(&tally);

        // DELETED watch event.
        tally.apply_event(&json!({
            "type": "DELETED",
            "object": { "metadata": { "name": "b", "namespace": "default" } }
        }));
        assert_by_node_index_matches_pods(&tally);

        // Terminal-phase MODIFIED event frees the slot the same way DELETED does.
        tally.apply_event(&bound_pod_added_event("a", "worker-2", "Succeeded", "1"));
        assert_by_node_index_matches_pods(&tally);

        // clear() must wipe both maps together, or a stale by_node entry
        // would outlive a watch reconnect and the pod it once pointed at.
        tally.assume(
            "default",
            "d",
            "worker-3",
            0,
            requests(500, 0, 0),
            Vec::new(),
            std::collections::HashMap::new(),
            Vec::new(),
        );
        let _ = tally.clear();
        assert_by_node_index_matches_pods(&tally);
        assert!(
            tally.pods_on("worker-3").is_empty(),
            "clear() must drop by_node along with pods — otherwise a node's \
             index entry outlives every pod it once tracked"
        );
    }

    /// `assert_by_node_index_matches_pods` only checks that every key
    /// PRESENT in `by_node` agrees with `pods` — it says nothing about an
    /// emptied-but-not-removed outer entry, since an empty `HashSet` has no
    /// keys to disagree about. This test catches that leak directly: without
    /// pruning, `by_node` retains one empty entry per distinct node name ever
    /// observed for the life of the process, growing unbounded across node
    /// churn (e.g. an autoscaler cycling through thousands of differently
    /// named nodes over the scheduler's lifetime).
    #[test]
    fn node_tally_remove_prunes_emptied_by_node_entry() {
        let mut tally = NodeTally::default();

        tally.assume(
            "default",
            "e",
            "worker-9",
            0,
            requests(500, 0, 0),
            Vec::new(),
            std::collections::HashMap::new(),
            Vec::new(),
        );
        assert_eq!(
            tally.by_node.len(),
            1,
            "sanity check: assume must have tallied the pod under worker-9"
        );

        tally.remove("default", "e");

        assert!(
            !tally.by_node.contains_key("worker-9"),
            "removing the last pod on a node must prune worker-9's outer \
             by_node entry, not just empty its pod set — a leaked empty \
             entry here is invisible to assert_by_node_index_matches_pods \
             and accumulates one per node name for the process's lifetime"
        );
    }

    /// A DELETED watch event must remove the pod from the tally — this is how
    /// a preemption victim's eviction becomes visible cluster-wide (not just
    /// via main.rs's own immediate `remove` call), and how any other actor's
    /// pod deletion is picked up.
    #[test]
    fn node_tally_apply_event_deleted_removes_the_pod() {
        let mut tally = NodeTally::default();
        tally.apply_event(&bound_pod_added_event("a", "worker-0", "Running", "1"));
        assert_eq!(tally.usage_by_node()["worker-0"].pod_count, 1);

        tally.apply_event(&json!({
            "type": "DELETED",
            "object": { "metadata": { "name": "a", "namespace": "default" } }
        }));

        assert!(
            !tally.usage_by_node().contains_key("worker-0"),
            "a DELETED event must remove the pod's tallied usage — otherwise a \
             real pod deletion would leave a phantom reservation that blocks \
             scheduling onto a node that actually has room"
        );
    }

    /// Live-reproduced once `main.rs`'s best-effort `nominatedNodeName`
    /// status PATCH landed in the critical path before eviction/bind: that
    /// PATCH changes only `status`, but its watch-echo still carries
    /// `spec.nodeName` empty (the bind that actually sets it hasn't happened
    /// yet) — and `apply_event` used to treat ANY empty-`spec.nodeName`
    /// ADDED/MODIFIED event as "this pod occupies no slot, drop it", which
    /// erased the `assume` reservation `verify_and_reserve_preemption` had
    /// already committed for this exact pod moments earlier. A concurrently
    /// scheduled THIRD pod's capacity check then saw phantom free room (the
    /// tally had "forgotten" this pod), got force-bound, and the kubelet
    /// rejected it OutOfResource even though nothing was actually wrong with
    /// preemption's victim selection.
    #[test]
    fn apply_event_does_not_erase_an_assumed_reservation_for_a_still_unbound_watch_echo() {
        let mut tally = NodeTally::default();
        tally.assume(
            "default",
            "preemptor",
            "worker-0",
            1000,
            requests(1000, 0, 0),
            Vec::new(),
            std::collections::HashMap::new(),
            Vec::new(),
        );

        // Mirrors the nominatedNodeName status PATCH's watch-echo: same pod,
        // `spec.nodeName` still empty, `status` is the only thing that changed.
        tally.apply_event(&json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "preemptor", "namespace": "default" },
                "spec": { "containers": [] },
                "status": { "phase": "Pending" }
            }
        }));

        assert_eq!(
            tally.usage_by_node().get("worker-0").map(|u| u.pod_count),
            Some(1),
            "a stale/echoed watch event that predates this scheduler's own \
             assume() for this pod must never erase that fresher reservation \
             — otherwise a concurrently-scheduled pod's capacity check sees \
             phantom free room and gets force-bound onto a node that is, in \
             physical reality, already full"
        );
    }

    // ---------------------------------------------------------------------------
    // NodePorts predicate: hostPort/hostIP/protocol conflict detection between a
    // pending pod and pods already tallied on a candidate node.
    //
    // Before this fix, crates/scheduler/src/lib.rs had ZERO handling of
    // spec.containers[].ports[].hostPort anywhere — select_node_with_capacity
    // would happily bind two pods requesting the same hostPort/protocol onto
    // the same node. The kubelet can only actually bind one of them to that
    // socket; the loser crashes at container-start time ("address already in
    // use") instead of staying Pending, where a controller could safely retry
    // it elsewhere. This is the upstream conformance-tagged scenario
    // "Scheduling, HostPort and Protocol match, HostIPs different but one is
    // default HostIP (0.0.0.0)" (predicates.go:706).
    // ---------------------------------------------------------------------------

    fn host_port_claim(host_port: u16, host_ip: &str, protocol: &str) -> HostPortClaim {
        HostPortClaim {
            host_port,
            host_ip: host_ip.to_owned(),
            protocol: protocol.to_owned(),
        }
    }

    /// Two pods claiming the identical hostIP/hostPort/protocol must conflict
    /// — the base case every other test in this section builds on.
    #[test]
    fn host_ports_conflict_true_for_identical_claims() {
        let a = host_port_claim(8080, "10.0.0.5", "TCP");
        let b = host_port_claim(8080, "10.0.0.5", "TCP");
        assert!(
            host_ports_conflict(&a, &b),
            "two pods binding the exact same hostIP:hostPort/protocol must be \
             seen as a conflict — the kubelet can only start one of them"
        );
    }

    /// Different protocols on the same hostIP/hostPort must NOT conflict — TCP
    /// and UDP bind independent sockets. Matches upstream's (non-conformance)
    /// "validates that there is no conflict between pods with same hostPort
    /// but different hostIP and protocol" (pod2 TCP vs pod3 UDP, same
    /// hostIP:port).
    #[test]
    fn host_ports_conflict_false_for_different_protocol() {
        let tcp = host_port_claim(54321, "10.0.0.5", "TCP");
        let udp = host_port_claim(54321, "10.0.0.5", "UDP");
        assert!(
            !host_ports_conflict(&tcp, &udp),
            "TCP and UDP claims on the same hostIP:hostPort are independent \
             sockets — treating them as conflicting would wrongly block a \
             schedulable pod"
        );
    }

    /// Different concrete (non-wildcard) hostIPs on the same hostPort/protocol
    /// must NOT conflict — each binds a different network interface. Matches
    /// upstream's pod1 (127.0.0.1) vs pod2 (the node's real IP), same
    /// port/TCP.
    #[test]
    fn host_ports_conflict_false_for_different_concrete_host_ips() {
        let a = host_port_claim(54321, "127.0.0.1", "TCP");
        let b = host_port_claim(54321, "192.168.1.5", "TCP");
        assert!(
            !host_ports_conflict(&a, &b),
            "two distinct, non-wildcard hostIPs bind different interfaces and \
             must not conflict — over-broad matching here would wrongly reject \
             a node with free capacity on the interface the pending pod \
             actually wants"
        );
    }

    /// THE conformance scenario (predicates.go:706): one pod leaves hostIP
    /// empty (binds ALL interfaces — the 0.0.0.0 wildcard), the other pins the
    /// node's real IP, same hostPort/protocol. These must conflict — the
    /// wildcard pod's socket already occupies that port on the interface the
    /// second pod would also try to use, so the kubelet cannot start both.
    /// Without treating "" (and the literal "0.0.0.0") as a wildcard, this
    /// scheduler would never detect this conflict at all — the exact gap this
    /// fix closes.
    #[test]
    fn host_ports_conflict_true_when_either_side_is_wildcard_host_ip() {
        let wildcard = host_port_claim(54322, "", "TCP");
        let concrete = host_port_claim(54322, "203.0.113.10", "TCP");
        assert!(
            host_ports_conflict(&wildcard, &concrete),
            "an empty (wildcard) hostIP binds every interface on the host, so \
             it must conflict with ANY other hostIP claiming the same \
             hostPort/protocol — not just an exact string match"
        );
        let literal_wildcard = host_port_claim(54322, "0.0.0.0", "TCP");
        assert!(
            host_ports_conflict(&literal_wildcard, &concrete),
            "the literal string \"0.0.0.0\" means the exact same thing as an \
             absent hostIP and must be treated as the same wildcard"
        );
    }

    /// `host_ports_fit` (the aggregate check `select_node_with_capacity`
    /// calls) must reject when ANY of the pod's ports conflicts with ANY
    /// already-claimed node port — not just when every port conflicts, since
    /// a pod cannot be partially scheduled.
    #[test]
    fn host_ports_fit_false_when_any_port_conflicts() {
        let node_ports = vec![host_port_claim(8080, "", "TCP")];
        let pod_ports = vec![
            host_port_claim(9090, "", "TCP"),         // no conflict
            host_port_claim(8080, "10.0.0.1", "TCP"), // conflicts via wildcard
        ];
        assert!(
            !host_ports_fit(&node_ports, &pod_ports),
            "a single conflicting port among several must fail the whole \
             check — a pod cannot be partially scheduled"
        );
    }

    /// `select_node_with_capacity` must skip a node whose already-tallied pod
    /// holds a hostPort that conflicts with the pending pod's — the actual
    /// Filter-phase wiring, not just the pure predicate. Reproduces
    /// predicates.go:706's pod4-vs-pod5: pod4 is already bound with
    /// hostIP="" (wildcard), pod5 wants the same hostPort/protocol on the
    /// node's real hostIP.
    #[test]
    fn select_node_with_capacity_skips_node_with_conflicting_host_port() {
        let list = NodeList {
            items: vec![make_node_with_capacity("worker-0", &[], "110")],
        };
        let mut pod = empty_pending_pod();
        pod.host_ports = vec![host_port_claim(54322, "203.0.113.10", "TCP")];
        let mut usage = usage_with_pod_count(1);
        usage.host_ports = vec![host_port_claim(54322, "", "TCP")];
        let counts: std::collections::HashMap<String, NodeUsage> =
            [("worker-0".to_owned(), usage)].into();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert!(
            result.is_err(),
            "a node already holding a wildcard-hostIP claim on the pending \
             pod's requested hostPort/protocol must be rejected — without \
             this check, both pods are bound to the same node and the loser \
             crashes at container-start with 'address already in use' \
             instead of staying Pending — got: {:?}",
            result.ok()
        );
    }

    /// `select_node_with_capacity` must still select a node when the pending
    /// pod's hostPort request does NOT conflict with anything already there
    /// (different protocol) — guards against an over-broad implementation
    /// that blocks otherwise-schedulable pods. Matches upstream's
    /// non-conformance "no conflict ... different protocol" scenario.
    #[test]
    fn select_node_with_capacity_allows_node_with_non_conflicting_host_port() {
        let list = NodeList {
            items: vec![make_node_with_capacity("worker-0", &[], "110")],
        };
        let mut pod = empty_pending_pod();
        pod.host_ports = vec![host_port_claim(54321, "10.0.0.5", "UDP")];
        let mut usage = usage_with_pod_count(1);
        usage.host_ports = vec![host_port_claim(54321, "10.0.0.5", "TCP")];
        let counts: std::collections::HashMap<String, NodeUsage> =
            [("worker-0".to_owned(), usage)].into();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert_eq!(
            result.unwrap(),
            "worker-0",
            "a different protocol on the same hostIP:hostPort must not block \
             scheduling — TCP and UDP are independent sockets"
        );
    }

    /// `NodeTally::assume`'s fast path — recording a scheduler-decided bind
    /// before its own HTTP bind call even completes — must make the bind's
    /// hostPort claim visible to the very next scheduling decision, with NO
    /// window where a watch event round-trip through `apply_event` is
    /// needed. Before `assume` threaded `host_ports` through (it used to
    /// hardcode `Vec::new()`), a pod scheduled immediately after another that
    /// just claimed the same hostPort would see the candidate node as having
    /// zero hostPort claims — `usage_by_node`'s only source for
    /// `host_ports` was `apply_event` — and could be bound to that same
    /// node/hostPort too; the loser then crashes at container-start with
    /// "address already in use" instead of staying Pending where a
    /// controller could retry it elsewhere. The sequential conformance test
    /// never exercises this: each pod there is created and waited-on before
    /// the next, giving the real watch event time to round-trip through
    /// `apply_event` first — only concurrent scheduling load hits this race.
    #[test]
    fn assume_records_host_port_claim_visible_to_the_very_next_scheduling_decision() {
        let mut tally = NodeTally::default();
        let list = || NodeList {
            items: vec![make_node_with_capacity("worker-0", &[], "110")],
        };

        let mut pod_a = empty_pending_pod();
        pod_a.pod_name = "pod-a".to_owned();
        pod_a.host_ports = vec![host_port_claim(8080, "", "TCP")];
        let chosen = select_node_with_capacity(
            list(),
            &pod_a,
            &tally.usage_by_node(),
            &tally.tallied_pod_labels(),
        )
        .expect("pod-a has no competing claim yet, so it must schedule");
        tally.assume(
            "default",
            "pod-a",
            &chosen,
            0,
            ResourceRequests::default(),
            pod_a.host_ports.clone(),
            pod_a.labels.clone(),
            pod_a.pvc_names.clone(),
        );

        // No `apply_event` call in between — pod-b's decision must not need
        // one to see pod-a's just-`assume`d claim.
        let mut pod_b = empty_pending_pod();
        pod_b.pod_name = "pod-b".to_owned();
        pod_b.host_ports = vec![host_port_claim(8080, "", "TCP")];
        let result = select_node_with_capacity(
            list(),
            &pod_b,
            &tally.usage_by_node(),
            &tally.tallied_pod_labels(),
        );

        assert!(
            result.is_err(),
            "pod-a's assume()d hostPort claim must be visible to pod-b's \
             scheduling decision without waiting for a watch event \
             round-trip — otherwise two pods requesting the same hostPort \
             can both be bound to the same node under concurrent scheduling \
             load, and the loser crashes at container-start with 'address \
             already in use' instead of never being scheduled there; got \
             {:?}",
            result.ok()
        );
    }

    /// `needs_scheduling` must extract hostPort/hostIP/protocol from a
    /// container's ports — if this parsing is dropped, `PendingPod.host_ports`
    /// is always empty and the NodePorts filter above can never fire for any
    /// real pod, no matter how correct the conflict logic is.
    #[test]
    fn needs_scheduling_extracts_host_port_claims() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "hostport-pod", "namespace": "default" },
                "spec": {
                    "containers": [{
                        "ports": [{
                            "hostPort": 54322,
                            "containerPort": 8080,
                            "protocol": "TCP",
                            "hostIP": "203.0.113.10"
                        }]
                    }]
                }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.host_ports,
            vec![host_port_claim(54322, "203.0.113.10", "TCP")],
            "container.ports[].hostPort/hostIP/protocol must be captured into \
             PendingPod.host_ports verbatim"
        );
    }

    /// A container port with no `hostPort` is a plain `containerPort` — it
    /// binds nothing on the node's own network namespace and must NOT become
    /// a hostPort claim, or an ordinary pod using `containerPort` purely for
    /// documentation would spuriously conflict with anything.
    #[test]
    fn needs_scheduling_ignores_container_ports_without_host_port() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "plain-port-pod", "namespace": "default" },
                "spec": {
                    "containers": [{
                        "ports": [{ "containerPort": 8080 }]
                    }]
                }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert!(
            pending.host_ports.is_empty(),
            "a containerPort with no hostPort must not produce a hostPort claim"
        );
    }

    /// An absent `protocol` must default to TCP, matching `v1.ContainerPort`'s
    /// own API default — if this scheduler defaulted to empty/unknown instead,
    /// a TCP-vs-TCP conflict would be missed whenever one side omits the field.
    #[test]
    fn needs_scheduling_defaults_host_port_protocol_to_tcp() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "no-protocol-pod", "namespace": "default" },
                "spec": {
                    "containers": [{
                        "ports": [{ "hostPort": 8080 }]
                    }]
                }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.host_ports,
            vec![host_port_claim(8080, "", "TCP")],
            "an omitted protocol must default to TCP, and an omitted hostIP \
             must default to the empty-string wildcard"
        );
    }

    /// A container whose `ports` field is a real, present JSON `null` (not an
    /// absent key) must still be scheduled with an empty `host_ports` list —
    /// live-reproduced against a real conformance stack: this apiserver
    /// serializes an unset `ports` as literal `null`, and a first-cut
    /// `#[serde(default)] ports: Vec<ContainerPortSpec>` only covers an
    /// ABSENT key, not an explicit `null`. That first cut made deserializing
    /// the whole `PodObject` fail, which `needs_scheduling`'s catch-all
    /// fallback silently turns into "not ADDED/MODIFIED" — so the pod (e.g.
    /// sonobuoy's own aggregator pod, which never sets `ports`) never entered
    /// the scheduling cycle at all and stayed Pending forever, with no error
    /// logged anywhere. Reverting `ports` from `Option<Vec<_>>` back to a bare
    /// `Vec<_>` reproduces this exact silent total-scheduling-outage.
    #[test]
    fn needs_scheduling_tolerates_null_ports_field() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "sonobuoy-like-pod", "namespace": "default" },
                "spec": {
                    "containers": [{ "name": "kube-sonobuoy", "ports": null }]
                }
            }
        });
        let pending = needs_scheduling(&event);
        assert!(
            pending.is_some(),
            "a container with an explicit JSON null `ports` field must still \
             deserialize successfully and enter the scheduling cycle — a \
             bare Vec<_> field silently drops the whole pod instead"
        );
        assert!(
            pending.unwrap().host_ports.is_empty(),
            "a null ports field carries no hostPort claims"
        );
    }

    // ---------------------------------------------------------------------------
    // PreemptionWaiters / deferred preemption bind (Option A)
    //
    // Regression coverage for the exact race live-reproduced against
    // `validates basic preemption works`: `preempt_and_pick_node` used to treat
    // `evict_victims`'s successful graceful DELETE as "the node is free" and
    // bind the preemptor synchronously — ~1.4ms after the DELETE call
    // returned, while the real out-of-process kubelet running the victim
    // didn't finish tearing it down for another ~1.2s, so its own admission
    // check rejected the bind OutOfResource (a terminal, unrecoverable Failed
    // phase for a bare Pod). These tests exercise the fix at the same level
    // `main.rs`'s `preempt_and_pick_node`/`attempt_deferred_bind` call
    // through — `NodeTally::register_preemption_waiter` and
    // `NodeTally::apply_event`'s DELETED-branch hook — since neither of those
    // main.rs functions is unit-testable without a live API server.
    // ---------------------------------------------------------------------------

    /// The core regression: registering a plan (mirroring what
    /// `preempt_and_pick_node` now does instead of binding immediately) must
    /// NOT resolve on an unrelated pod's DELETE, and must resolve on the
    /// plan's own victim's DELETE — the real signal the kubelet emits only
    /// once it has actually stopped the container. If this regressed back to
    /// resolving eagerly (e.g. `preempt_and_pick_node` binding right after
    /// `evict_victims` returns `Ok(())`, without ever consulting this map),
    /// the scheduler would once again decide to bind before the real kubelet
    /// has freed the resource — exactly the failure this fix closes.
    #[test]
    fn preemption_waiter_only_resolves_once_its_own_victim_is_confirmed_gone() {
        let mut tally = NodeTally::default();
        let mut preemptor = empty_pending_pod();
        preemptor.pod_name = "preemptor-pod".to_owned();
        // Mirrors preempt_and_pick_node: the preemptor was already `assume`d
        // by `verify_and_reserve_preemption` before eviction ran.
        tally.assume(
            "default",
            "preemptor-pod",
            "worker-0",
            1000,
            ResourceRequests::default(),
            Vec::new(),
            std::collections::HashMap::new(),
            Vec::new(),
        );
        tally.register_preemption_waiter(
            preemptor,
            "worker-0".to_owned(),
            &["default/victim".to_owned()],
        );

        let unrelated = tally.apply_event(&json!({
            "type": "DELETED",
            "object": { "metadata": { "name": "someone-else", "namespace": "default" } }
        }));
        assert!(
            unrelated.is_empty(),
            "an unrelated pod's DELETE must never resolve a different pod's \
             preemption waiter — got {unrelated:?}"
        );

        let ready = tally.apply_event(&json!({
            "type": "DELETED",
            "object": { "metadata": { "name": "victim", "namespace": "default" } }
        }));
        assert_eq!(
            ready.len(),
            1,
            "the victim's own real DELETED event must resolve exactly this \
             one waiting plan, making it ready for the deferred bind"
        );
        assert_eq!(ready[0].0.pod_name, "preemptor-pod");
        assert_eq!(ready[0].1, "worker-0");
    }

    /// A plan with more than one victim (the shape krae9's concurrent 3v3
    /// scenario can produce) must wait for ALL of them, not just the first —
    /// the other victim's container may still be running and occupying the
    /// node's capacity the preemptor actually needs. Binding after only a
    /// partial confirmation would reproduce the same OutOfResource race one
    /// victim at a time instead of all at once.
    #[test]
    fn preemption_waiter_with_multiple_victims_waits_for_all_of_them() {
        let mut tally = NodeTally::default();
        let mut preemptor = empty_pending_pod();
        preemptor.pod_name = "preemptor-pod".to_owned();
        tally.register_preemption_waiter(
            preemptor,
            "worker-0".to_owned(),
            &["default/victim-a".to_owned(), "default/victim-b".to_owned()],
        );

        let after_first = tally.apply_event(&json!({
            "type": "DELETED",
            "object": { "metadata": { "name": "victim-a", "namespace": "default" } }
        }));
        assert!(
            after_first.is_empty(),
            "a two-victim plan must not resolve after only one victim is \
             confirmed gone — the other victim may still be occupying the \
             capacity the preemptor needs"
        );

        let after_second = tally.apply_event(&json!({
            "type": "DELETED",
            "object": { "metadata": { "name": "victim-b", "namespace": "default" } }
        }));
        assert_eq!(
            after_second.len(),
            1,
            "the plan must resolve once the LAST awaited victim is confirmed gone"
        );
    }

    /// `main.rs` now holds a pod's `in_flight` dedup key reserved for the
    /// whole preempt-then-wait sequence a registered waiter represents (see
    /// `attempt_deferred_bind`'s doc comment) — so if a watch reconnect drops
    /// that waiter here before it ever resolves, `clear` MUST hand back its
    /// pod key so `main.rs` can release `in_flight` too. Without this, a pod
    /// whose deferred bind was abandoned this way would stay wrongly deduped
    /// as "already being scheduled" forever, even though nothing is
    /// scheduling it any more — a stuck-forever pod, worse than the race this
    /// whole in_flight-retention fix closes.
    #[test]
    fn node_tally_clear_returns_abandoned_waiters_pod_keys() {
        let mut tally = NodeTally::default();
        let mut preemptor = empty_pending_pod();
        preemptor.pod_name = "preemptor-pod".to_owned();
        tally.register_preemption_waiter(
            preemptor,
            "worker-0".to_owned(),
            &["default/victim".to_owned()],
        );

        let abandoned = tally.clear();

        assert_eq!(
            abandoned,
            vec!["default/preemptor-pod".to_owned()],
            "clear must report every waiting plan's pod key it just dropped, so the caller \
             can release it from in_flight — losing this silently strands that pod as \
             permanently deduped"
        );
    }

    /// kn79c guardrail: `attempt_deferred_bind` (main.rs) must never bind a
    /// deferred preemption purely because `PreemptionWaiters` says the plan's
    /// victims are gone — it must re-verify fit under the CURRENT tally
    /// first, exactly as this test does directly against
    /// `preemption_reservation_still_fits`. Simulates the drift scenario the
    /// restart-safety audit flagged: between a plan's commit and its
    /// victims' real DELETE landing, some OTHER pod independently claims the
    /// same node's remaining capacity (e.g. a watch reconnect wiped this
    /// preemptor's own `assume` reservation, and a concurrent, unrelated
    /// scheduling decision filled the gap it left) — `attempt_deferred_bind`
    /// has no FailedScheduling branch on a `false` result here at all, so a
    /// regression that made this always return `true` would let the fast
    /// path bind onto a node that's actually full, reproducing the same
    /// OutOfResource failure Option A exists to fix, instead of falling back
    /// to the 30s resync backstop.
    #[test]
    fn preemption_reservation_still_fits_refuses_when_capacity_drifted_after_reservation() {
        let tally = std::sync::Mutex::new(NodeTally::default());
        let mut node = make_node_with_capacity("worker-0", &[], "110");
        node.status.allocatable.cpu = "2".to_owned(); // 2000m total

        let mut pod = empty_pending_pod();
        pod.pod_name = "preemptor".to_owned();
        pod.requests.cpu_milli = 2000;
        tally.lock().expect("tally lock poisoned").assume(
            "default",
            "preemptor",
            "worker-0",
            1000,
            pod.requests.clone(),
            Vec::new(),
            std::collections::HashMap::new(),
            Vec::new(),
        );

        // Baseline: with nothing else on the node, the reservation still
        // fits — this must be true, or every ordinary (non-drifted) deferred
        // bind would wrongly fall back to the slow 30s resync path too.
        assert!(
            preemption_reservation_still_fits(&pod, &node, &tally),
            "an undrifted reservation must still fit"
        );

        // Some other pod independently claims the node's remaining capacity
        // in the interim.
        tally.lock().expect("tally lock poisoned").assume(
            "default",
            "unrelated-pod",
            "worker-0",
            0,
            requests(1000, 0, 0),
            Vec::new(),
            std::collections::HashMap::new(),
            Vec::new(),
        );

        assert!(
            !preemption_reservation_still_fits(&pod, &node, &tally),
            "capacity claimed by another pod after the plan committed must \
             make the reservation no longer fit — binding anyway here is \
             exactly the 'the map says so' shortcut the fast path must never \
             take"
        );
    }

    // parse_quantity_milli tests — the resource-quantity arithmetic underlying
    // NodeResourcesFit's cpu/memory/ephemeral-storage checks. A parsing bug here
    // silently mis-sizes every resource comparison the scheduler makes.

    #[test]
    fn parse_quantity_milli_handles_cpu_milli_suffix() {
        assert_eq!(parse_quantity_milli("500m"), 500);
    }

    #[test]
    fn parse_quantity_milli_handles_plain_cpu_cores() {
        assert_eq!(
            parse_quantity_milli("2"),
            2000,
            "a plain integer is whole cores, so '2' must be 2000 milli-cpu"
        );
    }

    #[test]
    fn parse_quantity_milli_handles_binary_memory_suffix() {
        assert_eq!(
            parse_quantity_milli("1Gi"),
            1024 * 1024 * 1024 * 1000,
            "1Gi must convert to exact bytes (Gi is binary, 1024-based), times 1000 for milli-units"
        );
    }

    #[test]
    fn parse_quantity_milli_returns_zero_for_empty_or_unparseable() {
        assert_eq!(
            parse_quantity_milli(""),
            0,
            "an absent quantity must be 0, treated by callers as 'unknown/unset', \
             not an error that blocks scheduling"
        );
        assert_eq!(parse_quantity_milli("not-a-quantity"), 0);
    }

    /// A fractional plain-unit quantity ("1.5" CPU cores) must parse to 1500, not 0. Before
    /// the fix every branch called `.parse::<i64>()` directly, which rejects any decimal
    /// point — a container requesting "1.5" CPU would contribute 0 to the node's committed
    /// total, so NodeResourcesFit would think the node has 1.5 more free cores than it
    /// actually does and schedule a pod onto a node that then fails to fit at the kubelet.
    #[test]
    fn parse_quantity_milli_fractional_plain_counts_toward_fit_check() {
        assert_eq!(
            parse_quantity_milli("1.5"),
            1500,
            "\"1.5\" CPU cores must resolve to 1500 milli-cores — silently reading this as 0 \
             would let the scheduler over-commit a node's real CPU capacity"
        );
    }

    /// A fractional quantity with a binary SI suffix ("1.5Gi" memory) must also parse — the
    /// same rejection bug independently affects the binary-suffix branch, and an undercounted
    /// memory request is exactly the kind of gap that lets a pod land on a node with too
    /// little free memory.
    #[test]
    fn parse_quantity_milli_fractional_binary_suffix_counts_toward_fit_check() {
        assert_eq!(
            parse_quantity_milli("1.5Gi"),
            1_610_612_736_000,
            "\"1.5Gi\" must resolve to 1.5 * 1024^3 * 1000 milli-bytes; reading it as 0 would \
             let the scheduler place a pod on a node without enough free memory to hold it"
        );
    }

    /// A negative fractional quantity must round-trip through the same f64 fallback as the
    /// positive cases — a fix that only handled positive fractions would still silently drop
    /// this input to 0.
    #[test]
    fn parse_quantity_milli_negative_fractional_parses_exactly() {
        assert_eq!(
            parse_quantity_milli("-1.5"),
            -1500,
            "a negative fractional quantity must parse to its exact negative milli-value, \
             not be silently read as 0"
        );
    }

    /// Whole-number input must stay on the exact i64 fast path, not get routed through f64 —
    /// large magnitudes (multi-exabyte node capacities) would lose precision if every input
    /// went through a float, and NodeResourcesFit depends on exact integer comparisons for
    /// the common non-fractional case.
    #[test]
    fn parse_quantity_milli_integer_unaffected_by_fractional_support() {
        assert_eq!(
            parse_quantity_milli("2"),
            2000,
            "adding fractional support must not change the exact-integer fast path existing \
             scheduler fit checks already depend on"
        );
        assert_eq!(
            parse_quantity_milli("30Gi"),
            30 * 1024 * 1024 * 1024 * 1000,
            "existing binary-suffix integer capacities/requests must still resolve exactly"
        );
    }

    /// `NaN`/`inf` are not valid Kubernetes quantities even though `f64::from_str` happily
    /// parses them — without an explicit finite check, the f64 fallback added for fractional
    /// support would treat a malformed capacity/request string as a nonsensical numeric value
    /// instead of the "unparseable" 0 every other invalid input maps to. This only exercises
    /// the non-finite half of the fallback's guard — see
    /// `parse_quantity_milli_rejects_overflowing_fractional` for the separate
    /// finite-but-too-large-to-fit-in-i64 half.
    #[test]
    fn parse_quantity_milli_rejects_non_finite() {
        assert_eq!(
            parse_quantity_milli("NaN"),
            0,
            "\"NaN\" must be treated as unparseable (0), not accepted via the fractional \
             fallback"
        );
        assert_eq!(
            parse_quantity_milli("inf"),
            0,
            "\"inf\" must be treated as unparseable (0), not accepted via the fractional \
             fallback"
        );
        assert_eq!(
            parse_quantity_milli("-inf"),
            0,
            "\"-inf\" must be treated as unparseable (0), not accepted via the fractional \
             fallback"
        );
    }

    /// `"1e19"` is FINITE (unlike `NaN`/`inf` above) but its milli-scaled value
    /// (1e19 * 1000 = 1e22) overflows `i64::MAX` (~9.22e18). Rust's `f64 as i64` cast
    /// SATURATES on overflow instead of signaling failure, so before the explicit range
    /// check this silently returned `i64::MAX` — a monster fractional cpu/memory
    /// request/capacity would be read as the saturated max instead of unparseable (0),
    /// letting the scheduler make a fit decision against a bogus huge value.
    #[test]
    fn parse_quantity_milli_rejects_overflowing_fractional() {
        assert_eq!(
            parse_quantity_milli("1e19"),
            0,
            "a fractional value whose milli-scaled magnitude exceeds i64::MAX must be \
             treated as unparseable (0), not silently saturated to i64::MAX"
        );
    }

    /// Mirrors the positive-overflow case above but for the negative saturation bound
    /// (`i64::MIN`) — a naive fix that only range-checked the upper bound would still
    /// silently accept `"-1e19"` as the saturated minimum.
    #[test]
    fn parse_quantity_milli_rejects_negative_overflowing_fractional() {
        assert_eq!(
            parse_quantity_milli("-1e19"),
            0,
            "a fractional value whose milli-scaled magnitude is below i64::MIN must be \
             treated as unparseable (0), not silently saturated to i64::MIN"
        );
    }

    /// A moderate-looking fractional value combined with a binary suffix ("1e19Gi") must
    /// also be rejected — the overflow can come from the numeric literal alone, the binary
    /// multiplier alone, or (as tested here) their product, so the guard must run on the
    /// fully mult-scaled value, not just the bare parsed float.
    #[test]
    fn parse_quantity_milli_rejects_overflowing_fractional_binary_suffix() {
        assert_eq!(
            parse_quantity_milli("1e19Gi"),
            0,
            "a fractional binary-suffixed quantity that overflows i64 once scaled by the \
             Gi multiplier must be treated as unparseable (0), not silently saturated"
        );
    }

    /// `9223372036854775808` is exactly `2^63`, one past `i64::MAX` (`2^63 - 1`). `i64::MAX`
    /// itself isn't exactly representable in f64 (63 bits needed, f64 has 53), so `i64::MAX
    /// as f64` rounds UP to `2^63.0` — a strict `scaled > i64::MAX as f64` guard would let
    /// `scaled == 2^63.0` through, then saturate to `i64::MAX` on the cast. The upper bound
    /// must be `>=` to close this exact-boundary hole.
    #[test]
    fn parse_quantity_milli_rejects_exact_two_pow_63_boundary() {
        assert_eq!(
            parse_quantity_milli("9223372036854775808m"),
            0,
            "2^63 milli-units is one past i64::MAX and must be treated as unparseable (0) — \
             a `>` (rather than `>=`) upper-bound check would let this saturate to i64::MAX \
             instead"
        );
    }

    /// Sanity check for the boundary fix above: `i64::MAX` itself (one milli-unit below
    /// `2^63`) must still parse successfully — an overly aggressive `>=` fix applied to the
    /// wrong operand, or an off-by-one in the other direction, would over-reject the exact
    /// maximum valid value.
    #[test]
    fn parse_quantity_milli_accepts_exact_i64_max() {
        assert_eq!(
            parse_quantity_milli("9223372036854775807m"),
            i64::MAX,
            "i64::MAX itself is a valid milli-quantity and must not be rejected by the \
             overflow guard"
        );
    }

    // resource_fits / NodeResourcesFit resource-dimension tests:
    // the scheduler previously only checked pod COUNT against
    // status.allocatable.pods; a node saturated on cpu/memory/ephemeral-storage
    // but with a free pod slot would still accept a pod the kubelet then rejects
    // OutOfcpu/OutOfephemeral-storage — a real kubelet failure, not a scheduler
    // FailedScheduling event, so the conformance test's event-watch timed out.

    fn node_allocatable(cpu: &str, memory: &str, ephemeral_storage: &str) -> NodeAllocatable {
        NodeAllocatable {
            pods: String::new(),
            cpu: cpu.to_owned(),
            memory: memory.to_owned(),
            ephemeral_storage: ephemeral_storage.to_owned(),
            extended: Default::default(),
        }
    }

    fn requests(
        cpu_milli: i64,
        memory_milli: i64,
        ephemeral_storage_milli: i64,
    ) -> ResourceRequests {
        ResourceRequests {
            cpu_milli,
            memory_milli,
            ephemeral_storage_milli,
            extended: Default::default(),
        }
    }

    /// The exact saturate-then-overflow shape from predicates.go:129: a node's
    /// cpu is already fully committed by existing pods, and the pending pod's
    /// own request would push usage over allocatable — must be rejected.
    #[test]
    fn resource_fits_false_when_cpu_would_be_overcommitted() {
        let allocatable = node_allocatable("4", "", "");
        let used = requests(4000, 0, 0); // node already fully committed at 4 cores
        let pending = requests(1000, 0, 0); // one more core requested
        assert!(
            !resource_fits(&allocatable, &used, &pending),
            "a pending pod's cpu request must be rejected when it would push \
             usage past allocatable cpu — reverting this lets the scheduler bind \
             pods the kubelet then fails OutOfcpu"
        );
    }

    /// The exact ephemeral-storage saturate-then-overflow shape from
    /// predicates.go:129.
    #[test]
    fn resource_fits_false_when_ephemeral_storage_would_be_overcommitted() {
        let allocatable = node_allocatable("", "", "10Gi");
        let used = requests(0, 0, 10 * 1024 * 1024 * 1024 * 1000);
        let pending = requests(0, 0, 1000); // 1 milli-byte over the line
        assert!(
            !resource_fits(&allocatable, &used, &pending),
            "a pending pod's ephemeral-storage request must be rejected when it \
             would push usage past allocatable ephemeral-storage"
        );
    }

    /// A pending pod that fits within remaining capacity must be accepted —
    /// the positive-path counterpart, so this predicate doesn't block all
    /// scheduling by always returning false.
    #[test]
    fn resource_fits_true_when_request_fits_within_remaining_capacity() {
        let allocatable = node_allocatable("4", "8Gi", "20Gi");
        let used = requests(2000, 4 * 1024 * 1024 * 1024 * 1000, 0);
        let pending = requests(1000, 1024 * 1024 * 1024 * 1000, 0);
        assert!(
            resource_fits(&allocatable, &used, &pending),
            "a request that fits within remaining allocatable must be accepted"
        );
    }

    /// An allocatable dimension of 0 (field absent/unparseable) means "unknown"
    /// — that dimension must not block scheduling, mirroring
    /// `parse_pod_capacity`'s existing convention for `status.allocatable.pods`.
    #[test]
    fn resource_fits_true_when_allocatable_dimension_unknown() {
        let allocatable = node_allocatable("", "", "");
        let used = requests(999_999_000, 0, 0);
        let pending = requests(999_999_000, 0, 0);
        assert!(
            resource_fits(&allocatable, &used, &pending),
            "an unknown (empty) allocatable dimension must not block scheduling"
        );
    }

    /// A pod's `spec.overhead` (set by the apiserver's RuntimeClass admission
    /// plugin from `RuntimeClass.overhead.podFixed`, e.g. gVisor/Kata sandbox
    /// tax) must be added on top of its container requests: the container sum
    /// alone (900m cpu) fits a 1-core node, but the true footprint including
    /// the 200m overhead (1100m) does not. Before this fix `needs_scheduling`
    /// dropped `spec.overhead` entirely, so this pod would be bound to a node
    /// it actually over-subscribes.
    #[test]
    fn resource_fits_false_when_runtime_class_overhead_pushes_pod_over_capacity() {
        let allocatable = node_allocatable("1", "", "");
        let used = requests(0, 0, 0);
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "sandboxed-pod", "namespace": "default" },
                "spec": {
                    "containers": [
                        { "resources": { "requests": { "cpu": "900m" } } }
                    ],
                    "overhead": { "cpu": "200m" }
                }
            }
        });
        let pending = needs_scheduling(&event).expect("unscheduled pod must be schedulable");
        assert_eq!(
            pending.requests.cpu_milli, 1100,
            "spec.overhead must be added on top of the container request sum"
        );
        assert!(
            !resource_fits(&allocatable, &used, &pending.requests),
            "a pod whose container requests alone fit, but whose RuntimeClass \
             overhead pushes it past allocatable cpu, must be rejected — \
             otherwise the scheduler over-subscribes the node"
        );
    }

    // resource_fits extended-resource tests: before this fix, resource_fits
    // only checked cpu/memory/ephemeral-storage, so a pod requesting an
    // extended resource (e.g. a GPU, or the SchedulerPreemption conformance
    // suite's synthetic `scheduling.k8s.io/foo`) always looked like it
    // requested nothing — NodeResourcesFit could never reject it, and
    // preemption could never see a shortage to act on.

    /// The exact SchedulerPreemption conformance shape: a node advertises 1
    /// unit of a fake extended resource, it is already fully used, and a
    /// pending pod wants 1 more — must be rejected, or the scheduler binds a
    /// pod the kubelet then fails OutOf<resource>.
    #[test]
    fn resource_fits_false_when_extended_resource_would_be_overcommitted() {
        let allocatable = node_allocatable_extended("scheduling.k8s.io/foo", "1");
        let used = extended_request("scheduling.k8s.io/foo", 1000); // already fully committed
        let pending = extended_request("scheduling.k8s.io/foo", 1000); // wants 1 more
        assert!(
            !resource_fits(&allocatable, &used, &pending),
            "a pending pod's extended-resource request must be rejected when it \
             would push usage past allocatable — reverting this is the root cause \
             of every SchedulerPreemption conformance failure: the scheduler binds \
             the pod anyway and the kubelet rejects it outright"
        );
    }

    /// Unlike cpu/memory/ephemeral-storage, a node that does not advertise an
    /// extended resource AT ALL must fail-closed, not be treated as
    /// "unknown/unlimited" — the node has none of a resource it never
    /// declared, so a pod requesting it can never be scheduled there.
    #[test]
    fn resource_fits_false_when_node_does_not_advertise_the_extended_resource() {
        let allocatable = NodeAllocatable::default(); // no scheduling.k8s.io/foo entry at all
        let used = ResourceRequests::default();
        let pending = extended_request("scheduling.k8s.io/foo", 1000);
        assert!(
            !resource_fits(&allocatable, &used, &pending),
            "requesting a resource the node never advertised must fail-closed, \
             not be silently ignored like an unset cpu/memory dimension"
        );
    }

    /// The positive-path counterpart: a pod requesting an extended resource
    /// that the node has enough spare capacity for must be accepted.
    #[test]
    fn resource_fits_true_when_extended_resource_fits_within_remaining_capacity() {
        let allocatable = node_allocatable_extended("scheduling.k8s.io/foo", "5");
        let used = extended_request("scheduling.k8s.io/foo", 2000); // 2 of 5 used
        let pending = extended_request("scheduling.k8s.io/foo", 1000); // wants 1 more
        assert!(
            resource_fits(&allocatable, &used, &pending),
            "a request that fits within remaining allocatable extended-resource \
             capacity must be accepted"
        );
    }

    // needs_scheduling / select_node_with_capacity resource-request wiring:
    // the pending pod's OWN requests must be extracted from the
    // watch event and factored into the fit check, not just the already-bound
    // pods' requests.

    /// needs_scheduling sums spec.containers[].resources.requests into
    /// pending.requests — if dropped, select_node_with_capacity always sees a
    /// zero-request pod and never rejects it for lack of resources.
    #[test]
    fn needs_scheduling_returns_resource_requests_from_event() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "big-pod", "namespace": "default" },
                "spec": {
                    "containers": [
                        { "resources": { "requests": { "cpu": "2", "memory": "4Gi" } } }
                    ]
                }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.requests.cpu_milli, 2000,
            "spec.containers[].resources.requests.cpu must be summed into pending.requests"
        );
        assert_eq!(pending.requests.memory_milli, 4 * 1024 * 1024 * 1024 * 1000);
    }

    /// Multiple containers' requests must be summed, not just the first
    /// container's — Kubernetes charges a pod for the sum of all its
    /// containers' requests, not the max.
    #[test]
    fn needs_scheduling_sums_requests_across_multiple_containers() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "multi-container-pod", "namespace": "default" },
                "spec": {
                    "containers": [
                        { "resources": { "requests": { "cpu": "500m" } } },
                        { "resources": { "requests": { "cpu": "500m" } } }
                    ]
                }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.requests.cpu_milli, 1000,
            "two 500m-cpu containers in one pod must sum to 1000 milli-cpu, not 500"
        );
    }

    /// An extended-resource request key (anything other than cpu/memory/
    /// ephemeral-storage) must be captured into pending.requests.extended — if
    /// dropped, a pod requesting only a GPU or the SchedulerPreemption suite's
    /// synthetic `scheduling.k8s.io/foo` always looks like it requests
    /// nothing, and NodeResourcesFit/preemption can never see it.
    #[test]
    fn needs_scheduling_captures_extended_resource_requests() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "gpu-pod", "namespace": "default" },
                "spec": {
                    "containers": [
                        { "resources": { "requests": { "scheduling.k8s.io/foo": "2" } } }
                    ]
                }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.requests.extended.get("scheduling.k8s.io/foo"),
            Some(&2000),
            "an extended-resource request must be summed into pending.requests.extended \
             in the same milli-unit convention as cpu/memory"
        );
    }

    /// select_node_with_capacity must reject a node where the pending pod's own
    /// cpu request would overflow allocatable cpu, even though the node has
    /// free pod-count capacity — this is the exact predicates.go:129
    /// saturate-then-overflow scenario the scheduler previously missed entirely.
    #[test]
    fn select_node_with_capacity_skips_node_that_cannot_fit_pending_pod_cpu_request() {
        let mut node = make_node_with_capacity("worker-0", &[], "110");
        node.status.allocatable.cpu = "4".to_owned();
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.requests.cpu_milli = 1000; // pending pod wants 1 core
        let usage: std::collections::HashMap<String, NodeUsage> = [(
            "worker-0".to_owned(),
            NodeUsage {
                pod_count: 1,
                requests: requests(4000, 0, 0), // node already fully committed at 4 cores
                host_ports: Vec::new(),
                pvc_names: Vec::new(),
                csi_attached_counts: Default::default(),
            },
        )]
        .into();
        let result = select_node_with_capacity(list, &pod, &usage, &[]);
        assert!(
            result.is_err(),
            "a node with free pod-count capacity but no free cpu must still be \
             rejected — got: {:?}",
            result.ok()
        );
    }

    /// select_node_with_capacity must accept a node where the pending pod's
    /// requests fit within remaining allocatable resources.
    #[test]
    fn select_node_with_capacity_selects_node_with_enough_remaining_resources() {
        let mut node = make_node_with_capacity("worker-0", &[], "110");
        node.status.allocatable.cpu = "4".to_owned();
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.requests.cpu_milli = 1000;
        let usage: std::collections::HashMap<String, NodeUsage> = [(
            "worker-0".to_owned(),
            NodeUsage {
                pod_count: 1,
                requests: requests(1000, 0, 0), // 1 of 4 cores already used
                host_ports: Vec::new(),
                pvc_names: Vec::new(),
                csi_attached_counts: Default::default(),
            },
        )]
        .into();
        let result = select_node_with_capacity(list, &pod, &usage, &[]);
        assert_eq!(
            result.unwrap(),
            "worker-0",
            "a node with enough remaining cpu for the pending pod's request must be selected"
        );
    }

    /// needs_scheduling extracts the nodeSelector from the watch event.
    ///
    /// The nodeSelector must be extracted at the watch-event boundary (typed deserialization)
    /// so the scheduler can pass it to pick_node. If nodeSelector is silently dropped here,
    /// the scheduler always sees an empty selector and schedules pods on any node.
    #[test]
    fn needs_scheduling_returns_node_selector_from_event() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "restricted-pod", "namespace": "sched-pred" },
                "spec": {
                    "nodeSelector": {
                        "scheduledOnNode": "lima-node-2"
                    }
                }
            }
        });
        let result = needs_scheduling(&event);
        assert!(
            result.is_some(),
            "expected Some for unscheduled pod with nodeSelector"
        );
        let pending = result.unwrap();
        assert_eq!(pending.namespace, "sched-pred");
        assert_eq!(pending.pod_name, "restricted-pod");
        assert_eq!(
            pending
                .node_selector
                .get("scheduledOnNode")
                .map(|s| s.as_str()),
            Some("lima-node-2"),
            "nodeSelector must be extracted from spec.nodeSelector in the watch event — \
             if the selector is dropped, pick_node sees an empty selector and schedules \
             the pod on any node, breaking the NodeSelector conformance test"
        );
    }

    /// needs_scheduling returns an empty nodeSelector for pods without one.
    ///
    /// A pod without spec.nodeSelector must produce an empty selector, which matches
    /// any node. If this returns a non-empty selector, normal pods might not be scheduled.
    #[test]
    fn needs_scheduling_returns_empty_selector_when_no_node_selector() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "normal-pod", "namespace": "default" },
                "spec": {}
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert!(
            pending.node_selector.is_empty(),
            "pod without nodeSelector must produce an empty selector (matches any node)"
        );
    }

    // ---------------------------------------------------------------------------
    // Preemption: needs_scheduling priority extraction,
    // NodeTally.pods_on, and select_preemption_victims.
    //
    // Without priority-aware preemption, a higher-priority pod stays Pending
    // forever whenever lower-priority pods already claimed every slot on every
    // matching node — priority would be metadata nobody ever acts on.
    // ---------------------------------------------------------------------------

    /// needs_scheduling extracts spec.priority from the watch event.
    ///
    /// If priority is silently dropped here (as it once was), every
    /// pod looks identical to preemption and a high-priority pod can never
    /// legitimately evict a low-priority one.
    #[test]
    fn needs_scheduling_returns_priority_from_event() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "high-pod", "namespace": "default" },
                "spec": { "priority": 1000 }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.priority, 1000,
            "spec.priority must be extracted from the watch event — otherwise \
             preemption cannot distinguish this pod from a default-priority one"
        );
    }

    /// A pod with no spec.priority (no PriorityClass resolved) must default to 0,
    /// the lowest rung — matching Kubernetes' default pod priority. Without this
    /// default, such pods would be indistinguishable from `Option::None` and
    /// preemption's integer comparisons would need special-casing everywhere.
    #[test]
    fn needs_scheduling_defaults_priority_to_zero_when_absent() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "plain-pod", "namespace": "default" },
                "spec": {}
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.priority, 0,
            "a pod with no priority set must default to 0, not be treated as \
             missing/unschedulable"
        );
    }

    /// The node cache `pick_node`/`find_preemption_plan`/`fetch_node` read in
    /// place of a live GET /api/v1/nodes must track ADDED/MODIFIED/DELETED
    /// events and `clear` the same way the pod tally already does — a
    /// phantom or missing node here would let the scheduler bind onto a node
    /// that no longer exists, or never even consider one that does.
    #[test]
    fn node_tally_node_cache_tracks_added_modified_deleted_and_clear() {
        let mut tally = NodeTally::default();
        tally.apply_node_event(&json!({
            "type": "ADDED",
            "object": {"metadata": {"name": "worker-0"}, "status": {"allocatable": {"cpu": "2"}}}
        }));
        assert_eq!(
            tally.node("worker-0").map(|n| n.status.allocatable.cpu),
            Some("2".to_owned()),
            "an ADDED node event must be visible via node()/node_list() — this is what \
             pick_node/find_preemption_plan/fetch_node read in place of a live GET"
        );

        tally.apply_node_event(&json!({
            "type": "MODIFIED",
            "object": {"metadata": {"name": "worker-0"}, "status": {"allocatable": {"cpu": "4"}}}
        }));
        assert_eq!(
            tally.node("worker-0").map(|n| n.status.allocatable.cpu),
            Some("4".to_owned()),
            "a MODIFIED event (e.g. a capacity change) must overwrite the cached node, \
             not stack a second entry — a stale cpu figure here would mis-schedule pods \
             against capacity the node no longer has (or now has)"
        );

        tally.apply_node_event(&json!({
            "type": "DELETED",
            "object": {"metadata": {"name": "worker-0"}}
        }));
        assert!(
            tally.node("worker-0").is_none(),
            "a DELETED node event must remove it from the cache — otherwise pick_node \
             could still bind a pod onto a node that no longer exists in the cluster"
        );

        tally.apply_node_event(&json!({
            "type": "ADDED",
            "object": {"metadata": {"name": "worker-1"}, "status": {}}
        }));
        tally.clear_node_cache();
        assert!(
            tally.node_list().items.is_empty(),
            "clear_node_cache must drop every cached node, the same way a pod watch \
             reconnect clears the pod tally — otherwise a node removed while this watch \
             was disconnected could survive here as a phantom entry forever"
        );
    }

    // NodeTally.pods_on tests — the per-node pod listing that drives
    // preemption victim selection. Unlike usage_by_node, this retains
    // identity (to DELETE the victim) and priority (to decide if it's a
    // legal victim).

    /// NodeTally excludes terminal-phase pods from `pods_on` (they are not
    /// occupying a slot, so evicting them would help nobody) and extracts
    /// each pod's key and priority.
    #[test]
    fn node_tally_pods_on_excludes_terminal_phases_and_extracts_priority() {
        let mut tally = NodeTally::default();
        tally.apply_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "a", "namespace": "ns1"},
                "spec": {"nodeName": "worker-0", "priority": 100},
                "status": {"phase": "Running"}
            }
        }));
        tally.apply_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "b", "namespace": "ns1"},
                "spec": {"nodeName": "worker-0", "priority": 5},
                "status": {"phase": "Succeeded"}
            }
        }));

        let pods = tally.pods_on("worker-0");
        assert_eq!(
            pods.len(),
            1,
            "a Succeeded pod is not consuming a slot and must never be offered as \
             a preemption victim"
        );
        assert_eq!(pods[0].key, "ns1/a");
        assert_eq!(pods[0].priority, 100);
    }

    /// A pod with no spec.priority must default to 0 via `pods_on` too — the
    /// same default `needs_scheduling` applies, so a pending pod at priority
    /// 1 can still legally preempt it.
    #[test]
    fn node_tally_pods_on_defaults_priority_to_zero_when_absent() {
        let mut tally = NodeTally::default();
        tally.apply_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "a", "namespace": "default"},
                "spec": {"nodeName": "worker-0"},
                "status": {"phase": "Running"}
            }
        }));

        let pods = tally.pods_on("worker-0");
        assert_eq!(
            pods[0].priority, 0,
            "a node-resident pod with no priority set must default to 0"
        );
    }

    /// NodeTally must also capture each pod's own resource requests
    /// (including extended resources) — without this, select_preemption_victims
    /// has no way to know how much capacity evicting a given pod would
    /// actually free, and can never select victims by resource shortage, only
    /// by pod-count.
    #[test]
    fn node_tally_pods_on_captures_resource_requests() {
        let mut tally = NodeTally::default();
        tally.apply_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "victim", "namespace": "default"},
                "spec": {
                    "nodeName": "worker-0",
                    "priority": 1,
                    "containers": [
                        { "resources": { "requests": { "scheduling.k8s.io/foo": "1" } } }
                    ]
                },
                "status": {"phase": "Running"}
            }
        }));

        let pods = tally.pods_on("worker-0");
        assert_eq!(
            pods[0].requests.extended.get("scheduling.k8s.io/foo"),
            Some(&1000),
            "a preemption candidate's extended-resource request must be captured \
             so evicting it is known to free that resource"
        );
    }

    // select_preemption_victims tests — the victim-selection decision at the
    // heart of preemption.

    fn np(key: &str, priority: i32) -> NodePod {
        NodePod {
            key: key.to_owned(),
            priority,
            requests: ResourceRequests::default(),
            pvc_names: Vec::new(),
        }
    }

    /// A NodePod that additionally requests `amount` of extended resource
    /// `name` — for the resource-dimension (not just pod-count) preemption
    /// tests below.
    fn np_extended(key: &str, priority: i32, name: &str, amount: i64) -> NodePod {
        let mut requests = ResourceRequests::default();
        requests.extended.insert(name.to_owned(), amount);
        NodePod {
            key: key.to_owned(),
            priority,
            requests,
            pvc_names: Vec::new(),
        }
    }

    /// A full node's only lower-priority pod must be selected as a victim.
    /// Without this, a higher-priority pod stays Pending forever whenever a
    /// lower-priority pod got scheduled first — priority would be meaningless.
    #[test]
    fn select_preemption_victims_evicts_lower_priority_pod_when_node_is_full() {
        let node_pods = vec![np("default/low", 1)];
        let victims = select_preemption_victims(
            100,
            &ResourceRequests::default(),
            &node_pods,
            1,
            &NodeAllocatable::default(),
        );
        assert_eq!(
            victims,
            vec!["default/low".to_owned()],
            "the node's only pod is lower priority and must be evicted to fit \
             the pending pod"
        );
    }

    /// kube-scheduler never preempts equal-or-higher-priority pods; if u7s did,
    /// same-priority pods could evict each other in a cycle and scheduling would
    /// never stabilize.
    #[test]
    fn select_preemption_victims_never_evicts_equal_or_higher_priority_pods() {
        let node_pods = vec![np("default/same", 100), np("default/higher", 500)];
        let victims = select_preemption_victims(
            100,
            &ResourceRequests::default(),
            &node_pods,
            1,
            &NodeAllocatable::default(),
        );
        assert!(
            victims.is_empty(),
            "equal/higher priority pods must never be preemption victims — got {victims:?}"
        );
    }

    /// If the pending pod already fits (the node has a free slot), no eviction may
    /// happen — killing a running workload when there was room to spare would be
    /// a pure regression, not preemption.
    #[test]
    fn select_preemption_victims_returns_empty_when_pod_already_fits() {
        let node_pods = vec![np("default/low", 1)];
        let victims = select_preemption_victims(
            100,
            &ResourceRequests::default(),
            &node_pods,
            5,
            &NodeAllocatable::default(),
        );
        assert!(
            victims.is_empty(),
            "no eviction is needed when the node already has free capacity; got {victims:?}"
        );
    }

    /// If evicting every eligible lower-priority pod still would not free enough
    /// capacity, preemption must give up rather than evict pods for nothing — the
    /// pending pod would still not fit, so the disruption would help no one.
    #[test]
    fn select_preemption_victims_returns_empty_when_evicting_all_lower_priority_pods_still_not_enough(
    ) {
        // capacity=1, 3 pods present → 3 slots must free (needed = 3-1+1 = 3).
        // Only one pod (priority 1) is an eligible (lower-priority) victim; the
        // other two outrank the pending pod and can never be evicted. Evicting
        // the sole eligible pod only frees 1 of the 3 needed slots.
        let node_pods = vec![
            np("default/low", 1),
            np("default/high-1", 500),
            np("default/high-2", 500),
        ];
        let victims = select_preemption_victims(
            100,
            &ResourceRequests::default(),
            &node_pods,
            1,
            &NodeAllocatable::default(),
        );
        assert!(
            victims.is_empty(),
            "must not evict any pod when doing so still would not free enough \
             capacity for the pending pod; got {victims:?}"
        );
    }

    /// When several lower-priority pods are eligible but only one eviction is
    /// needed, preemption must evict the cheapest (lowest-priority) pod and no
    /// more than necessary — over-eviction disrupts workloads for no benefit.
    #[test]
    fn select_preemption_victims_evicts_lowest_priority_first_and_no_more_than_needed() {
        let node_pods = vec![np("default/mid", 50), np("default/lowest", 1)];
        // capacity=2, used=2 (node exactly full) → needed = 2-2+1 = 1 slot.
        let victims = select_preemption_victims(
            100,
            &ResourceRequests::default(),
            &node_pods,
            2,
            &NodeAllocatable::default(),
        );
        assert_eq!(
            victims,
            vec!["default/lowest".to_owned()],
            "must evict the single lowest-priority pod, not the mid-priority one, \
             and must not evict more pods than needed to fit the pending pod"
        );
    }

    /// A node with unknown pod-capacity (0 — see parse_pod_capacity) is treated as
    /// unlimited by select_node_with_capacity, so pick_node would already have
    /// chosen it; preemption must never trigger for such a node.
    #[test]
    fn select_preemption_victims_returns_empty_for_unknown_capacity_node() {
        let node_pods = vec![np("default/low", 1)];
        let victims = select_preemption_victims(
            100,
            &ResourceRequests::default(),
            &node_pods,
            0,
            &NodeAllocatable::default(),
        );
        assert!(
            victims.is_empty(),
            "unknown capacity (0) must never trigger eviction; got {victims:?}"
        );
    }

    fn node_allocatable_extended(name: &str, capacity: &str) -> NodeAllocatable {
        NodeAllocatable {
            extended: [(name.to_owned(), capacity.to_owned())].into(),
            ..Default::default()
        }
    }

    fn extended_request(name: &str, amount: i64) -> ResourceRequests {
        let mut r = ResourceRequests::default();
        r.extended.insert(name.to_owned(), amount);
        r
    }

    // select_preemption_victims extended-resource tests: the SchedulerPreemption
    // conformance suite exhausts a synthetic extended resource
    // (`scheduling.k8s.io/foo`), never pod-count or cpu/memory. Before this
    // fix, select_preemption_victims only understood pod-count, so a node
    // with 1 pod against a 110-pod cap always looked "not full", and a
    // higher-priority pod blocked purely by an exhausted extended resource
    // could never trigger eviction — it stayed unschedulable forever, and the
    // real kubelet then rejected it outright (OutOf<resource>) once bound.

    /// The exact SchedulerPreemption conformance shape: a node advertises 1
    /// unit of a fake extended resource, a low-priority pod holds it, and a
    /// higher-priority pod wants the same unit. Pod-count capacity is huge
    /// (110) and never binding — only the extended resource is scarce.
    #[test]
    fn select_preemption_victims_evicts_lower_priority_pod_for_extended_resource_shortage() {
        let node_pods = vec![np_extended(
            "default/victim",
            1,
            "scheduling.k8s.io/foo",
            1000,
        )];
        let victims = select_preemption_victims(
            1000,
            &extended_request("scheduling.k8s.io/foo", 1000),
            &node_pods,
            110,
            &node_allocatable_extended("scheduling.k8s.io/foo", "1"),
        );
        assert_eq!(
            victims,
            vec!["default/victim".to_owned()],
            "a pending pod blocked purely by an exhausted extended resource must \
             still evict the lower-priority pod holding it — pod-count alone is \
             not the only capacity dimension preemption must recognize"
        );
    }

    /// Live-reproduced regression: on a node short on an extended resource, a
    /// zero-priority pod that holds NONE of that resource (e.g. coredns,
    /// which never requests `scheduling.k8s.io/foo`) must never be evicted
    /// just because its priority happens to be lower than the actual
    /// resource-holding victim's — evicting it frees nothing relevant and
    /// only causes collateral damage. Caught by manually reproducing the
    /// SchedulerPreemption conformance scenario against a live stack: the
    /// first version of this fix evicted kube-system/coredns and
    /// kube-system/konnectivity-agent (priority 0, no `scheduling.k8s.io/foo`
    /// request) instead of the pod actually holding the contended resource.
    #[test]
    fn select_preemption_victims_never_evicts_a_pod_holding_none_of_the_short_resource() {
        let node_pods = vec![
            // Lower priority than the resource-holder, but requests nothing —
            // must be skipped even though it is the "cheapest" by priority.
            np("kube-system/irrelevant-system-pod", 0),
            np_extended("default/victim", 1, "scheduling.k8s.io/foo", 1000),
        ];
        let victims = select_preemption_victims(
            1000,
            &extended_request("scheduling.k8s.io/foo", 1000),
            &node_pods,
            110,
            &node_allocatable_extended("scheduling.k8s.io/foo", "1"),
        );
        assert_eq!(
            victims,
            vec!["default/victim".to_owned()],
            "must evict only the pod actually holding the contended resource, \
             never the lower-priority pod that holds none of it; got {victims:?}"
        );
    }

    /// If the extended resource the pending pod wants is not actually
    /// exhausted, no eviction may happen — mirrors
    /// `select_preemption_victims_returns_empty_when_pod_already_fits` for the
    /// extended-resource dimension specifically.
    #[test]
    fn select_preemption_victims_returns_empty_when_extended_resource_already_fits() {
        let node_pods = vec![np_extended("default/low", 1, "scheduling.k8s.io/foo", 1000)];
        let victims = select_preemption_victims(
            100,
            &extended_request("scheduling.k8s.io/foo", 1000),
            &node_pods,
            110,
            &node_allocatable_extended("scheduling.k8s.io/foo", "5"),
        );
        assert!(
            victims.is_empty(),
            "1 of 5 units already used plus a 1-unit request still fits — no \
             pod should be evicted; got {victims:?}"
        );
    }

    /// When a single victim's extended-resource share is not enough, preemption
    /// must keep evicting (lowest priority first) until the deficit is
    /// actually cleared — mirrors the pod-count "minimal but sufficient"
    /// eviction test for the extended-resource dimension.
    #[test]
    fn select_preemption_victims_evicts_multiple_pods_to_clear_extended_resource_deficit() {
        let node_pods = vec![
            np_extended("default/lowest", 1, "scheduling.k8s.io/foo", 1000),
            np_extended("default/mid", 50, "scheduling.k8s.io/foo", 1000),
        ];
        // capacity=2 units, both used (2/2) — pending needs 2 more, so BOTH
        // existing pods must go; evicting only one frees just 1 of the 2 needed.
        let victims = select_preemption_victims(
            100,
            &extended_request("scheduling.k8s.io/foo", 2000),
            &node_pods,
            110,
            &node_allocatable_extended("scheduling.k8s.io/foo", "2"),
        );
        assert_eq!(
            victims,
            vec!["default/lowest".to_owned(), "default/mid".to_owned()],
            "evicting only the lowest-priority pod is not enough to clear a \
             2-unit deficit that needs both pods freed; got {victims:?}"
        );
    }

    // delete_pod_path / check_delete_response tests — the eviction request shape
    // and error handling, mirroring binding_path / check_bind_response.

    #[test]
    fn delete_pod_path_produces_correct_api_path() {
        let path = delete_pod_path("default", "victim-pod");
        assert_eq!(path, "/api/v1/namespaces/default/pods/victim-pod");
    }

    /// A 404 means the victim is already gone (e.g. a retried eviction) — that is
    /// the desired end state, so it must be treated as success, not an error that
    /// aborts the rest of the preemption flow.
    #[test]
    fn check_delete_response_ok_on_404_already_gone() {
        assert!(
            check_delete_response(404).is_ok(),
            "404 (already deleted) must be treated as success for eviction"
        );
    }

    #[test]
    fn check_delete_response_ok_on_2xx() {
        assert!(check_delete_response(200).is_ok());
        assert!(check_delete_response(202).is_ok());
    }

    /// `delete_pod`'s single soft-delete can race a concurrent write to the same
    /// victim (e.g. the kubelet's routine status sync while it terminates, or
    /// another in-flight preemption evicting the same pod) and lose with a 409.
    /// That is a benign "already changing" signal, not a real failure —
    /// treating it as a hard error aborts the entire preemption `?`-chain in
    /// main.rs's eviction loop, leaving the higher-priority preemptor pod stuck
    /// Pending until a passive watch reconnect minutes later, well past
    /// conformance test timeouts.
    #[test]
    fn check_delete_response_ok_on_409_conflict() {
        assert!(
            check_delete_response(409).is_ok(),
            "409 from a benign concurrent-write race on the victim must be tolerated, or a \
             single benign conflict aborts the whole preemption cycle and strands the preemptor"
        );
    }

    /// A genuine failure (e.g. 500, or 403 if RBAC forbids the scheduler from
    /// deleting pods) must surface as Err so the caller aborts rather than binding
    /// the preemptor onto a node that never actually freed capacity.
    #[test]
    fn check_delete_response_err_on_failure() {
        assert!(check_delete_response(500).is_err());
        assert!(check_delete_response(403).is_err());
    }

    /// `delete_pod` must send the eviction DELETE exactly once, not twice.
    ///
    /// An earlier version force-issued the DELETE twice back-to-back
    /// (soft-delete, then an immediate second call the apiserver treats as
    /// "already Terminating, no finalizers" and hard-deletes) to drive a
    /// preemption victim straight to gone. That made the victim disappear
    /// from the apiserver in about a second — too fast for upstream's e2e
    /// preemption test (`test/e2e/scheduling/preemption.go`, 1s poll
    /// interval) to ever observe the "DeletionTimestamp set, still Gettable"
    /// state it polls for, so the test failed with `Pod ... not found`.
    ///
    /// Drives `delete_pod` against a real in-process TLS mock server so the
    /// number of requests actually sent over the wire — not a mocked return
    /// value — is what's under test. Fails on revert: reinstating the
    /// `for _ in 0..2` loop makes the mock server observe two connections
    /// instead of one.
    #[tokio::test]
    async fn delete_pod_sends_exactly_one_delete_request() {
        use rcgen::{CertificateParams, KeyPair, SanType};
        use rustls::pki_types::PrivateKeyDer;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        // A single self-signed cert for 127.0.0.1, trusted directly by the
        // client as its own root — no separate CA needed for this test.
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

        // Counts distinct TLS connections handled — HyperApiClient opens a
        // fresh connection per request, so this is exactly the DELETE count.
        let requests_seen = Arc::new(AtomicUsize::new(0));
        let requests_seen_srv = requests_seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let requests_seen = requests_seen_srv.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = vec![0u8; 4096];
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
                    // Incrementing before writing the response guarantees the
                    // caller's `delete_pod().await` cannot return until this
                    // is visible: it only completes once it has read the
                    // response we write right after.
                    requests_seen.fetch_add(1, Ordering::SeqCst);
                    let body = r#"{"kind":"Status","status":"Success"}"#;
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
        delete_pod(&connector, &server, "default", "victim")
            .await
            .expect("delete_pod must succeed against a mock server that returns 200");

        assert_eq!(
            requests_seen.load(Ordering::SeqCst),
            1,
            "delete_pod must issue exactly one DELETE — a second, immediate force-delete makes \
             the preemption victim disappear from the apiserver before upstream's 1s-interval \
             e2e poll can ever observe it Terminating with a DeletionTimestamp"
        );
    }

    // disruption_target_patch tests: upstream kube-scheduler stamps a
    // DisruptionTarget condition on a preemption victim before
    // deleting it. Before this fix u7s's preemption path deleted victims with
    // no condition at all, so `validates pod disruption condition is added to
    // the preempted pod` failed even when eviction itself worked correctly —
    // the eviction mechanism and the status bookkeeping are separate gaps.

    /// The condition type/status/reason must match what
    /// `VerifyPodHasConditionWithType` (test/e2e/framework/pod/resource.go)
    /// and `kubectl describe pod` expect from a real scheduler preemption:
    /// `DisruptionTarget`/`True`/`PreemptionByScheduler`.
    #[test]
    fn disruption_target_patch_sets_condition_type_status_and_reason() {
        let patch = disruption_target_patch("preemptor-pod");
        let condition = &patch["status"]["conditions"][0];
        assert_eq!(condition["type"], "DisruptionTarget");
        assert_eq!(condition["status"], "True");
        assert_eq!(
            condition["reason"], "PreemptionByScheduler",
            "the reason must match upstream's v1.PodReasonPreemptionByScheduler, \
             not a made-up string — it tells `kubectl describe pod` who evicted \
             the pod and why"
        );
    }

    /// The message must name the preemptor pod so a user reading `kubectl
    /// describe pod` on the victim can tell which pod displaced it.
    #[test]
    fn disruption_target_patch_message_names_the_preemptor() {
        let patch = disruption_target_patch("high-priority-pod");
        let message = patch["status"]["conditions"][0]["message"]
            .as_str()
            .expect("message must be a string");
        assert!(
            message.contains("high-priority-pod"),
            "the message must reference the preemptor pod by name; got {message:?}"
        );
    }

    // nominated_node_name_patch tests: before this fix u7s's scheduler never
    // wrote status.nominatedNodeName at all, so any client (kubectl, or the
    // SchedulerAsyncPreemption e2e test) polling for it after a preemption
    // plan is committed saw it stay empty forever, even though the pod later
    // bound and ran correctly — the nomination and the eventual bind are
    // separate, and only the latter existed.

    /// Must produce exactly `{"status":{"nominatedNodeName":"<node>"}}` — the
    /// apiserver's status-patch merge (`apply_status_patch`) treats
    /// `nominatedNodeName` as a plain scalar merge-patch field, so any other
    /// shape (nesting, wrapping, wrong key name/casing) would silently fail
    /// to set the field a client is polling for.
    #[test]
    fn nominated_node_name_patch_yields_status_patch_with_target_node() {
        let patch = nominated_node_name_patch("node-a");
        assert_eq!(
            patch,
            json!({"status": {"nominatedNodeName": "node-a"}}),
            "patch body must be exactly {{status: {{nominatedNodeName}}}} — a client \
             polling status.nominatedNodeName only ever reads this exact shape"
        );
    }

    /// The chosen node's name must round-trip verbatim into the patch — a
    /// preemptor nominated for the wrong node would send eviction-watching
    /// tooling (and any downstream scheduler decision reading nominations)
    /// to look at the wrong place entirely.
    #[test]
    fn nominated_node_name_patch_names_the_planned_node() {
        let patch = nominated_node_name_patch("worker-7");
        assert_eq!(patch["status"]["nominatedNodeName"], "worker-7");
    }

    // ---------------------------------------------------------------------------
    // Scheduling Events: scheduling_event_name/scheduling_event_payload
    // /events_path. Before this fix the scheduler never created an Event object on
    // bind success or failure, so `kubectl describe pod` showed nothing and the
    // SchedulerPredicates e2e suite's observeEventAfterAction watch timed out
    // waiting for a FailedScheduling/Scheduled event that was never posted.
    // ---------------------------------------------------------------------------

    /// scheduling_event_name must start with pod_name — upstream's
    /// scheduleFailureEvent/scheduleSuccessEvent predicates match on
    /// `strings.HasPrefix(e.Name, podName)`. A name that doesn't start with the
    /// pod name would make a correctly-created event invisible to that check.
    #[test]
    fn scheduling_event_name_starts_with_pod_name() {
        let name = scheduling_event_name("my-pod", 0x1234abcd);
        assert!(
            name.starts_with("my-pod"),
            "event name must start with pod_name for upstream's HasPrefix match; got {name}"
        );
    }

    /// Two events for the same pod at different times must get distinct names —
    /// otherwise the second POST would collide with (and be rejected as a
    /// duplicate of) the first.
    #[test]
    fn scheduling_event_name_is_unique_per_nanos() {
        let a = scheduling_event_name("my-pod", 1);
        let b = scheduling_event_name("my-pod", 2);
        assert_ne!(
            a, b,
            "distinct timestamps must produce distinct event names to avoid create collisions"
        );
    }

    /// scheduling_event_payload must set reason/type/message exactly as given —
    /// this is what upstream's predicate matches on (e.Type == "Warning" &&
    /// e.Reason == "FailedScheduling" for the failure case).
    #[test]
    fn scheduling_event_payload_sets_failure_fields() {
        let payload = scheduling_event_payload(
            "sched-pred",
            "unschedulable-pod",
            "unschedulable-pod.abc123",
            "FailedScheduling",
            "0/1 nodes are available: node(s) didn't match Pod's node affinity/selector.",
            "Warning",
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(payload["kind"], "Event");
        assert_eq!(payload["apiVersion"], "v1");
        assert_eq!(payload["reason"], "FailedScheduling");
        assert_eq!(payload["type"], "Warning");
        assert_eq!(payload["metadata"]["name"], "unschedulable-pod.abc123");
        assert_eq!(payload["metadata"]["namespace"], "sched-pred");
    }

    /// scheduling_event_payload's involvedObject must reference the pod by name,
    /// namespace, and kind "Pod" — without this, the event exists but cannot be
    /// correlated back to the pod it reports on (`kubectl describe pod` filters
    /// events by involvedObject).
    #[test]
    fn scheduling_event_payload_involved_object_references_pod() {
        let payload = scheduling_event_payload(
            "staging",
            "web-pod",
            "web-pod.deadbeef",
            "Scheduled",
            "Successfully assigned staging/web-pod to worker-2",
            "Normal",
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(payload["involvedObject"]["kind"], "Pod");
        assert_eq!(payload["involvedObject"]["name"], "web-pod");
        assert_eq!(payload["involvedObject"]["namespace"], "staging");
    }

    /// scheduling_event_payload's message must be preserved verbatim — upstream's
    /// scheduleSuccessEvent predicate checks
    /// `strings.Contains(e.Message, "Successfully assigned ns/pod to node")`.
    #[test]
    fn scheduling_event_payload_preserves_message() {
        let payload = scheduling_event_payload(
            "default",
            "my-pod",
            "my-pod.123",
            "Scheduled",
            "Successfully assigned default/my-pod to node-1",
            "Normal",
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(
            payload["message"], "Successfully assigned default/my-pod to node-1",
            "message must be preserved verbatim for the success-event Contains() check"
        );
    }

    /// scheduling_event_payload must set firstTimestamp/lastTimestamp to the given
    /// timestamp, not leave them null. Real kube-scheduler always sets both on a
    /// newly created Event; a null firstTimestamp/lastTimestamp makes `kubectl get
    /// events`'s AGE column show `<unknown>` and breaks any client that sorts or
    /// filters Events by age (e.g. the Event garbage collector, or a conformance
    /// wait that only accepts events newer than a cutoff).
    #[test]
    fn scheduling_event_payload_sets_first_and_last_timestamp() {
        let payload = scheduling_event_payload(
            "default",
            "my-pod",
            "my-pod.123",
            "Scheduled",
            "Successfully assigned default/my-pod to node-1",
            "Normal",
            "2026-07-28T14:45:00Z",
        );
        assert_eq!(
            payload["firstTimestamp"], "2026-07-28T14:45:00Z",
            "firstTimestamp must carry the real creation time, not be left null"
        );
        assert_eq!(
            payload["lastTimestamp"], "2026-07-28T14:45:00Z",
            "lastTimestamp must carry the real creation time, not be left null"
        );
    }

    /// scheduling_event_timestamp must produce a timestamp client-go and kubectl
    /// can actually parse and read back the same instant from — a wrong calendar
    /// conversion would silently corrupt every Event's displayed age without
    /// ever failing an HTTP call or a schema check.
    #[test]
    fn scheduling_event_timestamp_matches_known_epoch_offset() {
        let nanos = 1_704_067_200u128 * 1_000_000_000;
        assert_eq!(
            scheduling_event_timestamp(nanos),
            "2024-01-01T00:00:00Z",
            "a known Unix timestamp must convert to its correct RFC3339 calendar date"
        );
    }

    #[test]
    fn events_path_produces_correct_api_path() {
        let path = events_path("kube-system");
        assert_eq!(path, "/api/v1/namespaces/kube-system/events");
    }

    // ---------------------------------------------------------------------------
    // csi_volume_limits_fit / CSILimits predicate — a pod exceeding the CSI
    // driver's advertised per-node attach limit (CSINode.spec.drivers[].
    // allocatable.count) must stay Pending/Unschedulable instead of running: a
    // node's real hardware/driver cannot actually attach more volumes than it
    // advertises, so binding past the limit leaves the kubelet stuck retrying
    // a mount that can never succeed. Before this predicate existed,
    // `crates/scheduler/src/lib.rs` had zero notion of CSINode allocatable
    // counts and an over-limit pod scheduled and ran anyway.
    // ---------------------------------------------------------------------------

    #[test]
    fn csi_volume_limits_fit_rejects_a_driver_at_its_advertised_limit() {
        // Node already has 2 volumes of "hostpath.csi.k8s.io" attached (headroom
        // 0 remaining out of a limit of 2); the pending pod needs one more of
        // the SAME driver. Reverting this predicate would let the pod bind onto
        // a node the CSI driver itself says it cannot serve.
        let headroom = [("hostpath.csi.k8s.io".to_owned(), 0i64)].into();
        let wants = [("hostpath.csi.k8s.io".to_owned(), 1i64)].into();
        assert!(
            !csi_volume_limits_fit(&headroom, &wants),
            "a pod requesting one more volume than a driver's remaining headroom must not fit"
        );
    }

    #[test]
    fn csi_volume_limits_fit_allows_a_driver_with_remaining_headroom() {
        let headroom = [("hostpath.csi.k8s.io".to_owned(), 3i64)].into();
        let wants = [("hostpath.csi.k8s.io".to_owned(), 1i64)].into();
        assert!(
            csi_volume_limits_fit(&headroom, &wants),
            "a pod requesting fewer volumes than remaining headroom must fit"
        );
    }

    #[test]
    fn csi_volume_limits_fit_does_not_check_a_driver_with_no_advertised_limit() {
        // Mirrors resource_fits' "unknown capacity means unchecked" convention:
        // a driver absent from CSINode's allocatable map advertises no limit at
        // all, so requesting it must never be treated as a fail-closed reject.
        let headroom = std::collections::BTreeMap::new();
        let wants = [("some-other.csi.k8s.io".to_owned(), 5i64)].into();
        assert!(
            csi_volume_limits_fit(&headroom, &wants),
            "a driver with no advertised limit must not block scheduling"
        );
    }

    #[test]
    fn csi_volume_limits_fit_is_true_when_pod_needs_no_csi_volumes() {
        let headroom = [("hostpath.csi.k8s.io".to_owned(), 0i64)].into();
        assert!(
            csi_volume_limits_fit(&headroom, &std::collections::BTreeMap::new()),
            "a pod needing no CSI volumes must never be blocked by a volume-count predicate"
        );
    }

    // ---------------------------------------------------------------------------
    // csi_topology_fit / the VolumeBinding provisioning-topology predicate — a
    // pod whose own unbound PVC still needs a CSI driver provisioned must not
    // be bound to a node that driver has never registered on (CSINode). The
    // csi-hostpath e2e driver runs as a single-replica StatefulSet: without
    // this predicate, a "populate" pod (lib-volume-populator) can land on the
    // node WITHOUT the driver, its prime PVC's eventual PV gets a nodeAffinity
    // pinning it to the driver's real node, and the kubelet blocks forever on
    // `MountVolume.NodeAffinity check failed` — the AnyVolumeDataSource
    // conformance hang this predicate exists to close.
    // ---------------------------------------------------------------------------

    #[test]
    fn csi_topology_fit_false_when_node_does_not_register_required_driver() {
        let registered: std::collections::HashSet<String> = Default::default();
        let wants = vec!["csi-hostpath-provisioning-6547".to_owned()];
        assert!(
            !csi_topology_fit(&registered, &wants),
            "a node whose CSINode does not register the driver a pod's unbound \
             PVC needs must not be treated as feasible — its eventual PV can \
             only be mounted where the driver actually runs"
        );
    }

    #[test]
    fn csi_topology_fit_true_when_node_registers_required_driver() {
        let registered: std::collections::HashSet<String> =
            ["csi-hostpath-provisioning-6547".to_owned()].into();
        let wants = vec!["csi-hostpath-provisioning-6547".to_owned()];
        assert!(
            csi_topology_fit(&registered, &wants),
            "a node whose CSINode registers the exact driver a pod's unbound \
             PVC needs must qualify"
        );
    }

    #[test]
    fn csi_topology_fit_is_true_when_pod_has_no_unbound_csi_pvcs() {
        let registered: std::collections::HashSet<String> = Default::default();
        assert!(
            csi_topology_fit(&registered, &[]),
            "a pod with no unbound CSI-backed PVCs must never be blocked by \
             this predicate, regardless of what any node's CSINode registers"
        );
    }

    /// Mirrors the AnyVolumeDataSource populate-pod scenario end to end: the
    /// csi-hostpath driver's single replica registers only on `driver-node`'s
    /// CSINode, a second node does not — and, the trap that makes this
    /// fail-on-revert meaningful, the WRONG node is the LESS loaded one, so
    /// the ordinary least-loaded tie-break would prefer it if the
    /// `csi_topology_fit` conjunct did not filter it out first.
    #[test]
    fn select_node_with_capacity_binds_to_node_registering_unbound_csi_pvcs_driver_over_less_loaded_node(
    ) {
        const DRIVER: &str = "csi-hostpath-provisioning-6547";
        let driver_node = make_node_with_capacity("lima-node-4", &[], "110");
        let other_node = make_node_with_capacity("lima-node-3", &[], "110");
        let mut list = NodeList {
            items: vec![driver_node, other_node],
        };
        list.items[0].csi_registered_drivers = [DRIVER.to_owned()].into();
        let mut pod = empty_pending_pod();
        pod.unbound_csi_pvc_drivers = vec![DRIVER.to_owned()];
        let counts: std::collections::HashMap<String, NodeUsage> = [
            ("lima-node-4".to_owned(), usage_with_pod_count(5)),
            ("lima-node-3".to_owned(), usage_with_pod_count(0)),
        ]
        .into();
        let result = select_node_with_capacity(list, &pod, &counts, &[]);
        assert_eq!(
            result.ok(),
            Some("lima-node-4".to_owned()),
            "must bind to the node registering the unbound PVC's CSI driver \
             even though the other node is less loaded — reverting the \
             csi_topology_fit conjunct picks lima-node-3 by the ordinary \
             least-loaded tie-break, exactly the bug that stranded the \
             lib-volume-populator populate pod on a node without the \
             csi-hostpath driver and hung the AnyVolumeDataSource e2e test"
        );
    }

    /// When NO node has registered the driver yet (e.g. its single-replica
    /// StatefulSet is still starting), the pod must stay Pending rather than
    /// be scheduled to an arbitrary node — mirrors upstream: a provisioning
    /// claim's driver location being unknown is never "any node will do".
    #[test]
    fn select_node_with_capacity_leaves_pod_pending_when_no_node_registers_the_required_driver() {
        let list = NodeList {
            items: vec![
                make_node_with_capacity("lima-node-4", &[], "110"),
                make_node_with_capacity("lima-node-3", &[], "110"),
            ],
        };
        let mut pod = empty_pending_pod();
        pod.unbound_csi_pvc_drivers = vec!["csi-hostpath-provisioning-6547".to_owned()];
        let result = select_node_with_capacity(list, &pod, &std::collections::HashMap::new(), &[]);
        assert!(
            result.is_err(),
            "with no node's CSINode registering the driver anywhere, every \
             node must be rejected — not scheduled to a wrong one — so the \
             pod stays Pending until the driver's CSINode registration lands: \
             got {result:?}"
        );
    }

    #[test]
    fn select_node_with_capacity_rejects_a_node_over_its_csi_attach_limit() {
        // Before CSILimits existed, this scenario (a node with zero remaining
        // CSI headroom) had no predicate to reject it at all, so
        // `select_node_with_capacity` would bind the pod here — the exact bug
        // the csi-hostpath `volumeLimits` conformance test caught (pod stayed
        // Running instead of Pending/Unschedulable).
        let mut node = make_node("worker-0", &[]);
        node.csi_driver_headroom = [("hostpath.csi.k8s.io".to_owned(), 0i64)].into();
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.csi_volume_counts = [("hostpath.csi.k8s.io".to_owned(), 1i64)].into();
        let usage = std::collections::HashMap::new();
        let err = select_node_with_capacity(list, &pod, &usage, &[])
            .expect_err("a node with no remaining CSI attach headroom must not be selected");
        // The conformance test's PodScheduled=False condition message is
        // matched against the regex `max.+volume.+count` — asserting the
        // literal upstream-equivalent text here, not just Err(_), so a future
        // change that silently reverts to the generic NodeResourcesFit
        // message (correct rejection, wrong reason) is caught too.
        assert!(
            err.to_string().contains("max")
                && err.to_string().contains("volume")
                && err.to_string().contains("count"),
            "the rejection reason must mention the volume-count limit (got: {err})"
        );
    }

    #[test]
    fn select_node_with_capacity_allows_a_node_under_its_csi_attach_limit() {
        let mut node = make_node("worker-0", &[]);
        node.csi_driver_headroom = [("hostpath.csi.k8s.io".to_owned(), 1i64)].into();
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.csi_volume_counts = [("hostpath.csi.k8s.io".to_owned(), 1i64)].into();
        let usage = std::collections::HashMap::new();
        let name = select_node_with_capacity(list, &pod, &usage, &[])
            .expect("a node with enough remaining CSI attach headroom must be selected");
        assert_eq!(name, "worker-0");
    }

    /// `select_and_reserve_node`'s tally-backed CSI netting must see a
    /// just-`assume()`d pod's own CSI volume claim on the very next
    /// scheduling decision, with NO pod watch event round-trip in between —
    /// only the PVC/PV/CSINode identity caches (populated once via
    /// `apply_pvc_event`/`apply_pv_event`/`apply_csi_node_event`, which don't
    /// change per bind) need to already be warm. Before this fix, the
    /// "already attached" side was computed via a fresh `GET /api/v1/pods`
    /// per decision: pod-a's bind hadn't landed in that live list yet when
    /// pod-b's scan ran, so two pods needing the same CSI driver's last
    /// remaining volume slot — created in the same `kubectl apply` batch —
    /// both scheduled past the 1-volume limit. The sequential conformance
    /// test never exercises this: each pod there is created and waited-on
    /// before the next, giving the real watch event time to round-trip
    /// through `apply_event` first.
    #[test]
    fn select_and_reserve_node_sees_a_just_assumed_pods_own_csi_volume_via_the_tally() {
        let mut tally = NodeTally::default();
        tally.apply_pvc_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "pvc-a", "namespace": "default" },
                "spec": { "volumeName": "pv-a" }
            }
        }));
        tally.apply_pv_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "pv-a" },
                "spec": { "csi": { "driver": "hostpath.csi.k8s.io" } }
            }
        }));
        tally.apply_csi_node_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "worker-0" },
                "spec": { "drivers": [{ "name": "hostpath.csi.k8s.io", "allocatable": { "count": 1 } }] }
            }
        }));

        let mut pod_a = empty_pending_pod();
        pod_a.pod_name = "pod-a".to_owned();
        pod_a.pvc_names = vec!["pvc-a".to_owned()];
        // No apply_event for pod-a's own bind — assume() alone must be
        // enough for the very next decision to see it.
        tally.assume(
            "default",
            "pod-a",
            "worker-0",
            0,
            ResourceRequests::default(),
            Vec::new(),
            Default::default(),
            pod_a.pvc_names.clone(),
        );

        let tally = std::sync::Mutex::new(tally);
        let mut pod_b = empty_pending_pod();
        pod_b.pod_name = "pod-b".to_owned();
        pod_b.csi_volume_counts = [("hostpath.csi.k8s.io".to_owned(), 1i64)].into();
        let list = NodeList {
            items: vec![make_node_with_capacity("worker-0", &[], "110")],
        };
        let result = select_and_reserve_node(list, &pod_b, &tally);

        assert!(
            result.is_err(),
            "pod-a's assume()d CSI volume claim must already be reflected \
             when pod-b's decision nets fresh headroom under the SAME lock \
             — otherwise pod-b's fit check undercounts the driver's \
             attached volumes and both pods schedule past its 1-volume \
             limit; got: {:?}",
            result.ok()
        );
    }

    /// The exact concurrent-scheduling race this bead fixes, reproduced with
    /// real OS threads instead of a live cluster: `CONTENDERS` pods, each
    /// needing ONE volume from a CSI driver that only has room for exactly
    /// one, lined up on a `Barrier` so as many `select_and_reserve_node`
    /// calls as possible overlap — mirrors
    /// `select_and_reserve_node_never_double_books_a_single_free_slot`'s cpu
    /// version. Before this fix, CSI headroom was netted in a SEPARATE,
    /// earlier lock acquisition than the one that calls `assume()`
    /// (`populate_csi_driver_headroom`, called before `select_and_reserve_node`
    /// ever ran) — narrowing the originally-reported HTTP-round-trip race to
    /// a smaller but still-open mutex-reacquisition gap: two threads could
    /// each snapshot headroom before either committed via `assume()`, so
    /// neither's snapshot reflected the other's reservation, and both would
    /// pass the fit check.
    #[test]
    fn select_and_reserve_node_never_double_books_a_single_csi_volume_slot() {
        let mut tally = NodeTally::default();
        tally.apply_csi_node_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "worker-0" },
                "spec": { "drivers": [{ "name": "hostpath.csi.k8s.io", "allocatable": { "count": 1 } }] }
            }
        }));
        const CONTENDERS: usize = 8;
        for i in 0..CONTENDERS {
            tally.apply_pvc_event(&json!({
                "type": "ADDED",
                "object": {
                    "metadata": { "name": format!("pvc-{i}"), "namespace": "default" },
                    "spec": { "volumeName": format!("pv-{i}") }
                }
            }));
            tally.apply_pv_event(&json!({
                "type": "ADDED",
                "object": {
                    "metadata": { "name": format!("pv-{i}") },
                    "spec": { "csi": { "driver": "hostpath.csi.k8s.io" } }
                }
            }));
        }

        let tally = std::sync::Arc::new(std::sync::Mutex::new(tally));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(CONTENDERS));
        let handles: Vec<_> = (0..CONTENDERS)
            .map(|i| {
                let tally = std::sync::Arc::clone(&tally);
                let barrier = std::sync::Arc::clone(&barrier);
                // Plenty of pod-count/cpu capacity — only the CSI driver's
                // single attach slot is scarce here.
                let list = NodeList {
                    items: vec![make_node_with_capacity("worker-0", &[], "110")],
                };
                let mut pod = empty_pending_pod();
                pod.pod_name = format!("pod-{i}");
                pod.pvc_names = vec![format!("pvc-{i}")];
                pod.csi_volume_counts = [("hostpath.csi.k8s.io".to_owned(), 1i64)].into();
                std::thread::spawn(move || {
                    barrier.wait();
                    select_and_reserve_node(list, &pod, &tally)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            ok_count, 1,
            "exactly one of {CONTENDERS} pods racing for a CSI driver's \
             single remaining attach slot must win — netting CSI headroom \
             in a separate, earlier lock acquisition than the one that \
             calls assume() lets more than one thread see the slot as free \
             and bind, which is the exact concurrent-scheduling race this \
             predicate exists to close; got {ok_count} winners: {results:?}"
        );

        let usage = tally.lock().expect("tally lock poisoned").usage_by_node();
        assert_eq!(
            usage["worker-0"]
                .csi_attached_counts
                .get("hostpath.csi.k8s.io"),
            Some(&1),
            "the tally must reflect exactly one CSI volume reservation \
             after the race settles, not zero (a lost update) or more than \
             one (double-booked)"
        );
    }

    /// `verify_and_reserve_preemption`'s counterpart to
    /// `select_and_reserve_node_never_double_books_a_single_csi_volume_slot`:
    /// its final CSI re-check must also be fresh under the SAME lock as its
    /// own `assume()`, not the separate, earlier snapshot the search loop
    /// (`find_preemption_candidate`) used — mirrors
    /// `verify_and_reserve_preemption_never_double_books_shared_victims`'s
    /// cpu version. `plan.victims` is empty for every contender: this test
    /// isolates the CSI dimension specifically, so ample pod-count/cpu
    /// capacity must never be what decides the winner here.
    #[test]
    fn verify_and_reserve_preemption_never_double_books_a_single_csi_volume_slot() {
        let mut tally = NodeTally::default();
        tally.apply_csi_node_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "worker-0" },
                "spec": { "drivers": [{ "name": "hostpath.csi.k8s.io", "allocatable": { "count": 1 } }] }
            }
        }));
        const CONTENDERS: usize = 8;
        for i in 0..CONTENDERS {
            tally.apply_pvc_event(&json!({
                "type": "ADDED",
                "object": {
                    "metadata": { "name": format!("pvc-{i}"), "namespace": "default" },
                    "spec": { "volumeName": format!("pv-{i}") }
                }
            }));
            tally.apply_pv_event(&json!({
                "type": "ADDED",
                "object": {
                    "metadata": { "name": format!("pv-{i}") },
                    "spec": { "csi": { "driver": "hostpath.csi.k8s.io" } }
                }
            }));
        }

        let tally = std::sync::Arc::new(std::sync::Mutex::new(tally));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(CONTENDERS));
        let handles: Vec<_> = (0..CONTENDERS)
            .map(|i| {
                let tally = std::sync::Arc::clone(&tally);
                let barrier = std::sync::Arc::clone(&barrier);
                let node = make_node_with_capacity("worker-0", &[], "110");
                let mut pod = empty_pending_pod();
                pod.pod_name = format!("pod-{i}");
                pod.pvc_names = vec![format!("pvc-{i}")];
                pod.csi_volume_counts = [("hostpath.csi.k8s.io".to_owned(), 1i64)].into();
                let plan = PreemptionPlan {
                    node_name: "worker-0".to_owned(),
                    victims: Vec::new(),
                };
                std::thread::spawn(move || {
                    barrier.wait();
                    verify_and_reserve_preemption(&pod, &node, &plan, &tally)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            ok_count, 1,
            "exactly one of {CONTENDERS} preemption plans racing for a CSI \
             driver's single remaining attach slot must win — checking CSI \
             fit against a stale, pre-lock snapshot instead of a fresh \
             in-lock re-check lets more than one thread pass and reserve; \
             got {ok_count} winners: {results:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // read_write_once_pod_conflict_free / read_write_once_pod_preemption_victims
    // — the VolumeRestrictions/ReadWriteOncePod predicate. A PVC with the
    // ReadWriteOncePod access mode is Kubernetes' strictest volume guarantee:
    // at most ONE pod, cluster-wide, may use it at a time. Before this
    // predicate existed, two pods mounting the same ReadWriteOncePod PVC could
    // both bind to the same node with no conflict detected at all — the exact
    // bug the csi-hostpath RWOP preemption conformance test caught.
    // ---------------------------------------------------------------------------

    #[test]
    fn read_write_once_pod_conflict_free_rejects_a_node_already_using_the_pvc() {
        let node_pvc_names = vec!["data-pvc".to_owned()];
        let rwop_pvcs = vec!["data-pvc".to_owned()];
        assert!(
            !read_write_once_pod_conflict_free(&node_pvc_names, &rwop_pvcs),
            "a node where another pod already references the SAME ReadWriteOncePod \
             PVC must not be usable — Kubernetes guarantees at most one pod may \
             mount it at a time"
        );
    }

    #[test]
    fn read_write_once_pod_conflict_free_allows_a_node_with_no_overlapping_pvc() {
        let node_pvc_names = vec!["other-pvc".to_owned()];
        let rwop_pvcs = vec!["data-pvc".to_owned()];
        assert!(
            read_write_once_pod_conflict_free(&node_pvc_names, &rwop_pvcs),
            "an unrelated PVC on the node must never block a pod wanting a \
             DIFFERENT ReadWriteOncePod PVC"
        );
    }

    #[test]
    fn read_write_once_pod_conflict_free_is_true_when_pod_has_no_rwop_pvcs() {
        let node_pvc_names = vec!["data-pvc".to_owned()];
        assert!(
            read_write_once_pod_conflict_free(&node_pvc_names, &[]),
            "a pod with no ReadWriteOncePod PVCs at all must never be blocked by \
             this predicate, regardless of what else is on the node"
        );
    }

    #[test]
    fn select_node_with_capacity_rejects_a_node_where_another_pod_already_uses_the_rwop_pvc() {
        // Regression test: before this predicate existed, `select_node_with_capacity`
        // had no notion of PVC access modes at all, so a second pod wanting the
        // same ReadWriteOncePod PVC as an already-tallied pod on this node would
        // have been bound right alongside it.
        let list = NodeList {
            items: vec![make_node("worker-0", &[])],
        };
        let mut pod = empty_pending_pod();
        pod.read_write_once_pod_pvcs = vec!["data-pvc".to_owned()];
        // `NodeUsage::pvc_names` holds namespace-qualified keys (as
        // `NodeTally::usage_by_node` produces them) — "default" matches
        // `pod`'s own namespace (`empty_pending_pod`), so this is the
        // SAME-namespace conflict this predicate must catch.
        let usage: std::collections::HashMap<String, NodeUsage> = [(
            "worker-0".to_owned(),
            NodeUsage {
                pvc_names: vec!["default/data-pvc".to_owned()],
                ..Default::default()
            },
        )]
        .into();
        let result = select_node_with_capacity(list, &pod, &usage, &[]);
        assert!(
            result.is_err(),
            "a node already running a pod that holds this pod's ReadWriteOncePod \
             PVC must be rejected, not selected"
        );
    }

    #[test]
    fn select_node_with_capacity_allows_a_node_when_the_conflicting_pvc_name_is_in_a_different_namespace(
    ) {
        // Two PVCs can share a bare name across namespaces (e.g. both teams
        // provisioned a PVC called "data-pvc"). Before namespace-qualifying
        // `NodeUsage`/`NodePod`'s PVC keys, this pod would have been wrongly
        // rejected here forever — a same-named PVC in an unrelated namespace
        // is not the same volume and must never block scheduling.
        let list = NodeList {
            items: vec![make_node("worker-0", &[])],
        };
        let mut pod = empty_pending_pod();
        pod.namespace = "team-b".to_owned();
        pod.read_write_once_pod_pvcs = vec!["data-pvc".to_owned()];
        let usage: std::collections::HashMap<String, NodeUsage> = [(
            "worker-0".to_owned(),
            NodeUsage {
                pvc_names: vec!["team-a/data-pvc".to_owned()],
                ..Default::default()
            },
        )]
        .into();
        let result = select_node_with_capacity(list, &pod, &usage, &[]);
        assert_eq!(
            result.unwrap(),
            "worker-0",
            "a PVC named \"data-pvc\" in namespace team-a must never conflict \
             with a DIFFERENT PVC of the same bare name in namespace team-b"
        );
    }

    #[test]
    fn read_write_once_pod_preemption_victims_targets_the_lower_priority_pvc_holder() {
        let node_pods = vec![NodePod {
            key: "default/holder".to_owned(),
            priority: 0,
            requests: ResourceRequests::default(),
            pvc_names: vec!["data-pvc".to_owned()],
        }];
        let victims =
            read_write_once_pod_preemption_victims(&node_pods, &["data-pvc".to_owned()], 1000)
                .expect("a strictly-lower-priority holder must always be a legal victim");
        assert_eq!(
            victims,
            vec!["default/holder".to_owned()],
            "the pod holding the contended ReadWriteOncePod PVC must be named as \
             a mandatory victim — nothing else on the node is even relevant to \
             this conflict"
        );
    }

    #[test]
    fn read_write_once_pod_preemption_victims_refuses_when_holder_priority_is_not_lower() {
        // kube-scheduler (and this scheduler) never preempts an equal-or-higher
        // priority pod. If this returned Some(victims) here, a same-priority
        // pod could be evicted just for holding a contended volume — violating
        // the priority guarantee preemption exists to respect.
        let node_pods = vec![NodePod {
            key: "default/holder".to_owned(),
            priority: 1000,
            requests: ResourceRequests::default(),
            pvc_names: vec!["data-pvc".to_owned()],
        }];
        let victims =
            read_write_once_pod_preemption_victims(&node_pods, &["data-pvc".to_owned()], 1000);
        assert!(
            victims.is_none(),
            "a same-or-higher-priority PVC holder must make this node permanently \
             non-viable for preemption, not silently offer it as a victim"
        );
    }

    #[test]
    fn find_preemption_candidate_evicts_the_pod_holding_a_conflicting_read_write_once_pod_pvc() {
        // The exact csi-hostpath RWOP conformance scenario: pod1 (default
        // priority) holds a ReadWriteOncePod PVC and runs with room to spare;
        // pod2 (higher priority) wants the SAME PVC. Direct scheduling already
        // rejects every node (read_write_once_pod_conflict_free), so this is
        // the ONLY path that can ever get pod2 running — if it doesn't select
        // pod1 as a victim, pod2 stays Pending forever despite outranking pod1.
        let list = NodeList {
            items: vec![make_node_with_capacity("worker-0", &[], "110")],
        };
        let node_labels_by_name: std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        > = list
            .items
            .iter()
            .map(|n| (n.metadata.name.clone(), n.metadata.labels.clone()))
            .collect();
        let tally = std::sync::Mutex::new(NodeTally::default());
        tally.lock().expect("tally lock poisoned").assume(
            "default",
            "pod1",
            "worker-0",
            0,
            ResourceRequests::default(),
            Vec::new(),
            std::collections::HashMap::new(),
            vec!["data-pvc".to_owned()],
        );
        let tallied_pods = tally
            .lock()
            .expect("tally lock poisoned")
            .tallied_pod_labels();

        let mut pod2 = empty_pending_pod();
        pod2.pod_name = "pod2".to_owned();
        pod2.priority = 1000;
        pod2.read_write_once_pod_pvcs = vec!["data-pvc".to_owned()];

        let (_, plan) =
            find_preemption_candidate(&list, &pod2, &tallied_pods, &node_labels_by_name, &tally)
                .expect(
                    "evicting pod1 fully resolves the RWOP conflict — this node must \
                     be a viable preemption target",
                );
        assert_eq!(
            plan.victims,
            vec!["default/pod1".to_owned()],
            "pod1 is the only thing blocking pod2 (plenty of spare cpu/memory/pod \
             slots) — it must be the preemption plan's sole victim"
        );
    }

    #[test]
    fn find_preemption_candidate_never_evicts_a_pod_over_a_same_named_pvc_in_a_different_namespace()
    {
        // Same setup as the RWOP-conflict test above, EXCEPT pod1 and pod2 are
        // in different namespaces. Before namespace-qualifying `NodeTally`'s
        // PVC keys, "data-pvc" in namespace team-a matched "data-pvc" in
        // namespace team-b, so pod1 would have been wrongly named a mandatory
        // preemption victim for a PVC it does not actually contend with —
        // an innocent workload evicted for no real conflict.
        let list = NodeList {
            items: vec![make_node_with_capacity("worker-0", &[], "110")],
        };
        let node_labels_by_name: std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        > = list
            .items
            .iter()
            .map(|n| (n.metadata.name.clone(), n.metadata.labels.clone()))
            .collect();
        let tally = std::sync::Mutex::new(NodeTally::default());
        tally.lock().expect("tally lock poisoned").assume(
            "team-a",
            "pod1",
            "worker-0",
            0,
            ResourceRequests::default(),
            Vec::new(),
            std::collections::HashMap::new(),
            vec!["data-pvc".to_owned()],
        );
        let tallied_pods = tally
            .lock()
            .expect("tally lock poisoned")
            .tallied_pod_labels();

        let mut pod2 = empty_pending_pod();
        pod2.namespace = "team-b".to_owned();
        pod2.pod_name = "pod2".to_owned();
        pod2.priority = 1000;
        pod2.read_write_once_pod_pvcs = vec!["data-pvc".to_owned()];

        let result =
            find_preemption_candidate(&list, &pod2, &tallied_pods, &node_labels_by_name, &tally);
        assert!(
            result.is_none(),
            "pod1's PVC is in a DIFFERENT namespace from pod2's — there is no \
             real RWOP conflict here, so no preemption plan (and certainly \
             not one evicting pod1) should exist: got {result:?}"
        );
    }

    #[test]
    fn find_preemption_candidate_never_preempt_binds_onto_a_node_with_zero_csi_headroom() {
        // A node with a lower-priority pod occupying its only pod slot AND
        // zero remaining CSI attach headroom for the driver the pending pod
        // needs. Evicting the low-priority pod frees the pod-count slot, but
        // does nothing for the CSI driver's attach limit (this scheduler
        // tracks no per-pod CSI-driver usage to know otherwise) — so this
        // node must stay non-viable. Before `find_preemption_plan` populated
        // `csi_driver_headroom` and this function checked it, the pod-count
        // eviction alone would have made this node look viable, preempt-
        // binding the pending pod onto a node the CSI driver cannot actually
        // serve.
        let node = make_node_with_capacity("worker-0", &[], "1");
        let list = NodeList { items: vec![node] };
        let node_labels_by_name: std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        > = list
            .items
            .iter()
            .map(|n| (n.metadata.name.clone(), n.metadata.labels.clone()))
            .collect();
        let mut tally = NodeTally::default();
        // The zero-headroom advertisement now comes from the tally's own
        // watch-maintained CSINode cache (fresh-read by
        // `find_preemption_candidate`), not a field set directly on `node` —
        // matching how `find_preemption_candidate` computes headroom since
        // the fix for the concurrent-scheduling read-after-write race.
        tally.apply_csi_node_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "worker-0" },
                "spec": { "drivers": [{ "name": "hostpath.csi.k8s.io", "allocatable": { "count": 0 } }] }
            }
        }));
        let tally = std::sync::Mutex::new(tally);
        tally.lock().expect("tally lock poisoned").assume(
            "default",
            "low-priority-pod",
            "worker-0",
            0,
            ResourceRequests::default(),
            Vec::new(),
            std::collections::HashMap::new(),
            Vec::new(),
        );
        let tallied_pods = tally
            .lock()
            .expect("tally lock poisoned")
            .tallied_pod_labels();

        let mut pod = empty_pending_pod();
        pod.priority = 1000;
        pod.csi_volume_counts = [("hostpath.csi.k8s.io".to_owned(), 1i64)].into();

        let result =
            find_preemption_candidate(&list, &pod, &tallied_pods, &node_labels_by_name, &tally);
        assert!(
            result.is_none(),
            "evicting the low-priority pod frees a pod-count slot but not any \
             CSI attach headroom, so this node must never be offered as a \
             preemption target: got {result:?}"
        );
    }

    #[test]
    fn find_preemption_candidate_never_preempt_binds_onto_a_node_missing_the_required_csi_driver() {
        // A node with a lower-priority pod occupying its only pod slot, but
        // whose CSINode does not register the driver the pending pod's
        // unbound PVC needs. Evicting the low-priority pod frees the
        // pod-count slot, but does nothing to make the driver appear on this
        // node — so this node must stay non-viable, exactly like the
        // zero-CSI-headroom case above. Without this check, preemption could
        // evict a real running pod for no benefit: the pending pod still
        // could not mount its eventual volume here.
        let node = make_node_with_capacity("lima-node-3", &[], "1");
        let list = NodeList { items: vec![node] };
        let node_labels_by_name: std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        > = list
            .items
            .iter()
            .map(|n| (n.metadata.name.clone(), n.metadata.labels.clone()))
            .collect();
        let mut tally = NodeTally::default();
        // lima-node-3 registers no CSI drivers at all — the single-replica
        // csi-hostpath driver runs on a DIFFERENT node entirely.
        tally.apply_csi_node_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "lima-node-3" },
                "spec": { "drivers": [] }
            }
        }));
        let tally = std::sync::Mutex::new(tally);
        tally.lock().expect("tally lock poisoned").assume(
            "default",
            "low-priority-pod",
            "lima-node-3",
            0,
            ResourceRequests::default(),
            Vec::new(),
            std::collections::HashMap::new(),
            Vec::new(),
        );
        let tallied_pods = tally
            .lock()
            .expect("tally lock poisoned")
            .tallied_pod_labels();

        let mut pod = empty_pending_pod();
        pod.priority = 1000;
        pod.unbound_csi_pvc_drivers = vec!["csi-hostpath-provisioning-6547".to_owned()];

        let result =
            find_preemption_candidate(&list, &pod, &tallied_pods, &node_labels_by_name, &tally);
        assert!(
            result.is_none(),
            "evicting the low-priority pod frees a pod-count slot but the \
             driver still never registers on this node, so it must never be \
             offered as a preemption target: got {result:?}"
        );
    }
}
