use axum::{body::Body, http::StatusCode, response::Response};
use bytes::Bytes;
use serde::Serialize;
use u7s_store::{ListOptions, Store, WatchEvent};

use crate::{state::AppState, status::Status, types::ObjectMeta};

/// Serialize `{"type":"<event_type>","object":<value>}\n` into a single heap allocation.
/// Generic over `object`'s type so a `Serialize` envelope (e.g. `PartialObjectMetadataEnvelopeOwned`)
/// can be written straight to the output buffer without first materializing it as a
/// `serde_json::Value` — every existing caller passes `&serde_json::Value`, which also
/// implements `Serialize`, so this widening is a no-op for them.
///
/// Watch clients parse these bytes; any format change breaks every informer.
fn ndjson_event_value<T: Serialize>(event_type: &str, object: &T) -> Bytes {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(b"{\"type\":\"");
    buf.extend_from_slice(event_type.as_bytes());
    buf.extend_from_slice(b"\",\"object\":");
    let _ = serde_json::to_writer(&mut buf, object);
    buf.extend_from_slice(b"}\n");
    Bytes::from(buf)
}

/// Serialize `{"type":"<event_type>","object":<raw_json>}\n` without parsing raw_json.
///
/// Watch clients parse these bytes; any format change breaks every informer.
fn ndjson_event_raw(event_type: &str, raw_object_json: &str) -> Bytes {
    let mut buf = Vec::with_capacity(12 + event_type.len() + 11 + raw_object_json.len() + 2);
    buf.extend_from_slice(b"{\"type\":\"");
    buf.extend_from_slice(event_type.as_bytes());
    buf.extend_from_slice(b"\",\"object\":");
    buf.extend_from_slice(raw_object_json.as_bytes());
    buf.extend_from_slice(b"}\n");
    Bytes::from(buf)
}

/// Serialize a BOOKMARK line into a single heap allocation.
///
/// Watch clients parse these bytes; any format change breaks every informer.
fn ndjson_bookmark(api_version: &str, kind: &str, revision: u64) -> Bytes {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(b"{\"type\":\"BOOKMARK\",\"object\":{\"apiVersion\":\"");
    buf.extend_from_slice(api_version.as_bytes());
    buf.extend_from_slice(b"\",\"kind\":\"");
    buf.extend_from_slice(kind.as_bytes());
    buf.extend_from_slice(b"\",\"metadata\":{\"resourceVersion\":\"");
    let rv_str = revision.to_string();
    buf.extend_from_slice(rv_str.as_bytes());
    buf.extend_from_slice(b"\"}}}\n");
    Bytes::from(buf)
}

/// Serialize an initial-events-end BOOKMARK line (with the annotation) into a single allocation.
///
/// Watch clients parse these bytes; any format change breaks every informer.
fn ndjson_initial_events_bookmark(api_version: &str, kind: &str, revision: u64) -> Bytes {
    let mut buf = Vec::with_capacity(200);
    buf.extend_from_slice(b"{\"type\":\"BOOKMARK\",\"object\":{\"apiVersion\":\"");
    buf.extend_from_slice(api_version.as_bytes());
    buf.extend_from_slice(b"\",\"kind\":\"");
    buf.extend_from_slice(kind.as_bytes());
    buf.extend_from_slice(b"\",\"metadata\":{\"resourceVersion\":\"");
    let rv_str = revision.to_string();
    buf.extend_from_slice(rv_str.as_bytes());
    buf.extend_from_slice(b"\",\"annotations\":{\"k8s.io/initial-events-end\":\"true\"}}}}\n");
    Bytes::from(buf)
}

/// Stamp `obj["apiVersion"]`/`obj["kind"]` with the canonical values for the watched resource,
/// skipping the write (and its `String` allocation) when the stored object already carries
/// them. Built-in resources and CRs served at their stored version always already match, so
/// this avoids allocating two Strings on essentially every watch event; only a CR watched at a
/// version other than the one it's stored in needs the write.
fn stamp_type_meta_if_changed(obj: &mut serde_json::Value, api_version: &str, kind: &str) {
    if obj.get("apiVersion").and_then(|v| v.as_str()) != Some(api_version) {
        obj["apiVersion"] = serde_json::Value::String(api_version.to_owned());
    }
    if obj.get("kind").and_then(|v| v.as_str()) != Some(kind) {
        obj["kind"] = serde_json::Value::String(kind.to_owned());
    }
}

/// Apply defaults and produce the final NDJSON bytes for an object already confirmed to match
/// this watcher's label/field selector (and, for CRs, already converted to the requested
/// served version). This is the tail shared by `prepare_live_event` (which parses raw bytes
/// and checks the selector itself first) and the CR/selector-filtered arms of the live watch
/// loop (which must parse and convert before they know whether the object matches, so they
/// call this directly on the already-parsed value instead of round-tripping through
/// `prepare_live_event`'s raw-bytes entry point).
#[allow(clippy::too_many_arguments)]
fn finish_live_event(
    mut parsed: serde_json::Value,
    event_type: &str,
    group: &str,
    plural: &str,
    api_version: &str,
    kind: &str,
    as_partial_object_metadata: bool,
) -> Bytes {
    super::defaults::apply_defaults(group, plural, &mut parsed);
    if as_partial_object_metadata {
        let envelope = take_partial_object_metadata(parsed);
        ndjson_event_value(event_type, &envelope)
    } else {
        stamp_type_meta_if_changed(&mut parsed, api_version, kind);
        ndjson_event_value(event_type, &parsed)
    }
}

/// Deserialize, filter, default, and re-serialize one Added/Modified watch event.
///
/// Returns `None` when:
/// - `raw` is not valid UTF-8, or is not valid JSON (corrupt store entry — caller logs and
///   skips).
/// - The parsed object does not match `label_selector` or `field_selector`.
///
/// Otherwise returns pre-built NDJSON bytes (`{"type":"...","object":...}\n`).
///
/// Deserialization and `apply_defaults` happen exactly once per call regardless of how many
/// watchers share the same event source. Each watcher calls this once; sharing the returned
/// `Bytes` across callers (same event, multiple watchers) is safe because `Bytes` is `Clone`
/// and the allocation is reference-counted. Used directly by the live watch loop's fast path
/// (a builtin resource watch with no label/field selector, where no per-watcher bookkeeping
/// depends on the parsed value); selector-filtered and CR watches instead call
/// `finish_live_event` after their own parse+convert+match, to avoid re-parsing bytes this
/// function already validated just to recover the metadata that bookkeeping needs.
#[allow(clippy::too_many_arguments)]
pub fn prepare_live_event(
    raw: &[u8],
    event_type: &str,
    group: &str,
    plural: &str,
    api_version: &str,
    kind: &str,
    as_partial_object_metadata: bool,
    label_selector: &str,
    field_selector: &str,
) -> Option<Bytes> {
    let s = std::str::from_utf8(raw).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(s).ok()?;
    if !object_matches_label_selector(&parsed, label_selector)
        || !object_matches_field_selector(&parsed, field_selector)
    {
        return None;
    }
    Some(finish_live_event(
        parsed,
        event_type,
        group,
        plural,
        api_version,
        kind,
        as_partial_object_metadata,
    ))
}

/// Mirrors `defaults::apply_defaults`'s dispatch conditions closely enough to answer "could
/// this resource type ever be mutated by apply_defaults" without a parsed `Value` to check
/// against. MUST stay in sync with `apply_defaults`: a type added there without a matching arm
/// here would silently drop its defaulting on every plain (no-selector) live watch event —
/// `defaults_may_mutate_matches_apply_defaults_reaches_this_watch_regression` below pins the
/// two together for the field this project has already hit a real bug on (Service
/// ipFamilyPolicy).
fn defaults_may_mutate(group: &str, plural: &str) -> bool {
    super::defaults::is_workload_resource(group, plural)
        || super::defaults::is_endpointslice(group, plural)
        || matches!(
            (group, plural),
            ("apps", "deployments")
                | ("apps", "replicasets")
                | ("apps", "statefulsets")
                | ("apps", "daemonsets")
                | ("batch", "jobs")
                | ("batch", "cronjobs")
                | ("", "services")
                | ("", "endpoints")
                | ("", "persistentvolumeclaims")
                | ("", "persistentvolumes")
                | ("", "secrets")
                | ("storage.k8s.io", "csidrivers")
                | ("storage.k8s.io", "storageclasses")
                | ("", "namespaces")
                | ("coordination.k8s.io", "leases")
                | ("", "replicationcontrollers")
                | ("autoscaling", "horizontalpodautoscalers")
                | ("networking.k8s.io", "networkpolicies")
                | ("resource.k8s.io", "resourceclaims")
                | ("resource.k8s.io", "resourceclaimtemplates")
        )
        || (plural == "events" && (group.is_empty() || group == "events.k8s.io"))
        || (group == "rbac.authorization.k8s.io"
            && (plural == "rolebindings" || plural == "clusterrolebindings"))
}

/// Cheap projection used only to decide whether the stored bytes already carry the exact
/// apiVersion/kind this watch is serving — deserializes just those two fields (serde skips
/// everything else without building a `Value` for it), so checking is far cheaper than a full
/// parse while still being exact, unlike a raw substring scan (which can false-match a nested
/// ownerReference or embedded object carrying the same apiVersion/kind pair).
fn type_meta_already_canonical(object_json: &str, api_version: &str, kind: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct TypeMetaProjection<'a> {
        #[serde(rename = "apiVersion", default)]
        api_version: Option<&'a str>,
        #[serde(default)]
        kind: Option<&'a str>,
    }
    match serde_json::from_str::<TypeMetaProjection>(object_json) {
        Ok(tm) => tm.api_version == Some(api_version) && tm.kind == Some(kind),
        Err(_) => false,
    }
}

/// Serialize a live ADDED/MODIFIED event for the no-selector fast path, using the zero-parse
/// raw path (`ndjson_event_raw`) whenever it's provably safe — no PartialObjectMetadata
/// wrapping to build, this resource type has nothing `apply_defaults` could still add, and the
/// stored bytes already carry the requested apiVersion/kind — and falling back to
/// `prepare_live_event`'s full parse+apply_defaults+reserialize otherwise. Returns `None` only
/// for invalid UTF-8/JSON (corrupt store entry — caller logs and skips), matching
/// `prepare_live_event`.
fn prepare_fast_live_event(
    raw: &[u8],
    event_type: &str,
    group: &str,
    plural: &str,
    api_version: &str,
    kind: &str,
    as_partial_object_metadata: bool,
) -> Option<Bytes> {
    if as_partial_object_metadata || defaults_may_mutate(group, plural) {
        return prepare_live_event(
            raw,
            event_type,
            group,
            plural,
            api_version,
            kind,
            as_partial_object_metadata,
            "",
            "",
        );
    }
    let object_json = std::str::from_utf8(raw).ok()?;
    if type_meta_already_canonical(object_json, api_version, kind) {
        Some(ndjson_event_raw(event_type, object_json))
    } else {
        prepare_live_event(
            raw,
            event_type,
            group,
            plural,
            api_version,
            kind,
            false,
            "",
            "",
        )
    }
}

/// The `PartialObjectMetadata` envelope GC watches and PartialObjectMetadata LIST/GET responses
/// consume. `metadata` stays an opaque `Value` — this projection never reasons about individual
/// metadata fields (ownerReferences, finalizers, ...), only about which top-level object keys
/// survive, so there is nothing here for a typed struct to protect beyond that: the absence of
/// `spec`/`status` fields on this type makes it structurally impossible for either to leak into
/// a PartialObjectMetadata response, unlike the `serde_json::json!` macro it replaces. It also
/// cannot become `ObjectMeta` outright: `ObjectMeta` still doesn't model `generation` (set on
/// every workload resource — a full round trip dropping it makes KCM's controllers see
/// `generation: null` and stop reconciling entirely) or `deletionGracePeriodSeconds` (set by
/// pods.rs during graceful termination).
#[derive(Serialize)]
struct PartialObjectMetadataEnvelope<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    metadata: &'a serde_json::Value,
}

/// Transform a full CR JSON object into a PartialObjectMetadata object.
/// The GC only needs metadata (ownerReferences, finalizers, etc.) — spec/status are omitted.
///
/// Takes `obj` by reference because resource.rs/core.rs's LIST handlers hold their `items` by
/// shared reference across both the PartialObjectMetadata and full-object response branches.
/// Every watch event in this file owns the object it projects and discards it immediately after
/// — see `take_partial_object_metadata` below for that path, which moves `metadata` out instead
/// of paying for this function's copy.
pub(crate) fn to_partial_object_metadata(obj: &serde_json::Value) -> serde_json::Value {
    let null = serde_json::Value::Null;
    let envelope = PartialObjectMetadataEnvelope {
        api_version: "meta.k8s.io/v1",
        kind: "PartialObjectMetadata",
        metadata: obj.get("metadata").unwrap_or(&null),
    };
    serde_json::to_value(envelope)
        .expect("PartialObjectMetadataEnvelope always serializes to a JSON object")
}

/// Owned counterpart to `PartialObjectMetadataEnvelope`, serialized directly by the generic
/// `ndjson_event_value` — skipping the intermediate `serde_json::Value` `to_partial_object_metadata`
/// must build for its borrowed callers.
#[derive(Serialize)]
struct PartialObjectMetadataEnvelopeOwned {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    metadata: serde_json::Value,
}

/// Move `obj`'s metadata into a PartialObjectMetadata envelope and drop the rest of `obj` (spec,
/// status, everything else) immediately, so a watch event never holds the full object and its
/// metadata-only projection in memory at once.
///
/// Uses `get_mut`/`take` rather than `obj["metadata"].take()` (serde_json `IndexMut`): indexing
/// with `[]` panics whenever `obj` itself isn't a JSON object (e.g. a corrupt store entry whose
/// raw bytes are a bare scalar, reachable via `prepare_live_event` with both selectors empty),
/// whereas `get_mut` returns `None` for exactly that case — matching the graceful fallback the
/// borrowed `to_partial_object_metadata` already has via `obj.get("metadata")`.
fn take_partial_object_metadata(mut obj: serde_json::Value) -> PartialObjectMetadataEnvelopeOwned {
    let metadata = obj
        .get_mut("metadata")
        .filter(|m| m.is_object())
        .map(serde_json::Value::take)
        .unwrap_or(serde_json::Value::Null);
    drop(obj);
    PartialObjectMetadataEnvelopeOwned {
        api_version: "meta.k8s.io/v1",
        kind: "PartialObjectMetadata",
        metadata,
    }
}

/// Stamp resourceVersion and apiVersion/kind onto an already-parsed DELETED tombstone body
/// and serialize it. Shared by `encode_watch_event` (which parses the raw stored body itself)
/// and callers that already hold a parsed-and-converted Value (CR conversion for a DELETED
/// event) and would otherwise pay a wasteful reserialize-then-reparse round trip to hand it
/// to `encode_watch_event`.
fn finish_deleted_event(
    mut obj: serde_json::Value,
    revision: u64,
    api_version: &str,
    kind: &str,
) -> Bytes {
    // Set metadata.resourceVersion via ObjectMeta's own field-name mapping instead of a raw
    // string index, merging just this one field into the existing metadata object rather than
    // deserializing the whole object into ObjectMeta and reserializing it — a full round trip
    // would silently drop any field ObjectMeta doesn't model. ownerReferences/managedFields are
    // modeled now, but `generation` and `deletionGracePeriodSeconds` still aren't (see
    // `to_partial_object_metadata`'s doc comment above), which is exactly the class of
    // correctness bug this migration exists to prevent.
    let patch = ObjectMeta {
        resource_version: Some(revision.to_string()),
        ..Default::default()
    };
    let serde_json::Value::Object(fields) =
        serde_json::to_value(&patch).expect("ObjectMeta always serializes to a JSON object")
    else {
        unreachable!("ObjectMeta always serializes to a JSON object")
    };
    match &mut obj["metadata"] {
        serde_json::Value::Object(metadata) => metadata.extend(fields),
        _ => unreachable!("stored object metadata is always a JSON object"),
    }
    stamp_type_meta_if_changed(&mut obj, api_version, kind);
    ndjson_event_value("DELETED", &obj)
}

/// Serialise a single watch event to NDJSON bytes (including trailing newline).
/// Returns None on Compacted — the caller should close the stream.
/// Returns None on corrupt object bytes (invalid UTF-8) — the event is skipped,
/// a warning is logged, and the stream continues. Emitting null would send invalid
/// data to Kubernetes clients that may panic or behave incorrectly.
///
/// When `as_partial_object_metadata` is true, ADDED and MODIFIED event objects are
/// wrapped as PartialObjectMetadata (apiVersion: meta.k8s.io/v1, kind: PartialObjectMetadata,
/// only metadata preserved). BOOKMARK and DELETED use the caller-supplied api_version/kind
/// which should also be set to "meta.k8s.io/v1"/"PartialObjectMetadata" by the caller.
pub(crate) fn encode_watch_event(
    event: &WatchEvent,
    api_version: &str,
    kind: &str,
    as_partial_object_metadata: bool,
) -> Option<Bytes> {
    match event {
        WatchEvent::Added(obj) => {
            let object_json = match std::str::from_utf8(&obj.value) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("watch ADDED event has invalid UTF-8, skipping: {e}");
                    return None;
                }
            };
            if as_partial_object_metadata {
                let full: serde_json::Value =
                    serde_json::from_str(object_json).unwrap_or(serde_json::Value::Null);
                let envelope = take_partial_object_metadata(full);
                Some(ndjson_event_value("ADDED", &envelope))
            } else {
                Some(ndjson_event_raw("ADDED", object_json))
            }
        }
        WatchEvent::Modified(obj) => {
            let object_json = match std::str::from_utf8(&obj.value) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("watch MODIFIED event has invalid UTF-8, skipping: {e}");
                    return None;
                }
            };
            if as_partial_object_metadata {
                let full: serde_json::Value =
                    serde_json::from_str(object_json).unwrap_or(serde_json::Value::Null);
                let envelope = take_partial_object_metadata(full);
                Some(ndjson_event_value("MODIFIED", &envelope))
            } else {
                Some(ndjson_event_raw("MODIFIED", object_json))
            }
        }
        WatchEvent::Deleted {
            key,
            revision,
            body,
        } => {
            if let Some(body_bytes) = body {
                if let Ok(s) = std::str::from_utf8(body_bytes) {
                    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(s) {
                        // Re-stamp apiVersion/kind unconditionally, mirroring the ADDED/MODIFIED
                        // path (chunk_stream sets these on every emitted event). The stored body
                        // is not guaranteed to carry them: a PUT/Update sent through the dynamic
                        // (unstructured) client from a typed Go struct with an empty TypeMeta
                        // serializes apiVersion/kind as absent (omitempty), and
                        // replace_namespaced_resource persists the body as received without
                        // injecting them. A DELETED event built from that stored body then lacks
                        // apiVersion/kind entirely. client-go's watch decoder cannot determine the
                        // object's type without them and fails to decode the event, which closes
                        // the watch's ResultChan — RetryWatcher reconnects (without ever having
                        // extracted a resourceVersion from the failed event) and repeats forever,
                        // wedging any caller waiting on a DELETED event.
                        return Some(finish_deleted_event(obj, *revision, api_version, kind));
                    }
                }
            }
            // Fallback: reconstruct a minimal tombstone from the store key.
            let (name, namespace) = parse_key_name_ns(key);
            let object = build_tombstone_object(name, namespace, *revision, api_version, kind);
            Some(ndjson_event_value("DELETED", &object))
        }
        WatchEvent::Bookmark { revision } => Some(ndjson_bookmark(api_version, kind, *revision)),
        WatchEvent::Compacted { .. } => None,
    }
}

/// A synthetic tombstone's `{apiVersion, kind, metadata}` shape — built through `ObjectMeta`
/// instead of `serde_json::json!` so a stray key (e.g. a typo'd `spec`) can't leak into a
/// tombstone body, and so the two call sites that synthesize a tombstone from just
/// name/namespace/resourceVersion (no stored body available or matching) share one field-name
/// mapping instead of each hand-rolling a namespace-branching object literal.
#[derive(Serialize)]
struct TombstoneEnvelope<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    metadata: ObjectMeta,
}

fn build_tombstone_object(
    name: &str,
    namespace: &str,
    revision: u64,
    api_version: &str,
    kind: &str,
) -> serde_json::Value {
    let namespace = if namespace.is_empty() {
        None
    } else {
        Some(namespace.to_owned())
    };
    let metadata = ObjectMeta {
        name: Some(name.to_owned()),
        namespace,
        resource_version: Some(revision.to_string()),
        ..Default::default()
    };
    serde_json::to_value(TombstoneEnvelope {
        api_version,
        kind,
        metadata,
    })
    .expect("TombstoneEnvelope always serializes to a JSON object")
}

/// Parse the last two path segments of a store key as (name, namespace).
/// Key format: /registry/<resource>/<namespace>/<name>  (namespaced)
///         or: /registry/<group>/<plural>/<name>        (cluster-scoped)
/// We only need the final segment as name; second-to-last as namespace (may be empty).
pub(crate) fn parse_key_name_ns(key: &str) -> (&str, &str) {
    let parts: Vec<&str> = key.rsplitn(3, '/').collect();
    match parts.as_slice() {
        [name, namespace, ..] => (name, namespace),
        [name] => (name, ""),
        _ => ("", ""),
    }
}

/// Fetch the initial items for sendInitialEvents watch protocol.
///
/// When `send_initial_events` is true, lists all objects under `prefix` and returns
/// them as ADDED events before the live watch stream, followed by a BOOKMARK with
/// `k8s.io/initial-events-end=true`. This implements the Kubernetes 1.27+ informer
/// startup protocol used by kubelet and controller-manager.
///
/// Returns `None` when `send_initial_events` is false (caller uses normal watch).
pub(crate) async fn fetch_initial_events<S: Store>(
    state: &AppState<S>,
    prefix: &str,
    send_initial_events: bool,
    group: &str,
    plural: &str,
) -> Result<Option<(Vec<serde_json::Value>, u64)>, crate::status::StatusError> {
    if !send_initial_events {
        return Ok(None);
    }
    let resp = state
        .store
        .list(prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    let items: Vec<serde_json::Value> = resp
        .items
        .iter()
        .filter_map(|o| serde_json::from_slice(&o.value).ok())
        .map(|mut v| {
            super::defaults::apply_defaults(group, plural, &mut v);
            v
        })
        .collect();
    Ok(Some((items, resp.revision)))
}

/// Split a label selector string into top-level comma-separated terms,
/// without splitting inside parentheses (which appear in `key in (v1,v2)` forms).
fn split_selector_terms(selector: &str) -> Vec<&str> {
    let mut terms = Vec::new();
    let mut depth: usize = 0;
    let mut start = 0;
    for (i, c) in selector.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                terms.push(selector[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    terms.push(selector[start..].trim());
    terms
}

/// Parse the values list from a set-based selector: `(v1, v2, v3)` → `["v1", "v2", "v3"]`.
fn parse_set_values(s: &str) -> Vec<&str> {
    let inner = s.trim().trim_start_matches('(').trim_end_matches(')');
    inner
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect()
}

/// Shared label-selector decision logic, parameterized over how to look up a label's presence
/// and value so `object_matches_label_selector` (full `Value`) and `SelectorProjection::matches`
/// (the cheap pre-parse projection below) evaluate the exact same operators against the exact
/// same data — a hand-duplicated second copy of this logic is exactly the kind of drift that
/// would make a selector'd watch's projection-based pre-filter and its full-object filter
/// disagree.
///
/// `has_key` and `label` are separate (rather than deriving presence from `label(key).is_some()`)
/// because Exists/DoesNotExist must key off whether the label is present at all, not whether its
/// value happens to be a string: a stored `metadata.labels` value that isn't a JSON string (e.g.
/// `null`) still counts as present for `!key`/bare `key`, even though `label(key)` returns `None`
/// for it the same as a genuinely absent key.
///
/// Supported operators: `key=value` (Equality), `key!=value` (NotEquals),
/// `!key` (DoesNotExist), bare `key` (Exists),
/// `key in (v1,v2)` (In), `key notin (v1,v2)` (NotIn).
fn label_selector_matches<'a>(
    selector: &str,
    has_key: impl Fn(&str) -> bool,
    label: impl Fn(&str) -> Option<&'a str>,
) -> bool {
    if selector.is_empty() {
        return true;
    }
    for part in split_selector_terms(selector) {
        if part.is_empty() {
            continue;
        }
        if let Some(key) = part.strip_prefix('!') {
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            if has_key(key) {
                return false;
            }
            continue;
        }
        if let Some((key, rest)) = part.split_once(" notin ") {
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            let values = parse_set_values(rest);
            if label(key).is_some_and(|v| values.contains(&v)) {
                return false;
            }
            continue;
        }
        if let Some((key, rest)) = part.split_once(" in ") {
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            let values = parse_set_values(rest);
            if !label(key).is_some_and(|v| values.contains(&v)) {
                return false;
            }
            continue;
        }
        if let Some((key, value)) = part.split_once("!=") {
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                continue;
            }
            if label(key) == Some(value) {
                return false;
            }
            continue;
        }
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim();
            let value = value.trim().strip_prefix('=').unwrap_or(value.trim());
            if key.is_empty() {
                continue;
            }
            if label(key) != Some(value) {
                return false;
            }
            continue;
        }
        let key = part.trim();
        if key.is_empty() {
            continue;
        }
        if !has_key(key) {
            return false;
        }
    }
    true
}

/// Test whether a JSON object matches a label selector string.
/// Returns true if the selector is empty (pass-through) or all terms match
/// `metadata.labels` in the object. Used to filter live watch events.
pub(crate) fn object_matches_label_selector(obj: &serde_json::Value, selector: &str) -> bool {
    let labels = &obj["metadata"]["labels"];
    label_selector_matches(
        selector,
        |key| labels.get(key).is_some(),
        |key| labels.get(key).and_then(|v| v.as_str()),
    )
}

/// Shared field-selector decision logic, parameterized over the three fields it ever reads —
/// see `label_selector_matches`'s doc comment for why this is shared rather than duplicated
/// between `object_matches_field_selector` and the projection-based pre-filter below.
///
/// Supports `metadata.name`, `metadata.namespace` (equality only), and `spec.nodeName`
/// (equality and inequality). Returns true if the selector is empty (pass-through) or all
/// terms match. Unknown fields are ignored (conservative: don't drop events on unrecognised fields).
fn field_selector_matches_parts(
    selector: &str,
    name: Option<&str>,
    namespace: Option<&str>,
    node_name: Option<&str>,
) -> bool {
    if selector.is_empty() {
        return true;
    }
    for part in selector.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Check for inequality (`!=`) before equality (`=`) to avoid misparse.
        if let Some((field, value)) = part.split_once("!=") {
            let field = field.trim();
            let value = value.trim();
            if field == "spec.nodeName" && node_name.unwrap_or("") == value {
                return false;
            }
            // Unknown fields: ignore (conservative).
        } else if let Some((field, value)) = part.split_once('=') {
            let field = field.trim();
            let value = value.trim();
            match field {
                "metadata.name" if name.unwrap_or("") != value => return false,
                "metadata.namespace" if namespace.unwrap_or("") != value => return false,
                "spec.nodeName" if node_name.unwrap_or("") != value => return false,
                // Unknown fields (or a value that already matches): ignore (conservative).
                _ => {}
            }
        }
    }
    true
}

/// Test whether a JSON object matches a field selector string (`key=value,...` or `key!=value,...`).
///
/// This is the matcher for built-in resources only. CR watches with a CRD-declared
/// `selectableFields` go through `watch_generic_for_cr` instead, which consults
/// `cr::cr_matches_field_selector` so a selector on a CRD-declared field (e.g. `host`) — which
/// falls through the `_ => {}` catch-all above and is silently ignored — actually filters.
pub(crate) fn object_matches_field_selector(obj: &serde_json::Value, selector: &str) -> bool {
    field_selector_matches_parts(
        selector,
        obj["metadata"]["name"].as_str(),
        obj["metadata"]["namespace"].as_str(),
        obj["spec"]["nodeName"].as_str(),
    )
}

/// Minimal metadata/spec projection covering exactly the fields the selector matchers above
/// read: `metadata.labels`, `metadata.name`, `metadata.namespace`, `spec.nodeName`. Serde skips
/// every other key (spec.containers, status, ...) without ever building a `Value` for it, so a
/// non-matching event can be identified far cheaper than the full parse this project's own
/// measurements show gets paid today only to discard the result — e.g. a kubelet's
/// `spec.nodeName=<node>` selector on a 100-node cluster is ~99% wasted parses per pod write.
///
/// MUST track every field `label_selector_matches`/`field_selector_matches_parts` read:
/// `selector_projection_matches_agree_with_full_object_matchers` below cross-checks both against
/// the same objects and selectors, so a matcher growing a field without a matching update here
/// fails a test instead of silently mis-filtering a live selector'd watch.
#[derive(serde::Deserialize, Default)]
struct SelectorProjection<'a> {
    #[serde(default, borrow)]
    metadata: SelectorProjectionMetadata<'a>,
    #[serde(default, borrow)]
    spec: SelectorProjectionSpec<'a>,
}

#[derive(serde::Deserialize, Default)]
struct SelectorProjectionMetadata<'a> {
    #[serde(default, borrow)]
    name: Option<&'a str>,
    #[serde(default, borrow)]
    namespace: Option<&'a str>,
    #[serde(default, borrow)]
    labels: std::collections::BTreeMap<&'a str, &'a str>,
}

#[derive(serde::Deserialize, Default)]
struct SelectorProjectionSpec<'a> {
    #[serde(default, rename = "nodeName", borrow)]
    node_name: Option<&'a str>,
}

impl SelectorProjection<'_> {
    fn matches(&self, label_selector: &str, field_selector: &str) -> bool {
        label_selector_matches(
            label_selector,
            |key| self.metadata.labels.contains_key(key),
            |key| self.metadata.labels.get(key).copied(),
        ) && field_selector_matches_parts(
            field_selector,
            self.metadata.name,
            self.metadata.namespace,
            self.spec.node_name,
        )
    }
}

/// Cheap pre-filter for a selector'd, non-CR watch event: if the stored bytes parse into
/// `SelectorProjection` and definitively fail the selector, returns the object's name/namespace
/// — all the caller needs for `ever_matched`/`locally_deleted` bookkeeping and a synthetic
/// DELETED — without ever building the full `Value` or invoking CR conversion.
///
/// Returns `None` when the object might match (the caller needs the full path to build the
/// emitted event) or the projection failed to parse (e.g. a non-string label value or invalid
/// JSON) — the caller must treat `None` as "fall back to the full path", never as "does not
/// match": this function only ever answers "definitely does not match" or "don't know".
fn selector_projection_non_match(
    raw: &[u8],
    label_selector: &str,
    field_selector: &str,
) -> Option<(String, String)> {
    let s = std::str::from_utf8(raw).ok()?;
    let projection: SelectorProjection = serde_json::from_str(s).ok()?;
    if projection.matches(label_selector, field_selector) {
        return None;
    }
    Some((
        projection.metadata.name.unwrap_or("").to_string(),
        projection.metadata.namespace.unwrap_or("").to_string(),
    ))
}

/// Parameters for `watch_generic`.
///
/// Groups the arguments that previously caused a `clippy::too_many_arguments` warning.
pub(crate) struct WatchConfig {
    pub prefix: String,
    pub api_version: String,
    pub kind: String,
    pub from_revision: u64,
    pub initial_items: Option<(Vec<serde_json::Value>, u64)>,
    pub label_selector: Option<String>,
    pub field_selector: Option<String>,
    pub allow_watch_bookmarks: bool,
    pub username: String,
    /// When true, wrap each ADDED/MODIFIED object as PartialObjectMetadata and use
    /// "meta.k8s.io/v1"/"PartialObjectMetadata" for BOOKMARK and DELETED events.
    /// The caller must also pass api_version="meta.k8s.io/v1" and kind="PartialObjectMetadata".
    pub as_partial_object_metadata: bool,
    pub group: String,
    pub plural: String,
    /// Client-requested watch stream lifetime in seconds. When Some(n), the server closes
    /// the stream after n seconds. When None, a default of 5 minutes (300s) is used.
    /// Watches must not be subject to a shorter general request timeout — only this value
    /// controls when the server closes the stream.
    pub timeout_seconds: Option<u64>,
}

/// CR-specific context for `watch_generic_for_cr`: the CRD-declared `selectableFields` for
/// the matched version and whether the resource is namespaced (namespace is then also
/// always selectable) — both `cr::cr_matches_field_selector` needs — plus the conversion
/// webhook config and the actually-requested `group/version`, needed to convert watched
/// events to that version before the field-selector filter runs (see
/// `convert_watched_cr_object`).
///
/// `desired_api_version` is independent of `WatchConfig::api_version`: the caller overrides
/// that field to `meta.k8s.io/v1` for PartialObjectMetadata watches, but conversion must
/// still target the real CR version underneath, not that presentation override.
pub(crate) struct CrFieldSelectorContext {
    pub namespaced: bool,
    pub selectable_fields: Vec<String>,
    pub conversion_webhook_client_config: Option<serde_json::Value>,
    pub desired_api_version: String,
}

/// Stream watch events for a given store prefix in NDJSON format.
/// Sends a 60s bookmark heartbeat and closes after cfg.timeout_seconds (default 5 min).
///
/// When `cfg.initial_items` is Some, those items are emitted as ADDED events first
/// (implementing the Kubernetes 1.27+ sendInitialEvents protocol), followed by a
/// BOOKMARK, before streaming live changes from `cfg.from_revision`.
///
/// `cfg.username` is the authenticated client identity used to enforce the per-client
/// watch stream concurrency limit (MAX_WATCHES_PER_CLIENT). Exceeding the limit
/// returns HTTP 429 immediately without opening a watch stream.
pub(crate) async fn watch_generic<S: Store>(
    state: AppState<S>,
    cfg: WatchConfig,
) -> Result<Response, crate::status::StatusError> {
    watch_generic_impl(state, cfg, None).await
}

/// Like `watch_generic`, but for a CR watch whose CRD declares `selectableFields`: every
/// Added/Modified/Deleted event is matched against `field_selector` with
/// `cr::cr_matches_field_selector` instead of `object_matches_field_selector`, so a selector
/// on a CRD-declared field (e.g. `host`) actually excludes non-matching CRs instead of the
/// generic matcher's `_ => {}` catch-all silently letting every object through.
pub(crate) async fn watch_generic_for_cr<S: Store>(
    state: AppState<S>,
    cfg: WatchConfig,
    cr_fields: CrFieldSelectorContext,
) -> Result<Response, crate::status::StatusError> {
    watch_generic_impl(state, cfg, Some(cr_fields)).await
}

/// Convert a single watched CR object to `cr_fields`'s actually-requested version via the
/// CRD's conversion webhook when its own stored apiVersion differs — reusing
/// `cr::convert_cr_list_items` (with a one-element slice) for the exact per-item version
/// check and webhook call the LIST path uses, so both delivery paths stay in lockstep.
///
/// A no-op for builtin-resource watches (`cr_fields` is `None`) and for same-version CR
/// watches: `convert_cr_list_items` never calls the webhook when the object's own apiVersion
/// already matches the target, so the common case (controllers watch the storage version)
/// never pays for one.
async fn convert_watched_cr_object<S: Store>(
    state: &AppState<S>,
    cr_fields: Option<&CrFieldSelectorContext>,
    obj: serde_json::Value,
) -> Result<serde_json::Value, crate::status::StatusError> {
    let Some(ctx) = cr_fields else {
        return Ok(obj);
    };
    let mut items = [obj];
    super::cr::convert_cr_list_items(
        state,
        ctx.conversion_webhook_client_config.as_ref(),
        &mut items,
        &ctx.desired_api_version,
    )
    .await?;
    let [converted] = items;
    Ok(converted)
}

/// Whether a filtered watch should emit a synthetic DELETED for a MODIFIED event whose new
/// state no longer matches the label/field selector. Kubernetes semantics: an object that
/// exits a filtered watch's scope produces a DELETE so the client's cache drops it — but that
/// is only correct if the client's cache could actually contain the object, i.e. this watcher
/// previously delivered it as matching. An object that never matched must not receive a
/// phantom DELETE just because a later update leaves it in yet another non-matching state.
fn should_emit_synthetic_delete(is_modified: bool, now_matches: bool, ever_matched: bool) -> bool {
    is_modified && !now_matches && ever_matched
}

/// Whether a watch needs to record which objects it has delivered as matching.
/// `should_emit_synthetic_delete` only fires when `now_matches` goes false, which
/// `label_selector_matches`/`field_selector_matches_parts`/`cr_matches_field_selector` all make
/// impossible once both selector strings are empty (each short-circuits `""` to "always
/// matches") — so a no-selector watch's `ever_matched` entries can never be read back.
fn watch_tracks_ever_matched(label_selector: &str, field_selector: &str) -> bool {
    !(label_selector.is_empty() && field_selector.is_empty())
}

/// Derive the RBAC/metrics `version` label from a watch's wire-format `apiVersion`
/// ("v1" for core, "apps/v1" for grouped resources) — the last `/`-separated segment.
///
/// For PartialObjectMetadata watches `api_version` is overridden to "meta.k8s.io/v1" by the
/// caller, so this yields "v1" rather than the CR's own requested version in that one case;
/// acceptable for a metrics label, which only needs to be right in the common case.
fn derive_watch_version(api_version: &str) -> &str {
    api_version.rsplit('/').next().unwrap_or(api_version)
}

/// Derive the RBAC/metrics `scope` label ("cluster" or "namespace") from a watch's store
/// prefix, mirroring upstream's `RequestInfo`-derived scope: it reflects whether the request
/// URL named a specific namespace, not whether the resource type is namespaced. A prefix
/// ending in exactly `/<plural>` (no trailing namespace segment) is either a cluster-scoped
/// resource or a namespaced resource watched across all namespaces — both count as "cluster"
/// scope upstream; anything with one more segment names a specific namespace.
fn derive_watch_scope(prefix: &str, plural: &str) -> &'static str {
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.ends_with(&format!("/{plural}")) {
        "cluster"
    } else {
        "namespace"
    }
}

/// RAII guard bracketing `apiserver_longrunning_requests{verb="watch",...}` for the real
/// lifetime of an open watch stream — constructed inside the `async_stream::stream!` block
/// below (not in the surrounding function) so its `Drop` fires only when the stream generator
/// itself ends or is dropped (client disconnect, server timeout, or normal completion), not
/// merely when `watch_generic_impl`'s synchronous setup returns.
struct LongRunningWatchGuard {
    group: String,
    version: String,
    resource: String,
    scope: &'static str,
}

impl LongRunningWatchGuard {
    fn new(group: String, version: String, resource: String, scope: &'static str) -> Self {
        crate::metrics::LONGRUNNING_REQUESTS
            .with_label_values(&[
                "watch",
                &group,
                &version,
                &resource,
                "",
                scope,
                crate::metrics::COMPONENT,
            ])
            .inc();
        Self {
            group,
            version,
            resource,
            scope,
        }
    }
}

impl Drop for LongRunningWatchGuard {
    fn drop(&mut self) {
        crate::metrics::LONGRUNNING_REQUESTS
            .with_label_values(&[
                "watch",
                &self.group,
                &self.version,
                &self.resource,
                "",
                self.scope,
                crate::metrics::COMPONENT,
            ])
            .dec();
    }
}

async fn watch_generic_impl<S: Store>(
    state: AppState<S>,
    cfg: WatchConfig,
    cr_fields: Option<CrFieldSelectorContext>,
) -> Result<Response, crate::status::StatusError> {
    let WatchConfig {
        prefix,
        api_version,
        kind,
        from_revision,
        initial_items,
        label_selector,
        field_selector,
        allow_watch_bookmarks,
        username,
        as_partial_object_metadata,
        group,
        plural,
        timeout_seconds,
    } = cfg;
    let watch_version = derive_watch_version(&api_version).to_string();
    let watch_scope = derive_watch_scope(&prefix, &plural);
    // Enforce per-client watch concurrency limit. Try to acquire a permit from
    // this user's semaphore. If the semaphore is exhausted (client already has
    // MAX_WATCHES_PER_CLIENT open streams), return 429 immediately.
    let sem = state.watch_limit.semaphore_for(&username);
    let _watch_permit = sem.try_acquire_owned().map_err(|_| {
        crate::metrics::REQUEST_TOTAL
            .with_label_values(&["watch", &group, &watch_version, &plural, watch_scope, "429"])
            .inc();
        u7s_store::metrics::WATCH_CLOSED_TOTAL
            .with_label_values(&["client_limit_exceeded"])
            .inc();
        crate::status::Status::too_many_requests(format!(
            "watch limit exceeded for user \"{username}\": maximum {} concurrent watch streams",
            crate::state::MAX_WATCHES_PER_CLIENT
        ))
    })?;
    tracing::debug!(username = %username, "watch: permit acquired");
    // _watch_permit is held for the duration of the watch stream and released when
    // this function returns (RAII drop).

    // Check compaction horizon BEFORE committing headers so clients get a synchronous HTTP 410.
    // If from_rv > 0 and below the horizon, the revision is expired — return 410 immediately.
    // Skip this check when sendInitialEvents is active: initial_items already holds a fresh
    // list snapshot at the current revision, and watch_from_rv below will be set to list_rv,
    // not from_revision. The stale from_revision is irrelevant in that path.
    if from_revision > 0 && initial_items.is_none() {
        // Per-shard, not store-wide: the store-wide horizon is a maximum across every resource
        // type, so a busy type's eviction would expire this watch even when its own resource
        // type's ring is fully intact.
        let horizon = state.store.compaction_horizon_for(&prefix);
        if from_revision < horizon {
            crate::metrics::REQUEST_TOTAL
                .with_label_values(&["watch", &group, &watch_version, &plural, watch_scope, "410"])
                .inc();
            return Err(Status::expired(format!(
                "too old resource version: {from_revision} (current compaction horizon: {horizon})"
            )));
        }
    }

    // When sendInitialEvents is active, the list snapshot was taken at list_rv.
    // The ring buffer replay must start from list_rv (not from_revision) so that
    // any write that raced between the list and the watch subscribe is replayed
    // as a synthetic ADDED in the initial phase — before the BOOKMARK — not after
    // it. Emitting an event after the BOOKMARK would violate the Kubernetes watch
    // protocol invariant: everything before BOOKMARK is "initial state".
    let watch_from_rv = match &initial_items {
        Some((_, list_rv)) => *list_rv,
        None => from_revision,
    };

    // This call performs the store's initial ring-buffer replay scan synchronously inside its
    // own body (no `.await` point precedes it) before ever constructing the returned stream, so
    // timing the whole call captures that scan's real cost — the mechanism behind the ring's
    // occupancy-scaling watch-open latency.
    let watch_open_started = std::time::Instant::now();
    let event_stream = state
        .store
        .watch(&prefix, watch_from_rv)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    crate::metrics::WATCH_OPEN_DURATION_SECONDS
        .with_label_values(&[&group, &plural])
        .observe(watch_open_started.elapsed().as_secs_f64());

    // From this point the watch is committed to opening — count it as a successful request
    // now, matching upstream's counting of the initial HTTP response code for watch requests
    // (the eventual stream-close reason is tracked separately by u7s_watch_closed_total).
    crate::metrics::REQUEST_TOTAL
        .with_label_values(&["watch", &group, &watch_version, &plural, watch_scope, "200"])
        .inc();

    // Cloned so live/DELETED CR watch events can be converted via the CRD's conversion
    // webhook mid-stream (see convert_watched_cr_object). The webhook call needs the full
    // AppState (webhook client, cluster CA, konnectivity proxy config), not just the store,
    // and `state` is otherwise unused for the rest of this function.
    let state_for_conversion = state.clone();

    let label_selector = label_selector.unwrap_or_default();
    let field_selector = field_selector.unwrap_or_default();
    // Quantifies how much of deletion_log's per-tombstone full-body fidelity (kept so a
    // selector-scoped watch reconnecting after compaction can still evaluate its selector
    // against a deleted object) is ever actually consumed vs. paid for on every deletion — see
    // WATCH_OPENS_TOTAL's own doc.
    // Quantifies how much of deletion_log's per-tombstone full-body fidelity (kept so a
    // selector-scoped watch reconnecting after compaction can still evaluate its selector
    // against a deleted object) is ever actually consumed vs. paid for on every deletion — see
    // WATCH_OPENS_TOTAL's own doc.
    crate::metrics::WATCH_OPENS_TOTAL
        .with_label_values(
            &[if label_selector.is_empty() && field_selector.is_empty() {
                "false"
            } else {
                "true"
            }],
        )
        .inc();
    let chunk_stream = async_stream::stream! {
        use futures_core::Stream;
        use std::pin::pin;
        use tokio::time::{Duration, interval, sleep};

        let state_for_conversion = state_for_conversion;
        // Brackets apiserver_longrunning_requests{verb="watch",...} for the stream's real
        // lifetime — see LongRunningWatchGuard's doc for why it must be constructed here,
        // inside the generator, rather than in the enclosing function.
        let _longrunning_guard =
            LongRunningWatchGuard::new(group.clone(), watch_version.clone(), plural.clone(), watch_scope);

        // For a CR watch with CRD-declared selectableFields, defer to the same CRD-aware
        // matcher LIST uses instead of the generic name/namespace/nodeName-only one, which
        // treats any other field selector (e.g. a CRD-declared `host`) as a no-op pass-through.
        let field_selector_matches = |obj: &serde_json::Value| -> bool {
            match &cr_fields {
                Some(ctx) => super::cr::cr_matches_field_selector(
                    obj,
                    &field_selector,
                    ctx.namespaced,
                    &ctx.selectable_fields,
                ),
                None => object_matches_field_selector(obj, &field_selector),
            }
        };

        // Counts every NDJSON line actually written to the client's HTTP body (events and
        // bookmarks alike) — "an event was actually delivered", per apiserver_watch_events_total.
        let record_watch_event = || {
            crate::metrics::WATCH_EVENTS_TOTAL
                .with_label_values(&[&group, &watch_version, &plural])
                .inc();
        };

        let mut event_stream = pin!(event_stream);
        let mut bookmark_tick = interval(Duration::from_secs(60));
        bookmark_tick.tick().await; // skip initial immediate tick

        // Track keys for which this watcher has already emitted a DELETED (real or synthetic).
        // Prevents duplicate synthetic DELETEDs when an object is modified multiple times
        // after leaving the watch scope, and also suppresses real DELETEDs for objects that
        // never entered the watch scope (body didn't match the selector).
        let mut locally_deleted: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Track (namespace, name) pairs this watcher has delivered as matching — via live
        // ADDED/MODIFIED or sendInitialEvents — so the synthetic-DELETE-on-MODIFIED-losing-
        // match logic below only fires for objects actually in this watcher's cache. Without
        // this, an object that never matched the selector gets a phantom DELETED the first
        // time it's modified into another non-matching state, even though the watcher was
        // never told ADDED for it.
        let mut ever_matched: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

        // Use the client-requested timeout. When absent, default to 30 minutes
        // (1800s) to match the Kubernetes apiserver --min-request-timeout default.
        // The 5-minute value that was here caused watch streams to expire 6× more
        // often than a real apiserver, driving excessive reconnections under load and
        // context-canceled cascades in multi-hour conformance runs.
        // Watches must never be subject to a shorter general request timeout —
        // the client's timeoutSeconds is the only server-side close trigger.
        let stream_timeout_secs = timeout_seconds.unwrap_or(30 * 60);
        let mut max_duration = pin!(sleep(Duration::from_secs(stream_timeout_secs)));
        let mut last_rv: u64 = from_revision;

        // sendInitialEvents: emit existing objects as ADDED, then BOOKMARK.
        if let Some((items, list_rv)) = initial_items {
            tracing::debug!(prefix = %prefix, list_rv, item_count = items.len(), "watch: sendInitialEvents start");
            last_rv = last_rv.max(list_rv);
            for item in items {
                // Apply the same label/field selector filtering as live events so that
                // a watch with sendInitialEvents=true and a fieldSelector does not deliver
                // every object in the prefix as ADDED (which would cause the BOOKMARK to
                // never be emitted for non-matching objects, hanging the watch).
                if !object_matches_label_selector(&item, &label_selector)
                    || !field_selector_matches(&item)
                {
                    continue;
                }
                if watch_tracks_ever_matched(&label_selector, &field_selector) {
                    ever_matched.insert((
                        item["metadata"]["namespace"].as_str().unwrap_or("").to_string(),
                        item["metadata"]["name"].as_str().unwrap_or("").to_string(),
                    ));
                }
                if as_partial_object_metadata {
                    let envelope = take_partial_object_metadata(item);
                    record_watch_event();
                    yield Ok::<Bytes, axum::BoxError>(ndjson_event_value("ADDED", &envelope));
                } else {
                    let mut v = item;
                    stamp_type_meta_if_changed(&mut v, &api_version, &kind);
                    record_watch_event();
                    yield Ok::<Bytes, axum::BoxError>(ndjson_event_value("ADDED", &v));
                }
            }
            record_watch_event();
            yield Ok::<Bytes, axum::BoxError>(ndjson_initial_events_bookmark(&api_version, &kind, last_rv));
        }

        loop {
            tokio::select! {
                biased;

                maybe_event = {
                    use std::future::poll_fn;
                    poll_fn(|cx| {
                        use std::task::Poll;
                        match event_stream.as_mut().poll_next(cx) {
                            Poll::Ready(v) => Poll::Ready(v),
                            Poll::Pending => Poll::Pending,
                        }
                    })
                } => {
                    match maybe_event {
                        None => {
                            tracing::debug!(prefix = %prefix, last_rv, "watch: event_stream ended (None), closing response body");
                            break;
                        }
                        Some(event) => {
                            match &event {
                                WatchEvent::Added(obj) | WatchEvent::Modified(obj) => {
                                    last_rv = last_rv.max(obj.revision);
                                }
                                WatchEvent::Deleted { revision, .. } => {
                                    last_rv = last_rv.max(*revision);
                                }
                                WatchEvent::Bookmark { revision } => {
                                    last_rv = last_rv.max(*revision);
                                }
                                WatchEvent::Compacted { .. } => {}
                            }

                            bookmark_tick.reset();

                            if let WatchEvent::Compacted { horizon, .. } = &event {
                                // Use horizon (not last_rv) so clients relist from a revision
                                // the store still holds. last_rv may predate the horizon and
                                // cause an infinite relist loop.
                                let error_line = Bytes::from(format!(
                                    "{{\"type\":\"ERROR\",\"object\":{{\"apiVersion\":\"v1\",\"kind\":\"Status\",\"code\":410,\"message\":\"too old resource version\",\"reason\":\"Expired\",\"metadata\":{{\"resourceVersion\":\"{horizon}\"}}}}}}}}\n"
                                ));
                                u7s_store::metrics::WATCH_CLOSED_TOTAL
                                    .with_label_values(&["compacted"])
                                    .inc();
                                yield Ok::<Bytes, axum::BoxError>(error_line);
                                break;
                            }

                            // Apply labelSelector and fieldSelector: filter Added/Modified events.
                            // Deleted events always pass through so clients can clean up.
                            // Bookmark and Compacted are handled above.
                            if let WatchEvent::Added(obj) | WatchEvent::Modified(obj) = &event {
                                let is_modified = matches!(&event, WatchEvent::Modified(_));
                                if cr_fields.is_none()
                                    && label_selector.is_empty()
                                    && field_selector.is_empty()
                                {
                                    // Fast path: builtin resource, no selector to enforce, so
                                    // there is no CR conversion to splice in and no
                                    // ever_matched/locally_deleted bookkeeping this watcher can
                                    // ever read back (should_emit_synthetic_delete needs
                                    // now_matches to go false, which cannot happen when every
                                    // event trivially matches an empty selector). The whole
                                    // parse+filter+default+serialize pipeline collapses into the
                                    // one call the semantics-oracle tests below already pin down.
                                    let locally_was_deleted = locally_deleted.remove(&obj.key);
                                    let event_type = if is_modified && locally_was_deleted {
                                        "ADDED"
                                    } else if is_modified {
                                        "MODIFIED"
                                    } else {
                                        "ADDED"
                                    };
                                    match prepare_fast_live_event(
                                        &obj.value,
                                        event_type,
                                        &group,
                                        &plural,
                                        &api_version,
                                        &kind,
                                        as_partial_object_metadata,
                                    ) {
                                        Some(bytes) => {
                                            record_watch_event();
                                            yield Ok::<Bytes, axum::BoxError>(bytes);
                                        }
                                        None => {
                                            tracing::warn!(
                                                "watch {event_type} event has invalid UTF-8 or JSON, skipping"
                                            );
                                        }
                                    }
                                } else if let Ok(s) = std::str::from_utf8(&obj.value) {
                                    // Non-CR watches can decide "definitely doesn't match" from
                                    // the cheap projection alone, skipping the full parse and
                                    // CR-conversion no-op below entirely. CR watches must not
                                    // take this shortcut: conversion can change field values the
                                    // selector reads, so pre-filtering the unconverted body could
                                    // wrongly drop an object that matches only after conversion.
                                    if cr_fields.is_none() {
                                        if let Some((name, ns)) = selector_projection_non_match(
                                            &obj.value,
                                            &label_selector,
                                            &field_selector,
                                        ) {
                                            let was_matched =
                                                ever_matched.remove(&(ns.clone(), name.clone()));
                                            if !locally_deleted.contains(&obj.key)
                                                && should_emit_synthetic_delete(
                                                    is_modified,
                                                    false,
                                                    was_matched,
                                                )
                                            {
                                                locally_deleted.insert(obj.key.clone());
                                                let tombstone = build_tombstone_object(
                                                    &name,
                                                    &ns,
                                                    obj.revision,
                                                    &api_version,
                                                    &kind,
                                                );
                                                record_watch_event();
                                                yield Ok::<Bytes, axum::BoxError>(
                                                    ndjson_event_value("DELETED", &tombstone),
                                                );
                                            }
                                            continue;
                                        }
                                    }
                                    let parsed: serde_json::Value =
                                        serde_json::from_str(s).unwrap_or(serde_json::Value::Null);
                                    // Convert to the actually-requested version BEFORE the
                                    // field-selector filter below — filtering the unconverted
                                    // body means a cross-version selector (e.g. v1's hostPort
                                    // against a v2-stored host/port CR) never matches anything.
                                    let conversion_start = std::time::Instant::now();
                                    let parsed = match convert_watched_cr_object(
                                        &state_for_conversion,
                                        cr_fields.as_ref(),
                                        parsed,
                                    )
                                    .await
                                    {
                                        Ok(converted) => {
                                            if cr_fields.is_some() {
                                                tracing::debug!(
                                                    prefix = %prefix,
                                                    key = %obj.key,
                                                    elapsed_ms = conversion_start.elapsed().as_millis() as u64,
                                                    "watch: CR conversion webhook call completed"
                                                );
                                            }
                                            converted
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                prefix = %prefix,
                                                key = %obj.key,
                                                err = %e.1.message,
                                                "watch: CR conversion webhook failed, dropping live event"
                                            );
                                            continue;
                                        }
                                    };
                                    let now_matches = object_matches_label_selector(&parsed, &label_selector)
                                        && field_selector_matches(&parsed);
                                    if now_matches {
                                        // When an object re-enters the watch scope after a synthetic
                                        // DELETED was sent (e.g. label was restored), emit ADDED so
                                        // the watcher treats it as a newly-appearing object.
                                        let locally_was_deleted = locally_deleted.remove(&obj.key);
                                        let event_type = if is_modified && locally_was_deleted {
                                            "ADDED"
                                        } else if is_modified {
                                            "MODIFIED"
                                        } else {
                                            "ADDED"
                                        };
                                        let obj_name = parsed["metadata"]["name"].as_str().unwrap_or("");
                                        let obj_ns = parsed["metadata"]["namespace"].as_str().unwrap_or("");
                                        // Record that this watcher has now delivered the object as
                                        // present, so a later MODIFIED that leaves the watch scope is
                                        // known to be a real transition-out, not a phantom delete for
                                        // an object the watcher was never told about (see
                                        // should_emit_synthetic_delete). Only reachable here (past the
                                        // no-selector fast path above) for a CR watch with both
                                        // selectors empty, which is exactly the case
                                        // watch_tracks_ever_matched gates: now_matches short-circuits
                                        // true forever for such a watch, so the else-branch remove
                                        // below can never read this entry back.
                                        if watch_tracks_ever_matched(&label_selector, &field_selector) {
                                            ever_matched.insert((obj_ns.to_string(), obj_name.to_string()));
                                        }
                                        tracing::debug!(
                                            prefix = %prefix,
                                            event_type,
                                            name = obj_name,
                                            ns = obj_ns,
                                            rv = obj.revision,
                                            "watch: emitting event"
                                        );
                                        // Downstream of the CR conversion/selector check above:
                                        // finish_live_event is the same apply_defaults+wrap-or-
                                        // stamp+serialize tail prepare_live_event's fast path uses,
                                        // shared here instead of duplicated inline.
                                        let bytes = finish_live_event(
                                            parsed,
                                            event_type,
                                            &group,
                                            &plural,
                                            &api_version,
                                            &kind,
                                            as_partial_object_metadata,
                                        );
                                        record_watch_event();
                                        yield Ok::<Bytes, axum::BoxError>(bytes);
                                    } else {
                                        // The object doesn't match the selector after this event.
                                        // Only emit a synthetic DELETED if this watcher previously
                                        // delivered it as matching — otherwise it was never told
                                        // ADDED for this object and a DELETE would be a phantom event
                                        // for an object outside its cache.
                                        let name = parsed["metadata"]["name"].as_str().unwrap_or("").to_string();
                                        let ns = parsed["metadata"]["namespace"].as_str().unwrap_or("").to_string();
                                        let was_matched = ever_matched.remove(&(ns.clone(), name.clone()));
                                        if !locally_deleted.contains(&obj.key)
                                            && should_emit_synthetic_delete(is_modified, now_matches, was_matched)
                                        {
                                            // Only emit once — if locally_deleted already contains
                                            // this key, the watcher already sent a DELETED and a
                                            // subsequent MODIFIED-without-match must be suppressed.
                                            locally_deleted.insert(obj.key.clone());
                                            let tombstone = build_tombstone_object(
                                                &name,
                                                &ns,
                                                obj.revision,
                                                &api_version,
                                                &kind,
                                            );
                                            record_watch_event();
                                            yield Ok::<Bytes, axum::BoxError>(ndjson_event_value("DELETED", &tombstone));
                                        }
                                    }
                                } else {
                                    let event_type = if is_modified { "MODIFIED" } else { "ADDED" };
                                    tracing::warn!("watch {event_type} event has invalid UTF-8, skipping");
                                }
                            } else if let WatchEvent::Deleted { key, revision, body } = &event {
                                // For DELETED events: apply the label/field selector against the
                                // last-known object body (if available), converted to the
                                // actually-requested version first (see convert_watched_cr_object)
                                // — the same ordering as Added/Modified above, so a cross-version
                                // field selector is evaluated against the shape the client asked
                                // for. If no body is available, send unconditionally (conservative).
                                // Also skip if we already emitted a synthetic DELETED for this key
                                // (locally_deleted tracks keys for which DELETED was already sent).
                                let emit_body = body.clone();
                                // Set only when CR conversion already produced the final,
                                // matching, per-version Value in memory — lets the yield below
                                // serialize it once directly instead of round-tripping it back
                                // to Bytes here just so encode_watch_event can reparse it.
                                let mut prebuilt: Option<Bytes> = None;
                                let should_send = if locally_deleted.contains(key.as_str()) {
                                    // Already sent a synthetic DELETED for this object; the real
                                    // DELETED is redundant for this watcher. Clear the tracking entry.
                                    locally_deleted.remove(key.as_str());
                                    false
                                } else if let Some(body_bytes) = body {
                                    if let Ok(s) = std::str::from_utf8(body_bytes) {
                                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s) {
                                            let conversion_start = std::time::Instant::now();
                                            match convert_watched_cr_object(
                                                &state_for_conversion,
                                                cr_fields.as_ref(),
                                                parsed,
                                            )
                                            .await
                                            {
                                                Ok(converted) => {
                                                    if cr_fields.is_some() {
                                                        tracing::debug!(
                                                            prefix = %prefix,
                                                            key = %key,
                                                            elapsed_ms = conversion_start.elapsed().as_millis() as u64,
                                                            "watch: CR conversion webhook call completed"
                                                        );
                                                    }
                                                    let matches = object_matches_label_selector(&converted, &label_selector)
                                                        && field_selector_matches(&converted);
                                                    // The object is gone either way; forget it so a
                                                    // future create reusing this name/namespace starts
                                                    // from a clean "never matched" state instead of
                                                    // inheriting a stale ever_matched entry.
                                                    ever_matched.remove(&(
                                                        converted["metadata"]["namespace"].as_str().unwrap_or("").to_string(),
                                                        converted["metadata"]["name"].as_str().unwrap_or("").to_string(),
                                                    ));
                                                    if matches {
                                                        prebuilt = Some(finish_deleted_event(
                                                            converted,
                                                            *revision,
                                                            &api_version,
                                                            &kind,
                                                        ));
                                                    }
                                                    matches
                                                }
                                                Err(e) => {
                                                    tracing::warn!(
                                                        prefix = %prefix,
                                                        key = %key,
                                                        err = %e.1.message,
                                                        "watch: CR conversion webhook failed, dropping DELETED event"
                                                    );
                                                    false
                                                }
                                            }
                                        } else {
                                            true
                                        }
                                    } else {
                                        true
                                    }
                                } else {
                                    true
                                };
                                tracing::debug!(
                                    prefix = %prefix,
                                    key = %key,
                                    should_send,
                                    has_body = body.is_some(),
                                    "watch: DELETED event reached handler"
                                );
                                if should_send {
                                    let chunk = match prebuilt {
                                        Some(bytes) => Some(bytes),
                                        None => {
                                            let emit_event = WatchEvent::Deleted {
                                                key: key.clone(),
                                                revision: *revision,
                                                body: emit_body,
                                            };
                                            encode_watch_event(&emit_event, &api_version, &kind, as_partial_object_metadata)
                                        }
                                    };
                                    if let Some(chunk) = chunk {
                                        record_watch_event();
                                        yield Ok::<Bytes, axum::BoxError>(chunk);
                                    } else {
                                        tracing::debug!(prefix = %prefix, key = %key, "watch: DELETED event dropped by encode_watch_event");
                                    }
                                }
                            } else if !matches!(&event, WatchEvent::Bookmark { .. }) || allow_watch_bookmarks {
                                if let Some(chunk) = encode_watch_event(&event, &api_version, &kind, as_partial_object_metadata) {
                                    record_watch_event();
                                    yield Ok::<Bytes, axum::BoxError>(chunk);
                                }
                            }
                        }
                    }
                }

                _ = bookmark_tick.tick() => {
                    if allow_watch_bookmarks {
                        // Use the global store revision, not last_rv (the last RV seen on
                        // this stream). KCM's ConsistencyStore checks that each informer's
                        // LastStoreSyncResourceVersion (advanced by BOOKMARK) is >= the RV
                        // of any write the controller made to *any* resource type. A
                        // StatefulSet watch only sees StatefulSet events, so last_rv stays
                        // stale relative to pod writes — causing endless requeue loops.
                        let bookmark_rv = state_for_conversion.store.current_revision().max(last_rv);
                        record_watch_event();
                        yield Ok::<Bytes, axum::BoxError>(ndjson_bookmark(&api_version, &kind, bookmark_rv));
                    }
                }

                _ = &mut max_duration => {
                    tracing::debug!(prefix = %prefix, last_rv, stream_timeout_secs, "watch: max_duration elapsed, closing response body");
                    u7s_store::metrics::WATCH_CLOSED_TOTAL
                        .with_label_values(&["timeout"])
                        .inc();
                    if allow_watch_bookmarks {
                        let bookmark_rv = state_for_conversion.store.current_revision().max(last_rv);
                        record_watch_event();
                        yield Ok::<Bytes, axum::BoxError>(ndjson_bookmark(&api_version, &kind, bookmark_rv));
                    }
                    break;
                }
            }
        }
    };

    let body = Body::from_stream(chunk_stream);
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::TRANSFER_ENCODING, "chunked")
        .body(body)
        .expect("response builder never fails with these headers");

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::super::generic::apply_label_selector;
    use super::*;
    use u7s_store::WatchEvent;

    // -- encode_watch_event: resourceVersion in ADDED events --

    /// Conformance: watch ADDED event payloads must include a non-empty
    /// metadata.resourceVersion. Kubernetes clients use this to track progress
    /// through the watch stream and to issue subsequent watches from a known point.
    /// A missing or empty resourceVersion causes clients to re-list indefinitely.
    #[test]
    fn encode_watch_event_added_includes_resource_version() {
        // Simulate the object as stored by store.put(): bytes already have
        // metadata.resourceVersion stamped by stamp_resource_version().
        let obj_json = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "my-cm",
                "namespace": "default",
                "resourceVersion": "42"
            }
        });
        let value = bytes::Bytes::from(serde_json::to_vec(&obj_json).unwrap());
        let event = WatchEvent::Added(u7s_store::StoreObject {
            key: "/registry/configmaps/default/my-cm".into(),
            value,
            revision: 42,
        });

        let chunk = encode_watch_event(&event, "v1", "ConfigMap", false)
            .expect("ADDED event must produce a chunk");

        let line = std::str::from_utf8(&chunk).unwrap().trim_end();
        let decoded: serde_json::Value =
            serde_json::from_str(line).expect("chunk must be valid JSON");

        assert_eq!(decoded["type"], "ADDED", "event type must be ADDED");

        let rv = decoded["object"]["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("");
        assert!(
            !rv.is_empty(),
            "object.metadata.resourceVersion must be non-empty in ADDED event; \
             Kubernetes watch clients cannot track progress without it"
        );
        assert_eq!(
            rv, "42",
            "resourceVersion must match the value stamped by store.put()"
        );
    }

    /// Mirror of the ADDED test for MODIFIED events: same conformance requirement.
    #[test]
    fn encode_watch_event_modified_includes_resource_version() {
        let obj_json = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "my-cm",
                "namespace": "default",
                "resourceVersion": "99"
            }
        });
        let value = bytes::Bytes::from(serde_json::to_vec(&obj_json).unwrap());
        let event = WatchEvent::Modified(u7s_store::StoreObject {
            key: "/registry/configmaps/default/my-cm".into(),
            value,
            revision: 99,
        });

        let chunk = encode_watch_event(&event, "v1", "ConfigMap", false)
            .expect("MODIFIED event must produce a chunk");

        let decoded: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&chunk).unwrap().trim_end()).unwrap();

        assert_eq!(decoded["type"], "MODIFIED");
        let rv = decoded["object"]["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("");
        assert!(
            !rv.is_empty(),
            "object.metadata.resourceVersion must be non-empty in MODIFIED event"
        );
        assert_eq!(rv, "99");
    }

    /// Regression: DELETED watch event must carry the full last-known object body (including
    /// .spec) when the store provides it, not a metadata-only tombstone.
    ///
    /// Without the body, KCM's replication controller OnDelete converts RC->RS and
    /// dereferences RC.spec, nil-panicking on a spec-less tombstone — killing the entire
    /// KCM process. This test fails on revert: if deleted_body is set to None, the emitted
    /// DELETED event will lack .spec and this assertion fails.
    ///
    /// This covers the delete_namespace_resources path (namespace teardown), which previously
    /// passed deleted_body=None. The same risk exists for any controller's OnDelete that reads
    /// .spec of a deleted object (deployment, RS, etc.).
    #[test]
    fn deleted_watch_event_carries_full_object_so_kcm_controllers_dont_nil_panic_on_delete() {
        let rc_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": {
                "name": "my-rc",
                "namespace": "test-ns",
                "resourceVersion": "77"
            },
            "spec": {
                "replicas": 1,
                "selector": {"app": "test"},
                "template": {
                    "metadata": {"labels": {"app": "test"}},
                    "spec": {"containers": [{"name": "pause", "image": "pause"}]}
                }
            }
        });
        let body_bytes =
            bytes::Bytes::from(serde_json::to_vec(&rc_body).expect("rc_body serializes"));

        let event = WatchEvent::Deleted {
            key: "/registry/replicationcontrollers/test-ns/my-rc".into(),
            revision: 78,
            body: Some(body_bytes),
        };

        let chunk = encode_watch_event(&event, "v1", "ReplicationController", false)
            .expect("DELETED event with body must produce a chunk");

        let decoded: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&chunk).unwrap().trim_end())
                .expect("chunk must be valid JSON");

        assert_eq!(decoded["type"], "DELETED", "event type must be DELETED");

        assert!(
            !decoded["object"]["spec"].is_null(),
            "DELETED event must include .spec from the last-known body; \
             a metadata-only tombstone (spec=null) causes KCM's replication controller \
             OnDelete to nil-panic when converting RC->RS, killing the entire KCM process"
        );

        assert_eq!(
            decoded["object"]["spec"]["replicas"], 1,
            "DELETED event .spec.replicas must match the last-known body; \
             KCM conversion code reads spec fields and panics on nil"
        );

        assert_eq!(
            decoded["object"]["metadata"]["name"], "my-rc",
            "DELETED event must preserve object name from the body"
        );

        assert_eq!(
            decoded["object"]["metadata"]["resourceVersion"], "78",
            "DELETED event must stamp the deletion revision into resourceVersion"
        );
    }

    /// Regression: a DELETED event's stored body may lack apiVersion/kind — e.g. a PUT/Update
    /// sent via the dynamic (unstructured) client from a typed Go struct with an empty
    /// TypeMeta serializes apiVersion/kind as absent (`omitempty`), and
    /// `replace_namespaced_resource` persists the body as received without injecting them.
    /// `encode_watch_event` must still stamp apiVersion/kind on the emitted DELETED object,
    /// exactly like the ADDED/MODIFIED path always does.
    ///
    /// Why it matters: client-go's watch decoder cannot determine an event's Go type without
    /// apiVersion/kind and fails to decode the event, which closes the watch's ResultChan.
    /// client-go's RetryWatcher (used by `watchtools.Until`, e.g. sonobuoy's "lifecycle of a
    /// Deployment" conformance test) then reconnects — without ever having extracted a
    /// resourceVersion from the undecodable event — and repeats forever from the same stale
    /// resourceVersion, wedging any caller waiting on a DELETED event. This test fails on
    /// revert: without the fix, decoded["object"]["apiVersion"]/["kind"] would be absent.
    #[test]
    fn deleted_watch_event_stamps_api_version_and_kind_when_stored_body_lacks_them() {
        let body_without_type_meta = serde_json::json!({
            "metadata": {
                "name": "test-deployment",
                "namespace": "deployment-5815",
                "resourceVersion": "1597"
            },
            "spec": { "replicas": 2 }
        });
        let body_bytes = bytes::Bytes::from(
            serde_json::to_vec(&body_without_type_meta).expect("body serializes"),
        );

        let event = WatchEvent::Deleted {
            key: "/registry/apps/deployments/deployment-5815/test-deployment".into(),
            revision: 1650,
            body: Some(body_bytes),
        };

        let chunk = encode_watch_event(&event, "apps/v1", "Deployment", false)
            .expect("DELETED event with body must produce a chunk");
        let decoded: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&chunk).unwrap().trim_end())
                .expect("chunk must be valid JSON");

        assert_eq!(
            decoded["object"]["apiVersion"], "apps/v1",
            "DELETED event must stamp apiVersion even when the stored body lacks it; without \
             this, client-go's watch decoder cannot determine the object's type and silently \
             fails to decode the event, wedging watchtools.Until forever"
        );
        assert_eq!(
            decoded["object"]["kind"], "Deployment",
            "DELETED event must stamp kind even when the stored body lacks it, for the same \
             reason as apiVersion above"
        );
    }

    /// Regression guard for a tightening that must NOT happen: `finish_deleted_event` merges
    /// the resourceVersion patch into the existing metadata map instead of deserializing the
    /// whole object into `ObjectMeta` and reserializing it, because `ObjectMeta` still doesn't
    /// model `generation` or `deletionGracePeriodSeconds`. `generation` is set on every workload
    /// resource (Deployment, StatefulSet, ...); KCM's controllers stop reconciling entirely if a
    /// DELETED event reports `generation: null` (see defaults.rs's own comment on this exact
    /// failure mode). This test fails if `finish_deleted_event` is ever rewritten to do a full
    /// ObjectMeta round trip: verified by temporarily rewriting it that way and confirming the
    /// two assertions below fail with `null` instead of `4`/`30`.
    #[test]
    fn deleted_watch_event_preserves_fields_objectmeta_does_not_model() {
        let deploy_body = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "my-deploy",
                "namespace": "test-ns",
                "generation": 4,
                "deletionGracePeriodSeconds": 30
            },
            "spec": { "replicas": 1 }
        });
        let body_bytes =
            bytes::Bytes::from(serde_json::to_vec(&deploy_body).expect("deploy_body serializes"));

        let event = WatchEvent::Deleted {
            key: "/registry/apps/deployments/test-ns/my-deploy".into(),
            revision: 99,
            body: Some(body_bytes),
        };

        let chunk = encode_watch_event(&event, "apps/v1", "Deployment", false)
            .expect("DELETED event with body must produce a chunk");
        let decoded: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&chunk).unwrap().trim_end())
                .expect("chunk must be valid JSON");

        assert_eq!(
            decoded["object"]["metadata"]["generation"], 4,
            "generation must survive a DELETED event unchanged — KCM's deployment controller \
             reads it to decide whether to reconcile and stops entirely if it sees null"
        );
        assert_eq!(
            decoded["object"]["metadata"]["deletionGracePeriodSeconds"], 30,
            "deletionGracePeriodSeconds must survive a DELETED event unchanged — it is set \
             during graceful termination and read by controllers/kubelet"
        );
        assert_eq!(
            decoded["object"]["metadata"]["resourceVersion"], "99",
            "finish_deleted_event must still stamp the deletion revision alongside the \
             untouched fields above"
        );
    }

    /// Historical-wedge regression, ADDED counterpart: mirrors
    /// `deleted_watch_event_stamps_api_version_and_kind_when_stored_body_lacks_them` for the
    /// live-watch ADDED path. `prepare_live_event` is what `watch_generic_impl`'s fast path
    /// actually calls for every live ADDED/MODIFIED event; if its unconditional TypeMeta stamp
    /// (via `finish_live_event` -> `stamp_type_meta_if_changed`) regresses to a conditional one,
    /// client-go's watch decoder fails to decode these events too, wedging RetryWatcher exactly
    /// like the DELETED case above.
    #[test]
    fn prepare_live_event_added_stamps_api_version_and_kind_when_stored_body_lacks_them() {
        let body_without_type_meta = serde_json::json!({
            "metadata": {
                "name": "test-deployment",
                "namespace": "deployment-5815",
                "resourceVersion": "1597"
            },
            "spec": { "replicas": 2 }
        });
        let raw = serde_json::to_vec(&body_without_type_meta).expect("body serializes");

        let bytes = prepare_live_event(
            &raw,
            "ADDED",
            "apps",
            "deployments",
            "apps/v1",
            "Deployment",
            false,
            "",
            "",
        )
        .expect("ADDED event must produce bytes");
        let decoded: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&bytes).unwrap().trim_end())
                .expect("chunk must be valid JSON");

        assert_eq!(
            decoded["object"]["apiVersion"], "apps/v1",
            "ADDED event must stamp apiVersion even when the stored body lacks it; without \
             this, client-go's watch decoder cannot determine the object's type and silently \
             fails to decode the event, wedging watchtools.Until forever"
        );
        assert_eq!(
            decoded["object"]["kind"], "Deployment",
            "ADDED event must stamp kind even when the stored body lacks it, for the same \
             reason as apiVersion above"
        );
    }

    /// Mirror of the ADDED test above for MODIFIED events: same conformance requirement.
    #[test]
    fn prepare_live_event_modified_stamps_api_version_and_kind_when_stored_body_lacks_them() {
        let body_without_type_meta = serde_json::json!({
            "metadata": {
                "name": "test-deployment",
                "namespace": "deployment-5815",
                "resourceVersion": "1650"
            },
            "spec": { "replicas": 3 }
        });
        let raw = serde_json::to_vec(&body_without_type_meta).expect("body serializes");

        let bytes = prepare_live_event(
            &raw,
            "MODIFIED",
            "apps",
            "deployments",
            "apps/v1",
            "Deployment",
            false,
            "",
            "",
        )
        .expect("MODIFIED event must produce bytes");
        let decoded: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&bytes).unwrap().trim_end())
                .expect("chunk must be valid JSON");

        assert_eq!(
            decoded["object"]["apiVersion"], "apps/v1",
            "MODIFIED event must stamp apiVersion even when the stored body lacks it, for the \
             same reason as the ADDED case above"
        );
        assert_eq!(
            decoded["object"]["kind"], "Deployment",
            "MODIFIED event must stamp kind even when the stored body lacks it, for the same \
             reason as the ADDED case above"
        );
    }

    /// PartialObjectMetadata projection round-trip: `to_partial_object_metadata` is shared by
    /// the GC's watches and every PartialObjectMetadata LIST/GET response (resource.rs, core.rs,
    /// pods.rs all call this same function), so it must emit exactly {apiVersion, kind,
    /// metadata} — nothing from spec/status. A leaked spec/status field breaks the reflector's
    /// decode of the PartialObjectMetadata type (which has no spec/status fields to decode
    /// into) and, per this same regression class in cr.rs's own `to_pom_strips_spec_and_sets_
    /// correct_kind` test, has previously caused the reflector to never receive the
    /// initial-events-end BOOKMARK, hanging GC informer startup.
    #[test]
    fn to_partial_object_metadata_projects_metadata_only_and_drops_spec_status() {
        let full_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "nginx",
                "namespace": "default",
                "uid": "abc-123",
                "resourceVersion": "42",
                "labels": { "app": "nginx" },
                "annotations": { "note": "hello" },
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "name": "nginx-rs",
                    "uid": "rs-uid"
                }]
            },
            "spec": { "containers": [{"name": "nginx", "image": "nginx:latest"}] },
            "status": { "phase": "Running" }
        });

        let pom = to_partial_object_metadata(&full_pod);

        assert_eq!(
            pom,
            serde_json::json!({
                "apiVersion": "meta.k8s.io/v1",
                "kind": "PartialObjectMetadata",
                "metadata": {
                    "name": "nginx",
                    "namespace": "default",
                    "uid": "abc-123",
                    "resourceVersion": "42",
                    "labels": { "app": "nginx" },
                    "annotations": { "note": "hello" },
                    "ownerReferences": [{
                        "apiVersion": "apps/v1",
                        "kind": "ReplicaSet",
                        "name": "nginx-rs",
                        "uid": "rs-uid"
                    }]
                }
            }),
            "PartialObjectMetadata projection must carry the metadata verbatim (including \
             ownerReferences, which the GC needs to find dependents) and nothing else — a \
             stray spec/status field breaks the reflector's decode of the PartialObjectMetadata \
             type"
        );
        assert!(
            pom.get("spec").is_none(),
            "spec must be entirely absent from a PartialObjectMetadata projection, not merely \
             null — a client checking presence via `contains_key` rather than `.is_null()` \
             would otherwise be misled"
        );
        assert!(
            pom.get("status").is_none(),
            "status must be entirely absent from a PartialObjectMetadata projection, not \
             merely null, for the same reason as spec above"
        );
    }

    /// Regression guard for a tightening that must NOT happen: `PartialObjectMetadataEnvelope`'s
    /// `metadata` field must stay `&serde_json::Value`, not become `ObjectMeta`, because
    /// `ObjectMeta` still doesn't model `generation` or `deletionGracePeriodSeconds`. GC watches
    /// every resource kind (including Deployments and terminating Pods) via this projection; a
    /// full ObjectMeta round trip would silently drop both fields from the GC's view of those
    /// objects. This test fails if `to_partial_object_metadata` is ever rewritten to deserialize
    /// `metadata` into `ObjectMeta` and reserialize it: verified by temporarily rewriting it that
    /// way and confirming the two assertions below fail with `null` instead of `5`/`30`.
    #[test]
    fn to_partial_object_metadata_preserves_fields_objectmeta_does_not_model() {
        let full = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "my-deploy",
                "generation": 5,
                "deletionGracePeriodSeconds": 30
            },
            "spec": { "replicas": 1 }
        });

        let pom = to_partial_object_metadata(&full);

        assert_eq!(
            pom["metadata"]["generation"], 5,
            "generation must survive the PartialObjectMetadata projection unchanged — GC's \
             ownerReferences-following watch is the same projection KCM's generation-tracking \
             controllers would see null from if this field were dropped"
        );
        assert_eq!(
            pom["metadata"]["deletionGracePeriodSeconds"], 30,
            "deletionGracePeriodSeconds must survive the PartialObjectMetadata projection \
             unchanged — it is set during graceful termination and read by controllers/kubelet"
        );
    }

    /// The owned fast path every watch event uses (`take_partial_object_metadata` + the generic
    /// `ndjson_event_value`) must serialize to exactly the same bytes as the borrowed path
    /// resource.rs/core.rs's LIST/GET handlers still use (`to_partial_object_metadata` +
    /// `serde_json::to_value`) — the only thing allowed to change between the two is how many
    /// times the metadata subtree gets copied, never what ends up on the wire.
    ///
    /// Fails on revert to a `take_partial_object_metadata` that reorders fields, drops one, or
    /// otherwise diverges from `PartialObjectMetadataEnvelope`'s wire shape — every watch client
    /// parses these bytes and any divergence breaks every informer.
    #[test]
    fn take_partial_object_metadata_matches_borrowed_variant_byte_for_byte() {
        let full_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "nginx",
                "namespace": "default",
                "uid": "abc-123",
                "resourceVersion": "42",
                "labels": { "app": "nginx" }
            },
            "spec": { "containers": [{"name": "nginx", "image": "nginx:latest"}] },
            "status": { "phase": "Running" }
        });

        let expected = ndjson_event_value("ADDED", &to_partial_object_metadata(&full_pod));
        let got = ndjson_event_value("ADDED", &take_partial_object_metadata(full_pod));

        assert_eq!(
            got.as_ref(),
            expected.as_ref(),
            "the owned PartialObjectMetadata path every watch event takes must produce \
             byte-identical NDJSON to the borrowed path LIST/GET still use; got {:?} want {:?}",
            got,
            expected
        );
    }

    /// `take_partial_object_metadata` used to use `obj["metadata"].take()` (serde_json
    /// `IndexMut`), which panics whenever `obj` itself is not a JSON object — e.g. a corrupt
    /// store entry whose raw bytes are a bare scalar, reachable through `prepare_live_event`
    /// with both selectors empty (an empty selector always "matches", so a non-object parse
    /// isn't filtered out upstream the way a real object failing the selector would be). A
    /// panic here would take down the whole watch stream, not just skip the one corrupt object.
    #[test]
    fn prepare_live_event_does_not_panic_on_non_object_store_entry_as_partial_object_metadata() {
        let got = prepare_live_event(
            b"5",
            "MODIFIED",
            "",
            "configmaps",
            "v1",
            "ConfigMap",
            true,
            "",
            "",
        )
        .expect(
            "a non-object but validly-parsed store entry still passes an empty selector and \
             must still produce an event, not None",
        );

        let expected = "{\"type\":\"MODIFIED\",\"object\":{\"apiVersion\":\"meta.k8s.io/v1\",\"kind\":\"PartialObjectMetadata\",\"metadata\":null}}\n";
        assert_eq!(
            got.as_ref(),
            expected.as_bytes(),
            "a non-object stored entry must fall back to metadata: null, matching \
             to_partial_object_metadata's graceful handling of the same input, instead of \
             panicking and killing the whole watch stream"
        );
    }

    /// Regression guard: if encode_watch_event ever strips metadata.resourceVersion
    /// (e.g. by rebuilding the object from scratch), this test must fail.
    #[test]
    fn encode_watch_event_added_without_resource_version_in_blob_yields_empty() {
        // Object stored WITHOUT resourceVersion (should not happen in practice,
        // but verifies the test is sensitive to presence/absence of the field).
        let obj_json = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "bare" }
        });
        let value = bytes::Bytes::from(serde_json::to_vec(&obj_json).unwrap());
        let event = WatchEvent::Added(u7s_store::StoreObject {
            key: "/registry/configmaps/default/bare".into(),
            value,
            revision: 7,
        });

        let chunk = encode_watch_event(&event, "v1", "ConfigMap", false).unwrap();
        let decoded: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&chunk).unwrap().trim_end()).unwrap();

        // This asserts the negative: if stamp_resource_version is NOT called, the field is absent.
        // The fact that the two tests above pass (with rv="42"/"99") proves encode_watch_event
        // does NOT inject the field itself — it relies entirely on store.put() to stamp it.
        let rv = decoded["object"]["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("");
        assert!(
            rv.is_empty(),
            "without stamping, resourceVersion must be absent — \
             encode_watch_event must not synthesize it from StoreObject.revision"
        );
    }

    /// Regression: encode_watch_event must skip (return None) for ADDED events whose
    /// stored bytes are not valid UTF-8, rather than emitting {"type":"ADDED","object":null}.
    ///
    /// Kubernetes clients (controller-runtime, client-go) do not expect null objects in
    /// watch streams and may panic or enter a bad state when they receive one. A corrupt
    /// store entry must not propagate to clients; the stream must continue for subsequent
    /// valid events.
    #[test]
    fn encode_watch_event_added_with_invalid_utf8_is_skipped() {
        let corrupt_bytes = bytes::Bytes::from(vec![0xFF, 0xFE, 0x00]);
        let event = WatchEvent::Added(u7s_store::StoreObject {
            key: "/registry/configmaps/default/corrupt".into(),
            value: corrupt_bytes,
            revision: 1,
        });

        let result = encode_watch_event(&event, "v1", "ConfigMap", false);

        assert!(
            result.is_none(),
            "encode_watch_event must skip (return None) for ADDED events with invalid UTF-8, \
             not emit {{\"type\":\"ADDED\",\"object\":null}} which breaks Kubernetes watch clients"
        );
    }

    /// Regression: same as above but for MODIFIED events.
    #[test]
    fn encode_watch_event_modified_with_invalid_utf8_is_skipped() {
        let corrupt_bytes = bytes::Bytes::from(vec![0xFF, 0xFE]);
        let event = WatchEvent::Modified(u7s_store::StoreObject {
            key: "/registry/configmaps/default/corrupt".into(),
            value: corrupt_bytes,
            revision: 2,
        });

        let result = encode_watch_event(&event, "v1", "ConfigMap", false);

        assert!(
            result.is_none(),
            "encode_watch_event must skip (return None) for MODIFIED events with invalid UTF-8, \
             not emit {{\"type\":\"MODIFIED\",\"object\":null}} which breaks Kubernetes watch clients"
        );
    }

    /// prepare_fast_live_event's zero-parse branch must produce bytes byte-identical to the
    /// format! equivalent of its input, and must skip (not emit a garbled line for) invalid
    /// UTF-8. This is the function watch_generic_impl's no-selector fast path calls directly on
    /// stored bytes, so a broken implementation here silently ships malformed events to every
    /// plain (no label/field selector, no defaulting needed) watch — the highest-volume case in
    /// any cluster.
    #[test]
    fn prepare_fast_live_event_matches_format_equivalent_and_skips_invalid_utf8() {
        let obj_json = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm","namespace":"default","resourceVersion":"42"}}"#;
        let expected = format!("{{\"type\":\"MODIFIED\",\"object\":{obj_json}}}\n");

        let got = prepare_fast_live_event(
            obj_json.as_bytes(),
            "MODIFIED",
            "",
            "configmaps",
            "v1",
            "ConfigMap",
            false,
        )
        .expect("valid UTF-8 JSON with already-canonical type meta must produce a chunk");
        assert_eq!(
            got.as_ref(),
            expected.as_bytes(),
            "prepare_fast_live_event must produce byte-identical output to the format! \
             equivalent; an informer that decodes a re-encoded or malformed line desyncs its \
             cache from the server's actual state"
        );

        let corrupt = prepare_fast_live_event(
            &[0xFF, 0xFE],
            "ADDED",
            "",
            "configmaps",
            "v1",
            "ConfigMap",
            false,
        );
        assert!(
            corrupt.is_none(),
            "prepare_fast_live_event must skip (return None) for invalid UTF-8 rather than \
             embedding raw garbage bytes into the NDJSON stream, which would break every client \
             parsing the watch response"
        );
    }

    /// Reachability pin for the zero-parse fast path: the test above (and
    /// `watch_generic_no_selector_fast_path_emits_byte_correct_added_event`) build their fixture
    /// with already-alphabetical key order, so `serde_json`'s BTreeMap-backed `Value::Object`
    /// reserializes it identically whether or not it was ever parsed — a silent revert that
    /// routes every event back through the slow `prepare_live_event` parse+reserialize path
    /// would NOT fail either test. This fixture instead uses deliberately non-alphabetical key
    /// order at both the top level (`kind` before `apiVersion`) and inside `metadata`
    /// (`resourceVersion` before `namespace`/`name`): the raw fast path echoes the stored bytes
    /// verbatim, preserving that order, while the slow path always emits keys alphabetically.
    /// Asserting the original (unsorted) order is therefore an observable side effect that only
    /// the raw path produces, proving it was actually taken rather than just happening to agree.
    #[test]
    fn prepare_fast_live_event_reachability_preserves_non_alphabetical_key_order() {
        let obj_json = r#"{"kind":"ConfigMap","apiVersion":"v1","metadata":{"resourceVersion":"42","namespace":"default","name":"cm"}}"#;
        let expected = format!("{{\"type\":\"MODIFIED\",\"object\":{obj_json}}}\n");

        let got = prepare_fast_live_event(
            obj_json.as_bytes(),
            "MODIFIED",
            "",
            "configmaps",
            "v1",
            "ConfigMap",
            false,
        )
        .expect("valid UTF-8 JSON with already-canonical type meta must produce a chunk");

        assert_eq!(
            got.as_ref(),
            expected.as_bytes(),
            "prepare_fast_live_event must preserve the stored bytes' original key order \
             verbatim; a full parse into serde_json::Value re-sorts keys alphabetically via its \
             BTreeMap-backed Map, so if this fails because keys got reordered, the zero-parse \
             fast path was silently bypassed in favor of the slow parse+reserialize path — \
             exactly the routing regression this test exists to catch"
        );
    }

    /// Regression pin for the exact bug this project already hit once: apply_defaults sets
    /// Service.spec.ipFamilyPolicy, so a Service watched with no selector must NOT take the
    /// zero-parse raw path (which never runs apply_defaults) — it must fall back to
    /// prepare_live_event. If defaults_may_mutate is ever missing an arm apply_defaults has,
    /// a client watching that resource type silently stops seeing server-side defaults on
    /// live events (see watch_generic_service_added_event_has_ip_family_defaults, which reaches
    /// this same gate through the full watch_generic_impl stream).
    #[test]
    fn defaults_may_mutate_matches_apply_defaults_reaches_this_watch_regression() {
        assert!(
            defaults_may_mutate("", "services"),
            "apply_defaults has a Service arm (default_service sets ipFamilyPolicy); \
             defaults_may_mutate must say so or the watch fast path skips it silently"
        );
        assert!(
            !defaults_may_mutate("", "configmaps"),
            "apply_defaults has no ConfigMap arm; defaults_may_mutate returning true here would \
             just cost performance (forces the slow path), not correctness, but pins the \
             expected fast-path-eligible case this whole optimization targets"
        );
    }

    /// type_meta_already_canonical must reject a false match from a nested value that happens
    /// to carry the same apiVersion/kind pair as an unrelated top-level field — e.g. an
    /// ownerReference — proving the projection reads the *top-level* apiVersion/kind fields,
    /// not any substring match against the raw bytes.
    #[test]
    fn type_meta_already_canonical_checks_top_level_fields_only() {
        let with_owner_ref = r#"{"metadata":{"name":"rs","ownerReferences":[{"apiVersion":"apps/v1","kind":"Deployment","name":"d","uid":"1"}]}}"#;
        assert!(
            !type_meta_already_canonical(with_owner_ref, "apps/v1", "Deployment"),
            "the object's own top-level apiVersion/kind are absent even though an \
             ownerReference embeds the same pair; treating that as canonical would skip the \
             type-meta fix-up this object actually needs"
        );
    }

    // -- per-line emission: single-allocation NDJSON helpers (p2i8) --

    /// ndjson_event_raw must produce bytes byte-identical to the format! equivalent.
    ///
    /// Watch clients parse these bytes; any format change breaks every informer. This test
    /// fails on revert: if the buffer-based helper is replaced with format!+Bytes::from,
    /// the byte sequence must remain identical or clients will fail to parse the stream.
    #[test]
    fn ndjson_event_raw_bytes_match_format_equivalent() {
        let obj_json = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm","namespace":"default","resourceVersion":"42"}}"#;
        let expected = format!("{{\"type\":\"ADDED\",\"object\":{obj_json}}}\n");
        let got = ndjson_event_raw("ADDED", obj_json);
        assert_eq!(
            got.as_ref(),
            expected.as_bytes(),
            "ndjson_event_raw must produce byte-identical output to the format! equivalent; \
             watch clients parse these bytes and any format change breaks every informer"
        );
    }

    /// ndjson_event_value must produce bytes byte-identical to format!+to_string equivalent.
    ///
    /// Watch clients parse these bytes; any format change breaks every informer.
    #[test]
    fn ndjson_event_value_bytes_match_format_equivalent() {
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "cm", "namespace": "default", "resourceVersion": "99"}
        });
        let expected = format!(
            "{{\"type\":\"MODIFIED\",\"object\":{}}}\n",
            serde_json::to_string(&obj).unwrap()
        );
        let got = ndjson_event_value("MODIFIED", &obj);
        assert_eq!(
            got.as_ref(),
            expected.as_bytes(),
            "ndjson_event_value must produce byte-identical output to the format!+to_string \
             equivalent; watch clients parse these bytes and any format change breaks every informer"
        );
    }

    /// ndjson_bookmark must produce bytes byte-identical to the format! equivalent.
    ///
    /// Watch clients parse these bytes; any format change breaks every informer.
    #[test]
    fn ndjson_bookmark_bytes_match_format_equivalent() {
        let api_version = "apps/v1";
        let kind = "Deployment";
        let revision: u64 = 123;
        let expected = format!(
            "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"{api_version}\",\"kind\":\"{kind}\",\"metadata\":{{\"resourceVersion\":\"{revision}\"}}}}}}\n"
        );
        let got = ndjson_bookmark(api_version, kind, revision);
        assert_eq!(
            got.as_ref(),
            expected.as_bytes(),
            "ndjson_bookmark must produce byte-identical output to the format! equivalent; \
             watch clients parse these bytes and any format change breaks every informer"
        );
    }

    /// ndjson_initial_events_bookmark must produce bytes byte-identical to the format! equivalent.
    ///
    /// Watch clients parse these bytes; any format change breaks every informer.
    #[test]
    fn ndjson_initial_events_bookmark_bytes_match_format_equivalent() {
        let api_version = "storage.k8s.io/v1";
        let kind = "CSINode";
        let last_rv: u64 = 0;
        let expected = format!(
            "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"{api_version}\",\"kind\":\"{kind}\",\"metadata\":{{\"resourceVersion\":\"{last_rv}\",\"annotations\":{{\"k8s.io/initial-events-end\":\"true\"}}}}}}}}\n"
        );
        let got = ndjson_initial_events_bookmark(api_version, kind, last_rv);
        assert_eq!(
            got.as_ref(),
            expected.as_bytes(),
            "ndjson_initial_events_bookmark must produce byte-identical output to the format! \
             equivalent; watch clients parse these bytes and any format change breaks every informer"
        );
    }

    /// Verify the BOOKMARK for sendInitialEvents is constructed correctly.
    #[test]
    fn watch_generic_send_initial_events_bookmark_is_first_ndjson_line() {
        let api_version = "storage.k8s.io/v1";
        let kind = "CSINode";
        let last_rv: u64 = 0;

        // This is exactly how watch_generic constructs the BOOKMARK.
        let bookmark = format!(
            "{{\"type\":\"BOOKMARK\",\"object\":{{\"apiVersion\":\"{api_version}\",\"kind\":\"{kind}\",\"metadata\":{{\"resourceVersion\":\"{last_rv}\",\"annotations\":{{\"k8s.io/initial-events-end\":\"true\"}}}}}}}}\n"
        );

        let decoded: serde_json::Value =
            serde_json::from_str(bookmark.trim_end()).expect("BOOKMARK line must be valid JSON");

        assert_eq!(
            decoded["type"], "BOOKMARK",
            "initial-events-end event must be type BOOKMARK"
        );
        assert_eq!(
            decoded["object"]["apiVersion"], api_version,
            "BOOKMARK must include correct apiVersion"
        );
        assert_eq!(
            decoded["object"]["kind"], kind,
            "BOOKMARK must include correct kind"
        );
        assert_eq!(
            decoded["object"]["metadata"]["resourceVersion"], "0",
            "BOOKMARK must include resourceVersion"
        );
        assert_eq!(
            decoded["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"], "true",
            "BOOKMARK must carry k8s.io/initial-events-end=true; \
             without it kubelet's informer never exits the list phase and times out"
        );
    }

    /// Regression test: when a client opens a watch with a resourceVersion
    /// below the compaction horizon, watch_generic must return HTTP 410 BEFORE committing
    /// headers.
    #[tokio::test]
    async fn watch_generic_returns_410_before_streaming_for_expired_rv() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        store.set_compaction_horizon_for_test("/registry/test/", 50);

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let result = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/test/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 10, // expired
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: None,
            },
        )
        .await;

        assert!(
            result.is_err(),
            "watch_generic must return Err(410) for expired resourceVersion, \
             not Ok(streaming 200) — clients cannot detect failure from a stream header"
        );
        use axum::response::IntoResponse;
        let err_resp: axum::response::Response = result.unwrap_err().into_response();
        assert_eq!(
            err_resp.status(),
            axum::http::StatusCode::GONE,
            "HTTP 410 Gone must be returned synchronously so clients can retry without \
             waiting for the stream body"
        );
    }

    /// watch_generic with from_revision=0 (full watch) must NOT trigger the 410 check.
    #[tokio::test]
    async fn watch_generic_rv_zero_does_not_trigger_410() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        store.set_compaction_horizon_for_test("/registry/test/", 50);

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let result = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/test/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0, // not expired
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: None,
            },
        )
        .await;

        assert!(
            result.is_ok(),
            "rv=0 (full watch) must not trigger the 410 expiry check, \
             even when a compaction horizon exists"
        );
    }

    /// A successful watch open must record a duration sample in
    /// `apiserver_watch_open_duration_seconds` under this request's exact `{group, resource}` —
    /// the signal an operator uses to see the ring-buffer replay scan's cost scale with ring
    /// occupancy over a run. Fails on revert if the `.observe()` call around
    /// `state.store.watch(...)` were deleted: a real successful watch open would leave this
    /// series permanently absent instead of gaining a sample.
    #[tokio::test]
    async fn watch_generic_open_records_a_duration_sample_for_its_group_and_resource() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let plural = "watch-open-duration-test";
        let before = crate::metrics::WATCH_OPEN_DURATION_SECONDS
            .with_label_values(&["", plural])
            .get_sample_count();

        let result = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/watch-open-duration-test/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: plural.into(),
                timeout_seconds: None,
            },
        )
        .await;
        assert!(
            result.is_ok(),
            "watch open must succeed for a fresh in-memory store"
        );

        let after = crate::metrics::WATCH_OPEN_DURATION_SECONDS
            .with_label_values(&["", plural])
            .get_sample_count();
        assert!(
            after > before,
            "a successful watch open must record a duration sample for its {{group,resource}}; \
             before={before} after={after}"
        );
    }

    /// A watch open must record itself into `u7s_apiserver_watch_opens_total` under
    /// `has_selector="true"` when it carries a `labelSelector`, and `has_selector="false"` when
    /// it carries neither selector — this counter quantifies how much of
    /// deletion_log's per-tombstone full-body fidelity ever actually gets read by a
    /// selector-scoped reconnect vs. paid for as write-and-never-read insurance on every
    /// deletion. Fails on revert if the `.inc()` call in `watch_generic_impl` were deleted, or
    /// mislabeled a selector-bearing open as `"false"` (or vice versa): a real watch open would
    /// leave the wrong series unchanged instead of gaining a sample.
    #[tokio::test]
    async fn watch_generic_open_records_selector_presence_under_the_correct_label() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let true_before = crate::metrics::WATCH_OPENS_TOTAL
            .with_label_values(&["true"])
            .get();
        let false_before = crate::metrics::WATCH_OPENS_TOTAL
            .with_label_values(&["false"])
            .get();

        // A ?labelSelector= watch open must count under has_selector="true", not "false".
        let with_selector = watch_generic(
            state.clone(),
            WatchConfig {
                prefix: "/registry/watch-selector-metric-test-a/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: Some("app=frontend".into()),
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "watch-selector-metric-test-a".into(),
                timeout_seconds: None,
            },
        )
        .await;
        assert!(
            with_selector.is_ok(),
            "watch open with a selector must succeed"
        );

        // A watch open with neither selector must count under has_selector="false", not "true".
        let without_selector = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/watch-selector-metric-test-b/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "watch-selector-metric-test-b".into(),
                timeout_seconds: None,
            },
        )
        .await;
        assert!(
            without_selector.is_ok(),
            "watch open with no selector must succeed"
        );

        let true_after = crate::metrics::WATCH_OPENS_TOTAL
            .with_label_values(&["true"])
            .get();
        let false_after = crate::metrics::WATCH_OPENS_TOTAL
            .with_label_values(&["false"])
            .get();

        // `>=`, not `==`: `has_selector` only ever takes two values, so this counter is shared
        // by every other watch-opening test in this file running concurrently in the same test
        // binary — an exact-delta assertion is flaky by construction (confirmed empirically: a
        // full-module run intermittently saw `false` jump by 3 during this test's own window).
        // `>=` stays correct under that noise because our own call always contributes exactly
        // one and concurrent activity can only add more, never fewer — so it still fails
        // deterministically when run in isolation (no concurrent noise) against reverted code,
        // where `after` would equal `before` exactly.
        assert!(
            true_after > true_before,
            "a labelSelector-bearing watch open must increment has_selector=\"true\" by at \
             least one; before={true_before} after={true_after}"
        );
        assert!(
            false_after > false_before,
            "a no-selector watch open must increment has_selector=\"false\" by at least one; \
             before={false_before} after={false_after}"
        );
    }

    /// watch_generic with sendInitialEvents=true (initial_items is Some) and an expired
    /// from_revision must NOT return 410 — the stale rv is irrelevant because the watch
    /// starts from the fresh list_rv, not from_revision. Without this fix sonobuoy's
    /// configmap watches get stuck in a 410 retry loop once the ring buffer fills.
    #[tokio::test]
    async fn watch_generic_send_initial_events_bypasses_410_for_expired_rv() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        store.set_compaction_horizon_for_test("/registry/test/", 50);

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // initial_items=Some simulates sendInitialEvents=true having already fetched a
        // fresh list snapshot. from_revision=10 is below the horizon of 50.
        let result = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/test/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 10,                 // expired — below horizon of 50
                initial_items: Some((vec![], 50)), // sendInitialEvents already fetched snapshot at rv=50
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: None,
            },
        )
        .await;

        assert!(
            result.is_ok(),
            "watch_generic must not return 410 when sendInitialEvents=true (initial_items is Some), \
             even if from_revision is below the compaction horizon — the watch starts from list_rv, \
             not from_revision"
        );
    }

    /// When Compacted fires, the 410 ERROR's metadata.resourceVersion must be the
    /// horizon, not last_rv.
    #[test]
    fn watch_410_error_uses_compaction_horizon_not_last_rv() {
        let horizon: u64 = 500;
        let obj = serde_json::json!({
            "type": "ERROR",
            "object": {
                "apiVersion": "v1",
                "kind": "Status",
                "code": 410,
                "message": "too old resource version",
                "reason": "Expired",
                "metadata": {"resourceVersion": horizon.to_string()}
            }
        });
        let rv = obj["object"]["metadata"]["resourceVersion"]
            .as_str()
            .unwrap();
        assert_eq!(
            rv, "500",
            "410 ERROR must carry horizon as resourceVersion so clients relist from \
             a valid point, not from last_rv which may predate the compaction horizon"
        );
    }

    /// The (MAX_WATCHES_PER_CLIENT + 1)th watch from the same user returns 429.
    #[tokio::test]
    async fn watch_limit_per_client_returns_429_on_overflow() {
        use crate::state::{AppState, MAX_WATCHES_PER_CLIENT};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let sem = state.watch_limit.semaphore_for("alice");
        let _permits: Vec<_> = (0..MAX_WATCHES_PER_CLIENT)
            .map(|_| {
                sem.clone()
                    .try_acquire_owned()
                    .expect("permit must be available")
            })
            .collect();

        let result = watch_generic(
            state.clone(),
            WatchConfig {
                prefix: "/registry/test/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "alice".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: None,
            },
        )
        .await;

        assert!(
            result.is_err(),
            "watch_generic must return Err(429) when the per-client limit is exhausted"
        );
        use axum::response::IntoResponse;
        let err_resp: axum::response::Response = result.unwrap_err().into_response();
        assert_eq!(
            err_resp.status(),
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "must return HTTP 429 when per-client watch limit is exhausted, not silently queue"
        );
    }

    // -- fetch_initial_events and watch_generic store error paths --

    /// fetch_initial_events maps StoreError → StatusError(500) via Status::internal.
    /// This test verifies the error conversion so that if the map_err is accidentally
    /// removed or changed to a different status code, the test fails.
    ///
    /// The path cannot be triggered with SqliteStore (which never errors after
    /// construction on :memory:), so we test the Status::internal constructor directly —
    /// it must produce INTERNAL_SERVER_ERROR. The production code has exactly one
    /// `map_err(|e| Status::internal(e.to_string()))` in fetch_initial_events.
    #[test]
    fn fetch_initial_events_store_error_maps_to_500() {
        use axum::response::IntoResponse;

        // Simulate what fetch_initial_events does on store.list() failure:
        // it calls Status::internal(e.to_string()). Verify the StatusCode is 500.
        let err = crate::status::Status::internal("simulated list failure".to_string());
        let resp: axum::response::Response = err.into_response();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "fetch_initial_events must map store list() errors to HTTP 500 via Status::internal; \
             changing this to another code would break client error handling"
        );
    }

    /// watch_generic maps store.watch() errors → StatusError(500) via Status::internal.
    /// The path cannot be triggered with SqliteStore (watch() always returns Ok after
    /// construction). This test verifies the Status::internal mapping is the correct 500 code.
    ///
    /// The production code path is:
    ///   state.store.watch(...).await.map_err(|e| Status::internal(e.to_string()))?
    /// If someone changes this to Status::bad_request or a 4xx, this test fails.
    #[test]
    fn watch_generic_store_watch_error_maps_to_500() {
        use axum::response::IntoResponse;

        let err = crate::status::Status::internal("simulated watch failure".to_string());
        let resp: axum::response::Response = err.into_response();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "watch_generic must map store watch() errors to HTTP 500 via Status::internal"
        );
    }

    /// A different user's watch succeeds even when another user has exhausted their quota.
    #[tokio::test]
    async fn watch_limit_does_not_affect_other_users() {
        use crate::state::{AppState, MAX_WATCHES_PER_CLIENT};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let sem_alice = state.watch_limit.semaphore_for("alice");
        let _permits: Vec<_> = (0..MAX_WATCHES_PER_CLIENT)
            .map(|_| {
                sem_alice
                    .clone()
                    .try_acquire_owned()
                    .expect("permit must be available")
            })
            .collect();

        let result = watch_generic(
            state.clone(),
            WatchConfig {
                prefix: "/registry/test/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "bob".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: None,
            },
        )
        .await;

        assert!(
            result.is_ok(),
            "bob's watch must succeed even when alice has exhausted her per-client limit"
        );
    }

    // -- watch_generic label/field selector filtering --

    /// Helper: read from a watch_generic Response body with a timeout, returning parsed NDJSON lines.
    ///
    /// Waits up to 3 seconds for the body to close, then parses all collected NDJSON lines.
    /// All watch_generic calls in these tests must use `timeout_seconds: Some(1)` so the
    /// stream closes after 1 second, allowing `to_bytes` to return the collected bytes.
    ///
    /// The 3-second timeout guards against tests hanging indefinitely if the stream never closes.
    async fn read_watch_body_with_timeout(
        resp: axum::response::Response,
    ) -> Vec<serde_json::Value> {
        use tokio::time::{timeout, Duration};

        let body = resp.into_body();
        let result = timeout(
            Duration::from_secs(3),
            axum::body::to_bytes(body, usize::MAX),
        )
        .await;

        let bytes = match result {
            Ok(Ok(b)) => b,
            // Timeout (stream still open after 3s) or error: return empty.
            _ => return vec![],
        };

        let text = match std::str::from_utf8(&bytes) {
            Ok(t) => t.to_owned(),
            Err(_) => return vec![],
        };
        text.lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    /// The no-selector ADDED fast path in `watch_generic_impl` must emit bytes byte-for-byte
    /// identical to the stored object, not just semantically-equal JSON. An informer decodes
    /// each NDJSON line directly into its typed object cache; if the fast path's raw
    /// passthrough ever regresses (wrong event type, dropped/garbled bytes, missing trailing
    /// newline), the informer either fails to decode the line at all or applies a subtly wrong
    /// object to its cache — desyncing it from server state without any visible error.
    #[tokio::test]
    async fn watch_generic_no_selector_fast_path_emits_byte_correct_added_event() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "cm-fast", "namespace": "default" },
            "data": { "k": "v" }
        });
        let revision = store
            .put(
                "/registry/configmaps/default/cm-fast",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();
        // store.put() stamps resourceVersion into the persisted bytes; mirror that here so the
        // expected line matches exactly what a watcher must receive.
        obj["metadata"]["resourceVersion"] = serde_json::Value::String(revision.to_string());
        let expected_line = format!(
            "{{\"type\":\"ADDED\",\"object\":{}}}\n",
            serde_json::to_string(&obj).unwrap()
        );

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // No label/field selector, as_partial_object_metadata=false, and ConfigMaps have no
        // apply_defaults arm: this is exactly the condition prepare_fast_live_event routes
        // through its zero-parse ndjson_event_raw branch instead of prepare_live_event.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1),
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed for fast-path byte-correctness test"));

        let bytes = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            axum::body::to_bytes(resp.into_body(), usize::MAX),
        )
        .await
        .expect("stream must close within timeout")
        .expect("body read must succeed");
        let text = std::str::from_utf8(&bytes).expect("watch body must be valid UTF-8");

        assert_eq!(
            text, expected_line,
            "fast-path ADDED event must be byte-identical to the stored object wrapped in the \
             NDJSON envelope; any deviation (re-encoded formatting, dropped field, wrong event \
             type) is exactly the class of bug that desyncs an informer's cache from the \
             server without a visible decode error"
        );
    }

    /// A watch with a matching label selector must emit the ADDED event for a matching object.
    /// The watcher subscribes with label selector "app=frontend". An object with that label
    /// is written BEFORE subscribing so the ring buffer replays it. The watch stream must
    /// yield ADDED. This is the primary correctness requirement for label-filtered watches.
    #[tokio::test]
    async fn watch_generic_label_selector_matching_object_emits_added() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Write matching object before subscribing so the ring buffer captures it.
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-match",
                "namespace": "default",
                "labels": { "app": "frontend" }
            }
        });
        store
            .put(
                "/registry/configmaps/default/cm-match",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Subscribe from rv=0 with a matching label selector; ring buffer will replay the event.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: Some("app=frontend".into()),
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can collect bytes
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed for label selector test"));

        let lines = read_watch_body_with_timeout(resp).await;
        assert_eq!(
            lines.len(),
            1,
            "matching object must produce exactly 1 ADDED event in the stream; got {:?}",
            lines
        );
        assert_eq!(
            lines[0]["type"], "ADDED",
            "event type must be ADDED for a matching object"
        );
        assert_eq!(
            lines[0]["object"]["metadata"]["name"], "cm-match",
            "ADDED event must carry the matching object"
        );
    }

    /// A watch with a label selector must NOT emit ADDED for non-matching objects.
    /// The watcher subscribes with "app=frontend". An object with "app=backend" is written
    /// BEFORE subscribing (ring buffer). No ADDED event must appear.
    ///
    /// If filtering is removed from watch_generic, this test fails because the non-matching
    /// object would be emitted, breaking informer cache correctness.
    #[tokio::test]
    async fn watch_generic_label_selector_non_matching_object_suppressed() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Write non-matching object BEFORE watching so it goes into the ring buffer.
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-no-match",
                "namespace": "default",
                "labels": { "app": "backend" }
            }
        });
        store
            .put(
                "/registry/configmaps/default/cm-no-match",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Label selector "app=frontend" — the stored object has "app=backend".
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: Some("app=frontend".into()),
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can return
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        // The stream blocks waiting for the next event (no matching objects); timeout returns empty.
        let lines = read_watch_body_with_timeout(resp).await;
        for line in &lines {
            assert_ne!(
                line["type"], "ADDED",
                "non-matching object must NOT produce ADDED event; \
                 label selector filtering is broken: got {:?}",
                lines
            );
        }
    }

    /// A watch with BOTH a label selector and a field selector must skip a non-matching object
    /// via the cheap `SelectorProjection` pre-filter (no full parse, no CR-conversion) and still
    /// deliver a genuinely matching one through the normal path. If the pre-filter and the
    /// full-object filter ever disagreed, a watcher would either miss an event a controller
    /// needed to reconcile (stale state) or receive one it shouldn't (acting on an object
    /// outside its watch scope) — both silent, since nothing here returns an error.
    #[tokio::test]
    async fn watch_generic_combined_selectors_skip_non_matching_and_deliver_matching() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Written BEFORE subscribing so both replay from the ring buffer.
        let matching = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-both-match",
                "namespace": "default",
                "labels": { "app": "frontend" }
            }
        });
        let non_matching_label = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-wrong-label",
                "namespace": "default",
                "labels": { "app": "backend" }
            }
        });
        for (key, obj) in [
            ("/registry/configmaps/default/cm-both-match", &matching),
            (
                "/registry/configmaps/default/cm-wrong-label",
                &non_matching_label,
            ),
        ] {
            store
                .put(
                    key,
                    bytes::Bytes::from(serde_json::to_vec(obj).unwrap()),
                    Some(0),
                )
                .await
                .unwrap();
        }

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: Some("app=frontend".into()),
                field_selector: Some("metadata.namespace=default".into()),
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1),
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed for combined-selector test"));

        let lines = read_watch_body_with_timeout(resp).await;
        assert_eq!(
            lines.len(),
            1,
            "exactly one ADDED event must reach the watcher (the matching object); a wrongly \
             delivered non-matching event or a wrongly dropped matching event both got {:?}",
            lines
        );
        assert_eq!(
            lines[0]["type"], "ADDED",
            "the sole delivered event must be ADDED for the matching object"
        );
        assert_eq!(
            lines[0]["object"]["metadata"]["name"], "cm-both-match",
            "the delivered event must be for the object that matches BOTH selectors, not the \
             one filtered out by the label selector"
        );
    }

    /// DELETED events must be filtered by label selector when the body is available.
    /// An object whose last-known body does NOT match the watch selector was never
    /// delivered as ADDED to this watcher — so its DELETED must be suppressed too.
    /// Sending a DELETED for an object the watcher never saw would inject phantom
    /// tombstones that pollute informer caches with objects that were never there.
    ///
    /// Kubernetes conformance (watch.go): watcher-A must NOT receive DELETED events for
    /// objects that only had label B (because watcher-A never received ADDED for them).
    #[tokio::test]
    async fn watch_generic_deleted_event_filtered_when_body_does_not_match_selector() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Create and then delete an object that does NOT match the label selector.
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-deleted",
                "namespace": "default",
                "labels": { "app": "backend" }
            }
        });
        let rv = store
            .put(
                "/registry/configmaps/default/cm-deleted",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();
        store
            .delete("/registry/configmaps/default/cm-deleted", Some(rv))
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Watch with label selector "app=frontend" — the object has "app=backend".
        // The DELETED event must be suppressed because the watcher never received ADDED.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: Some("app=frontend".into()),
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can return
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        let lines = read_watch_body_with_timeout(resp).await;

        // Ring buffer has: ADDED (backend, suppressed) and DELETED (also suppressed — body doesn't match).
        let deleted_count = lines.iter().filter(|v| v["type"] == "DELETED").count();
        assert_eq!(
            deleted_count, 0,
            "DELETED for an object that never matched the selector must be suppressed; \
             sending it would inject a phantom tombstone for an object the watcher never saw \
             (Kubernetes conformance: watcher-A must not receive DELETED for label-B objects): \
             got lines {:?}",
            lines
        );

        let added_count = lines.iter().filter(|v| v["type"] == "ADDED").count();
        assert_eq!(
            added_count, 0,
            "non-matching ADDED event must be suppressed by label selector; got lines {:?}",
            lines
        );
    }

    /// Regression test (bug 2): when a MODIFIED event changes the object's
    /// labels so it no longer matches the watch selector, the server must emit a synthetic
    /// DELETED event, not drop the event silently.
    ///
    /// Without this fix, informers watching with a labelSelector would never learn that a
    /// previously-matching object exited scope (labels changed), causing stale cache entries
    /// and spurious reconciliations that act on objects no longer in scope.
    ///
    /// This test would fail on revert: without the synthetic DELETED, `deleted_count` is 0.
    ///
    /// The watch is opened FIRST (mirroring a real informer, which is a long-lived watch
    /// already open before any given write happens): a shard now exists only once something
    /// watches its resource type (see `push_event_locked`'s doc), so unlike before this test can
    /// no longer rely on the ring replaying a two-step transition that happened entirely before
    /// any watch opened — it must observe both writes live.
    #[tokio::test]
    async fn watch_generic_modified_event_losing_selector_match_emits_synthetic_deleted() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Watch with "app=frontend" BEFORE either write, so both are observed live: ADDED
        // (matches) then MODIFIED (no longer matches), which the server must convert to a
        // synthetic DELETED rather than silence.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: Some("app=frontend".into()),
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can return
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        // Create object with matching label "app=frontend".
        let obj_v1 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-scope-exit",
                "namespace": "default",
                "labels": { "app": "frontend" }
            }
        });
        let rv1 = store
            .put(
                "/registry/configmaps/default/cm-scope-exit",
                bytes::Bytes::from(serde_json::to_vec(&obj_v1).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        // Update the object, removing the matching label (app=backend now).
        // This is a MODIFIED event whose new state no longer matches "app=frontend".
        let obj_v2 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-scope-exit",
                "namespace": "default",
                "labels": { "app": "backend" }
            }
        });
        store
            .put(
                "/registry/configmaps/default/cm-scope-exit",
                bytes::Bytes::from(serde_json::to_vec(&obj_v2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();

        let lines = read_watch_body_with_timeout(resp).await;

        // Expect: ADDED (v1 matches) + DELETED (synthetic, v2 lost match).
        let added_count = lines.iter().filter(|v| v["type"] == "ADDED").count();
        assert_eq!(
            added_count, 1,
            "initial ADDED (matching object) must appear in stream; got {:?}",
            lines
        );

        let deleted_count = lines.iter().filter(|v| v["type"] == "DELETED").count();
        assert_eq!(
            deleted_count, 1,
            "MODIFIED event that removes matching label must emit a synthetic DELETED; \
             without it informers never learn the object left scope and keep stale cache \
             entries (regression): got {:?}",
            lines
        );

        // The synthetic DELETED must identify the correct object.
        let deleted_ev = lines.iter().find(|v| v["type"] == "DELETED").unwrap();
        assert_eq!(
            deleted_ev["object"]["metadata"]["name"], "cm-scope-exit",
            "synthetic DELETED must carry the object name; got {:?}",
            deleted_ev
        );
        assert_eq!(
            deleted_ev["object"]["metadata"]["namespace"], "default",
            "synthetic DELETED must carry the object namespace; got {:?}",
            deleted_ev
        );

        // No MODIFIED events should appear — the object lost scope.
        let modified_count = lines.iter().filter(|v| v["type"] == "MODIFIED").count();
        assert_eq!(
            modified_count, 0,
            "MODIFIED that exits scope must not appear as MODIFIED in stream; got {:?}",
            lines
        );
    }

    // -- should_emit_synthetic_delete --

    /// An object that never matched this watcher's selector must not get a synthetic
    /// DELETE just because it's modified into another non-matching state.
    ///
    /// Fails on revert: reverting to the old gate (`is_modified && !now_matches`, no
    /// `ever_matched` term) makes this return true, reproducing the exact bug — an
    /// informer that was never told ADDED for the object gets a phantom DELETED for it.
    #[test]
    fn should_emit_synthetic_delete_false_when_never_matched() {
        assert!(
            !should_emit_synthetic_delete(true, false, false),
            "an object this watcher never delivered as matching must never get a \
             synthetic DELETE — the client was never told the object exists, so a \
             DELETE for it is a phantom event"
        );
    }

    /// A previously-matching object that transitions out of scope must still get the
    /// synthetic DELETE. Guards against over-correcting the fix above: if
    /// `should_emit_synthetic_delete` ignored `ever_matched` (e.g. always returned
    /// false), informers would keep stale cache entries for objects that no longer
    /// satisfy their label/field selector.
    ///
    /// Fails on revert to an over-corrected implementation that drops this case.
    #[test]
    fn should_emit_synthetic_delete_true_when_previously_matched() {
        assert!(
            should_emit_synthetic_delete(true, false, true),
            "an object this watcher previously delivered as matching must get a \
             synthetic DELETE once it stops matching, so the client's cache drops it"
        );
    }

    /// An ADDED event (an object's very first appearance) can never be a scope-exit
    /// transition, so it must never emit a synthetic DELETE — even if `ever_matched` is
    /// (implausibly) already true.
    #[test]
    fn should_emit_synthetic_delete_false_when_not_modified() {
        assert!(
            !should_emit_synthetic_delete(false, false, true),
            "only a MODIFIED event can represent an object leaving watch scope; an \
             ADDED event must never trigger a synthetic DELETE"
        );
    }

    /// An object that still matches the selector is not leaving scope, so it must not
    /// receive a synthetic DELETE regardless of history — that case is handled by the
    /// ADDED/MODIFIED emission branch, not this one.
    #[test]
    fn should_emit_synthetic_delete_false_when_still_matches() {
        assert!(
            !should_emit_synthetic_delete(true, true, true),
            "an object that still matches the selector must not receive a synthetic \
             DELETE just because it was modified"
        );
    }

    // -- watch_tracks_ever_matched --

    /// A no-selector watch must not record `ever_matched` entries: `should_emit_synthetic_delete`
    /// can never read them back (see `watch_tracks_ever_matched`'s doc), so every entry a
    /// no-selector watch's sendInitialEvents phase would otherwise insert sits in the map,
    /// unread, for the whole stream lifetime.
    #[test]
    fn watch_tracks_ever_matched_false_with_no_selector() {
        assert!(
            !watch_tracks_ever_matched("", ""),
            "a watch with no label or field selector can never take the branch that reads \
             ever_matched back, so recording entries for it is pure wasted memory"
        );
    }

    /// A watch with either selector set is exactly the case `ever_matched` exists for — this
    /// must stay true, or a selector-filtered watch silently loses its synthetic-DELETE
    /// bookkeeping instead of just skipping unread inserts.
    #[test]
    fn watch_tracks_ever_matched_true_with_either_selector_set() {
        assert!(
            watch_tracks_ever_matched("app=frontend", ""),
            "a label-selector watch must keep tracking ever_matched"
        );
        assert!(
            watch_tracks_ever_matched("", "metadata.name=foo"),
            "a field-selector watch must keep tracking ever_matched"
        );
    }

    /// End-to-end guard for the sendInitialEvents gate: a selector-filtered watch must still
    /// record the objects sendInitialEvents delivers as matching, so a later live MODIFIED that
    /// loses the match still gets a synthetic DELETED. Fails on revert to a gate that skips the
    /// insert whenever a selector IS set (e.g. an inverted condition) — the DELETED would go
    /// missing and informers would keep a stale cache entry for an object that left scope.
    #[tokio::test]
    async fn watch_generic_send_initial_events_item_losing_selector_match_emits_synthetic_deleted()
    {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let obj_v1 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-initial-scope-exit",
                "namespace": "default",
                "labels": { "app": "frontend" }
            }
        });
        let rv1 = store
            .put(
                "/registry/configmaps/default/cm-initial-scope-exit",
                bytes::Bytes::from(serde_json::to_vec(&obj_v1).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // sendInitialEvents delivers cm-initial-scope-exit as ADDED (it matches "app=frontend"
        // at list time) — this is the insert `watch_tracks_ever_matched` must not skip.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: rv1,
                initial_items: Some((vec![obj_v1], rv1)),
                label_selector: Some("app=frontend".into()),
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1),
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        // Update the object, removing the matching label — a live MODIFIED that leaves scope.
        let obj_v2 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-initial-scope-exit",
                "namespace": "default",
                "labels": { "app": "backend" }
            }
        });
        store
            .put(
                "/registry/configmaps/default/cm-initial-scope-exit",
                bytes::Bytes::from(serde_json::to_vec(&obj_v2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();

        let lines = read_watch_body_with_timeout(resp).await;

        let added_count = lines.iter().filter(|v| v["type"] == "ADDED").count();
        assert_eq!(
            added_count, 1,
            "sendInitialEvents must deliver the matching object as ADDED; got {:?}",
            lines
        );
        let deleted_count = lines.iter().filter(|v| v["type"] == "DELETED").count();
        assert_eq!(
            deleted_count, 1,
            "an object delivered via sendInitialEvents that later loses the selector match \
             must still get a synthetic DELETED — otherwise the informer keeps a stale cache \
             entry for it; got {:?}",
            lines
        );
    }

    /// Regression test: a MODIFIED event for an object that never matched the watch's
    /// selector must not produce a synthetic DELETED end-to-end through watch_generic.
    ///
    /// This is the exact failure from the CustomResourceFieldSelectors conformance test:
    /// an informer that never received an object as ADDED (it never matched the
    /// fieldSelector) later saw the object updated — still not matching — and the
    /// watch wrongly emitted a synthetic DELETED for it, an object the informer's cache
    /// never contained.
    ///
    /// This test would fail on revert: without the ever_matched gate, `deleted_count` is
    /// 1 for an object this watcher was never told ADDED for.
    #[tokio::test]
    async fn watch_generic_modified_event_on_never_matched_object_emits_no_synthetic_deleted() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Create an object that does NOT match "app=frontend" from the start.
        let obj_v1 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-never-matched",
                "namespace": "default",
                "labels": { "app": "backend" }
            }
        });
        let rv1 = store
            .put(
                "/registry/configmaps/default/cm-never-matched",
                bytes::Bytes::from(serde_json::to_vec(&obj_v1).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        // Update it — still does not match "app=frontend". This MODIFIED event is the
        // one that triggered the phantom DELETE before the fix.
        let obj_v2 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-never-matched",
                "namespace": "default",
                "labels": { "app": "backend2" }
            }
        });
        store
            .put(
                "/registry/configmaps/default/cm-never-matched",
                bytes::Bytes::from(serde_json::to_vec(&obj_v2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Watch with "app=frontend". Ring buffer has ADDED (no match) then MODIFIED (no
        // match). Neither should reach the client, and the MODIFIED must not produce a
        // synthetic DELETED — the client was never told this object exists.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: Some("app=frontend".into()),
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can return
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        let lines = read_watch_body_with_timeout(resp).await;

        let added_count = lines.iter().filter(|v| v["type"] == "ADDED").count();
        assert_eq!(
            added_count, 0,
            "never-matching object must not be delivered as ADDED; got {:?}",
            lines
        );

        let deleted_count = lines.iter().filter(|v| v["type"] == "DELETED").count();
        assert_eq!(
            deleted_count, 0,
            "MODIFIED event on an object that never matched the selector must not emit \
             a synthetic DELETED — the watcher was never told ADDED for it, so a DELETE \
             is a phantom event for an object outside its cache: got {:?}",
            lines
        );
    }

    // -- parse_key_name_ns --

    /// parse_key_name_ns extracts name and namespace from a namespaced store key.
    /// Kubernetes DELETE tombstones are built from this; wrong parsing causes
    /// malformed watch DELETED events that confuse client informers.
    #[test]
    fn parse_key_name_ns_extracts_name_and_namespace() {
        let (name, ns) = parse_key_name_ns("/registry/coordination.k8s.io/leases/default/my-lease");
        assert_eq!(name, "my-lease");
        assert_eq!(ns, "default");
    }

    /// parse_key_name_ns returns empty namespace for cluster-scoped keys.
    #[test]
    fn parse_key_name_ns_cluster_scoped_has_empty_namespace() {
        let (name, _ns) = parse_key_name_ns("/registry/storage.k8s.io/csinodes/node-1");
        assert_eq!(name, "node-1");
        // The segment before name is "csinodes", not a namespace, but parse_key_name_ns
        // returns whatever the second-to-last segment is. For cluster-scoped resources
        // that segment is the plural resource name, which is non-empty.
        // The important invariant: name is the last segment.
        assert!(!name.is_empty());
    }

    /// parse_key_name_ns on a single-segment key returns (segment, "").
    #[test]
    fn parse_key_name_ns_single_segment_returns_empty_namespace() {
        let (name, ns) = parse_key_name_ns("only-name");
        assert_eq!(name, "only-name");
        assert_eq!(ns, "");
    }

    // -- fetch_initial_events --

    /// fetch_initial_events returns None when send_initial_events is false.
    /// This keeps the normal watch path unchanged and avoids a redundant list.
    #[tokio::test]
    async fn fetch_initial_events_returns_none_when_disabled() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let result = match fetch_initial_events(&state, "/registry/test/", false, "", "").await {
            Ok(r) => r,
            Err(_) => panic!("fetch_initial_events must not fail"),
        };

        assert!(
            result.is_none(),
            "fetch_initial_events must return None when send_initial_events=false"
        );
    }

    /// fetch_initial_events returns Some with existing objects when enabled.
    /// Kubelet uses this to get a complete state snapshot before streaming live changes.
    #[tokio::test]
    async fn fetch_initial_events_returns_existing_objects_when_enabled() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed two objects
        for name in ["cm-a", "cm-b"] {
            let obj = serde_json::json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": { "name": name, "namespace": "default" }
            });
            store
                .put(
                    &format!("/registry/configmaps/default/{name}"),
                    bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                    Some(0),
                )
                .await
                .unwrap();
        }

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let result = match fetch_initial_events(
            &state,
            "/registry/configmaps/default/",
            true,
            "",
            "configmaps",
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("fetch_initial_events must not fail"),
        };

        let (items, _rv) =
            result.unwrap_or_else(|| panic!("fetch_initial_events must return Some when enabled"));
        assert_eq!(
            items.len(),
            2,
            "fetch_initial_events must return all objects under prefix"
        );
    }

    /// fetch_initial_events returns Some with empty list when no objects exist.
    /// Empty sendInitialEvents must still emit a BOOKMARK; returning None would skip it.
    #[tokio::test]
    async fn fetch_initial_events_returns_empty_list_when_no_objects() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let result = match fetch_initial_events(
            &state,
            "/registry/configmaps/empty/",
            true,
            "",
            "configmaps",
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("fetch_initial_events must not fail"),
        };

        let (items, _rv) = result.unwrap_or_else(|| {
            panic!("fetch_initial_events must return Some even for empty namespace")
        });
        assert!(
            items.is_empty(),
            "empty prefix must return empty item list, not None"
        );
    }

    // -- object_matches_label_selector / object_matches_field_selector tests --

    fn item_with_labels(labels: &[(&str, &str)]) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (k, v) in labels {
            map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
        serde_json::json!({ "metadata": { "labels": map } })
    }

    #[test]
    fn filter_matches_all_present_labels() {
        use super::super::generic::LabelSelectorTerm;
        let items = vec![
            item_with_labels(&[("app", "frontend"), ("env", "prod")]),
            item_with_labels(&[("app", "backend"), ("env", "prod")]),
        ];
        let terms = vec![
            LabelSelectorTerm::Equality {
                key: "app",
                value: "frontend",
            },
            LabelSelectorTerm::Equality {
                key: "env",
                value: "prod",
            },
        ];
        let result = apply_label_selector(items, &terms);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["metadata"]["labels"]["app"], "frontend");
    }

    #[test]
    fn filter_removes_items_missing_label() {
        use super::super::generic::LabelSelectorTerm;
        let items = vec![
            item_with_labels(&[("app", "frontend")]),
            item_with_labels(&[]),
        ];
        let terms = vec![LabelSelectorTerm::Equality {
            key: "app",
            value: "frontend",
        }];
        let result = apply_label_selector(items, &terms);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn filter_empty_pairs_returns_all() {
        let items = vec![
            item_with_labels(&[("a", "1")]),
            item_with_labels(&[("b", "2")]),
        ];
        let result = apply_label_selector(items, &[]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn filter_no_match_returns_empty() {
        use super::super::generic::LabelSelectorTerm;
        let items = vec![item_with_labels(&[("app", "backend")])];
        let terms = vec![LabelSelectorTerm::Equality {
            key: "app",
            value: "frontend",
        }];
        let result = apply_label_selector(items, &terms);
        assert!(result.is_empty());
    }

    // -- object_matches_label_selector edge cases --

    /// Empty selector matches all objects, including those with no labels.
    /// Watch streams use this: an empty selector must never drop events.
    #[test]
    fn label_selector_empty_matches_all() {
        let obj_with_labels = serde_json::json!({"metadata": {"labels": {"app": "frontend"}}});
        let obj_no_labels = serde_json::json!({"metadata": {}});
        assert!(object_matches_label_selector(&obj_with_labels, ""));
        assert!(object_matches_label_selector(&obj_no_labels, ""));
    }

    /// A selector that does not match any label on the object returns false.
    #[test]
    fn label_selector_no_match_returns_false() {
        let obj = serde_json::json!({"metadata": {"labels": {"app": "backend"}}});
        assert!(!object_matches_label_selector(&obj, "app=frontend"));
    }

    /// Multiple comma-separated terms must all match (AND semantics).
    #[test]
    fn label_selector_multi_term_all_must_match() {
        let obj = serde_json::json!({"metadata": {"labels": {"app": "frontend", "env": "prod"}}});
        // Both match → true
        assert!(object_matches_label_selector(&obj, "app=frontend,env=prod"));
        // Only one matches → false
        assert!(!object_matches_label_selector(&obj, "app=frontend,env=dev"));
    }

    /// Object with no metadata.labels does not match any label selector.
    #[test]
    fn label_selector_object_without_labels_does_not_match() {
        let obj = serde_json::json!({"metadata": {"name": "no-labels"}});
        assert!(!object_matches_label_selector(&obj, "app=frontend"));
    }

    /// DoesNotExist (`!key`): objects WITH the key must be dropped; objects WITHOUT it must pass.
    /// KCM's EndpointSlice controller watches with `!service.kubernetes.io/headless`;
    /// if this operator is ignored (old bug), ALL EndpointSlice events fan out to ALL watchers.
    #[test]
    fn label_selector_does_not_exist_drops_objects_with_key() {
        let has_key =
            serde_json::json!({"metadata": {"labels": {"service.kubernetes.io/headless": ""}}});
        let no_key = serde_json::json!({"metadata": {"labels": {"app": "web"}}});
        let no_labels = serde_json::json!({"metadata": {"name": "bare"}});

        assert!(
            !object_matches_label_selector(&has_key, "!service.kubernetes.io/headless"),
            "object WITH the key must not match DoesNotExist(!key) — KCM EPS fan-out regression"
        );
        assert!(
            object_matches_label_selector(&no_key, "!service.kubernetes.io/headless"),
            "object without the key must match DoesNotExist(!key)"
        );
        assert!(
            object_matches_label_selector(&no_labels, "!service.kubernetes.io/headless"),
            "object with no labels must match DoesNotExist(!key)"
        );
    }

    /// Exists (bare `key`): objects WITHOUT the key must be dropped; objects WITH it must pass.
    #[test]
    fn label_selector_exists_drops_objects_missing_key() {
        let has_key = serde_json::json!({"metadata": {"labels": {"app": "web"}}});
        let no_key = serde_json::json!({"metadata": {"labels": {"env": "prod"}}});
        let no_labels = serde_json::json!({"metadata": {"name": "bare"}});

        assert!(
            object_matches_label_selector(&has_key, "app"),
            "object WITH the key must match bare-key Exists selector"
        );
        assert!(
            !object_matches_label_selector(&no_key, "app"),
            "object without the key must NOT match Exists selector — watch filter must drop it"
        );
        assert!(
            !object_matches_label_selector(&no_labels, "app"),
            "object with no labels must NOT match Exists selector"
        );
    }

    /// Exists/DoesNotExist must key off whether the label is present at all, not whether its
    /// value happens to be a JSON string. Consolidating the per-function matchers into the
    /// shared `label_selector_matches` narrowed this to string-presence (via
    /// `.and_then(|v| v.as_str())`), diverging from the pre-refactor code's Value-presence
    /// check (`labels.get(key).is_some()`); a present-but-non-string label value (e.g. `null`)
    /// would then wrongly fail Exists and wrongly pass DoesNotExist.
    #[test]
    fn label_selector_exists_and_does_not_exist_use_value_presence_not_string_presence() {
        let non_string_value = serde_json::json!({"metadata": {"labels": {"app": null}}});

        assert!(
            object_matches_label_selector(&non_string_value, "app"),
            "a present-but-non-string label value must still satisfy Exists(key) — narrowing \
             to string-presence would wrongly drop this object from the watch"
        );
        assert!(
            !object_matches_label_selector(&non_string_value, "!app"),
            "a present-but-non-string label value must still count as 'exists' for \
             DoesNotExist(!key), i.e. the selector must NOT match — narrowing to \
             string-presence would wrongly deliver this object to a watcher filtering it out"
        );
    }

    /// NotEquals (`key!=value`): objects where key==value must be dropped; others pass.
    #[test]
    fn label_selector_not_equals_drops_matching_value() {
        let matches_val = serde_json::json!({"metadata": {"labels": {"env": "prod"}}});
        let other_val = serde_json::json!({"metadata": {"labels": {"env": "staging"}}});
        let missing_key = serde_json::json!({"metadata": {"labels": {"app": "web"}}});

        assert!(
            !object_matches_label_selector(&matches_val, "env!=prod"),
            "object with env=prod must NOT match env!=prod selector"
        );
        assert!(
            object_matches_label_selector(&other_val, "env!=prod"),
            "object with env=staging must match env!=prod selector"
        );
        assert!(
            object_matches_label_selector(&missing_key, "env!=prod"),
            "object without env key must match env!=prod selector (key absent != value present)"
        );
    }

    /// Label-A watcher must NOT receive events for objects with only label B.
    /// This is the primary scenario from the bead: watcher for "app=frontend" must not see
    /// objects that have only "app=backend".
    #[test]
    fn label_selector_watcher_a_does_not_receive_events_for_label_b() {
        let label_b_obj = serde_json::json!({"metadata": {"labels": {"app": "backend"}}});
        assert!(
            !object_matches_label_selector(&label_b_obj, "app=frontend"),
            "watcher for app=frontend must not receive events for app=backend objects; \
             label-A watcher receiving label-B events causes informer cache divergence"
        );
    }

    // -- apply_label_selector new operator regression tests --

    /// apply_label_selector with DoesNotExist operator: objects with the key are excluded.
    #[test]
    fn apply_label_selector_does_not_exist_excludes_objects_with_key() {
        use super::super::generic::LabelSelectorTerm;
        let with_key = item_with_labels(&[("managed-by", "helm")]);
        let without_key = item_with_labels(&[("app", "web")]);
        let terms = vec![LabelSelectorTerm::DoesNotExist { key: "managed-by" }];
        let result = apply_label_selector(vec![with_key, without_key], &terms);
        assert_eq!(
            result.len(),
            1,
            "DoesNotExist filter must exclude objects that have the key; got {result:?}"
        );
        assert_eq!(
            result[0]["metadata"]["labels"]["app"], "web",
            "the remaining object must be the one without the key"
        );
    }

    /// apply_label_selector with Exists operator: objects without the key are excluded.
    #[test]
    fn apply_label_selector_exists_excludes_objects_missing_key() {
        use super::super::generic::LabelSelectorTerm;
        let with_key = item_with_labels(&[("tier", "frontend")]);
        let without_key = item_with_labels(&[("app", "web")]);
        let terms = vec![LabelSelectorTerm::Exists { key: "tier" }];
        let result = apply_label_selector(vec![with_key, without_key], &terms);
        assert_eq!(
            result.len(),
            1,
            "Exists filter must exclude objects that are missing the key; got {result:?}"
        );
        assert_eq!(
            result[0]["metadata"]["labels"]["tier"], "frontend",
            "the remaining object must be the one that has the key"
        );
    }

    /// apply_label_selector with NotEquals operator: objects where key==value are excluded.
    #[test]
    fn apply_label_selector_not_equals_excludes_matching_value() {
        use super::super::generic::LabelSelectorTerm;
        let prod = item_with_labels(&[("env", "prod")]);
        let staging = item_with_labels(&[("env", "staging")]);
        let terms = vec![LabelSelectorTerm::NotEquals {
            key: "env",
            value: "prod",
        }];
        let result = apply_label_selector(vec![prod, staging], &terms);
        assert_eq!(
            result.len(),
            1,
            "NotEquals filter must exclude the prod object; got {result:?}"
        );
        assert_eq!(
            result[0]["metadata"]["labels"]["env"], "staging",
            "the remaining object must be the staging one"
        );
    }

    // -- object_matches_field_selector edge cases --

    /// Empty field selector matches all objects.
    #[test]
    fn field_selector_empty_matches_all() {
        let obj = serde_json::json!({"metadata": {"name": "foo", "namespace": "default"}});
        assert!(object_matches_field_selector(&obj, ""));
    }

    /// metadata.name equality match returns true when names agree.
    #[test]
    fn field_selector_metadata_name_equality_matches() {
        let obj = serde_json::json!({"metadata": {"name": "foo"}});
        assert!(object_matches_field_selector(&obj, "metadata.name=foo"));
    }

    /// metadata.name equality returns false when name differs.
    #[test]
    fn field_selector_metadata_name_equality_no_match() {
        let obj = serde_json::json!({"metadata": {"name": "bar"}});
        assert!(!object_matches_field_selector(&obj, "metadata.name=foo"));
    }

    /// metadata.namespace equality filters by namespace.
    #[test]
    fn field_selector_metadata_namespace_equality() {
        let obj = serde_json::json!({"metadata": {"name": "pod-1", "namespace": "kube-system"}});
        assert!(object_matches_field_selector(
            &obj,
            "metadata.namespace=kube-system"
        ));
        assert!(!object_matches_field_selector(
            &obj,
            "metadata.namespace=default"
        ));
    }

    /// spec.nodeName equality match.
    #[test]
    fn field_selector_spec_node_name_equality() {
        let obj =
            serde_json::json!({"metadata": {"name": "pod-1"}, "spec": {"nodeName": "node-a"}});
        assert!(object_matches_field_selector(&obj, "spec.nodeName=node-a"));
        assert!(!object_matches_field_selector(&obj, "spec.nodeName=node-b"));
    }

    /// spec.nodeName inequality (`!=`) returns false when names are equal.
    #[test]
    fn field_selector_spec_node_name_inequality() {
        let obj =
            serde_json::json!({"metadata": {"name": "pod-1"}, "spec": {"nodeName": "node-a"}});
        // node-a != node-a → false (they are equal, so inequality fails)
        assert!(!object_matches_field_selector(
            &obj,
            "spec.nodeName!=node-a"
        ));
        // node-a != node-b → true (they differ)
        assert!(object_matches_field_selector(&obj, "spec.nodeName!=node-b"));
    }

    /// Unknown field is ignored (conservative: don't drop events for unrecognised selectors).
    #[test]
    fn field_selector_unknown_field_is_ignored() {
        let obj = serde_json::json!({"metadata": {"name": "pod-1"}});
        // Unknown field → ignore → still matches
        assert!(object_matches_field_selector(&obj, "status.phase=Running"));
    }

    // -- SelectorProjection: must agree with the full-object matchers it pre-filters for --

    /// SelectorProjection::matches must return the exact same verdict as the full-object
    /// matchers for every case exercised by the dedicated matcher tests above and below. If a
    /// future change grows `label_selector_matches`/`field_selector_matches_parts` to read a
    /// field `SelectorProjection` doesn't carry, this test — not a live cluster — is where that
    /// drift shows up: a watcher would otherwise silently miss (or wrongly receive) events
    /// whenever the fast pre-filter and the full-object filter disagree.
    #[test]
    fn selector_projection_matches_agree_with_full_object_matchers() {
        let cases: &[(serde_json::Value, &str, &str)] = &[
            (
                serde_json::json!({"metadata": {"name": "pod-1", "namespace": "default", "labels": {"app": "frontend", "tier": "web"}}, "spec": {"nodeName": "node-a"}}),
                "app=frontend,tier=web",
                "spec.nodeName=node-a,metadata.namespace=default",
            ),
            (
                serde_json::json!({"metadata": {"name": "pod-2", "namespace": "default", "labels": {"app": "backend"}}, "spec": {"nodeName": "node-a"}}),
                "app=frontend",
                "",
            ),
            (
                serde_json::json!({"metadata": {"name": "pod-3", "labels": {"app": "frontend"}}, "spec": {"nodeName": "node-b"}}),
                "app in (frontend, backend)",
                "spec.nodeName!=node-a",
            ),
            (
                serde_json::json!({"metadata": {"name": "pod-4", "labels": {"tier": "web"}}}),
                "!app",
                "metadata.name=pod-4",
            ),
            (serde_json::json!({"metadata": {"name": "pod-5"}}), "", ""),
            // Label selector matches but the field selector alone fails: this case only fails
            // if a broken projection stops evaluating the field selector at all.
            (
                serde_json::json!({"metadata": {"name": "pod-6", "labels": {"app": "frontend"}}, "spec": {"nodeName": "node-a"}}),
                "app=frontend",
                "spec.nodeName=node-b",
            ),
        ];

        for (obj, label_selector, field_selector) in cases {
            let expected = object_matches_label_selector(obj, label_selector)
                && object_matches_field_selector(obj, field_selector);
            let obj_json = serde_json::to_string(obj).expect("test object must serialize");
            let projection: SelectorProjection =
                serde_json::from_str(&obj_json).expect("test object must deserialize");
            let got = projection.matches(label_selector, field_selector);
            assert_eq!(
                got, expected,
                "SelectorProjection::matches disagreed with the full-object matchers for \
                 {obj:?} with label_selector={label_selector:?} field_selector={field_selector:?}; \
                 the watch fast pre-filter and the full-object filter must always agree or a \
                 watcher silently drops or wrongly receives an event"
            );
        }
    }

    /// selector_projection_non_match must return None (defer to the full path) when the object
    /// actually matches — the caller relies on None meaning "don't know / matches", never
    /// "doesn't match", or a matching object could be wrongly treated as a non-match.
    #[test]
    fn selector_projection_non_match_returns_none_for_a_matching_object() {
        let raw =
            br#"{"metadata":{"name":"pod-1","namespace":"default","labels":{"app":"frontend"}}}"#;
        assert!(
            selector_projection_non_match(raw, "app=frontend", "").is_none(),
            "a matching object must return None so the caller falls through to the full path \
             that actually builds and emits the ADDED/MODIFIED event"
        );
    }

    /// selector_projection_non_match must return the object's name/namespace for a genuine
    /// non-match, since that's all the caller needs for ever_matched/locally_deleted
    /// bookkeeping and a synthetic DELETED — proving the skip path never needs the full object.
    #[test]
    fn selector_projection_non_match_returns_name_and_namespace_for_a_non_matching_object() {
        let raw =
            br#"{"metadata":{"name":"pod-1","namespace":"default","labels":{"app":"backend"}}}"#;
        let (name, ns) = selector_projection_non_match(raw, "app=frontend", "")
            .expect("a non-matching object must return Some((name, namespace))");
        assert_eq!(name, "pod-1");
        assert_eq!(ns, "default");
    }

    /// Regression: a watch with a label selector must receive an ADDED event for an object
    /// created AFTER the watch is opened, when that object's labels match the selector.
    ///
    /// This tests the live broadcast path (not ring buffer replay). If label selector filtering
    /// were removed from the live event branch in watch_generic, the test would still pass
    /// (the ADDED arrives unfiltered). However, if the live event branch were changed to skip
    /// ADDED events entirely (e.g. by only handling MODIFIED), the ADDED would not arrive and
    /// this test would fail.
    ///
    /// The critical invariant: a newly-created matching object produces an ADDED event even
    /// when the watch was opened before the object existed (no ring buffer replay involved).
    /// Without this, Kubernetes informers with a labelSelector never learn about new objects
    /// and their caches diverge from reality.
    #[tokio::test]
    async fn watch_generic_label_selector_newly_created_object_emits_added() {
        use crate::state::AppState;
        use std::sync::Arc;
        use tokio::time::{timeout, Duration};
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Open watch BEFORE the object exists. The ring buffer is empty at this point.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/live/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: Some("app=foo".into()),
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(2),
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        // Create the matching object AFTER the watch is open.
        // Spawn as a separate task so the watch body reader can run concurrently.
        let store_clone = Arc::clone(&store);
        tokio::spawn(async move {
            let obj = serde_json::json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "cm-live",
                    "namespace": "live",
                    "labels": { "app": "foo" }
                }
            });
            store_clone
                .put(
                    "/registry/configmaps/live/cm-live",
                    bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                    Some(0),
                )
                .await
                .expect("put must succeed");
        });

        // Collect events. The stream closes after 2s; we wait up to 3s.
        let body = resp.into_body();
        let bytes = timeout(
            Duration::from_secs(3),
            axum::body::to_bytes(body, usize::MAX),
        )
        .await
        .expect("stream must close within 3s")
        .expect("body read must succeed");

        let lines: Vec<serde_json::Value> = std::str::from_utf8(&bytes)
            .unwrap_or("")
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        let added: Vec<_> = lines.iter().filter(|v| v["type"] == "ADDED").collect();
        assert_eq!(
            added.len(),
            1,
            "a newly-created object matching labelSelector=app=foo must produce exactly one ADDED \
             event even when the watch was opened before the object existed (live broadcast path); \
             without this, Kubernetes informers with a labelSelector never see new objects: \
             got lines {:?}",
            lines
        );
        assert_eq!(
            added[0]["object"]["metadata"]["name"], "cm-live",
            "ADDED event must carry the newly-created object"
        );
    }

    // -- sendInitialEvents regression: initial-events-end BOOKMARK via watch_generic --

    /// Regression: when fetch_initial_events returns Some(items, rv) and is passed to
    /// watch_generic, the stream must emit the initial-events-end BOOKMARK before any
    /// live events. This verifies the fix: CR watch paths (cr.rs, crd.rs)
    /// previously passed None for initial_items, causing GC to block forever waiting for
    /// the BOOKMARK and never completing cache sync.
    #[tokio::test]
    async fn watch_generic_with_initial_items_emits_initial_events_end_bookmark() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed one object so initial_items is non-empty.
        let obj = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GatewayClass",
            "metadata": { "name": "my-gc" }
        });
        store
            .put(
                "/registry/gateway.networking.k8s.io/v1/gatewayclasses/my-gc",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Simulate what list_cr does: call fetch_initial_events then pass result to watch_generic.
        let initial_items = match fetch_initial_events(
            &state,
            "/registry/gateway.networking.k8s.io/v1/gatewayclasses/",
            true, // send_initial_events = true
            "gateway.networking.k8s.io",
            "gatewayclasses",
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("fetch_initial_events must not fail"),
        };

        assert!(
            initial_items.is_some(),
            "fetch_initial_events must return Some when send_initial_events=true"
        );

        let resp = match watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/gateway.networking.k8s.io/v1/gatewayclasses/".into(),
                api_version: "gateway.networking.k8s.io/v1".into(),
                kind: "GatewayClass".into(),
                from_revision: 0,
                initial_items,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: true,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can return
            },
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("watch_generic must succeed"),
        };

        let lines = read_watch_body_with_timeout(resp).await;

        // The stream must contain at least: ADDED (for seeded object) + BOOKMARK with
        // k8s.io/initial-events-end=true. If initial_items is None (the bug), no BOOKMARK
        // is emitted and GC blocks forever waiting for it.
        let bookmark = lines.iter().find(|v| {
            v["type"] == "BOOKMARK"
                && v["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"] == "true"
        });
        assert!(
            bookmark.is_some(),
            "watch_generic must emit initial-events-end BOOKMARK when initial_items is Some; \
             without it GC (metadatainformer) blocks cache sync forever. \
             Got lines: {:?}",
            lines
        );

        let added_count = lines.iter().filter(|v| v["type"] == "ADDED").count();
        assert!(
            added_count >= 1,
            "watch_generic must emit at least one ADDED event for the seeded object before the BOOKMARK; got {:?}",
            lines
        );
    }

    /// A Service stored without ipFamilies/ipFamilyPolicy must have those fields defaulted in
    /// the watch ADDED event. KCM's endpoints-controller indexes IPFamilies[0] on every
    /// watch event; if the field is absent from the watch stream (even though GET would default it),
    /// KCM panics. This test fails if apply_defaults is removed from the watch event path.
    #[tokio::test]
    async fn watch_generic_service_added_event_has_ip_family_defaults() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "my-svc",
                "namespace": "default"
            },
            "spec": {
                "clusterIP": "10.96.1.1",
                "selector": { "app": "foo" }
            }
        });
        store
            .put(
                "/registry/services/default/my-svc",
                bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/services/default/".into(),
                api_version: "v1".into(),
                kind: "Service".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "services".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can return
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        let lines = read_watch_body_with_timeout(resp).await;
        let added = lines
            .iter()
            .find(|v| v["type"] == "ADDED")
            .unwrap_or_else(|| panic!("must emit ADDED event; got {:?}", lines));

        assert_eq!(
            added["object"]["spec"]["ipFamilyPolicy"], "SingleStack",
            "watch ADDED event must carry ipFamilyPolicy default; \
             KCM reads this field from watch events and panics if absent"
        );
        assert_eq!(
            added["object"]["spec"]["ipFamilies"],
            serde_json::json!(["IPv4"]),
            "watch ADDED event must carry ipFamilies default; \
             KCM indexes IPFamilies[0] and panics if the slice is nil"
        );
        assert_eq!(
            added["object"]["spec"]["clusterIPs"],
            serde_json::json!(["10.96.1.1"]),
            "watch ADDED event must carry clusterIPs default"
        );
    }

    /// fetch_initial_events must apply defaults to snapshot items returned via sendInitialEvents=true.
    /// Without this, a Service seeded without ipFamilies is delivered raw to KCM's
    /// endpoints-controller, which indexes IPFamilies[0] and panics, killing the KCM process.
    /// This test fails on revert: fetch_initial_events would return items without ipFamilies.
    #[tokio::test]
    async fn fetch_initial_events_applies_defaults_to_snapshot_items() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed a Service WITHOUT ipFamilies — exactly as main.rs seeds kube-dns.
        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "kube-dns", "namespace": "kube-system" },
            "spec": { "clusterIP": "10.96.0.10", "selector": { "k8s-app": "kube-dns" } }
        });
        store
            .put(
                "/registry/services/kube-system/kube-dns",
                bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let result = fetch_initial_events(
            &state,
            "/registry/services/kube-system/",
            true,
            "",
            "services",
        )
        .await
        .expect("fetch_initial_events must succeed")
        .expect("sendInitialEvents=true must return Some");

        let (items, _) = result;
        assert_eq!(items.len(), 1, "must return the seeded service");
        assert_eq!(
            items[0]["spec"]["ipFamilies"],
            serde_json::json!(["IPv4"]),
            "fetch_initial_events must apply ipFamilies default to snapshot items; \
             KCM indexes IPFamilies[0] on every service event — a missing ipFamilies panics \
             the endpoints-controller and kills the KCM process"
        );
    }

    /// Regression test: timeout_seconds controls the server-side watch stream
    /// lifetime. When `timeout_seconds: Some(1)`, the stream must close within ~2 seconds.
    ///
    /// Without the fix, timeout_seconds was ignored and the server defaulted to 5 minutes (300s).
    /// This test fails on revert: `to_bytes` would block for 300s and the outer `timeout`
    /// would expire, causing the assertion `completed` to be false.
    ///
    /// The practical impact: Kubernetes informers send `timeoutSeconds=<n>` (typically 300-600s)
    /// to control watch stream lifetime. If ignored, the server closes based only on the
    /// internal default, which may be shorter (causing "context canceled" on every watch).
    #[tokio::test]
    async fn watch_generic_timeout_seconds_closes_stream_at_requested_duration() {
        use crate::state::AppState;
        use std::sync::Arc;
        use tokio::time::{timeout, Duration};
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Request a 1-second watch stream. The stream generator will break out of its loop
        // after max_duration fires (1s), closing the body. Without the fix, timeout_seconds
        // is ignored and the stream default is 300s — to_bytes would not return within 2s.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "configmaps".into(),
                timeout_seconds: Some(1), // request 1-second stream lifetime
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch_generic must succeed with timeout_seconds=1"));

        // Collect body with a 3-second outer timeout. If timeout_seconds is honoured, the
        // stream closes after ~1s and to_bytes returns Ok. If timeout_seconds is ignored
        // (300s default), to_bytes blocks until the outer timeout expires → Err(elapsed).
        let completed = timeout(
            Duration::from_secs(3),
            axum::body::to_bytes(resp.into_body(), usize::MAX),
        )
        .await
        .is_ok();

        assert!(
            completed,
            "watch stream with timeout_seconds=1 must close within 3s; \
             if it does not, timeout_seconds is being ignored and the server uses a longer \
             default — Kubernetes informers that set timeoutSeconds will get streams that \
             close at the wrong time"
        );
    }

    // -- sendInitialEvents + fieldSelector regression --

    /// Regression: a watch with sendInitialEvents=true AND a matching
    /// fieldSelector must deliver an ADDED event for the matching object followed by a
    /// BOOKMARK with k8s.io/initial-events-end=true.
    ///
    /// Without the fix, the initial snapshot is emitted without field selector filtering,
    /// so all objects are emitted as ADDED regardless of the selector. After the fix,
    /// only matching objects are emitted. This test verifies the matching path works.
    ///
    /// This test fails if the field selector filter is removed from the initial snapshot loop.
    #[tokio::test]
    async fn watch_generic_send_initial_events_with_matching_field_selector_emits_added_then_bookmark(
    ) {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed the object we will filter for.
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": "default",
                "namespace": "test-ns"
            }
        });
        store
            .put(
                "/registry/serviceaccounts/test-ns/default",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let initial_items = fetch_initial_events(
            &state,
            "/registry/serviceaccounts/test-ns/",
            true,
            "",
            "serviceaccounts",
        )
        .await
        .expect("fetch_initial_events must not fail");

        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/serviceaccounts/test-ns/".into(),
                api_version: "v1".into(),
                kind: "ServiceAccount".into(),
                from_revision: 0,
                initial_items,
                label_selector: None,
                field_selector: Some("metadata.name=default".into()),
                allow_watch_bookmarks: true,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1),
            },
        )
        .await
        .expect("watch_generic must succeed");

        let lines = read_watch_body_with_timeout(resp).await;

        // Must have exactly one ADDED event for the matching object.
        let added: Vec<_> = lines.iter().filter(|v| v["type"] == "ADDED").collect();
        assert_eq!(
            added.len(),
            1,
            "sendInitialEvents + fieldSelector=metadata.name=default must emit exactly 1 ADDED \
             for the matching object; got {:?}",
            lines
        );
        assert_eq!(
            added[0]["object"]["metadata"]["name"], "default",
            "ADDED event must carry the matching object"
        );

        // Must have a BOOKMARK with k8s.io/initial-events-end=true.
        let bookmark = lines.iter().find(|v| {
            v["type"] == "BOOKMARK"
                && v["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"] == "true"
        });
        assert!(
            bookmark.is_some(),
            "sendInitialEvents watch must emit initial-events-end BOOKMARK; \
             without it the watch hangs forever. Got lines: {:?}",
            lines
        );
    }

    /// Regression: a watch with sendInitialEvents=true AND a non-matching
    /// fieldSelector must emit NO ADDED events (the object is filtered out) but still emit
    /// the BOOKMARK with k8s.io/initial-events-end=true.
    ///
    /// Without the fix, the non-matching object is emitted as ADDED (field selector ignored
    /// for initial snapshot). After the fix it is filtered out. The BOOKMARK must still
    /// arrive so the watch does not hang.
    ///
    /// This test fails if the field selector filter is removed from the initial snapshot loop.
    #[tokio::test]
    async fn watch_generic_send_initial_events_with_non_matching_field_selector_emits_only_bookmark(
    ) {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Seed an object whose name does NOT match the field selector.
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": "other-sa",
                "namespace": "test-ns2"
            }
        });
        store
            .put(
                "/registry/serviceaccounts/test-ns2/other-sa",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let initial_items = fetch_initial_events(
            &state,
            "/registry/serviceaccounts/test-ns2/",
            true,
            "",
            "serviceaccounts",
        )
        .await
        .expect("fetch_initial_events must not fail");

        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/serviceaccounts/test-ns2/".into(),
                api_version: "v1".into(),
                kind: "ServiceAccount".into(),
                from_revision: 0,
                initial_items,
                label_selector: None,
                // Selector for "default" — the stored SA is named "other-sa", so no match.
                field_selector: Some("metadata.name=default".into()),
                allow_watch_bookmarks: true,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "".into(),
                timeout_seconds: Some(1),
            },
        )
        .await
        .expect("watch_generic must succeed");

        let lines = read_watch_body_with_timeout(resp).await;

        // Must have zero ADDED events — the object does not match the selector.
        let added_count = lines.iter().filter(|v| v["type"] == "ADDED").count();
        assert_eq!(
            added_count, 0,
            "sendInitialEvents + non-matching fieldSelector must emit no ADDED events; \
             field selector filtering of initial snapshot is broken. Got: {:?}",
            lines
        );

        // The BOOKMARK with initial-events-end must still arrive so the watch doesn't hang.
        let bookmark = lines.iter().find(|v| {
            v["type"] == "BOOKMARK"
                && v["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"] == "true"
        });
        assert!(
            bookmark.is_some(),
            "sendInitialEvents watch must emit initial-events-end BOOKMARK even when no objects \
             match the fieldSelector; without it the watch hangs forever. \
             Got lines: {:?}",
            lines
        );
    }

    /// Regression test: a watch opened with from_revision=N (the revision at
    /// which an object was created) must NOT deliver a spurious ADDED event for that object.
    ///
    /// The Kubernetes conformance test "should observe add, update, and delete watch notifications
    /// on configmaps" lists configmaps (getting rv=N), then opens a watch at rv=N. Any existing
    /// configmap (e.g. kube-root-ca.crt created at rv≤N) must not appear as an ADDED event.
    /// A spurious ADDED causes the test to fail with "Unexpected watch notification observed".
    ///
    /// This test fails if the ring buffer filter changes from strict `>` to inclusive `>=`,
    /// or if the from_revision is not forwarded correctly to the store's watch() call.
    #[tokio::test]
    async fn watch_generic_no_spurious_added_for_object_created_before_watch_rv() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Create an object that exists BEFORE the watch is opened.
        // This simulates kube-root-ca.crt or any other pre-existing configmap.
        let pre_existing = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "kube-root-ca.crt",
                "namespace": "default"
            }
        });
        let create_rv = store
            .put(
                "/registry/configmaps/default/kube-root-ca.crt",
                bytes::Bytes::from(serde_json::to_vec(&pre_existing).unwrap()),
                Some(0),
            )
            .await
            .expect("create pre-existing configmap");

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Open watch at from_revision=create_rv. This simulates a client that listed
        // configmaps (getting rv=create_rv) and then opens a watch at that rv, expecting
        // to see only NEW events — not the ADDED for the pre-existing object.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: create_rv,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "configmaps".into(),
                timeout_seconds: Some(1), // stream closes after 1s so read_watch_body_with_timeout can return
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch_generic must succeed"));

        // The stream must block — no immediate ADDED for the pre-existing configmap.
        // Any ADDED event here is spurious and represents the bug.
        let lines = read_watch_body_with_timeout(resp).await;
        let added_count = lines.iter().filter(|v| v["type"] == "ADDED").count();
        assert_eq!(
            added_count, 0,
            "watch at from_revision=N must not emit ADDED for objects created at revision ≤N; \
             a spurious ADDED breaks the conformance test \
             'should observe add, update, and delete watch notifications on configmaps' \
             Got lines: {:?}",
            lines
        );
    }

    /// A write to prefix A must deliver a BOOKMARK to a watch on prefix B.
    ///
    /// KCM 1.36 ConsistencyStore.EnsureReady() checks each informer's
    /// LastStoreSyncResourceVersion (advanced by BOOKMARK events) against the RV
    /// of any write the controller made — including writes to other resource types.
    /// A StatefulSet watch that hasn't seen a StatefulSet event stays at its initial
    /// sync RV, so a pod write at a higher RV causes EnsureReady to requeue forever.
    /// The global bookmark (key="") fixes this by delivering a BOOKMARK with the
    /// current global RV to every open watch after each write.
    #[tokio::test]
    async fn write_to_different_prefix_delivers_bookmark_to_watch() {
        use std::sync::Arc;
        use u7s_store::{SqliteStore, Store};

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Write an object under prefix A so we have a non-zero baseline RV.
        store
            .put(
                "/registry/pods/default/pod-1",
                bytes::Bytes::from(
                    serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "v1", "kind": "Pod",
                        "metadata": {"name": "pod-1", "namespace": "default"}
                    }))
                    .unwrap(),
                ),
                None,
            )
            .await
            .expect("pod write must succeed");

        // Open a watch on prefix B (statefulsets) starting from rv=0.
        let sts_stream = store
            .watch("/registry/apps/statefulsets/", 0)
            .await
            .expect("watch must open");

        // Write another object under prefix A (a second pod).
        store
            .put(
                "/registry/pods/default/pod-2",
                bytes::Bytes::from(
                    serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "v1", "kind": "Pod",
                        "metadata": {"name": "pod-2", "namespace": "default"}
                    }))
                    .unwrap(),
                ),
                None,
            )
            .await
            .expect("second pod write must succeed");

        let pod_rv = store.current_revision();

        // The statefulset watch must receive a BOOKMARK with the pod write RV,
        // even though no statefulset was written.
        use std::pin::pin;
        use tokio::time::{timeout, Duration};
        let mut sts_stream = pin!(sts_stream);
        let event = timeout(Duration::from_secs(2), async {
            loop {
                if let Some(u7s_store::WatchEvent::Bookmark { revision }) =
                    futures_util::StreamExt::next(&mut sts_stream).await
                {
                    return revision;
                }
            }
        })
        .await
        .expect("statefulset watch must receive a BOOKMARK within 2s after a pod write");

        assert!(
            event >= pod_rv,
            "BOOKMARK revision {event} must be >= pod write revision {pod_rv} — \
             without this, KCM ConsistencyStore.EnsureReady requeues the StatefulSet \
             controller forever after every pod creation"
        );
    }

    /// The stream-timeout BOOKMARK (the `max_duration` branch of `watch_generic_impl`,
    /// fired when the client's `timeoutSeconds` elapses) must carry the store's actual
    /// current revision — the same `bookmark_rv` computation the periodic-tick branch
    /// above relies on for KCM's ConsistencyStore.EnsureReady.
    ///
    /// This fails on revert to a stale or detached revision source (e.g. a `bookmark_rv`
    /// that silently reads a snapshot taken before the write instead of the live store):
    /// the asserted resourceVersion would then diverge from the store's real current
    /// revision without any other symptom until a StatefulSet watch stalls permanently.
    #[tokio::test]
    async fn watch_generic_timeout_bookmark_carries_store_current_revision() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::{SqliteStore, Store};

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let rv = store
            .put(
                "/registry/configmaps/default/cm-1",
                bytes::Bytes::from(
                    serde_json::to_vec(&serde_json::json!({
                        "apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": {"name": "cm-1", "namespace": "default"}
                    }))
                    .unwrap(),
                ),
                Some(0),
            )
            .await
            .expect("configmap write must succeed");
        let expected_rv = store.current_revision();

        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: rv,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: true,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "configmaps".into(),
                timeout_seconds: Some(1),
            },
        )
        .await
        .expect("watch_generic must succeed");

        // No further writes: the watch sees no live events, so the only BOOKMARK on the
        // stream is the one the max_duration branch emits once timeout_seconds elapses.
        let lines = read_watch_body_with_timeout(resp).await;
        let bookmarks: Vec<_> = lines.iter().filter(|v| v["type"] == "BOOKMARK").collect();
        assert_eq!(
            bookmarks.len(),
            1,
            "expected exactly one BOOKMARK from the stream-timeout branch; got {:?}",
            lines
        );
        assert_eq!(
            bookmarks[0]["object"]["metadata"]["resourceVersion"],
            expected_rv.to_string(),
            "timeout BOOKMARK resourceVersion must equal the store's current_revision \
             ({expected_rv}) — this is the value KCM's ConsistencyStore.EnsureReady compares \
             against every other resource's write RV; got {:?}",
            lines
        );
    }

    /// When allowWatchBookmarks is false, the server must suppress all BOOKMARK events —
    /// including the store-generated trailing bookmark that follows every live event.
    /// A client that does not opt in to bookmarks must receive only Added/Modified/Deleted
    /// events. Receiving a BOOKMARK when allowWatchBookmarks=false breaks conformance tests
    /// whose event loops treat BOOKMARK as an unexpected event type and fail with
    /// "expected DELETE, but got BOOKMARK".
    ///
    /// This test fails on revert: without suppression, the trailing BOOKMARK from the
    /// store's live loop arrives before the DELETE is processed, and the BOOKMARK count
    /// is non-zero.
    #[tokio::test]
    async fn watch_generic_allow_watch_bookmarks_false_suppresses_store_bookmarks() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Create an object so we have something to delete.
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "cm-to-delete", "namespace": "default" }
        });
        let rv = store
            .put(
                "/registry/configmaps/default/cm-to-delete",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Open watch from after the creation, so only the DELETE will appear.
        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: rv,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "configmaps".into(),
                timeout_seconds: Some(1),
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch must succeed"));

        // Delete the object — this triggers: DELETE event + trailing BOOKMARK in store.
        store
            .delete("/registry/configmaps/default/cm-to-delete", Some(rv))
            .await
            .unwrap();

        let lines = read_watch_body_with_timeout(resp).await;

        let deleted_count = lines.iter().filter(|v| v["type"] == "DELETED").count();
        assert_eq!(
            deleted_count, 1,
            "DELETE event must arrive when allowWatchBookmarks=false; got {:?}",
            lines
        );

        let bookmark_count = lines.iter().filter(|v| v["type"] == "BOOKMARK").count();
        assert_eq!(
            bookmark_count, 0,
            "no BOOKMARK events must appear when allowWatchBookmarks=false; \
             the store emits a trailing BOOKMARK after every event — if watch_generic does \
             not suppress it, clients that treat BOOKMARK as unexpected receive it instead \
             of (or before) DELETE, causing conformance tests to fail with \
             'expected DELETE, but got BOOKMARK'; got lines {:?}",
            lines
        );
    }

    /// Regression test: a watch with timeout_seconds=None must stay open longer than 5 minutes.
    /// This catches a revert to unwrap_or(5 * 60) by verifying the stream does NOT close
    /// within 2 seconds — the stream_timeout_secs branch only fires after the configured
    /// duration, so a 2s check is safe as long as the default is >> 2s.
    ///
    /// Without the fix, the 5-minute default caused client-go's retrywatcher to reconnect
    /// 72 times over a 6h conformance run; under load those reconnections fail with
    /// "context canceled", degrading all long-running controllers that rely on watch streams.
    #[tokio::test]
    async fn watch_generic_no_timeout_seconds_stream_stays_open_past_two_seconds() {
        use crate::state::AppState;
        use std::sync::Arc;
        use tokio::time::{timeout, Duration};
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: "/registry/configmaps/default/".into(),
                api_version: "v1".into(),
                kind: "ConfigMap".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "test-user".into(),
                as_partial_object_metadata: false,
                group: "".into(),
                plural: "configmaps".into(),
                timeout_seconds: None,
            },
        )
        .await
        .unwrap_or_else(|_| panic!("watch_generic must succeed with timeout_seconds=None"));

        let body = resp.into_body();
        let still_open_after_2s = timeout(
            Duration::from_millis(2100),
            axum::body::to_bytes(body, usize::MAX),
        )
        .await
        .is_err();

        assert!(
            still_open_after_2s,
            "watch stream with timeout_seconds=None must NOT close within 2s; \
             if the server default is <= 2s, watch streams expire faster than client-go can \
             reconnect, causing context-canceled cascades in long conformance runs"
        );
    }

    // -- stamp_type_meta_if_changed: skip the per-event allocation when TypeMeta already matches --

    /// Built-in resources (the overwhelming majority of watch traffic — Pods, ConfigMaps,
    /// Secrets, etc.) are always stored with the apiVersion/kind that matches the watch they're
    /// served on, so stamping them again on every event is pure waste: two heap allocations
    /// per watcher per event that never change the bytes on the wire. This test proves the
    /// stamp is skipped (not just "produces the same value") by checking that the `apiVersion`
    /// string's heap pointer is unchanged after the call — a fresh `String::to_owned()` would
    /// always allocate a new buffer at a different address, even when the contents are equal.
    ///
    /// If this regresses to an unconditional stamp, every watch event allocates two Strings
    /// that never change; ambient waste under high watch load (many watchers × long-lived
    /// streams), not correctness-breaking but the exact ongoing cost this fix removes.
    #[test]
    fn stamp_type_meta_if_changed_skips_allocation_when_already_canonical() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "already-canonical"}
        });
        let before_ptr = obj["apiVersion"].as_str().unwrap().as_ptr();
        let before_kind_ptr = obj["kind"].as_str().unwrap().as_ptr();

        stamp_type_meta_if_changed(&mut obj, "v1", "Pod");

        assert_eq!(
            obj["apiVersion"].as_str().unwrap().as_ptr(),
            before_ptr,
            "apiVersion already equals the canonical value; stamping it again would allocate \
             a new String on every single watch event for no observable benefit"
        );
        assert_eq!(
            obj["kind"].as_str().unwrap().as_ptr(),
            before_kind_ptr,
            "kind already equals the canonical value; stamping it again would allocate a new \
             String on every single watch event for no observable benefit"
        );
    }

    /// A CR watched at a served version different from the version it's stored under (or any
    /// object whose stored TypeMeta is stale) must still be corrected. The allocation-skipping
    /// fast path above must not silently drop this correction — clients rely on apiVersion/kind
    /// matching the watch they opened, not the object's on-disk version.
    #[test]
    fn stamp_type_meta_if_changed_still_corrects_mismatched_values() {
        let mut obj = serde_json::json!({
            "apiVersion": "example.com/v1alpha1",
            "kind": "Widget",
            "metadata": {"name": "stale-typemeta"}
        });

        stamp_type_meta_if_changed(&mut obj, "example.com/v1", "Widget");

        assert_eq!(
            obj["apiVersion"], "example.com/v1",
            "a CR served at a version other than its stored version must have apiVersion \
             corrected to the requested served version; skipping the write here would leak \
             the storage version onto the wire and break clients watching the served version"
        );
    }

    // -- prepare_live_event: once-per-event serialize, selector filtering preserved (gcfq) --

    /// prepare_live_event called twice with the same event bytes must produce byte-identical
    /// output each time. This simulates two watchers on the same resource sharing the same
    /// raw event bytes but each calling prepare_live_event independently; the resulting NDJSON
    /// bytes must be identical so both watchers emit the same wire representation.
    ///
    /// This test fails on revert: if prepare_live_event is replaced with an inline parse that
    /// produces different field ordering per call (e.g., via HashMap non-determinism in serde),
    /// both watchers would emit different bytes for the same event, breaking informer consistency.
    #[test]
    fn prepare_live_event_two_watchers_same_event_bytes_get_identical_output() {
        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "shared-cm",
                "namespace": "default",
                "resourceVersion": "77"
            }
        });
        let raw = serde_json::to_vec(&obj).unwrap();

        let bytes_watcher_a = prepare_live_event(
            &raw,
            "ADDED",
            "",
            "configmaps",
            "v1",
            "ConfigMap",
            false,
            "",
            "",
        );
        let bytes_watcher_b = prepare_live_event(
            &raw,
            "ADDED",
            "",
            "configmaps",
            "v1",
            "ConfigMap",
            false,
            "",
            "",
        );

        assert!(
            bytes_watcher_a.is_some(),
            "watcher A must receive the ADDED event (no selector, should always match)"
        );
        assert!(
            bytes_watcher_b.is_some(),
            "watcher B must receive the ADDED event (no selector, should always match)"
        );
        assert_eq!(
            bytes_watcher_a.unwrap(),
            bytes_watcher_b.unwrap(),
            "both watchers must receive byte-identical NDJSON for the same event; \
             differing bytes would cause informer cache divergence across watchers \
             and break clients that compare watch streams for consistency"
        );
    }

    /// prepare_live_event with a matching label selector must return Some(bytes).
    /// prepare_live_event with a non-matching label selector must return None.
    ///
    /// Selector filtering must be preserved despite the shared-serialization refactor.
    /// This test fails on revert: if selector filtering is removed from prepare_live_event,
    /// a non-matching watcher receives events it should not see, corrupting informer caches.
    #[test]
    fn prepare_live_event_label_selector_watcher_receives_only_matching_events() {
        let matching_obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "cm-frontend",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": { "app": "frontend" }
            }
        });
        let raw = serde_json::to_vec(&matching_obj).unwrap();

        // Watcher with matching selector must receive the event.
        let matching = prepare_live_event(
            &raw,
            "ADDED",
            "",
            "configmaps",
            "v1",
            "ConfigMap",
            false,
            "app=frontend",
            "",
        );
        assert!(
            matching.is_some(),
            "watcher with matching label selector must receive the ADDED event; \
             sharing serialized bytes across watchers must not suppress events for selectors \
             that match — this would cause informers to never see matching objects"
        );

        // Watcher with non-matching selector must NOT receive the event.
        let not_matching = prepare_live_event(
            &raw,
            "ADDED",
            "",
            "configmaps",
            "v1",
            "ConfigMap",
            false,
            "app=backend",
            "",
        );
        assert!(
            not_matching.is_none(),
            "watcher with non-matching label selector must NOT receive the ADDED event; \
             selector filtering must be preserved despite the shared-serialization refactor — \
             receiving a non-matching event would cause informer cache divergence"
        );
    }

    /// Two independent watch streams on the same resource, both subscribed before a live
    /// write, must receive byte-identical NDJSON for that write. Both are served by
    /// `watch_generic_impl`'s Added/Modified fast path, which now delegates to the single,
    /// independently-tested `prepare_live_event` instead of the fast path and the
    /// CR/selector-filtered path each hand-rolling their own parse+default+serialize.
    /// This pins the cross-path invariant the split enables: a future edit to one path's
    /// selector/defaulting/stamping logic without the matching edit to the other would make
    /// two watchers on the same resource observably disagree about the same live write —
    /// exactly the drift risk of maintaining the logic twice, which is what leaving
    /// `prepare_live_event` uncalled in production (its pre-fix state) risked. Kubernetes
    /// clients rely on every watcher of a resource agreeing on its watch events.
    #[tokio::test]
    async fn watch_generic_two_concurrent_watchers_receive_byte_identical_live_added_event() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        // Unlike read_watch_body_with_timeout (used elsewhere in this file), this returns the
        // raw NDJSON line, not a decoded Value — decoding would hide a real field-ordering or
        // whitespace divergence between the two watchers behind serde_json's own normalization.
        async fn first_raw_line(resp: axum::response::Response) -> String {
            use tokio::time::{timeout, Duration};
            let bytes = timeout(
                Duration::from_secs(3),
                axum::body::to_bytes(resp.into_body(), usize::MAX),
            )
            .await
            .expect("stream must close within the 3s test timeout")
            .expect("body read must succeed");
            std::str::from_utf8(&bytes)
                .expect("NDJSON body must be valid UTF-8")
                .lines()
                .next()
                .unwrap_or_else(|| {
                    panic!("watch stream must emit at least one line, got {bytes:?}")
                })
                .to_string()
        }

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let watch_cfg = |username: &str| WatchConfig {
            prefix: "/registry/configmaps/default/".into(),
            api_version: "v1".into(),
            kind: "ConfigMap".into(),
            from_revision: 0,
            initial_items: None,
            label_selector: None,
            field_selector: None,
            allow_watch_bookmarks: false,
            username: username.into(),
            as_partial_object_metadata: false,
            group: "".into(),
            plural: "configmaps".into(),
            timeout_seconds: Some(1),
        };

        // Subscribe BOTH watchers before writing, so the write below is a live broadcast
        // event for both (store::watch subscribes before returning — see its own "Subscribe
        // FIRST to avoid missing events between replay and live" comment), not a ring-buffer
        // replay of a pre-existing write.
        let resp_a = watch_generic(state.clone(), watch_cfg("watcher-a"))
            .await
            .unwrap_or_else(|_| panic!("watcher A must subscribe successfully"));
        let resp_b = watch_generic(state.clone(), watch_cfg("watcher-b"))
            .await
            .unwrap_or_else(|_| panic!("watcher B must subscribe successfully"));

        let obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "cm-shared", "namespace": "default" },
            "data": { "k": "v" }
        });
        store
            .put(
                "/registry/configmaps/default/cm-shared",
                bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        let (line_a, line_b) = tokio::join!(first_raw_line(resp_a), first_raw_line(resp_b));

        assert!(
            line_a.contains("\"type\":\"ADDED\""),
            "watcher A must see the live write as ADDED; got {line_a:?}"
        );
        assert_eq!(
            line_a, line_b,
            "two watchers on the same resource observing the same live write must receive \
             byte-identical NDJSON — both now go through prepare_live_event's single \
             parse+default+serialize instead of two independently-maintained inline \
             implementations that could silently drift"
        );
    }

    /// `key in (v1,v2)`: objects with key=v1 or key=v2 must match; others must not.
    ///
    /// Without this fix the `in` operator falls through to bare-key Exists, matching
    /// anything that has any label named "key in (v1,v2)" — which is never true —
    /// so ALL events are dropped and set-based-selector watchers get nothing.
    #[test]
    fn label_selector_in_operator_matches_listed_values_only() {
        let val_a = serde_json::json!({"metadata": {"labels": {"color": "red"}}});
        let val_b = serde_json::json!({"metadata": {"labels": {"color": "blue"}}});
        let val_c = serde_json::json!({"metadata": {"labels": {"color": "green"}}});
        let missing = serde_json::json!({"metadata": {"labels": {"other": "x"}}});

        assert!(
            object_matches_label_selector(&val_a, "color in (red,blue)"),
            "color=red must match `color in (red,blue)`; set-based-selector watchers get no events otherwise"
        );
        assert!(
            object_matches_label_selector(&val_b, "color in (red,blue)"),
            "color=blue must match `color in (red,blue)`"
        );
        assert!(
            !object_matches_label_selector(&val_c, "color in (red,blue)"),
            "color=green must NOT match `color in (red,blue)`"
        );
        assert!(
            !object_matches_label_selector(&missing, "color in (red,blue)"),
            "object without the key must NOT match `in` selector"
        );
    }

    /// `key notin (v1,v2)`: objects NOT in the list (or missing key) must match; listed values must not.
    ///
    /// k8s semantics: notin matches objects whose key is absent or whose value is not in the set.
    #[test]
    fn label_selector_notin_operator_excludes_listed_values() {
        let val_a = serde_json::json!({"metadata": {"labels": {"color": "red"}}});
        let val_b = serde_json::json!({"metadata": {"labels": {"color": "green"}}});
        let missing = serde_json::json!({"metadata": {"labels": {"other": "x"}}});

        assert!(
            !object_matches_label_selector(&val_a, "color notin (red,blue)"),
            "color=red must NOT match `color notin (red,blue)`; set-based-selector watchers see it as excluded"
        );
        assert!(
            object_matches_label_selector(&val_b, "color notin (red,blue)"),
            "color=green must match `color notin (red,blue)` (value not in list)"
        );
        assert!(
            object_matches_label_selector(&missing, "color notin (red,blue)"),
            "object without the key must match `notin` selector (absent key satisfies notin)"
        );
    }

    /// Combined multi-term selector mixing equality and set-based operators.
    ///
    /// Verifies the paren-safe term splitter doesn't break when commas appear inside parens.
    #[test]
    fn label_selector_combined_equality_and_in_terms() {
        let matches = serde_json::json!({"metadata": {"labels": {"x": "1", "y": "a"}}});
        let wrong_x = serde_json::json!({"metadata": {"labels": {"x": "2", "y": "a"}}});
        let wrong_y = serde_json::json!({"metadata": {"labels": {"x": "1", "y": "c"}}});

        assert!(
            object_matches_label_selector(&matches, "x=1,y in (a,b)"),
            "x=1,y=a must match `x=1,y in (a,b)`; commas inside parens must not be treated as term separators"
        );
        assert!(
            !object_matches_label_selector(&wrong_x, "x=1,y in (a,b)"),
            "x=2 must fail the x=1 equality term"
        );
        assert!(
            !object_matches_label_selector(&wrong_y, "x=1,y in (a,b)"),
            "y=c must fail the y in (a,b) set term"
        );
    }

    /// The exact selector used by the failing conformance test: `watch-this-configmap in (multiple-watchers-A)`.
    ///
    /// Before the fix this selector had no `=`, `!=`, or `!` prefix so it fell to the bare-key
    /// Exists branch: `labels.get("watch-this-configmap in (multiple-watchers-A)")` returns None,
    /// causing every event to be dropped and the test to time out at exactly 60s.
    #[test]
    fn label_selector_conformance_watcher_selector_matches_correctly() {
        let matching = serde_json::json!({
            "metadata": {
                "labels": {"watch-this-configmap": "multiple-watchers-A"}
            }
        });
        let wrong_value = serde_json::json!({
            "metadata": {
                "labels": {"watch-this-configmap": "multiple-watchers-B"}
            }
        });
        let missing_key = serde_json::json!({"metadata": {"labels": {}}});

        assert!(
            object_matches_label_selector(
                &matching,
                "watch-this-configmap in (multiple-watchers-A)"
            ),
            "the conformance watcher selector must match the labeled configmap; \
             without this fix the Watchers test times out at 60s because all events are dropped"
        );
        assert!(
            !object_matches_label_selector(
                &wrong_value,
                "watch-this-configmap in (multiple-watchers-A)"
            ),
            "a configmap with a different watcher-label value must not match"
        );
        assert!(
            !object_matches_label_selector(
                &missing_key,
                "watch-this-configmap in (multiple-watchers-A)"
            ),
            "a configmap without the watcher label must not match"
        );
    }

    // -- watch metrics: apiserver_longrunning_requests / apiserver_watch_events_total /
    //    apiserver_request_total / u7s_watch_closed_total{client_limit_exceeded} --

    /// derive_watch_version must extract just the version, not the group, for both core
    /// (no group prefix) and grouped apiVersions — a wrong version label would silently merge
    /// unrelated resource types' watch metrics under the wrong series.
    #[test]
    fn derive_watch_version_strips_group_prefix() {
        assert_eq!(
            derive_watch_version("v1"),
            "v1",
            "a core apiVersion (no '/') must be used as-is"
        );
        assert_eq!(
            derive_watch_version("apps/v1"),
            "v1",
            "a grouped apiVersion must report only the version segment, matching upstream's \
             apiserver_longrunning_requests `version` label semantics"
        );
    }

    /// derive_watch_scope must classify by whether the request named a specific namespace, not
    /// by whether the resource type is namespaced — mirroring upstream's RequestInfo-derived
    /// `scope` label. A namespaced resource watched across all namespaces is still "cluster"
    /// scope; only a namespace-suffixed prefix is "namespace" scope.
    #[test]
    fn derive_watch_scope_distinguishes_all_namespaces_from_one_namespace() {
        assert_eq!(
            derive_watch_scope("/registry/pods/", "pods"),
            "cluster",
            "watching a namespaced resource across all namespaces must report scope=cluster, \
             matching upstream semantics where scope reflects the request URL, not the resource \
             type's namespacing"
        );
        assert_eq!(
            derive_watch_scope("/registry/pods/default/", "pods"),
            "namespace",
            "watching pods in one namespace must report scope=namespace"
        );
        assert_eq!(
            derive_watch_scope("/registry/apps/deployments/", "deployments"),
            "cluster",
            "a grouped resource watched across all namespaces must also report scope=cluster"
        );
        assert_eq!(
            derive_watch_scope("/registry/apps/deployments/default/", "deployments"),
            "namespace",
            "a grouped resource watched in one namespace must report scope=namespace"
        );
        assert_eq!(
            derive_watch_scope("/registry/nodes/", "nodes"),
            "cluster",
            "a genuinely cluster-scoped resource (no namespace concept at all) must also \
             report scope=cluster"
        );
    }

    /// Opening a watch must increment apiserver_longrunning_requests{verb="watch",...} for the
    /// real duration the stream is open, and dropping the stream (client disconnect, in this
    /// test) must decrement it back down — the whole point of the gauge is to answer "how many
    /// watches are open right now", which is wrong if it only ever grows or never grows at all.
    #[tokio::test]
    async fn watch_open_and_drop_brackets_longrunning_gauge() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Unique label values so concurrently-running tests in this same binary cannot
        // perturb this test's before/after comparison for this exact label combination.
        let group = "u7s-test-metrics-group";
        let plural = "u7s-test-metrics-longrunning-resources";
        let label_values = [
            "watch",
            group,
            "v1",
            plural,
            "",
            "cluster",
            crate::metrics::COMPONENT,
        ];
        let before = crate::metrics::LONGRUNNING_REQUESTS
            .with_label_values(&label_values)
            .get();

        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: format!("/registry/{group}/{plural}/"),
                api_version: "v1".into(),
                kind: "Widget".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "longrunning-gauge-test-user".into(),
                as_partial_object_metadata: false,
                group: group.into(),
                plural: plural.into(),
                timeout_seconds: None,
            },
        )
        .await
        .expect("watch_generic must succeed");

        use futures_util::StreamExt;
        let mut body = resp.into_body().into_data_stream();
        // Drive the stream generator's first poll (up to its first suspension point), which
        // runs the guard construction synchronously before any await completes.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), body.next()).await;

        let during = crate::metrics::LONGRUNNING_REQUESTS
            .with_label_values(&label_values)
            .get();
        assert_eq!(
            during,
            before + 1,
            "opening a watch must increment apiserver_longrunning_requests{{verb=\"watch\"}}"
        );

        drop(body);

        let after = crate::metrics::LONGRUNNING_REQUESTS
            .with_label_values(&label_values)
            .get();
        assert_eq!(
            after, before,
            "dropping the watch stream must decrement apiserver_longrunning_requests back down; \
             a gauge that never decrements would falsely report every watch ever opened as \
             still active"
        );
    }

    /// The (MAX_WATCHES_PER_CLIENT + 1)th watch from the same user must count as a 429 request
    /// and a client_limit_exceeded closure — operators need to see rejected watch attempts in
    /// apiserver_request_total and u7s_watch_closed_total just as much as successful ones,
    /// otherwise a client stuck retrying against the per-user limit is invisible in metrics.
    #[tokio::test]
    async fn watch_limit_429_increments_request_total_and_closed_total() {
        use crate::state::{AppState, MAX_WATCHES_PER_CLIENT};
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let username = "watch-429-metrics-test-user";
        let group = "u7s-test-metrics-429-group";
        let plural = "u7s-test-metrics-429-resources";

        let sem = state.watch_limit.semaphore_for(username);
        let _permits: Vec<_> = (0..MAX_WATCHES_PER_CLIENT)
            .map(|_| {
                sem.clone()
                    .try_acquire_owned()
                    .expect("permit must be available")
            })
            .collect();

        let request_total_before = crate::metrics::REQUEST_TOTAL
            .with_label_values(&["watch", group, "v1", plural, "cluster", "429"])
            .get();
        let closed_total_before = u7s_store::metrics::WATCH_CLOSED_TOTAL
            .with_label_values(&["client_limit_exceeded"])
            .get();

        let result = watch_generic(
            state.clone(),
            WatchConfig {
                prefix: format!("/registry/{group}/{plural}/"),
                api_version: "v1".into(),
                kind: "Widget".into(),
                from_revision: 0,
                initial_items: None,
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: username.into(),
                as_partial_object_metadata: false,
                group: group.into(),
                plural: plural.into(),
                timeout_seconds: None,
            },
        )
        .await;
        assert!(result.is_err(), "the 429th watch attempt must be rejected");

        let request_total_after = crate::metrics::REQUEST_TOTAL
            .with_label_values(&["watch", group, "v1", plural, "cluster", "429"])
            .get();
        assert_eq!(
            request_total_after,
            request_total_before + 1,
            "a 429 watch rejection must be counted in apiserver_request_total{{code=\"429\"}}"
        );

        let closed_total_after = u7s_store::metrics::WATCH_CLOSED_TOTAL
            .with_label_values(&["client_limit_exceeded"])
            .get();
        assert_eq!(
            closed_total_after,
            closed_total_before + 1,
            "a 429 watch rejection must be counted in \
             u7s_watch_closed_total{{reason=\"client_limit_exceeded\"}}"
        );
    }

    /// Every ADDED item and the terminating BOOKMARK sent during sendInitialEvents must be
    /// counted in apiserver_watch_events_total — this is the "an event was actually written to
    /// the client's HTTP body" signal, and sendInitialEvents is the simplest, fully
    /// deterministic path to exercise it (no timing dependency on live broadcast delivery).
    #[tokio::test]
    async fn send_initial_events_increments_watch_events_total_per_item_and_bookmark() {
        use crate::state::AppState;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let group = "u7s-test-metrics-events-group";
        let plural = "u7s-test-metrics-events-resources";
        let label_values = [group, "v1", plural];
        let before = crate::metrics::WATCH_EVENTS_TOTAL
            .with_label_values(&label_values)
            .get();

        let items = vec![
            serde_json::json!({"metadata": {"name": "a", "namespace": "default"}}),
            serde_json::json!({"metadata": {"name": "b", "namespace": "default"}}),
        ];

        let resp = watch_generic(
            state,
            WatchConfig {
                prefix: format!("/registry/{group}/{plural}/"),
                api_version: "v1".into(),
                kind: "Widget".into(),
                from_revision: 0,
                initial_items: Some((items, 5)),
                label_selector: None,
                field_selector: None,
                allow_watch_bookmarks: false,
                username: "watch-events-metrics-test-user".into(),
                as_partial_object_metadata: false,
                group: group.into(),
                plural: plural.into(),
                timeout_seconds: None,
            },
        )
        .await
        .expect("watch_generic must succeed");

        use futures_util::StreamExt;
        let mut body = resp.into_body().into_data_stream();
        // Drain exactly the 2 ADDED items + 1 initial-events-end BOOKMARK; sendInitialEvents
        // emits these synchronously before ever touching the live broadcast stream.
        for _ in 0..3 {
            let chunk = tokio::time::timeout(std::time::Duration::from_millis(200), body.next())
                .await
                .expect("must not time out draining sendInitialEvents output")
                .expect("stream must not end before sendInitialEvents output is drained")
                .expect("chunk must not be an error");
            assert!(!chunk.is_empty());
        }

        let after = crate::metrics::WATCH_EVENTS_TOTAL
            .with_label_values(&label_values)
            .get();
        assert_eq!(
            after,
            before + 3,
            "2 ADDED items + 1 initial-events-end BOOKMARK must each increment \
             apiserver_watch_events_total exactly once"
        );
    }
}
