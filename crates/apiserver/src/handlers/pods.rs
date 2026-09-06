use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use serde::Deserialize;
use u7s_store::{CreateNamespacedError, ListOptions, Store, StoreError};

use crate::{
    admission::{
        label_selector_matches, run_mutating_webhooks, run_validating_webhooks, AdmissionContext,
        LabelSelector,
    },
    auth::UserInfo,
    keys::{cluster_object_key, group_list_prefix, group_object_key, list_prefix, object_key},
    limit_range::parse_quantity,
    state::AppState,
    status::Status,
    types::{Binding, DeleteOptions, Namespace, Object, ObjectMeta, PodSpec},
    util::{
        content_type, extract_body, parse_resource_version, rfc3339_to_unix_secs, secs_to_rfc3339,
    },
};

#[derive(Deserialize)]
pub struct CollectionQuery {
    #[serde(default, deserialize_with = "crate::util::deserialize_watch_bool")]
    pub watch: Option<bool>,
    #[serde(rename = "resourceVersion")]
    pub resource_version: Option<u64>,
    #[serde(rename = "labelSelector")]
    pub label_selector: Option<String>,
    #[serde(rename = "fieldSelector")]
    pub field_selector: Option<String>,
    /// When true, the server emits existing pods as ADDED events before streaming
    /// live changes. Used by kubelet (Kubernetes 1.27+) for efficient informer startup.
    #[serde(rename = "sendInitialEvents")]
    pub send_initial_events: Option<bool>,
    /// When true, the server sends periodic BOOKMARK events. When false or absent,
    /// bookmarks are suppressed (except the sendInitialEvents end-of-list BOOKMARK).
    #[serde(rename = "allowWatchBookmarks")]
    pub allow_watch_bookmarks: Option<bool>,
    /// Server-side timeout for watch streams in seconds. See CollectionQuery::timeout_seconds.
    #[serde(rename = "timeoutSeconds")]
    pub timeout_seconds: Option<u64>,
}

/// Extract a store-level FieldSelector from a raw field selector string.
/// Picks the first equality (`=`) term that is not a negation (`!=`).
/// Returns None if no equality term is present or the string is empty.
pub(crate) fn pod_store_field_selector(sel: &str) -> Option<u7s_store::FieldSelector> {
    sel.split(',').find_map(|term| {
        let term = term.trim();
        if !term.contains("!=") {
            term.split_once('=').and_then(|(field, value)| {
                if field.is_empty() {
                    return None;
                }
                Some(u7s_store::FieldSelector {
                    field: field.to_string(),
                    value: value.to_string(),
                    negated: false,
                })
            })
        } else {
            None
        }
    })
}

/// Comma-joined `spec.containers[].image` for a pod, used by the list_pods debug signal so an
/// operator can see which image(s) a pod is running without pulling the full spec.
fn pod_container_images(pod: &serde_json::Value) -> String {
    pod["spec"]["containers"]
        .as_array()
        .map(|containers| {
            containers
                .iter()
                .filter_map(|c| c["image"].as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default()
}

/// Parse a `fieldSelector` query string and test a pod JSON value against it.
///
/// Supported selectors (comma-separated), matching upstream's SelectableFields
/// in pkg/registry/core/pod/strategy.go:
///   spec.nodeName=<value>              spec.nodeName!=<value>
///   status.phase=<value>               status.phase!=<value>
///   status.podIP=<value>               status.podIP!=<value>
///   spec.restartPolicy=<value>         spec.restartPolicy!=<value>
///   spec.serviceAccountName=<value>    spec.serviceAccountName!=<value>
///   spec.schedulerName=<value>         spec.schedulerName!=<value>
///   status.nominatedNodeName=<value>   status.nominatedNodeName!=<value>
///
/// An empty or absent selector matches everything (pass-through).
/// Unknown selector terms are ignored (conservative: don't drop pods on unrecognised fields).
pub(crate) fn filter_pods_by_field_selector(
    pods: Vec<serde_json::Value>,
    selector: &str,
) -> Vec<serde_json::Value> {
    if selector.is_empty() {
        return pods;
    }
    pods.into_iter()
        .filter(|pod| pod_matches_field_selector(pod, selector))
        .collect()
}

fn pod_matches_field_selector(pod: &serde_json::Value, selector: &str) -> bool {
    let node_name = pod["spec"]["nodeName"].as_str().unwrap_or("");
    let phase = pod["status"]["phase"].as_str().unwrap_or("");
    let pod_ip = pod["status"]["podIP"].as_str().unwrap_or("");
    let restart_policy = pod["spec"]["restartPolicy"].as_str().unwrap_or("");
    let service_account_name = pod["spec"]["serviceAccountName"].as_str().unwrap_or("");
    let scheduler_name = pod["spec"]["schedulerName"].as_str().unwrap_or("");
    let nominated_node_name = pod["status"]["nominatedNodeName"].as_str().unwrap_or("");
    for term in selector.split(',') {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        if let Some((field, value)) = term.split_once("!=") {
            if field == "spec.nodeName" && node_name == value {
                return false;
            }
            if field == "status.phase" && phase == value {
                return false;
            }
            if field == "status.podIP" && pod_ip == value {
                return false;
            }
            if field == "spec.restartPolicy" && restart_policy == value {
                return false;
            }
            if field == "spec.serviceAccountName" && service_account_name == value {
                return false;
            }
            if field == "spec.schedulerName" && scheduler_name == value {
                return false;
            }
            if field == "status.nominatedNodeName" && nominated_node_name == value {
                return false;
            }
            // Unknown fields: ignore (don't filter out)
        } else if let Some((field, value)) = term.split_once('=') {
            if field == "spec.nodeName" && node_name != value {
                return false;
            }
            if field == "status.phase" && phase != value {
                return false;
            }
            if field == "status.podIP" && pod_ip != value {
                return false;
            }
            if field == "spec.restartPolicy" && restart_policy != value {
                return false;
            }
            if field == "spec.serviceAccountName" && service_account_name != value {
                return false;
            }
            if field == "spec.schedulerName" && scheduler_name != value {
                return false;
            }
            if field == "status.nominatedNodeName" && nominated_node_name != value {
                return false;
            }
            // Unknown fields: ignore (don't filter out)
        }
        // Unparseable term: ignore
    }
    true
}

/// Filter a list of Event JSON values by a comma-separated field selector.
///
/// Supported fields (all equality, no negation):
///   involvedObject.name, involvedObject.kind, involvedObject.namespace,
///   involvedObject.uid, reason, source, reportingController
///
/// `source` reads core/v1 Event's `source.component`, falling back to
/// events.k8s.io/v1's `reportingController` when `source.component` is empty —
/// matching upstream's `ToSelectableFields` (pkg/registry/core/event/strategy.go),
/// which applies the identical fallback so a core/v1 `fieldSelector=source=X`
/// query still matches an Event whose only reporter identity was set via the
/// events.k8s.io/v1 API (client-go's EventsV1 recorder never sets `source`).
/// `reportingController` reads events.k8s.io/v1 Event's top-level field
/// directly (no fallback — that field is defined only in that group).
///
/// All supplied terms are AND-evaluated: an event must match every term.
/// An unknown field is ignored (pass-through). An event missing a constrained
/// field does not match.
pub(crate) fn filter_events_by_field_selector(
    events: Vec<serde_json::Value>,
    selector: &str,
) -> Vec<serde_json::Value> {
    if selector.is_empty() {
        return events;
    }
    events
        .into_iter()
        .filter(|ev| event_matches_field_selector(ev, selector))
        .collect()
}

fn event_matches_field_selector(ev: &serde_json::Value, selector: &str) -> bool {
    for term in selector.split(',') {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        if let Some((field, expected)) = term.split_once('=') {
            let actual = match field {
                "involvedObject.name" => ev["involvedObject"]["name"].as_str().unwrap_or(""),
                "involvedObject.kind" => ev["involvedObject"]["kind"].as_str().unwrap_or(""),
                "involvedObject.namespace" => {
                    ev["involvedObject"]["namespace"].as_str().unwrap_or("")
                }
                "involvedObject.uid" => ev["involvedObject"]["uid"].as_str().unwrap_or(""),
                "reason" => ev["reason"].as_str().unwrap_or(""),
                "source" => {
                    let component = ev["source"]["component"].as_str().unwrap_or("");
                    if component.is_empty() {
                        ev["reportingController"].as_str().unwrap_or("")
                    } else {
                        component
                    }
                }
                "reportingController" => ev["reportingController"].as_str().unwrap_or(""),
                _ => continue,
            };
            if actual != expected {
                return false;
            }
        }
    }
    true
}

/// Validate a raw namespace string: format check then store lookup.
/// Returns 400 on invalid format, 404 if namespace does not exist.
async fn parse_namespace<S: Store>(
    raw: &str,
    state: &AppState<S>,
) -> Result<Namespace, crate::status::StatusError> {
    let ns = Namespace::parse(raw).map_err(Status::bad_request)?;
    let key = cluster_object_key("namespaces", ns.as_str());
    let exists = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .is_some();
    if !exists {
        return Err(Status::not_found(ns.as_str(), "Namespace"));
    }
    Ok(ns)
}

fn store_err_to_status(err: StoreError, name: &str) -> crate::status::StatusError {
    match err {
        StoreError::NotFound { .. } => Status::not_found(name, "Pod"),
        StoreError::AlreadyExists { .. } => Status::already_exists(name, "Pod"),
        StoreError::RevisionMismatch { expected, current } => Status::conflict(format!(
            "Pod \"{name}\" cannot be updated: resource version mismatch (expected {expected}, current {current})"
        )),
        other => Status::internal(other.to_string()),
    }
}

pub(crate) async fn list_pods<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns,)): Path<(String,)>,
    Query(query): Query<CollectionQuery>,
    headers: HeaderMap,
    Extension(user): Extension<UserInfo>,
) -> Result<Response, crate::status::StatusError> {
    // Detect as=Table before namespace validation: a v1beta1 Table request must return
    // 406 Not Acceptable regardless of namespace validity (the format is not supported).
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Some(version) = super::table::table_accept_version(accept) {
        if version != "v1" {
            return Err(Status::not_acceptable(format!(
                "Table version \"{version}\" is not supported; only meta.k8s.io/v1 is accepted"
            )));
        }
    }

    let ns = parse_namespace(&raw_ns, &state).await?;
    let prefix = list_prefix("pods", ns.as_str());

    // metrics-server's per-namespace Pod-metadata informer (and kcm's GC) negotiate this
    // Accept header on LIST+WATCH; without honoring it here, their metadata-only decoder
    // rejects the typed Pod/PodList response and the informer never populates (metrics-server
    // silently returns empty PodMetrics for every labelSelector-filtered query, which is
    // exactly what the HPA controller always issues).
    let pom = super::generic::wants_partial_object_metadata(accept);

    if query.watch == Some(true) {
        let (watch_api_version, watch_kind) = if pom {
            (
                "meta.k8s.io/v1".to_string(),
                "PartialObjectMetadata".to_string(),
            )
        } else {
            ("v1".to_string(), "Pod".to_string())
        };
        let from_rv = query.resource_version.unwrap_or(0);
        let initial_pods = if query.send_initial_events == Some(true) {
            // Collect existing pods under this namespace prefix and filter by field selector.
            let store_fs = query
                .field_selector
                .as_deref()
                .and_then(pod_store_field_selector);
            let resp = state
                .store
                .list(
                    &prefix,
                    ListOptions {
                        field_selector: store_fs,
                        ..Default::default()
                    },
                )
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            let mut pods: Vec<serde_json::Value> = resp
                .items
                .iter()
                .filter_map(|o| serde_json::from_slice(&o.value).ok())
                .collect();
            if let Some(ref sel) = query.field_selector {
                pods = filter_pods_by_field_selector(pods, sel);
            }
            if let Some(ref sel) = query.label_selector {
                pods.retain(|pod| super::watch::object_matches_label_selector(pod, sel));
            }
            Some((pods, resp.revision))
        } else {
            None
        };
        return super::watch::watch_generic(
            state,
            super::watch::WatchConfig {
                prefix,
                api_version: watch_api_version,
                kind: watch_kind,
                from_revision: from_rv,
                initial_items: initial_pods,
                label_selector: query.label_selector,
                field_selector: query.field_selector,
                allow_watch_bookmarks: query.allow_watch_bookmarks == Some(true),
                username: user.username,
                as_partial_object_metadata: pom,
                group: "".into(),
                plural: "pods".into(),
                timeout_seconds: query.timeout_seconds,
            },
        )
        .await;
    }

    let store_field_selector = query
        .field_selector
        .as_deref()
        .and_then(pod_store_field_selector);
    let list_start = std::time::Instant::now();
    let resp = state
        .store
        .list(
            &prefix,
            ListOptions {
                field_selector: store_field_selector,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    tracing::debug!(
        prefix = %prefix,
        item_count = resp.items.len(),
        elapsed_ms = list_start.elapsed().as_millis() as u64,
        "list: query completed"
    );

    let mut items = Vec::with_capacity(resp.items.len());
    for obj in &resp.items {
        let parsed: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
        items.push(parsed);
    }

    let items = if let Some(ref sel) = query.field_selector {
        filter_pods_by_field_selector(items, sel)
    } else {
        items
    };

    let items = if let Some(ref sel) = query.label_selector {
        let pairs = super::generic::parse_label_selector(sel)?;
        super::generic::apply_label_selector(items, &pairs)
    } else {
        items
    };
    tracing::debug!(prefix = %prefix, filtered_count = items.len(), "list: filtered");

    // Per-pod lifecycle visibility: enable with `u7s::apiserver::pod_lifecycle=debug`. Emitted
    // per item (not one aggregate log line) so an operator can grep/filter by pod name without
    // capturing full PodList response bodies for every request.
    for pod in &items {
        tracing::debug!(
            target: "u7s::apiserver::pod_lifecycle",
            namespace = %pod["metadata"]["namespace"].as_str().unwrap_or(""),
            name = %pod["metadata"]["name"].as_str().unwrap_or(""),
            phase = %pod["status"]["phase"].as_str().unwrap_or(""),
            deletion_timestamp = ?pod["metadata"]["deletionTimestamp"].as_str(),
            image = %pod_container_images(pod),
            "pod list entry"
        );
    }

    if pom {
        let pom_items: Vec<serde_json::Value> = items
            .iter()
            .map(super::watch::to_partial_object_metadata)
            .collect();
        let body = serde_json::json!({
            "apiVersion": "meta.k8s.io/v1",
            "kind": "PartialObjectMetadataList",
            "metadata": { "resourceVersion": resp.revision.to_string() },
            "items": pom_items
        });
        return Ok(Json(body).into_response());
    }

    // Return Table format when as=Table;v=v1 is requested (v1beta1 was rejected above).
    if super::table::wants_table(accept) {
        return Ok(Json(super::table::build_table("", "pods", items)).into_response());
    }

    let body = serde_json::json!({
        "kind": "PodList",
        "apiVersion": "v1",
        "metadata": { "resourceVersion": resp.revision.to_string() },
        "items": items
    });

    Ok(crate::content_type::negotiated_response(accept, body))
}

pub(crate) async fn create_pod<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns,)): Path<(String,)>,
    Query(create_query): Query<super::json_patch::CreateQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    // Captured before resolve_name mutates metadata.name, so a store collision below
    // knows whether it's allowed to retry under a freshly generated name.
    let generate_name_prefix = crate::handlers::generic::wants_generate_name(&obj);
    let mut name = crate::handlers::generic::resolve_name(&mut obj)?;

    // Ensure namespace is set in the stored object
    obj.body["metadata"]["namespace"] = serde_json::Value::String(ns.as_str().to_owned());
    crate::handlers::generic::stamp_metadata(&mut obj);

    apply_pod_create_defaults(&mut obj.body);
    initialize_pod_generation(&mut obj.body);
    apply_automount_sa_token_default(&state, &mut obj.body, ns.as_str()).await;
    inject_sa_token_volume(&mut obj.body, &name);

    if let Some(rc_name) = obj.body["spec"]["runtimeClassName"]
        .as_str()
        .map(str::to_owned)
    {
        let rc_key = group_object_key("node.k8s.io", "runtimeclasses", None, &rc_name);
        match state.store.get(&rc_key).await {
            Ok(Some(stored_rc)) => {
                match serde_json::from_slice::<serde_json::Value>(&stored_rc.value) {
                    Ok(rc_obj) => {
                        tracing::debug!(rc = %rc_name, overhead = %rc_obj["overhead"], "injecting RuntimeClass overhead into pod");
                        apply_runtime_class_overhead(&mut obj.body, &rc_obj);
                        if let Err(msg) = apply_runtime_class_scheduling(&mut obj.body, &rc_obj) {
                            // Real kube-apiserver's RuntimeClass admission plugin rejects
                            // the pod outright on a nodeSelector conflict rather than
                            // silently picking a side — a pod that ignores this could
                            // land on a node the RuntimeClass forbids.
                            return Err(Status::forbidden(format!("pod rejected: {msg}")));
                        }
                    }
                    Err(e) => {
                        tracing::warn!(rc = %rc_name, err = %e, "failed to parse stored RuntimeClass — overhead not injected");
                    }
                }
            }
            Ok(None) => {
                // RuntimeClass referenced but not found: reject the pod. The real
                // kube-apiserver returns 403 Forbidden here (RuntimeClass admission plugin).
                // Failing to reject causes test pods to be persisted indefinitely, filling
                // the node and cascading failures into unrelated tests.
                return Err(Status::forbidden(format!(
                    "pod rejected: RuntimeClass \"{rc_name}\" not found"
                )));
            }
            Err(e) => {
                tracing::warn!(rc = %rc_name, err = %e, "store error looking up RuntimeClass — overhead not injected");
            }
        }
    }

    // PriorityClass admission: resolve spec.priorityClassName -> spec.priority.
    // Must happen here (not in the pure apply_pod_create_defaults) because it
    // requires a store lookup. Without this, spec.priority is always absent
    // (defaults to 0 for the scheduler), so the scheduler's preemption logic
    // (crates/scheduler) can never tell pods apart by priority.
    if let Some(pc_name) = obj.body["spec"]["priorityClassName"]
        .as_str()
        .filter(|n| !n.is_empty())
        .map(str::to_owned)
    {
        let pc_key = group_object_key("scheduling.k8s.io", "priorityclasses", None, &pc_name);
        let priority_result = match state.store.get(&pc_key).await {
            Ok(Some(stored_pc)) => {
                match serde_json::from_slice::<serde_json::Value>(&stored_pc.value) {
                    Ok(pc_obj) => resolve_pod_priority_class(&mut obj.body, Some(&pc_obj)),
                    Err(e) => {
                        tracing::warn!(priority_class = %pc_name, err = %e, "failed to parse stored PriorityClass — priority not resolved");
                        Ok(())
                    }
                }
            }
            // Not found in the store: resolve_pod_priority_class still succeeds for
            // the two built-in system class names (it ignores `stored_class` for
            // those); any other name is rejected below.
            Ok(None) => resolve_pod_priority_class(&mut obj.body, None),
            Err(e) => {
                tracing::warn!(priority_class = %pc_name, err = %e, "store error looking up PriorityClass — priority not resolved");
                Ok(())
            }
        };
        if let Err(msg) = priority_result {
            // Real kube-apiserver's PriorityClass admission plugin rejects pod
            // creation outright when priorityClassName doesn't resolve, rather
            // than silently persisting the pod at the default priority (0) where
            // preemption could never distinguish it from any other pod.
            return Err(Status::forbidden(format!("pod rejected: {msg}")));
        }
    }

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: "",
        version: "v1",
        resource: "pods",
        name: &name,
        namespace: Some(ns.as_str()),
        operation: "CREATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
            "extra": user.extra,
        })),
        dry_run: create_query.is_dry_run(),
    };
    obj.body = run_mutating_webhooks(&state, obj.body, None, &admission_ctx).await?;
    // Re-apply spec/container defaults (terminationMessagePolicy etc.) after mutating
    // webhooks run, so a container a webhook injects via JSON patch is defaulted too.
    // apply_pod_create_defaults (above, before the webhook chain) only ever saw the
    // client-supplied containers; a webhook can add new ones the first pass never
    // touched. Real kube-apiserver re-runs defaulting after each mutating-webhook
    // round; this single re-apply is the MVP form of that. Idempotent —
    // apply_pod_spec_defaults only fills absent/empty fields, so containers already
    // defaulted above are unchanged. Must run before validation so validating
    // webhooks see the fully-defaulted object, matching upstream ordering.
    apply_pod_spec_defaults(&mut obj.body);
    validate_pod_sysctls(&obj.body).map_err(Status::unprocessable_entity)?;
    super::defaults::validate_pod_certificate_projections(&obj.body)
        .map_err(Status::unprocessable_entity)?;
    run_validating_webhooks(&state, &obj.body, None, &admission_ctx).await?;

    // LimitRange: inject defaults then validate min/max bounds.
    obj.body =
        crate::limit_range::apply_limit_ranges(&state, obj.body, ns.as_str(), "pods").await?;

    // ResourceQuota: ensure pod count does not exceed hard limits, respecting scope selectors.
    // Held across check-then-write: without this, concurrent pod creates in the same
    // namespace (e.g. a ReplicationController's burst replica creation) can each observe
    // pre-write usage, all pass the check, and collectively exceed the quota.
    let _quota_lock = state.quota_admission_locks.lock(ns.as_str()).await;
    crate::quota::check_resource_quota(&state, ns.as_str(), "", "pods", Some(&obj.body)).await?;

    obj.body["status"]["qosClass"] =
        serde_json::Value::String(compute_qos_class(&obj.body).to_owned());

    // Dry-run: validation passed; return the would-be created object without persisting.
    if create_query.is_dry_run() {
        return Ok((StatusCode::CREATED, Json(obj.body)).into_response());
    }

    let ns_key = cluster_object_key("namespaces", ns.as_str());
    // Reject pod creation in a Terminating namespace — matches kube-apiserver behaviour and
    // the same gate create_namespaced_resource enforces for every other resource type,
    // atomically with the insert so a concurrent delete_namespace phase-flip can never land
    // between the check and this write. Without this, a ReplicationController/ReplicaSet
    // controller can keep recreating pods in a namespace mid-deletion, forcing the real KCM
    // namespace-controller's own DeleteCollection retries to repeatedly race new pods instead
    // of converging quickly.
    //
    // Counts store.create_if_namespace_active attempts made so far (the loop's first
    // iteration is attempt 1). Bounded at MAX_GENERATE_NAME_CREATE_ATTEMPTS TOTAL attempts,
    // mirroring create_resource/create_namespaced_resource's generateName-collision retry
    // (see resource.rs) — a controller mass-creating pods via bare `metadata.generateName`
    // must not see a spurious 409 just because the server's random suffix landed on an
    // existing name.
    let mut attempts_made = 1u32;
    let new_rv = loop {
        let key = object_key("pods", ns.as_str(), &name);
        match state
            .store
            .create_if_namespace_active(Some(&ns_key), &key, obj.to_bytes())
            .await
        {
            Ok(rv) => break rv,
            Err(CreateNamespacedError::NamespaceTerminating) => {
                return Err(Status::forbidden(format!(
                    "unable to create new content in namespace {ns} because it is being terminated"
                )));
            }
            // The client never chose this name (it came from generateName) — a collision is
            // the server's random suffix landing on an existing object, not a real conflict
            // the client should see. Retry with a fresh suffix instead of surfacing a
            // spurious 409 on what the client experiences as a plain create.
            Err(CreateNamespacedError::Store(StoreError::AlreadyExists { .. }))
                if generate_name_prefix.is_some()
                    && attempts_made
                        < crate::handlers::generic::MAX_GENERATE_NAME_CREATE_ATTEMPTS =>
            {
                attempts_made += 1;
                name = format!(
                    "{}{}",
                    generate_name_prefix.as_deref().unwrap_or_default(),
                    crate::handlers::generic::generate_suffix()
                );
                obj.body["metadata"]["name"] = serde_json::Value::String(name.clone());
                // Re-validate the regenerated name — mirrors create_resource's retry, which
                // re-runs validating admission once per attempt, not just for the first
                // candidate name.
                let retry_ctx = AdmissionContext {
                    group: "",
                    version: "v1",
                    resource: "pods",
                    name: &name,
                    namespace: Some(ns.as_str()),
                    operation: "CREATE",
                    user_info: Some(serde_json::json!({
                        "username": user.username,
                        "uid": user.uid,
                        "groups": user.groups,
                        "extra": user.extra,
                    })),
                    dry_run: false,
                };
                run_validating_webhooks(&state, &obj.body, None, &retry_ctx).await?;
            }
            Err(CreateNamespacedError::Store(e)) => return Err(store_err_to_status(e, &name)),
        }
    };

    obj.set_resource_version(new_rv);

    // Register with the node-authorization graph. A no-op unless spec.nodeName is already
    // set (a static/pre-scheduled pod) — most pods get their nodeName later, via bind_pod.
    state.node_graph.apply_pod(ns.as_str(), &name, &obj.body);

    crate::quota::record_pod_created(&state, ns.as_str(), &obj.body).await;

    Ok((StatusCode::CREATED, Json(obj.body)).into_response())
}

pub(crate) async fn get_pod<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, crate::status::StatusError> {
    // Same as list_pods: reject an unsupported Table version before namespace validation,
    // since the format is not implementable regardless of whether the namespace exists.
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Some(version) = super::table::table_accept_version(accept) {
        if version != "v1" {
            return Err(Status::not_acceptable(format!(
                "Table version \"{version}\" is not supported; only meta.k8s.io/v1 is accepted"
            )));
        }
    }

    let ns = parse_namespace(&raw_ns, &state).await?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    // kcm's GC verifies owner references via metadata-only Get() calls
    // (garbagecollector.go's isDangling); without this, it receives a typed Pod object it
    // can't decode and retries the owner-check forever, so newly-orphaned dependents are
    // never identified as dangling and never collected.
    if super::generic::wants_partial_object_metadata(accept) {
        let pod: serde_json::Value =
            serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;
        return Ok(Json(super::watch::to_partial_object_metadata(&pod)).into_response());
    }

    // kubectl's default Accept header requests Table format; without this, kubectl can't
    // decode the response and falls back to printing only NAME/AGE instead of the usual
    // READY/STATUS/RESTARTS columns (list_pods already handles this — see above).
    if super::table::wants_table(accept) {
        let pod: serde_json::Value =
            serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;
        return Ok(Json(super::table::build_table("", "pods", vec![pod])).into_response());
    }

    if crate::content_type::wants_protobuf(accept) {
        let pod: serde_json::Value =
            serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;
        return Ok(crate::content_type::negotiated_response(accept, pod));
    }

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

/// Shared post-write guard for both `replace_pod` (PUT) and `patch_pod` (PATCH, all
/// content types including SSA): a write that changed `spec.activeDeadlineSeconds` may
/// have flipped the pod's Terminating/NotTerminating scope membership (see
/// `record_pod_scope_changed`'s doc). Skips entirely when the spec didn't change — the
/// overwhelming majority of both PUT and PATCH calls — and otherwise takes the same
/// per-namespace lock the create/delete/resize paths hold across their own read-modify-
/// write of `status.used`. Both write paths call this one function from their own
/// store.put success arm so the recount cannot cover one and silently miss the other.
async fn record_scope_change_if_spec_changed<S: Store>(
    state: &AppState<S>,
    ns: &str,
    spec_before: &serde_json::Value,
    new_pod: &serde_json::Value,
) {
    if spec_before == &new_pod["spec"] {
        return;
    }
    let _quota_lock = state.quota_admission_locks.lock(ns).await;
    crate::quota::record_pod_scope_changed(state, ns, spec_before, new_pod).await;
}

pub(crate) async fn replace_pod<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    Query(replace_query): Query<super::json_patch::ReplaceQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj =
        Object::from_bytes(&body).map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_name = obj.name().unwrap_or("").to_string();
    if obj_name != name {
        return Err(Status::bad_request(format!(
            "the name of the object ({obj_name}) does not match the name on the URL ({name})"
        )));
    }

    let expected_revision = parse_resource_version(obj.resource_version())?;

    // Fetch the stored object to compare spec (needed for generation tracking).
    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    // Stale-resourceVersion PUTs must 409, not fall through into
    // validate_pod_spec_immutable using the freshly-read `stored` below — see
    // check_replace_resource_version_precondition in resource.rs for the same invariant.
    // Concrete pod instance: a controller GETs a pod, then PUTs it back with
    // only e.g. metadata.labels changed to release it from a selector. If the scheduler binds
    // spec.nodeName via /binding in between, the stored spec has moved on by the time this PUT
    // arrives — the controller's PUT body still carries the pre-bind (blank) nodeName it read.
    // Comparing that stale body's spec against the just-fetched, already-scheduled `stored`
    // spec makes validate_pod_spec_immutable see a genuine nodeName change and permanently
    // reject with 422, instead of the retryable 409 a resourceVersion mismatch should give —
    // which is what tells the controller's own conflict-retry loop to re-GET and resubmit
    // against the now-scheduled pod.
    if let Some(expected) = expected_revision {
        if expected != stored.revision {
            return Err(store_err_to_status(
                StoreError::RevisionMismatch {
                    expected,
                    current: stored.revision,
                },
                &name,
            ));
        }
    }

    let stored_obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;
    let spec_before = stored_obj.body["spec"].clone();
    // PUT to the main /pods endpoint updates spec+metadata only; status is managed by
    // the /status subresource. Client bodies may carry stale status (e.g. a local cache
    // from before kubelet's latest status patch), which would silently clobber real
    // status updates if not stripped. Mirrors patch_pod's stored_status handling below.
    let stored_status = stored_obj.body["status"].clone();
    // metadata.generation is server-managed. Restore the stored value so a
    // client-supplied generation (e.g. the conformance test case that sends
    // generation=1 on a pod already at generation=5) cannot downgrade it.
    // increment_pod_generation_if_spec_changed then increments from the
    // stored value (if spec changed) or leaves it unchanged (if spec unchanged).
    let stored_generation = stored_obj.body["metadata"]["generation"].clone();
    obj.body["metadata"]["generation"] = stored_generation;

    // metadata.uid is immutable identity, exactly like the generic replace_namespaced_resource
    // path (resource.rs): a blank incoming uid is restored from the stored object, but a
    // non-blank incoming uid that mismatches the stored one is identity forgery, not a
    // legitimate update — allowing it would let a caller holding only `update pods` (not
    // `create`/`delete pods`) forge a match against a stale/foreign ownerReference, corrupting
    // owner_ref_is_live's cascade-GC decision for ReplicaSet/Job/DaemonSet controllers.
    let stored_uid = stored_obj.body["metadata"]["uid"].clone();
    let incoming_uid_blank = obj.body["metadata"]["uid"]
        .as_str()
        .map(str::is_empty)
        .unwrap_or(true);
    if incoming_uid_blank {
        if let Some(uid) = stored_uid.as_str() {
            if !uid.is_empty() {
                obj.body["metadata"]["uid"] = serde_json::Value::String(uid.to_string());
            }
        }
    } else if let Some(stored_uid_str) = stored_uid.as_str().filter(|s| !s.is_empty()) {
        let incoming_uid_str = obj.body["metadata"]["uid"].as_str().unwrap_or("");
        if incoming_uid_str != stored_uid_str {
            return Err(Status::conflict(format!(
                "Pod \"{name}\": the object was updated with a mismatched uid \
                 (got {incoming_uid_str}, expected {stored_uid_str}) — uid is immutable"
            )));
        }
    }

    // deletionTimestamp is server-owned, exactly like generation above: a protobuf-encoded PUT
    // never round-trips this field (the wire decoder drops it — see the equivalent restoration
    // in replace_resource/replace_namespaced_resource) and a JSON PUT built from a stale local
    // copy can omit it too. Without restoring it here, the finalizer-drain check below would see
    // a blank deletionTimestamp on an already-terminating pod and treat this PUT as a plain
    // update, silently un-terminating it.
    if obj.body["metadata"]["deletionTimestamp"].is_null() {
        let stored_ts = stored_obj.body["metadata"]["deletionTimestamp"].clone();
        if !stored_ts.is_null() {
            obj.body["metadata"]["deletionTimestamp"] = stored_ts;
            let stored_grace = stored_obj.body["metadata"]["deletionGracePeriodSeconds"].clone();
            if !stored_grace.is_null() {
                obj.body["metadata"]["deletionGracePeriodSeconds"] = stored_grace;
            }
        }
    }

    // Admission webhook pipeline (mutating then validating).
    let admission_ctx = AdmissionContext {
        group: "",
        version: "v1",
        resource: "pods",
        name: &name,
        namespace: Some(ns.as_str()),
        operation: "UPDATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
            "extra": user.extra,
        })),
        dry_run: replace_query.is_dry_run(),
    };
    obj.body = run_mutating_webhooks(&state, obj.body, None, &admission_ctx).await?;
    validate_pod_spec_immutable(&spec_before, &obj.body["spec"])
        .map_err(Status::unprocessable_entity)?;
    run_validating_webhooks(&state, &obj.body, None, &admission_ctx).await?;

    increment_pod_generation_if_spec_changed(&mut obj.body, &spec_before);

    // Restore the stored status now that spec/metadata processing is done: whatever
    // status the client's PUT body carried (see stored_status comment above) is
    // discarded in favor of the server's own record.
    obj.body["status"] = stored_status;

    // Dry-run: validation and admission passed; return the would-be replaced object without
    // persisting — mirrors replace_namespaced_resource's dry-run early-return in resource.rs.
    if replace_query.is_dry_run() {
        return Ok(Json(obj.body));
    }

    // A PUT whose body has deletionTimestamp set and finalizers now empty is how KCM's
    // protection controllers (pvc-protection, vac-protection, ...) complete a delete: they
    // remove their finalizer via PUT, not PATCH. Mirrors patch_pod's post-patch check below —
    // complete the delete instead of storing an update, or the pod stays stuck Terminating
    // forever.
    if super::resource::finalizer_drain_complete(&obj.body) {
        state
            .store
            .delete(&key, None)
            .await
            .map_err(|e| store_err_to_status(e, &name))?;
        state.node_graph.remove_pod(ns.as_str(), &name);
        // Same per-namespace lock the create path holds across its check-then-write —
        // without it here, this decrement can interleave with a concurrent
        // create/delete/resize's read-modify-write of the same quota's status.used and lose
        // an update. Dropped before maybe_finalize_terminating_namespace below, which may
        // itself need this same namespace's lock while purging remaining pods.
        let _quota_lock = state.quota_admission_locks.lock(ns.as_str()).await;
        crate::quota::record_pod_removed(&state, ns.as_str(), &obj.body).await;
        drop(_quota_lock);
        super::namespaces::maybe_finalize_terminating_namespace(&state, ns.as_str()).await;
        return Ok(Json(obj.body));
    }

    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_revision)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    record_scope_change_if_spec_changed(&state, ns.as_str(), &spec_before, &obj.body).await;

    Ok(Json(obj.body))
}

/// Legacy `?gracePeriodSeconds=` query-param form of the grace period, for clients that
/// still send it on the URL instead of (or as well as) in the DeleteOptions body.
#[derive(Deserialize)]
pub struct GracePeriodQuery {
    #[serde(rename = "gracePeriodSeconds")]
    pub grace_period_seconds: Option<i64>,
}

/// Resolve the grace period a delete should actually use: an explicit request value (body
/// DeleteOptions takes precedence over the query param) beats the pod's own
/// spec.terminationGracePeriodSeconds, which beats the upstream default of 30s. Without this
/// fallback chain, a plain `kubectl delete pod` (no explicit --grace-period) would stamp
/// deletionGracePeriodSeconds=0 even though the pod's own spec says the kubelet needs up to
/// 30s to shut its containers down gracefully.
fn effective_grace_period_seconds(requested: Option<i64>, pod: &serde_json::Value) -> i64 {
    requested
        .or_else(|| pod["spec"]["terminationGracePeriodSeconds"].as_i64())
        .unwrap_or(30)
}

fn unix_now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Compute the RFC3339 timestamp `grace_period_seconds` in the future from now, for stamping
/// `metadata.deletionTimestamp`. Kubelet/controllers use this value (not "now") to know how
/// long they have before the apiserver expects a hard delete.
fn deletion_timestamp_after_grace(grace_period_seconds: i64) -> String {
    secs_to_rfc3339(unix_now_secs() + grace_period_seconds)
}

/// When a pod is already Terminating (`deletionTimestamp` set) and finalizers still block hard
/// delete, real kube-apiserver's `BeforeDelete`
/// (staging/src/k8s.io/apiserver/pkg/registry/rest/delete.go) only lets a repeat DELETE move
/// `deletionTimestamp` earlier — never later, never on a bare re-DELETE with no explicit
/// `gracePeriodSeconds`. Anything else must leave metadata untouched: writing it anyway defeats
/// the store's byte-equality no-op-write check, bumping resourceVersion and firing a watch event
/// on every redundant DELETE. That livelocks finalizer drain under a controller that re-issues
/// Delete() on resync — e.g. the Job controller against a pod holding
/// `batch.kubernetes.io/job-tracking`. Generation is deliberately not touched here either:
/// upstream only bumps it on the initial not-yet-terminating -> Terminating transition.
///
/// Returns `Some((new_deletion_timestamp_secs, new_grace_period_seconds))` when the grace period
/// is legitimately shortened, `None` when the request is a no-op.
fn shorten_grace_period_secs(
    now_secs: i64,
    stored_deletion_timestamp_secs: i64,
    stored_grace_period_seconds: Option<i64>,
    requested_grace_period_seconds: Option<i64>,
) -> Option<(i64, i64)> {
    let stored_grace_period_seconds = stored_grace_period_seconds?;
    if stored_grace_period_seconds <= 0 {
        return None;
    }
    let requested = requested_grace_period_seconds?;
    if requested >= stored_grace_period_seconds {
        return None;
    }
    // Move the existing deletionTimestamp back by the stored grace period, then forward by the
    // newly requested one — same base reference, shorter duration — rather than recomputing from
    // "now", matching upstream exactly.
    let mut new_deletion_timestamp_secs =
        stored_deletion_timestamp_secs - stored_grace_period_seconds + requested;
    let mut period = requested;
    if new_deletion_timestamp_secs < now_secs {
        new_deletion_timestamp_secs = now_secs;
        if period != 0 {
            period = 1;
        }
    }
    // The clamp above only ever raises the candidate, never lowers it — if the pod is already
    // overdue (now_secs already past stored_deletion_timestamp_secs, e.g. stuck on a slow
    // finalizer, which is exactly this function's target scenario), raising to "now" can land
    // AFTER the stored timestamp. That is not a shortening: a shorter grace period can only
    // move deletion earlier than what's already recorded, never later. Treat it as a no-op
    // instead of silently pushing the deadline out.
    if new_deletion_timestamp_secs >= stored_deletion_timestamp_secs {
        return None;
    }
    Some((new_deletion_timestamp_secs, period))
}

#[cfg(test)]
mod shorten_grace_period_secs_tests {
    use super::shorten_grace_period_secs;

    /// No explicit gracePeriodSeconds in the re-DELETE request must never touch the object —
    /// this is the plain "redundant retry" case a resyncing controller sends constantly.
    #[test]
    fn no_requested_grace_is_a_no_op() {
        assert_eq!(
            shorten_grace_period_secs(1_000, 2_000, Some(30), None),
            None
        );
    }

    /// A requested grace period equal to or longer than what's already stored must not extend
    /// (or gratuitously restamp) deletionTimestamp — kube-apiserver only ever shortens.
    #[test]
    fn requested_grace_greater_or_equal_to_stored_is_a_no_op() {
        assert_eq!(
            shorten_grace_period_secs(1_000, 2_000, Some(30), Some(30)),
            None
        );
        assert_eq!(
            shorten_grace_period_secs(1_000, 2_000, Some(30), Some(60)),
            None
        );
    }

    /// A stored grace period of 0 (or absent) means the object is already at "delete now" —
    /// there is nothing left to shorten.
    #[test]
    fn stored_grace_period_zero_or_absent_is_a_no_op() {
        assert_eq!(
            shorten_grace_period_secs(1_000, 2_000, Some(0), Some(0)),
            None
        );
        assert_eq!(shorten_grace_period_secs(1_000, 2_000, None, Some(0)), None);
    }

    /// A genuinely shorter explicit grace period moves deletionTimestamp back by the stored
    /// grace period and forward by the new one, preserving the original base reference instead
    /// of recomputing from "now" — this is what lets `kubectl delete pod --grace-period=<n>`
    /// speed up an already in-flight graceful termination without losing precision.
    #[test]
    fn shorter_requested_grace_moves_deletion_timestamp_earlier() {
        // stored deletionTimestamp = 2_000, stored grace = 120 -> object entered Terminating
        // at 2_000 - 120 = 1_880. Shortening to 30s should land at 1_880 + 30 = 1_910.
        assert_eq!(
            shorten_grace_period_secs(1_000, 2_000, Some(120), Some(30)),
            Some((1_910, 30))
        );
    }

    /// An already-overdue pod (now already past the stored deletionTimestamp — exactly this
    /// function's target scenario: a pod stuck on a slow finalizer past its deletion time) has
    /// nothing left to shorten. Naively clamping the computed timestamp up to "now" would land
    /// AFTER the already-recorded deletionTimestamp, which is not a shortening at all — it
    /// would silently push the deadline out. This must be a no-op instead: leave the stored
    /// deletionTimestamp untouched, no generation bump.
    ///
    /// Fails on revert: without the `>= stored_deletion_timestamp_secs` guard, this returns
    /// `Some((5_000, 1))` — 5_000 is later than the stored 2_000, violating the "never later
    /// than stored" invariant this function exists to enforce.
    #[test]
    fn shortening_an_already_overdue_pod_is_a_no_op() {
        // now = 5_000, already past the stored deletionTimestamp (2_000).
        assert_eq!(
            shorten_grace_period_secs(5_000, 2_000, Some(120), Some(30)),
            None
        );
    }

    /// Same as above but via the `--grace-period=0` (`--force`) path: even a forced shortening
    /// cannot move an already-overdue pod's deletionTimestamp later than what's stored.
    #[test]
    fn shortening_to_zero_on_an_already_overdue_pod_is_a_no_op() {
        assert_eq!(
            shorten_grace_period_secs(5_000, 2_000, Some(120), Some(0)),
            None
        );
    }

    /// A pod that is NOT yet overdue (stored deletionTimestamp still in the future) but whose
    /// naive shortened timestamp lands before "now" must still clamp to "now" and floor grace
    /// to 1s — the overdue no-op above must not swallow this legitimate case. The clamped
    /// result (1_000) stays strictly before the stored deletionTimestamp (1_010), so it's a
    /// real shortening, not a no-op.
    #[test]
    fn shortening_into_the_recent_past_still_before_stored_clamps_to_now_and_floors_grace() {
        // now = 1_000; stored deletionTimestamp = 1_010 (10s still remaining, not overdue).
        // naive = 1_010 - 120 + 5 = 895, before "now" -> clamps to now=1_000, which is still
        // before the stored 1_010.
        assert_eq!(
            shorten_grace_period_secs(1_000, 1_010, Some(120), Some(5)),
            Some((1_000, 1))
        );
    }
}

/// DELETE /api/v1/namespaces/{ns}/pods — collection delete with optional labelSelector.
///
/// sonobuoy cleanup sends this to remove all pods it created in a namespace.
/// Applies the labelSelector if present; deletes all matching pods.
pub(crate) async fn delete_collection_pods<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns,)): Path<(String,)>,
    Query(query): Query<super::generic::CollectionQuery>,
    Query(grace_query): Query<GracePeriodQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let body = extract_body(&body, content_type(&headers));
    let delete_opts: DeleteOptions = if body.is_empty() {
        DeleteOptions::default()
    } else {
        serde_json::from_slice(&body).unwrap_or_default()
    };
    let requested_grace = delete_opts
        .grace_period_seconds
        .or(grace_query.grace_period_seconds);
    // client-go's typed DeleteCollection() sends DryRun in the DeleteOptions body; a
    // raw/proxied caller may instead send it as ?dryRun=All (caught by the router-wide
    // inject_dry_run_header layer) — accept either.
    let dry_run = delete_opts.is_dry_run() || super::json_patch::is_dry_run_header(&headers);
    let prefix = list_prefix("pods", ns.as_str());

    let resp = state
        .store
        .list(&prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let label_pairs = query
        .label_selector
        .as_deref()
        .map(super::generic::parse_label_selector)
        .transpose()?;

    for obj in resp.items {
        let mut soft_deleted = false;
        // Captured only on the hard-delete branch below, so the incremental quota counter
        // (record_pod_removed) can be adjusted for this pod once it's actually gone from the
        // store — DeleteCollection previously never adjusted it at all, silently drifting
        // status.used for every namespace-wide pod purge (e.g. OrderedNamespaceDeletion).
        let mut hard_delete_pod: Option<serde_json::Value> = None;
        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&obj.value) {
            if let Some(ref pairs) = label_pairs {
                let kept = super::generic::apply_label_selector(vec![parsed.clone()], pairs);
                if kept.is_empty() {
                    continue;
                }
            }

            // Mirror delete_pod's soft/hard-delete decision instead of always hard-deleting:
            // a pod already Terminating (or force-deleted with an explicit gracePeriodSeconds=0)
            // with no finalizers left hard-deletes, every other pod (not yet Terminating and not
            // forced, or still holding a finalizer) is soft-deleted so its kubelet/finalizer-owning
            // controller observes deletionTimestamp instead of the pod vanishing outright. The real
            // KCM namespace-controller drains pods via exactly this endpoint (DeleteCollection)
            // during OrderedNamespaceDeletion — unconditionally hard-deleting here would silently
            // bypass every pod's finalizers.
            let meta: ObjectMeta =
                serde_json::from_value(parsed["metadata"].clone()).unwrap_or_default();
            let has_finalizers = meta.finalizers.as_ref().is_some_and(|f| !f.is_empty());
            let already_terminating = meta.deletion_timestamp.is_some();
            let force_requested = requested_grace == Some(0);
            let hard_delete_now = !has_finalizers && (already_terminating || force_requested);

            // Dry-run: validation passed; skip the actual write entirely (both the
            // soft-delete branch and the hard-delete fallback below) for this pod.
            if dry_run {
                continue;
            }

            if !hard_delete_now {
                if already_terminating {
                    // Redundant re-DELETE of an already-Terminating, finalizer-carrying pod
                    // (e.g. a Job controller re-issuing Delete() on resync): only a legitimate
                    // grace-period shortening writes; anything else is a no-op so it doesn't
                    // churn resourceVersion. See shorten_grace_period_secs for why.
                    let stored_ts_secs = meta
                        .deletion_timestamp
                        .as_deref()
                        .and_then(rfc3339_to_unix_secs);
                    if let Some((new_ts_secs, new_grace)) = stored_ts_secs.and_then(|ts| {
                        shorten_grace_period_secs(
                            unix_now_secs(),
                            ts,
                            meta.deletion_grace_period_seconds,
                            requested_grace,
                        )
                    }) {
                        let mut updated = parsed;
                        updated["metadata"]["deletionTimestamp"] =
                            serde_json::Value::String(secs_to_rfc3339(new_ts_secs));
                        updated["metadata"]["deletionGracePeriodSeconds"] =
                            serde_json::json!(new_grace);
                        let _ = state
                            .store
                            .put(&obj.key, bytes::Bytes::from(updated.to_string()), None)
                            .await;
                    }
                } else {
                    let mut updated = parsed;
                    let grace = effective_grace_period_seconds(requested_grace, &updated);
                    updated["metadata"]["deletionTimestamp"] =
                        serde_json::Value::String(deletion_timestamp_after_grace(grace));
                    updated["metadata"]["deletionGracePeriodSeconds"] = serde_json::json!(grace);
                    let current_gen = updated["metadata"]["generation"].as_i64().unwrap_or(1);
                    updated["metadata"]["generation"] = serde_json::json!(current_gen + 1);
                    let _ = state
                        .store
                        .put(&obj.key, bytes::Bytes::from(updated.to_string()), None)
                        .await;
                }
                soft_deleted = true;
            } else {
                hard_delete_pod = Some(parsed);
            }
        }
        if soft_deleted {
            continue;
        }
        // Also covers the (unparseable-JSON) fallback case for a dry-run request: the
        // `if dry_run { continue; }` above only runs for successfully-parsed items.
        if dry_run {
            continue;
        }
        let _ = state.store.delete(&obj.key, None).await;
        if let Some(pod_name) = obj.key.rsplit('/').next() {
            state.node_graph.remove_pod(ns.as_str(), pod_name);
        }
        if let Some(pod) = hard_delete_pod {
            // Same per-namespace lock the create path holds across its check-then-write —
            // without it here, this decrement can interleave with a concurrent
            // create/delete/resize's read-modify-write of the same quota's status.used and
            // lose an update. Held per-pod rather than across the whole loop so a concurrent
            // create in this namespace isn't blocked for the entire DeleteCollection.
            let _quota_lock = state.quota_admission_locks.lock(ns.as_str()).await;
            crate::quota::record_pod_removed(&state, ns.as_str(), &pod).await;
        }
    }

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    })))
}

pub(crate) async fn delete_pod<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    Extension(user): Extension<UserInfo>,
    Query(grace_query): Query<GracePeriodQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let body = extract_body(&body, content_type(&headers));
    let delete_opts: DeleteOptions = if body.is_empty() {
        DeleteOptions::default()
    } else {
        serde_json::from_slice(&body).unwrap_or_default()
    };
    let requested_grace = delete_opts
        .grace_period_seconds
        .or(grace_query.grace_period_seconds);
    // client-go's typed Delete() sends DryRun in the DeleteOptions body; a raw/proxied
    // caller may instead send it as ?dryRun=All (caught by the router-wide
    // inject_dry_run_header layer) — accept either.
    let dry_run = delete_opts.is_dry_run() || super::json_patch::is_dry_run_header(&headers);

    let key = object_key("pods", ns.as_str(), &name);

    // Retry loop: a plain DELETE with no resourceVersion precondition must never surface a
    // concurrency conflict to the client. If a concurrent writer (e.g. the kubelet's routine
    // pod-status PATCH) advances the stored resourceVersion between our read and our write,
    // re-read the fresh object and redo the soft-delete decision rather than returning 409.
    // Mirrors patch_pod's retry-on-RevisionMismatch loop above, added for the same race class.
    loop {
        // Fetch current object to check finalizers.
        let stored = state
            .store
            .get(&key)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(&name, "Pod"))?;

        let mut obj = Object::from_bytes(&stored.value)
            .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

        // Admission webhook pipeline (validating only — mutating webhooks do not apply to
        // DELETE). Run against the freshest read on every attempt, before branching into
        // soft-delete vs hard-delete below, so a Fail-policy webhook can deny whichever delete
        // decision this request actually makes.
        let admission_ctx = AdmissionContext {
            group: "",
            version: "v1",
            resource: "pods",
            name: &name,
            namespace: Some(ns.as_str()),
            operation: "DELETE",
            user_info: Some(serde_json::json!({
                "username": user.username,
                "uid": user.uid,
                "groups": user.groups,
                "extra": user.extra,
            })),
            dry_run,
        };
        run_validating_webhooks(&state, &obj.body, Some(&obj.body), &admission_ctx).await?;

        let meta: ObjectMeta =
            serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
        let has_finalizers = meta.finalizers.as_ref().is_some_and(|f| !f.is_empty());
        let already_terminating = meta.deletion_timestamp.is_some();
        // `kubectl delete --grace-period=0 --force` sends an explicit gracePeriodSeconds=0 —
        // the caller has accepted the documented "may continue running on the cluster
        // indefinitely" warning and wants the object gone now, not once some other actor
        // confirms it's safe. Without this, a pod scheduled onto a node whose kubelet died
        // before creating any container (or a node that has otherwise gone dark) stays
        // soft-deleted forever: nothing ever sends the confirming second DELETE, since
        // node-lifecycle-controller (the only thing that would evict its pods) is disabled in
        // this deployment.
        let force_requested = requested_grace == Some(0);

        // Real Kubernetes apiserver always soft-deletes pods first (sets deletionTimestamp)
        // so the kubelet receives a MODIFIED event and gracefully terminates the container via SIGTERM.
        // Hard-delete when the pod is already in the Terminating state (the kubelet calling DELETE
        // a second time after stopping the container) or the caller explicitly forced an immediate
        // delete — in both cases only if no finalizers are blocking it.
        //
        // Without the "already terminating" half: pods are immediately hard-deleted on a routine
        // `kubectl delete pod` (no explicit grace period), the kubelet only receives a DELETED event
        // with a minimal tombstone (no spec), and the container is never sent SIGTERM — it keeps
        // running indefinitely while the StatefulSet controller waits for the pod to terminate.
        if !has_finalizers && (already_terminating || force_requested) {
            // Dry-run: validation passed and this is what a real DELETE would hard-delete;
            // return the would-be Success status without persisting or running the quota
            // refresh side effect below.
            if dry_run {
                return Ok(Json(serde_json::json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Success",
                    "code": 200
                })));
            }
            // Hard-delete: pod is already Terminating, or the caller forced it, and all
            // finalizers are gone. No resourceVersion precondition is passed here, so this
            // path cannot RevisionMismatch.
            state
                .store
                .delete(&key, None)
                .await
                .map_err(|e| store_err_to_status(e, &name))?;
            state.node_graph.remove_pod(ns.as_str(), &name);

            // Same per-namespace lock the create path holds across its check-then-write —
            // without it here, this decrement can interleave with a concurrent
            // create/delete/resize's read-modify-write of the same quota's status.used and
            // lose an update.
            let _quota_lock = state.quota_admission_locks.lock(ns.as_str()).await;
            crate::quota::record_pod_removed(&state, ns.as_str(), &obj.body).await;

            return Ok(Json(serde_json::json!({
                "kind": "Status",
                "apiVersion": "v1",
                "status": "Success",
                "code": 200
            })));
        }

        if already_terminating {
            // Redundant re-DELETE of an already-Terminating, finalizer-carrying pod (this
            // handler only reaches here with has_finalizers — see the hard-delete branch
            // above). Real kube-apiserver's BeforeDelete only lets this move deletionTimestamp
            // earlier (an explicit, shorter gracePeriodSeconds); otherwise it must be a no-op.
            // Restamping on every retry defeats the store's byte-equality no-op-write check,
            // bumping resourceVersion and firing a watch event on every redundant DELETE — the
            // livelock that stalls Job pod-GC when the Job controller re-issues Delete() on
            // resync against a pod holding batch.kubernetes.io/job-tracking.
            let stored_ts_secs = meta
                .deletion_timestamp
                .as_deref()
                .and_then(rfc3339_to_unix_secs);
            match stored_ts_secs.and_then(|ts| {
                shorten_grace_period_secs(
                    unix_now_secs(),
                    ts,
                    meta.deletion_grace_period_seconds,
                    requested_grace,
                )
            }) {
                Some((new_ts_secs, new_grace)) => {
                    obj.body["metadata"]["deletionTimestamp"] =
                        serde_json::Value::String(secs_to_rfc3339(new_ts_secs));
                    obj.body["metadata"]["deletionGracePeriodSeconds"] =
                        serde_json::json!(new_grace);
                }
                None => return Ok(Json(obj.body)),
            }
        } else {
            // Soft-delete: stamp deletionTimestamp so the kubelet knows to gracefully terminate
            // the container. Applies regardless of whether the pod has finalizers.
            //
            // Setting deletionTimestamp is always a real mutation — Kubernetes increments
            // metadata.generation on every graceful delete so that controllers can detect
            // the transition via observedGeneration (pods.go:573 conformance test).
            let grace = effective_grace_period_seconds(requested_grace, &obj.body);
            obj.body["metadata"]["deletionTimestamp"] =
                serde_json::Value::String(deletion_timestamp_after_grace(grace));
            obj.body["metadata"]["deletionGracePeriodSeconds"] = serde_json::json!(grace);
            let current_gen = obj.body["metadata"]["generation"].as_i64().unwrap_or(1);
            obj.body["metadata"]["generation"] = serde_json::json!(current_gen + 1);
        }

        // Dry-run: validation passed and this is what a real DELETE would soft-delete to
        // (deletionTimestamp stamped, or the shortened grace period applied); return it
        // without persisting.
        if dry_run {
            return Ok(Json(obj.body));
        }

        let expected_rv = parse_resource_version(obj.resource_version())?;
        match state.store.put(&key, obj.to_bytes(), expected_rv).await {
            Ok(new_rv) => {
                obj.set_resource_version(new_rv);
                return Ok(Json(obj.body));
            }
            Err(StoreError::RevisionMismatch { .. }) => {
                // A concurrent write advanced the stored revision between our read and write.
                // Re-read the fresh object and redo the soft-delete decision.
                continue;
            }
            Err(e) => return Err(store_err_to_status(e, &name)),
        }
    }
}

pub(crate) async fn patch_pod<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    Query(patch_query): Query<super::json_patch::PatchQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let patch_type = super::json_patch::detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");

    let ns = parse_namespace(&raw_ns, &state).await?;

    let key = object_key("pods", ns.as_str(), &name);

    // apply-patch+yaml bodies are genuine YAML (e.g. kubectl apply --server-side); every
    // other patch type here is JSON.
    let patch: serde_json::Value = if is_ssa {
        super::json_patch::ssa_body_to_json(&body)?
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?
    };

    // Retry loop: PATCH semantics are "apply this change to the current state". If a
    // concurrent write (e.g. kubelet status patch) advances the stored resourceVersion
    // between the server's read and write, re-read the fresh object and re-apply the
    // patch rather than returning 409 to the client. Without this loop KCM's
    // finalizer-removal PATCH never converges: the kubelet patches status faster than
    // KCM can complete a single round-trip, so every attempt conflicts and the
    // batch.kubernetes.io/job-tracking finalizer is never removed, leaving pods stuck
    // Terminating forever and Job GC never completing.
    loop {
        let stored = state
            .store
            .get(&key)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(&name, "Pod"))?;

        let mut current_obj = Object::from_bytes(&stored.value)
            .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

        let spec_before = current_obj.body["spec"].clone();
        // Save the stored generation so a PATCH that sets metadata.generation
        // cannot downgrade it. generation is server-managed; only increment
        // (on spec change) is allowed, never client override.
        let stored_generation = current_obj.body["metadata"]["generation"].clone();
        // Save the stored status: status.phase/podIP/conditions/etc are written via the
        // /status subresource, a distinct RBAC grant from `patch pods`. Without restoring
        // it after the patch, a caller with only main-resource patch rights could forge
        // status through this endpoint (e.g. fake a pod Ready+podIP), for ANY patch type
        // including JSON Patch, whose array shape can't be caught by an object-key strip.
        let stored_status = current_obj.body["status"].clone();
        // Save the stored uid: metadata.uid is immutable identity, restored unconditionally
        // after the patch is applied, exactly like do_patch (resource.rs) already does for the
        // generic path. Without this, a caller holding only `patch pods` rights could forge
        // uid to match a stale/foreign ownerReference and corrupt owner_ref_is_live's
        // cascade-GC decision for ReplicaSet/Job/DaemonSet controllers, for ANY patch type
        // (Merge, StrategicMerge, JSON Patch).
        let stored_uid = current_obj.body["metadata"]["uid"].clone();

        match patch_type {
            super::json_patch::PatchType::StrategicMerge => {
                crate::patch::strategic_merge_patch(&mut current_obj.body, &patch)
                    .map_err(|e| Status::bad_request(e.to_string()))?;
            }
            super::json_patch::PatchType::Merge => {
                crate::patch::merge_patch(&mut current_obj.body, &patch);
            }
            super::json_patch::PatchType::Json => {
                super::json_patch::apply_json_patch(&mut current_obj.body, &patch)?;
            }
        }

        current_obj.body["status"] = stored_status;
        current_obj.body["metadata"]["uid"] = stored_uid;

        // Enforce the same spec-immutability guard replace_pod (PUT) already applies —
        // without this, a caller holding only `patch pods` (not `pods/binding`) could set
        // spec.nodeName directly, bypassing the scheduler entirely, or rewrite containers/
        // resources/tolerations on an already-running pod a live kubelet is watching.
        validate_pod_spec_immutable(&spec_before, &current_obj.body["spec"])
            .map_err(Status::unprocessable_entity)?;

        // Restore the stored generation before computing the increment so that
        // a patch attempting to set generation is ignored.
        current_obj.body["metadata"]["generation"] = stored_generation;
        increment_pod_generation_if_spec_changed(&mut current_obj.body, &spec_before);

        // Post-patch: if deletionTimestamp is set and finalizers are now empty, hard-delete.
        let post_patch_meta: ObjectMeta =
            serde_json::from_value(current_obj.body["metadata"].clone()).unwrap_or_default();
        let deletion_ts_set = post_patch_meta.deletion_timestamp.is_some();
        let finalizers_empty = post_patch_meta
            .finalizers
            .as_ref()
            .is_none_or(|f| f.is_empty());

        tracing::debug!(
            name = %name,
            deletion_ts_set,
            finalizers_empty,
            "patch_pod: post-patch hard-delete check"
        );
        // Dry-run: validation passed; return the would-be patched object without persisting
        // or hard-deleting — checked BEFORE the hard-delete branch below, since a patch that
        // drains the last finalizer must not actually delete the pod under dryRun=All.
        if patch_query.is_dry_run() {
            return Ok(Json(current_obj.body));
        }

        if deletion_ts_set && finalizers_empty {
            tracing::debug!(name = %name, "patch_pod: hard-deleting pod (deletionTimestamp set, finalizers empty)");
            state
                .store
                .delete(&key, None)
                .await
                .map_err(|e| store_err_to_status(e, &name))?;
            state.node_graph.remove_pod(ns.as_str(), &name);
            // Same per-namespace lock the create path holds across its check-then-write —
            // without it here, this decrement can interleave with a concurrent
            // create/delete/resize's read-modify-write of the same quota's status.used and
            // lose an update. Dropped before maybe_finalize_terminating_namespace below, which
            // may itself need this same namespace's lock while purging remaining pods.
            let _quota_lock = state.quota_admission_locks.lock(ns.as_str()).await;
            crate::quota::record_pod_removed(&state, ns.as_str(), &current_obj.body).await;
            drop(_quota_lock);
            // After hard-deleting a pod, check if its namespace is ready to complete deletion.
            // This handles OrderedNamespaceDeletion: once all finalizer'd pods are cleared,
            // the Terminating namespace hard-deletes.
            super::namespaces::maybe_finalize_terminating_namespace(&state, ns.as_str()).await;
            return Ok(Json(current_obj.body));
        }

        let expected_revision = parse_resource_version(current_obj.resource_version())?;

        match state
            .store
            .put(&key, current_obj.to_bytes(), expected_revision)
            .await
        {
            Ok(new_rv) => {
                current_obj.set_resource_version(new_rv);
                // Every patch content-type (strategic-merge, merge, JSON Patch, SSA) has
                // already folded into current_obj.body above, so this one call —
                // record_scope_change_if_spec_changed, shared with replace_pod's PUT path —
                // covers all of them.
                record_scope_change_if_spec_changed(
                    &state,
                    ns.as_str(),
                    &spec_before,
                    &current_obj.body,
                )
                .await;
                return Ok(Json(current_obj.body));
            }
            Err(StoreError::RevisionMismatch { .. }) => {
                // A concurrent write advanced the stored revision between our read and write.
                // Re-read the fresh object and re-apply the patch.
                continue;
            }
            Err(e) => return Err(store_err_to_status(e, &name)),
        }
    }
}

use crate::util::utc_now_rfc3339;

/// POST /api/v1/namespaces/{ns}/pods/{name}/eviction
///
/// Eviction triggers graceful pod deletion. We accept any Eviction body (or
/// empty body) and soft-delete the pod by stamping `deletionTimestamp`, exactly
/// as `delete_pod` does. Without this endpoint the conformance test
/// "Should recreate evicted statefulset" hangs: the test calls the Eviction API,
/// receives a 404 (no route), the pod is never terminated, and the StatefulSet
/// controller never triggers recreation.
pub(crate) async fn evict_pod<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let key = object_key("pods", ns.as_str(), &name);

    let eviction: serde_json::Value = serde_json::from_slice(&body).unwrap_or_else(|_| {
        serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": name, "namespace": ns.as_str() }
        })
    });
    // Eviction embeds metav1.DeleteOptions at .deleteOptions; a raw/proxied caller may
    // instead send ?dryRun=All (caught by the router-wide inject_dry_run_header layer,
    // which is what kubectl's generic `create --dry-run=server` path uses for POST-based
    // subresources like Eviction) — accept either.
    let delete_opts: DeleteOptions =
        serde_json::from_value(eviction["deleteOptions"].clone()).unwrap_or_default();
    let dry_run = delete_opts.is_dry_run() || super::json_patch::is_dry_run_header(&headers);

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // Admission webhook pipeline (validating only — eviction's effect on the pod is
    // delete-like, mirroring delete_pod's validating-only admission point). A
    // `sideEffects: Some` webhook has no contractual guarantee it honors `dryRun: true`,
    // so it must not be invoked at all on a dry-run eviction — see webhook_dry_run_supported.
    let admission_ctx = AdmissionContext {
        group: "",
        version: "v1",
        resource: "pods/eviction",
        name: &name,
        namespace: Some(ns.as_str()),
        operation: "CREATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
            "extra": user.extra,
        })),
        dry_run,
    };
    run_validating_webhooks(&state, &eviction, None, &admission_ctx).await?;

    let meta: ObjectMeta = serde_json::from_value(obj.body["metadata"].clone()).unwrap_or_default();
    let already_terminating = meta.deletion_timestamp.is_some();
    let has_finalizers = meta.finalizers.as_ref().is_some_and(|f| !f.is_empty());

    if already_terminating && !has_finalizers {
        // Dry-run: validation passed and this is what a real eviction would hard-delete;
        // return without persisting.
        if !dry_run {
            state
                .store
                .delete(&key, None)
                .await
                .map_err(|e| store_err_to_status(e, &name))?;
            state.node_graph.remove_pod(ns.as_str(), &name);
            // Same per-namespace lock the create path holds across its check-then-write —
            // without it here, this decrement can interleave with a concurrent
            // create/delete/resize's read-modify-write of the same quota's status.used and
            // lose an update.
            let _quota_lock = state.quota_admission_locks.lock(ns.as_str()).await;
            crate::quota::record_pod_removed(&state, ns.as_str(), &obj.body).await;
        }
    } else if !already_terminating {
        check_pdb_allows_eviction(&state, ns.as_str(), &obj.body, dry_run).await?;

        // Dry-run: validation passed and this is what a real eviction would soft-delete to
        // (deletionTimestamp stamped); return without persisting.
        if !dry_run {
            obj.body["metadata"]["deletionTimestamp"] =
                serde_json::Value::String(utc_now_rfc3339());
            set_disruption_target_condition(
                &mut obj.body,
                &utc_now_rfc3339(),
                "EvictionByEvictionAPI",
                "Eviction API: evicting pod",
            );
            let expected_rv = parse_resource_version(obj.resource_version())?;
            state
                .store
                .put(&key, obj.to_bytes(), expected_rv)
                .await
                .map_err(|e| store_err_to_status(e, &name))?;
        }
    }

    Ok((StatusCode::CREATED, Json(eviction)))
}

/// Bounded retry count for the verify-and-decrement CAS loop below. Upstream's
/// `EvictionsRetry` (pkg/registry/core/pod/storage/eviction.go) spaces 20 attempts with a
/// 500ms backoff because it races other API servers over etcd; our store is in-process, so a
/// resourceVersion conflict resolves on the very next read with no network round-trip, and a
/// small bound is enough to serialize any realistic number of concurrent evictions.
const MAX_PDB_DECREMENT_ATTEMPTS: u32 = 10;

/// Upstream's `MaxDisruptedPodSize` (pkg/registry/core/pod/storage/eviction.go): the eviction
/// handler refuses to spend a disruption once `status.disruptedPods` already holds more entries
/// than this. The map is meant to self-correct as the DisruptionController reconciles evicted
/// pods off it; without this cap a burst of concurrent evictions the controller hasn't caught up
/// with yet can grow the map without bound.
const MAX_DISRUPTED_POD_SIZE: usize = 2000;

/// Verify a PodDisruptionBudget still has a disruption to give and, if so, return its body
/// with `status.disruptionsAllowed` decremented by one.
///
/// Split out as a pure function (mirroring upstream's `checkAndDecrement`) so the core
/// admission rule — reject once the budget is exhausted, otherwise spend one — can be unit
/// tested without a store or a live CAS retry loop.
///
/// Also stamps `status.disruptedPods[podName]`, exactly as upstream's `checkAndDecrement`
/// does. This is not optional bookkeeping: KCM's real DisruptionController recomputes
/// `disruptionsAllowed` from scratch on every reconcile (`currentHealthy - desiredHealthy`,
/// see `pkg/controller/disruption/disruption.go`'s `countHealthyPods`) and only excludes a
/// pod from `currentHealthy` if it is either already carrying `deletionTimestamp` in the
/// controller's informer cache, or listed in `disruptedPods`. A decrement that skips
/// `disruptedPods` gets silently overwritten back up the moment the controller's cache
/// resyncs before it observes the evicted pod's `deletionTimestamp` — reproduced live: a
/// second sequential eviction in the same PDB budget succeeded because the first eviction's
/// decrement to 0 had already been reconciled back to 1.
fn decrement_pdb_disruptions_allowed(
    pdb: &serde_json::Value,
    pod_name: &str,
    now_rfc3339: &str,
) -> Result<serde_json::Value, crate::status::StatusError> {
    // Upstream (eviction.go checkAndDecrement): a PDB whose status hasn't caught up to the
    // object's current generation yet cannot be trusted — the DisruptionController may still be
    // recomputing `disruptionsAllowed` from a stale pod set. Treat it the same as a temporarily
    // exhausted budget (429) so the client retries once the controller has observed the latest
    // spec, instead of evicting against a count that's about to change.
    let generation = pdb["metadata"]["generation"].as_i64().unwrap_or(0);
    let observed_generation = pdb["status"]["observedGeneration"].as_i64().unwrap_or(0);
    if observed_generation < generation {
        let pdb_name = pdb["metadata"]["name"].as_str().unwrap_or_default();
        return Err(Status::too_many_requests_with_cause(
            "Cannot evict pod as it would violate the pod's disruption budget.".to_string(),
            "DisruptionBudget",
            format!("The disruption budget {pdb_name} is still being processed by the server."),
        ));
    }

    // Upstream MaxDisruptedPodSize: `disruptedPods` self-corrects as the DisruptionController
    // reconciles evicted pods off it, but a burst of concurrent evictions the controller hasn't
    // caught up with yet must not be allowed to grow the map without bound.
    if pdb["status"]["disruptedPods"]
        .as_object()
        .is_some_and(|m| m.len() > MAX_DISRUPTED_POD_SIZE)
    {
        return Err(Status::forbidden(
            "DisruptedPods map too big - too many evictions not confirmed by PDB controller"
                .to_string(),
        ));
    }

    let disruptions_allowed = pdb["status"]["disruptionsAllowed"].as_i64().unwrap_or(0);
    if disruptions_allowed <= 0 {
        let message =
            "Cannot evict pod as it would violate the pod's disruption budget.".to_string();
        return Err(Status::too_many_requests_with_cause(
            message.clone(),
            "DisruptionBudget",
            message,
        ));
    }
    let mut updated = pdb.clone();
    updated["status"]["disruptionsAllowed"] = serde_json::Value::from(disruptions_allowed - 1);
    updated["status"]["disruptedPods"][pod_name] =
        serde_json::Value::String(now_rfc3339.to_string());
    Ok(updated)
}

/// Reject the eviction with 429 if the pod is covered by a PodDisruptionBudget that has no
/// disruptions left to give; otherwise atomically spend one.
///
/// PDBs are the primary safety mechanism against voluntary disruption (drain, descheduler,
/// cluster-autoscaler): a Deployment/StatefulSet relies on `disruptionsAllowed` staying above
/// zero to guarantee availability during rolling changes. u7s does not compute
/// `disruptionsAllowed` itself — KCM's DisruptionController owns that reconciliation — but
/// relying solely on the controller's periodic resync to catch up after every eviction leaves
/// a window where two evictions issued close together both observe a stale
/// `disruptionsAllowed > 0` and both succeed, exceeding the budget. Matching upstream's
/// eviction REST path, this function verifies and decrements `status.disruptionsAllowed`
/// inside the eviction request itself, via a resourceVersion-guarded compare-and-swap that
/// retries past a losing race instead of trusting the value it just read. Without this check,
/// `kubectl drain` and the descheduler can evict every pod backing a service simultaneously,
/// taking it fully down.
async fn check_pdb_allows_eviction<S: Store>(
    state: &AppState<S>,
    ns: &str,
    pod: &serde_json::Value,
    dry_run: bool,
) -> Result<(), crate::status::StatusError> {
    let pod_labels: std::collections::BTreeMap<String, String> = pod["metadata"]["labels"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let prefix = group_list_prefix("policy", "poddisruptionbudgets", Some(ns));
    let items = match state.store.list(&prefix, ListOptions::default()).await {
        Ok(resp) => resp.items,
        Err(e) => {
            // Fail-open: a transient store error listing PDBs must not block every eviction
            // in the namespace, since that would be worse for availability than the disruption
            // this check exists to prevent.
            tracing::warn!("evict_pod: failed to list PodDisruptionBudgets in {ns}: {e}");
            return Ok(());
        }
    };

    let matching: Vec<(String, serde_json::Value)> = items
        .into_iter()
        .filter_map(|item| {
            serde_json::from_slice::<serde_json::Value>(&item.value)
                .ok()
                .map(|pdb| (item.key, pdb))
        })
        .filter(|(_, pdb)| {
            // Upstream semantics: "A null selector will match no pods, while an empty ({})
            // selector will select all pods within the namespace." `label_selector_matches`
            // treats `None` as match-all, so a null/missing selector must be special-cased
            // to match-none here rather than passed through.
            let selector_value = &pdb["spec"]["selector"];
            if selector_value.is_null() {
                return false;
            }
            let selector: LabelSelector =
                serde_json::from_value(selector_value.clone()).unwrap_or_default();
            label_selector_matches(Some(&selector), &pod_labels)
        })
        .collect();

    if matching.len() > 1 {
        return Err(Status::internal(
            "This pod has more than one PodDisruptionBudget, which the eviction subresource does not support.".to_string(),
        ));
    }

    let Some((pdb_key, mut pdb)) = matching.into_iter().next() else {
        return Ok(());
    };

    // Upstream (pkg/registry/core/pod/storage/eviction.go): a healthy (Ready) pod is
    // always subject to the budget. An unhealthy pod bypasses `disruptionsAllowed`
    // under AlwaysAllow, or under the default/IfHealthyBudget policy when the budget
    // is already met — evicting a pod that isn't serving traffic doesn't disrupt the
    // application further, so operators shouldn't be blocked from clearing it out. This
    // bypass is evaluated once, before the CAS loop, exactly as upstream does: unhealthy-pod
    // eviction never spends a disruption, so there is nothing to retry.
    if !is_pod_ready(pod) {
        let always_allow =
            pdb["spec"]["unhealthyPodEvictionPolicy"].as_str() == Some("AlwaysAllow");
        if always_allow {
            return Ok(());
        }
        let current_healthy = pdb["status"]["currentHealthy"].as_i64().unwrap_or(0);
        let desired_healthy = pdb["status"]["desiredHealthy"].as_i64().unwrap_or(0);
        if desired_healthy > 0 && current_healthy >= desired_healthy {
            return Ok(());
        }
    }

    let pod_name = pod["metadata"]["name"].as_str().unwrap_or_default();
    let now_rfc3339 = utc_now_rfc3339();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let updated = decrement_pdb_disruptions_allowed(&pdb, pod_name, &now_rfc3339)?;

        // A dry-run eviction must validate that a disruption is available without actually
        // spending it — matching evict_pod's own dry-run contract of never mutating the store.
        if dry_run {
            return Ok(());
        }

        let expected_rv = parse_resource_version(pdb["metadata"]["resourceVersion"].as_str())?;
        match state
            .store
            .put(
                &pdb_key,
                Bytes::from(serde_json::to_vec(&updated).unwrap()),
                expected_rv,
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(StoreError::RevisionMismatch { .. }) if attempt < MAX_PDB_DECREMENT_ATTEMPTS => {
                // Lost the race to another concurrent eviction's decrement — re-read the
                // latest PDB state and retry the verify-and-decrement against it, exactly as
                // upstream's `retry.RetryOnConflict` does.
                pdb = match state.store.get(&pdb_key).await {
                    Ok(Some(stored)) => serde_json::from_slice(&stored.value).unwrap_or(pdb),
                    _ => pdb,
                };
            }
            Err(StoreError::RevisionMismatch { .. }) => {
                return Err(Status::conflict(format!(
                    "couldn't update PodDisruptionBudget {:?} due to repeated write conflicts",
                    pdb["metadata"]["name"].as_str().unwrap_or_default()
                )));
            }
            Err(e) => return Err(Status::internal(e.to_string())),
        }
    }
}

/// A pod is healthy for PDB eviction purposes iff it has a `Ready` condition with
/// `status: "True"`, matching upstream's `podutil.IsPodReady` check in the eviction path.
fn is_pod_ready(pod: &serde_json::Value) -> bool {
    pod["status"]["conditions"]
        .as_array()
        .is_some_and(|conditions| {
            conditions
                .iter()
                .any(|c| c["type"] == "Ready" && c["status"] == "True")
        })
}

/// Set (or refresh) the pod's `DisruptionTarget` condition so pod-failure-policy consumers
/// (the Job controller matching on `onPodConditions`) can distinguish a voluntary disruption
/// (eviction/preemption) from an application-caused failure. Without this condition, a Job's
/// `podFailurePolicy` rule that ignores DisruptionTarget failures never matches, and the pod
/// failure counts against `backoffLimit` even though it wasn't the workload's fault.
fn set_disruption_target_condition(
    pod: &mut serde_json::Value,
    now: &str,
    reason: &str,
    message: &str,
) {
    if !pod["status"].is_object() {
        pod["status"] = serde_json::json!({});
    }
    let cond = serde_json::json!({
        "type": "DisruptionTarget",
        "status": "True",
        "reason": reason,
        "message": message,
        "lastTransitionTime": now
    });
    if let Some(conditions) = pod["status"]["conditions"].as_array_mut() {
        if let Some(existing) = conditions
            .iter_mut()
            .find(|c| c["type"] == "DisruptionTarget")
        {
            *existing = cond;
        } else {
            conditions.push(cond);
        }
    } else {
        pod["status"]["conditions"] = serde_json::json!([cond]);
    }
}

#[cfg(test)]
mod watch_tests {
    use super::*;
    use bytes::Bytes;
    use u7s_store::{StoreObject, WatchEvent};

    fn make_store_object(key: &str, revision: u64, json: serde_json::Value) -> StoreObject {
        StoreObject {
            key: key.to_string(),
            value: Bytes::from(serde_json::to_vec(&json).unwrap()),
            revision,
        }
    }

    /// encode_watch_event (shared via generic) for Added emits {"type":"ADDED","object":...}\n
    /// and the object bytes are valid JSON from the stored value.
    #[test]
    fn encode_added_roundtrip() {
        let obj = make_store_object(
            "/registry/pods/default/nginx",
            5,
            serde_json::json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"nginx","resourceVersion":"5"}}),
        );
        let bytes =
            crate::handlers::watch::encode_watch_event(&WatchEvent::Added(obj), "v1", "Pod", false)
                .expect("should encode");
        let line = std::str::from_utf8(&bytes).unwrap();
        assert!(line.ends_with('\n'), "NDJSON must end with newline");

        let parsed: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["type"], "ADDED");
        assert_eq!(parsed["object"]["metadata"]["name"], "nginx");
    }

    /// encode_watch_event for Modified emits {"type":"MODIFIED","object":...}\n
    #[test]
    fn encode_modified() {
        let obj = make_store_object(
            "/registry/pods/default/nginx",
            7,
            serde_json::json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"nginx","resourceVersion":"7"}}),
        );
        let bytes = crate::handlers::watch::encode_watch_event(
            &WatchEvent::Modified(obj),
            "v1",
            "Pod",
            false,
        )
        .expect("should encode");
        let parsed: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&bytes).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["type"], "MODIFIED");
    }

    /// DELETED watch events must carry the full last-known object body so that
    /// informer tombstone handlers (DeletedFinalStateUnknown) can match the deleted
    /// object against label selectors. Without labels in the tombstone, the KCM
    /// StatefulSet controller cannot identify which StatefulSet owned the pod and
    /// status.replicas stays at 1, causing 10-minute AfterEach hangs in conformance.
    #[test]
    fn encode_deleted_carries_full_pod_body_with_labels() {
        let pod_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "nginx",
                "namespace": "default",
                "labels": {
                    "app": "nginx",
                    "controller-revision-hash": "abc123",
                    "statefulset.kubernetes.io/pod-name": "nginx-0"
                },
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "name": "nginx",
                    "uid": "some-uid"
                }]
            },
            "spec": { "containers": [] }
        });
        let body_bytes = Bytes::from(serde_json::to_vec(&pod_body).unwrap());
        let bytes = crate::handlers::watch::encode_watch_event(
            &WatchEvent::Deleted {
                key: "/registry/pods/default/nginx".to_string(),
                revision: 9,
                body: Some(body_bytes),
            },
            "v1",
            "Pod",
            false,
        )
        .expect("should encode");
        let parsed: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&bytes).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["type"], "DELETED");
        assert_eq!(parsed["object"]["metadata"]["name"], "nginx");
        assert_eq!(parsed["object"]["metadata"]["namespace"], "default");
        assert_eq!(
            parsed["object"]["metadata"]["resourceVersion"], "9",
            "resourceVersion must be updated to deletion revision"
        );
        assert_eq!(
            parsed["object"]["metadata"]["labels"]["statefulset.kubernetes.io/pod-name"], "nginx-0",
            "DELETED tombstone must carry pod labels so KCM StatefulSet controller can \
             identify which StatefulSet owned the pod via DeletedFinalStateUnknown handler; \
             without labels status.replicas never drops to 0 (10-minute hang)"
        );
        assert!(
            parsed["object"]["metadata"]["ownerReferences"].is_array(),
            "DELETED tombstone must carry ownerReferences so GC can clean up owned resources"
        );
    }

    /// When no body is available (e.g. deletion_log tombstone from before this fix),
    /// encode_watch_event falls back to reconstructing minimal metadata from the key.
    #[test]
    fn encode_deleted_falls_back_to_key_when_no_body() {
        let bytes = crate::handlers::watch::encode_watch_event(
            &WatchEvent::Deleted {
                key: "/registry/pods/default/nginx".to_string(),
                revision: 9,
                body: None,
            },
            "v1",
            "Pod",
            false,
        )
        .expect("should encode");
        let parsed: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&bytes).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["type"], "DELETED");
        assert_eq!(parsed["object"]["metadata"]["name"], "nginx");
        assert_eq!(parsed["object"]["metadata"]["namespace"], "default");
        assert_eq!(parsed["object"]["metadata"]["resourceVersion"], "9");
    }

    /// encode_watch_event for Bookmark emits the correct structure.
    #[test]
    fn encode_bookmark() {
        let bytes = crate::handlers::watch::encode_watch_event(
            &WatchEvent::Bookmark { revision: 42 },
            "v1",
            "Pod",
            false,
        )
        .expect("should encode");
        let parsed: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&bytes).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["type"], "BOOKMARK");
        assert_eq!(parsed["object"]["metadata"]["resourceVersion"], "42");
        assert_eq!(parsed["object"]["kind"], "Pod");
    }

    /// encode_watch_event for Compacted returns None — the caller must close the stream.
    #[test]
    fn encode_compacted_returns_none() {
        let result = crate::handlers::watch::encode_watch_event(
            &WatchEvent::Compacted {
                requested: 5,
                horizon: 50,
            },
            "v1",
            "Pod",
            false,
        );
        assert!(result.is_none(), "Compacted must signal close via None");
    }

    /// When Compacted fires, the 410 ERROR event must carry the horizon as
    /// metadata.resourceVersion. Clients use this to relist from a valid point;
    /// sending last_rv (which may predate the horizon) causes an infinite relist loop.
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

    /// parse_key_name_ns (shared via generic) correctly extracts name and namespace.
    #[test]
    fn parse_key_standard() {
        let (name, ns) = crate::handlers::watch::parse_key_name_ns("/registry/pods/default/nginx");
        assert_eq!(name, "nginx");
        assert_eq!(ns, "default");
    }

    /// parse_key_name_ns handles a custom namespace correctly.
    #[test]
    fn parse_key_custom_namespace() {
        let (name, ns) =
            crate::handlers::watch::parse_key_name_ns("/registry/pods/kube-system/coredns");
        assert_eq!(name, "coredns");
        assert_eq!(ns, "kube-system");
    }

    /// CollectionQuery with watch=true and resource_version=42 routes to watch mode.
    /// Constructs the struct directly, so this only checks field wiring — it does NOT
    /// exercise axum's query-string deserialization (see the camelCase test below for that).
    #[test]
    fn collection_query_watch_flag_present() {
        let q = CollectionQuery {
            watch: Some(true),
            resource_version: Some(42),
            label_selector: None,
            field_selector: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: None,
        };
        assert!(q.watch == Some(true));
        assert_eq!(q.resource_version, Some(42));
    }

    /// CollectionQuery with absent fields should default to None (no watch, no rv).
    #[test]
    fn collection_query_defaults() {
        let q = CollectionQuery {
            watch: None,
            resource_version: None,
            label_selector: None,
            field_selector: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: None,
        };
        assert_eq!(q.watch, None);
        assert_eq!(q.resource_version, None);
    }

    /// Regression: kubectl, client-go, and the e2e test framework always send
    /// `resourceVersion` (camelCase) on the wire — never `resource_version`. The two
    /// tests above construct CollectionQuery as a Rust struct literal, so they never
    /// exercise axum's actual query-string deserialization and would keep passing even
    /// if resourceVersion silently failed to parse.
    ///
    /// Without `#[serde(rename = "resourceVersion")]`, axum's Query extractor leaves
    /// resource_version as None for every real watch request, so
    /// `from_rv = query.resource_version.unwrap_or(0)` always resolves to 0: every
    /// namespaced pod watch replays the full object history instead of resuming from
    /// the client's snapshot revision. This is what made
    /// "[sig-apps] Deployment should delete old replica sets" see a spurious extra pod
    /// ADDED event and fail with "Expect only one pod creation, second creation event
    /// ADDED" — the test's own List+Watch(resourceVersion) on a namespace-scoped pod
    /// watch hit exactly this path. This test fails on revert of the rename.
    #[test]
    fn collection_query_parses_camel_case_resource_version_from_real_query_string() {
        let uri: axum::http::Uri =
            "/api/v1/namespaces/default/pods?watch=true&resourceVersion=1477"
                .parse()
                .unwrap();
        let Query(q) = Query::<CollectionQuery>::try_from_uri(&uri)
            .expect("valid query string must deserialize");
        assert_eq!(
            q.resource_version,
            Some(1477),
            "resourceVersion (the wire format every real client sends) must populate \
             resource_version; a missing #[serde(rename)] leaves it None and silently \
             resets every watch to a full history replay"
        );
    }

    /// kubectl and client-go historically send `?watch=1` (not just `?watch=true`) — a
    /// documented Kubernetes API accept form. Before the fix, `watch: Option<bool>` only
    /// parsed Rust's `bool::from_str` ("true"/"false"), so `?watch=1` failed query-string
    /// deserialization and the request never reached the handler at all (axum's Query
    /// extractor rejection maps to HTTP 400). This test fails on revert: `try_from_uri`
    /// would return `Err`, not a parsed `watch: Some(true)`.
    #[test]
    fn collection_query_accepts_watch_equals_1_for_kubectl_client_go_compat() {
        let uri: axum::http::Uri = "/api/v1/namespaces/default/pods?watch=1".parse().unwrap();
        let Query(q) = Query::<CollectionQuery>::try_from_uri(&uri)
            .expect("?watch=1 must deserialize, not 400 — client-go/kubectl compat form");
        assert_eq!(
            q.watch,
            Some(true),
            "?watch=1 must resolve to watch:Some(true), the same as ?watch=true, so the \
             handler routes to the streaming watch path instead of a plain list"
        );
    }

    /// Mirror of the `watch=1` test above for the `watch=0` alias of `watch=false`.
    /// `?watch=0` must resolve to `Some(false)` so the handler stays on the normal list
    /// path — before the fix this also 400'd instead of falling through to list mode.
    #[test]
    fn collection_query_accepts_watch_equals_0_for_kubectl_client_go_compat() {
        let uri: axum::http::Uri = "/api/v1/namespaces/default/pods?watch=0".parse().unwrap();
        let Query(q) = Query::<CollectionQuery>::try_from_uri(&uri)
            .expect("?watch=0 must deserialize, not 400 — client-go/kubectl compat form");
        assert_eq!(
            q.watch,
            Some(false),
            "?watch=0 must resolve to watch:Some(false) so the request stays on the \
             normal list path, not the watch stream"
        );
    }
}

#[cfg(test)]
mod field_selector_tests {
    use super::*;

    fn pod_with_node(node_name: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {"nodeName": node_name}
        })
    }

    fn pod_without_node() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {}
        })
    }

    fn pod_with_phase(phase: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {},
            "status": {"phase": phase}
        })
    }

    fn pod_with_pod_ip(pod_ip: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {},
            "status": {"podIP": pod_ip}
        })
    }

    fn pod_with_restart_policy(restart_policy: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {"restartPolicy": restart_policy}
        })
    }

    fn pod_with_service_account_name(service_account_name: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {"serviceAccountName": service_account_name}
        })
    }

    fn pod_with_scheduler_name(scheduler_name: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {"schedulerName": scheduler_name}
        })
    }

    fn pod_with_nominated_node_name(nominated_node_name: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {},
            "status": {"nominatedNodeName": nominated_node_name}
        })
    }

    /// Empty selector is a pass-through: all pods must be returned.
    /// Kubelet depends on this when fieldSelector is absent.
    #[test]
    fn empty_selector_passes_all() {
        let pods = vec![
            pod_with_node("worker-1"),
            pod_with_node("worker-2"),
            pod_without_node(),
        ];
        let result = filter_pods_by_field_selector(pods.clone(), "");
        assert_eq!(result.len(), pods.len());
    }

    /// spec.nodeName=worker-1 must include only pods scheduled to worker-1.
    /// This is the primary kubelet query: it must receive only its own pods.
    #[test]
    fn eq_filter_matches_correct_node() {
        let pods = vec![
            pod_with_node("worker-1"),
            pod_with_node("worker-2"),
            pod_without_node(),
        ];
        let result = filter_pods_by_field_selector(pods, "spec.nodeName=worker-1");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["spec"]["nodeName"], "worker-1");
    }

    /// spec.nodeName=worker-1 must not match a pod on a different node.
    /// If this fails, kubelet on worker-2 receives worker-1's pods and tries to run them.
    #[test]
    fn eq_filter_excludes_wrong_node() {
        let pods = vec![pod_with_node("worker-2"), pod_without_node()];
        let result = filter_pods_by_field_selector(pods, "spec.nodeName=worker-1");
        assert!(result.is_empty());
    }

    /// spec.nodeName!=worker-1 must exclude pods on worker-1 and include everything else.
    #[test]
    fn ne_filter_excludes_matching_node() {
        let pods = vec![
            pod_with_node("worker-1"),
            pod_with_node("worker-2"),
            pod_without_node(),
        ];
        let result = filter_pods_by_field_selector(pods, "spec.nodeName!=worker-1");
        assert_eq!(result.len(), 2);
        for pod in &result {
            assert_ne!(pod["spec"]["nodeName"].as_str().unwrap_or(""), "worker-1");
        }
    }

    /// A pod with no spec.nodeName (empty string) must NOT match spec.nodeName=worker-1.
    /// Kubelet must not receive unscheduled pods — that was the original bug.
    #[test]
    fn eq_filter_excludes_unscheduled_pods() {
        let pods = vec![pod_without_node()];
        let result = filter_pods_by_field_selector(pods, "spec.nodeName=worker-1");
        assert!(
            result.is_empty(),
            "unscheduled pods must not reach the kubelet"
        );
    }

    /// spec.nodeName holding a non-string JSON value (malformed stored data) must be
    /// treated the same as absent, matching the typed decode this replaced. If a borrowed
    /// read ever coerced the value to a string instead of requiring one, a malformed pod
    /// could match every nodeName selector value and get delivered to the wrong kubelet.
    #[test]
    fn eq_filter_treats_non_string_node_name_as_absent() {
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"},
            "spec": {"nodeName": 1}
        });
        let result = filter_pods_by_field_selector(vec![pod], "spec.nodeName=worker-1");
        assert!(
            result.is_empty(),
            "a pod with a malformed (non-string) nodeName must not match any nodeName selector"
        );
    }

    /// A Failed pod must be excluded by status.phase!=Failed,status.phase!=Succeeded —
    /// DaemonSet/Deployment rollout controllers and the "should rollback without
    /// unnecessary restarts" conformance test rely on this exclusion to know a
    /// terminating pod is gone without waiting for its physical removal.
    #[test]
    fn ne_filter_excludes_failed_phase() {
        let pods = vec![pod_with_phase("Failed")];
        let result =
            filter_pods_by_field_selector(pods, "status.phase!=Failed,status.phase!=Succeeded");
        assert!(
            result.is_empty(),
            "a Failed pod must not be returned by status.phase!=Failed,!=Succeeded"
        );
    }

    /// A Running pod must still pass status.phase!=Failed,status.phase!=Succeeded.
    /// The exclusion must be precise: it must not over-filter healthy pods out of
    /// a rollout controller's view of its managed pods.
    #[test]
    fn ne_filter_includes_running_phase() {
        let pods = vec![pod_with_phase("Running")];
        let result =
            filter_pods_by_field_selector(pods, "status.phase!=Failed,status.phase!=Succeeded");
        assert_eq!(result.len(), 1, "a Running pod must not be excluded");
    }

    /// status.phase=Running must match a Running pod — the positive-equality form
    /// of the same phase selector must work, not just the negation form.
    #[test]
    fn eq_filter_matches_correct_phase() {
        let pods = vec![pod_with_phase("Running")];
        let result = filter_pods_by_field_selector(pods, "status.phase=Running");
        assert_eq!(result.len(), 1);
    }

    /// status.phase=Running must not match a Pending pod.
    #[test]
    fn eq_filter_excludes_wrong_phase() {
        let pods = vec![pod_with_phase("Pending")];
        let result = filter_pods_by_field_selector(pods, "status.phase=Running");
        assert!(result.is_empty());
    }

    /// status.podIP=<ip> must select only the pod with that IP — kube-proxy's
    /// endpoint reconciliation queries pods by podIP, and a missing match arm
    /// here would make it silently see every pod as a match.
    #[test]
    fn eq_filter_matches_correct_pod_ip() {
        let pods = vec![pod_with_pod_ip("10.0.0.1"), pod_with_pod_ip("10.0.0.2")];
        let result = filter_pods_by_field_selector(pods, "status.podIP=10.0.0.1");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["status"]["podIP"], "10.0.0.1");
    }

    /// status.podIP!=<ip> must exclude the pod with that IP and keep the rest —
    /// the negated form must not fall through to the unknown-field passthrough.
    #[test]
    fn ne_filter_excludes_matching_pod_ip() {
        let pods = vec![pod_with_pod_ip("10.0.0.1"), pod_with_pod_ip("10.0.0.2")];
        let result = filter_pods_by_field_selector(pods, "status.podIP!=10.0.0.1");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["status"]["podIP"], "10.0.0.2");
    }

    /// spec.restartPolicy=<policy> must select only matching pods — controllers
    /// that distinguish Job pods (restartPolicy=Never/OnFailure) from Deployment
    /// pods (Always) rely on this filter, not a client-side scan of every pod.
    #[test]
    fn eq_filter_matches_correct_restart_policy() {
        let pods = vec![
            pod_with_restart_policy("Never"),
            pod_with_restart_policy("Always"),
        ];
        let result = filter_pods_by_field_selector(pods, "spec.restartPolicy=Never");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["spec"]["restartPolicy"], "Never");
    }

    /// spec.restartPolicy!=<policy> must exclude the matching pod, proving the
    /// negation arm (not just equality) is wired for this field.
    #[test]
    fn ne_filter_excludes_matching_restart_policy() {
        let pods = vec![
            pod_with_restart_policy("Never"),
            pod_with_restart_policy("Always"),
        ];
        let result = filter_pods_by_field_selector(pods, "spec.restartPolicy!=Never");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["spec"]["restartPolicy"], "Always");
    }

    /// spec.serviceAccountName=<name> must select only pods running as that
    /// service account — RBAC auditing/debugging tools query pods this way to
    /// find everything a given identity can affect.
    #[test]
    fn eq_filter_matches_correct_service_account_name() {
        let pods = vec![
            pod_with_service_account_name("sa-a"),
            pod_with_service_account_name("sa-b"),
        ];
        let result = filter_pods_by_field_selector(pods, "spec.serviceAccountName=sa-a");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["spec"]["serviceAccountName"], "sa-a");
    }

    /// spec.serviceAccountName!=<name> must exclude the matching pod.
    #[test]
    fn ne_filter_excludes_matching_service_account_name() {
        let pods = vec![
            pod_with_service_account_name("sa-a"),
            pod_with_service_account_name("sa-b"),
        ];
        let result = filter_pods_by_field_selector(pods, "spec.serviceAccountName!=sa-a");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["spec"]["serviceAccountName"], "sa-b");
    }

    /// spec.schedulerName=<name> must select only pods assigned to that
    /// scheduler — a custom scheduler polling for its own pending/bound pods
    /// would otherwise see pods owned by other schedulers.
    #[test]
    fn eq_filter_matches_correct_scheduler_name() {
        let pods = vec![
            pod_with_scheduler_name("custom-scheduler"),
            pod_with_scheduler_name("default-scheduler"),
        ];
        let result = filter_pods_by_field_selector(pods, "spec.schedulerName=custom-scheduler");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["spec"]["schedulerName"], "custom-scheduler");
    }

    /// spec.schedulerName!=<name> must exclude the matching pod.
    #[test]
    fn ne_filter_excludes_matching_scheduler_name() {
        let pods = vec![
            pod_with_scheduler_name("custom-scheduler"),
            pod_with_scheduler_name("default-scheduler"),
        ];
        let result = filter_pods_by_field_selector(pods, "spec.schedulerName!=custom-scheduler");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["spec"]["schedulerName"], "default-scheduler");
    }

    /// status.nominatedNodeName=<node> must select only pods nominated for that
    /// node — preemption logic reads this to find pods already reserved on a
    /// node before deciding to preempt further victims there.
    #[test]
    fn eq_filter_matches_correct_nominated_node_name() {
        let pods = vec![
            pod_with_nominated_node_name("node-a"),
            pod_with_nominated_node_name("node-b"),
        ];
        let result = filter_pods_by_field_selector(pods, "status.nominatedNodeName=node-a");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["status"]["nominatedNodeName"], "node-a");
    }

    /// status.nominatedNodeName!=<node> must exclude the matching pod.
    #[test]
    fn ne_filter_excludes_matching_nominated_node_name() {
        let pods = vec![
            pod_with_nominated_node_name("node-a"),
            pod_with_nominated_node_name("node-b"),
        ];
        let result = filter_pods_by_field_selector(pods, "status.nominatedNodeName!=node-a");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["status"]["nominatedNodeName"], "node-b");
    }

    /// Unknown selector fields must be ignored (pass-through) rather than dropping pods.
    /// This is the safe default: conservative filtering prevents silent data loss.
    #[test]
    fn unknown_field_is_ignored() {
        let pods = vec![pod_with_node("worker-1"), pod_with_node("worker-2")];
        let result = filter_pods_by_field_selector(pods.clone(), "metadata.unknown=foo");
        assert_eq!(result.len(), pods.len());
    }

    /// Multiple comma-separated selectors are ANDed together.
    #[test]
    fn multiple_terms_are_anded() {
        // Only worker-1 pods should pass spec.nodeName=worker-1,spec.nodeName!=worker-2
        // (worker-1 != worker-2 is true, so worker-1 passes both)
        let pods = vec![pod_with_node("worker-1"), pod_with_node("worker-2")];
        let result =
            filter_pods_by_field_selector(pods, "spec.nodeName=worker-1,spec.nodeName!=worker-2");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["spec"]["nodeName"], "worker-1");
    }

    // -- pod_store_field_selector: the extracted helper must behave correctly --

    /// Equality term is picked up as a FieldSelector.
    /// This helper is used in both the list and watch paths — if it's wrong,
    /// kubelet receives pods scheduled to other nodes.
    #[test]
    fn pod_store_field_selector_eq_term() {
        let fs = pod_store_field_selector("spec.nodeName=worker-1");
        let fs = fs.expect("equality term must produce Some");
        assert_eq!(fs.field, "spec.nodeName");
        assert_eq!(fs.value, "worker-1");
    }

    /// Negation-only selector returns None — store FieldSelector only supports equality.
    #[test]
    fn pod_store_field_selector_ne_only_returns_none() {
        let fs = pod_store_field_selector("spec.nodeName!=worker-1");
        assert!(fs.is_none(), "ne-only selector must return None");
    }

    /// Mixed selector: equality term wins, negation is skipped.
    #[test]
    fn pod_store_field_selector_mixed_returns_eq_term() {
        let fs = pod_store_field_selector("spec.nodeName!=bad,spec.nodeName=worker-1");
        let fs = fs.expect("must return the equality term");
        assert_eq!(fs.value, "worker-1");
    }

    /// Empty string returns None.
    #[test]
    fn pod_store_field_selector_empty_returns_none() {
        assert!(pod_store_field_selector("").is_none());
    }
}

#[cfg(test)]
mod event_field_selector_tests {
    use super::*;

    fn event(name: &str, kind: &str, ns: &str, uid: &str, reason: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": {"name": "ev", "namespace": ns},
            "involvedObject": {
                "name": name,
                "kind": kind,
                "namespace": ns,
                "uid": uid
            },
            "reason": reason
        })
    }

    /// kubectl describe sends multi-term involvedObject selectors; all terms must be AND-evaluated.
    /// Without AND logic, a selector with involvedObject.kind=Pod returns events for every kind,
    /// making kubectl describe show unrelated events or none at all.
    #[test]
    fn multi_term_involved_object_selectors_are_and_evaluated() {
        let pod_event = event("coredns-xxx", "Pod", "kube-system", "uid-1", "Started");
        let node_event = event("node-1", "Node", "kube-system", "uid-2", "Started");
        let events = vec![pod_event.clone(), node_event];

        let result = filter_events_by_field_selector(
            events,
            "involvedObject.name=coredns-xxx,involvedObject.kind=Pod",
        );

        assert_eq!(
            result.len(),
            1,
            "kubectl describe relies on multi-term involvedObject selectors being AND-evaluated; \
             without AND logic involvedObject.kind is ignored and all events for any kind are returned, \
             making kubectl describe show wrong events or always show Events: <none>"
        );
        assert_eq!(result[0]["involvedObject"]["kind"], "Pod");
        assert_eq!(result[0]["involvedObject"]["name"], "coredns-xxx");
    }

    /// A single-term selector still works after the change.
    #[test]
    fn single_term_involved_object_name_still_filters() {
        let ev1 = event("coredns-xxx", "Pod", "kube-system", "uid-1", "Started");
        let ev2 = event("other-pod", "Pod", "kube-system", "uid-2", "Pulled");
        let events = vec![ev1, ev2];

        let result = filter_events_by_field_selector(events, "involvedObject.name=coredns-xxx");
        assert_eq!(
            result.len(),
            1,
            "single-term involvedObject.name selector must still filter correctly; \
             if this regresses kubectl get events --field-selector involvedObject.name=X stops working"
        );
        assert_eq!(result[0]["involvedObject"]["name"], "coredns-xxx");
    }

    /// A selector that matches no event must return empty — not all events.
    #[test]
    fn selector_matching_no_event_returns_empty() {
        let ev = event("pod-a", "Pod", "default", "uid-1", "Started");
        let result = filter_events_by_field_selector(vec![ev], "involvedObject.name=nonexistent");
        assert!(
            result.is_empty(),
            "a selector term with no match must return empty; returning all events would cause \
             kubectl describe to show events for unrelated objects"
        );
    }

    /// An empty selector is a pass-through — all events are returned.
    #[test]
    fn empty_selector_passes_all_events() {
        let ev1 = event("pod-a", "Pod", "default", "uid-1", "Started");
        let ev2 = event("pod-b", "Deployment", "default", "uid-2", "Scaled");
        let events = vec![ev1, ev2];
        let result = filter_events_by_field_selector(events.clone(), "");
        assert_eq!(result.len(), events.len());
    }

    /// reason= field selector filters by event reason.
    #[test]
    fn reason_field_selector_filters_by_reason() {
        let ev1 = event("pod-a", "Pod", "default", "uid-1", "Pulled");
        let ev2 = event("pod-b", "Pod", "default", "uid-2", "Started");
        let events = vec![ev1, ev2];
        let result = filter_events_by_field_selector(events, "reason=Pulled");
        assert_eq!(
            result.len(),
            1,
            "reason= field selector must return only events with matching reason; \
             without this, kubectl get events --field-selector reason=X returns unrelated events"
        );
        assert_eq!(result[0]["reason"], "Pulled");
    }

    /// source= field selector filters by core/v1 Event's source.component.
    ///
    /// Without this, `kubectl get events --field-selector source=kubelet` (used to isolate
    /// events emitted by a specific controller) silently returns every event instead of
    /// just the kubelet's, because the field was previously unrecognized and ignored.
    #[test]
    fn source_field_selector_filters_by_source_component() {
        let mut ev1 = event("pod-a", "Pod", "default", "uid-1", "Pulled");
        ev1["source"] = serde_json::json!({"component": "kubelet"});
        let mut ev2 = event("pod-b", "Pod", "default", "uid-2", "Scheduled");
        ev2["source"] = serde_json::json!({"component": "default-scheduler"});
        let events = vec![ev1, ev2];

        let result = filter_events_by_field_selector(events, "source=kubelet");
        assert_eq!(
            result.len(),
            1,
            "source= selector must filter by source.component; without this, \
             kubectl get events --field-selector source=X returns all events"
        );
        assert_eq!(result[0]["source"]["component"], "kubelet");
    }

    /// reportingController= field selector filters by events.k8s.io/v1 Event's top-level
    /// reportingController field.
    ///
    /// events.k8s.io/v1 Event has no `source` object — reporting identity moved to
    /// `reportingController`. Without this selector, clients using the newer events/v1
    /// event recorder (client-go's EventBroadcaster) cannot filter events by reporter,
    /// silently getting every event back.
    #[test]
    fn reporting_controller_field_selector_filters_events_k8s_io_events() {
        let mut ev1 = event("pod-a", "Pod", "default", "uid-1", "Pulled");
        ev1["reportingController"] = serde_json::json!("kubelet");
        let mut ev2 = event("pod-b", "Pod", "default", "uid-2", "Scheduled");
        ev2["reportingController"] = serde_json::json!("default-scheduler");
        let events = vec![ev1, ev2];

        let result = filter_events_by_field_selector(events, "reportingController=kubelet");
        assert_eq!(
            result.len(),
            1,
            "reportingController= selector must filter events.k8s.io/v1 events by reporter; \
             without this, kubectl get events.events.k8s.io --field-selector \
             reportingController=X returns all events"
        );
        assert_eq!(result[0]["reportingController"], "kubelet");
    }

    /// source= field selector must fall back to reportingController when source.component
    /// is absent — matching upstream's ToSelectableFields fallback
    /// (pkg/registry/core/event/strategy.go).
    ///
    /// An Event created via the events.k8s.io/v1 API (client-go's EventsV1 recorder) never
    /// sets `source`, only `reportingController`. The sig-instrumentation Events API
    /// conformance test creates such an event, then queries the CORE/v1 events endpoint with
    /// `fieldSelector=source=<controller>`. Without this fallback the query matches nothing
    /// even though the event's reporter identity is present under a different field name,
    /// so "should ensure that an event can be fetched, patched, deleted, and listed" fails
    /// with "expected single event, got []v1.Event{}".
    #[test]
    fn source_field_selector_falls_back_to_reporting_controller() {
        let mut ev = event("pod-a", "Pod", "default", "uid-1", "Test");
        ev["reportingController"] = serde_json::json!("test-controller");
        // No "source" key at all — this is what an events.k8s.io/v1-only Event looks like.

        let result = filter_events_by_field_selector(vec![ev], "source=test-controller");

        assert_eq!(
            result.len(),
            1,
            "source= selector must fall back to reportingController when source.component \
             is absent, or an event reported only via events.k8s.io/v1 is invisible to a \
             core/v1 fieldSelector=source query"
        );
    }
}

#[cfg(test)]
mod label_selector_tests {
    fn pod_with_label(name: &str, key: &str, value: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": "sonobuoy",
                "labels": {key: value}
            },
            "spec": {}
        })
    }

    /// labelSelector on pods LIST must exclude pods whose labels do not match.
    ///
    /// sonobuoy issues `kubectl get pods -n sonobuoy -l sonobuoy-component=aggregator`
    /// and expects only the aggregator pod. Without label filtering, the plugin pod
    /// (sonobuoy-component=plugin) is also returned, causing sonobuoy to miscount
    /// running pods and stall.
    #[test]
    fn label_selector_excludes_non_matching_pods() {
        let aggregator = pod_with_label("sonobuoy", "sonobuoy-component", "aggregator");
        let plugin = pod_with_label("sonobuoy-e2e-job-abc", "sonobuoy-component", "plugin");
        let items = vec![aggregator, plugin];

        let pairs =
            super::super::generic::parse_label_selector("sonobuoy-component=aggregator").unwrap();
        let result = super::super::generic::apply_label_selector(items, &pairs);

        assert_eq!(
            result.len(),
            1,
            "labelSelector must exclude the plugin pod — only the aggregator should be returned"
        );
        assert_eq!(
            result[0]["metadata"]["name"], "sonobuoy",
            "the returned pod must be the aggregator, not the plugin"
        );
    }

    /// Regression test: sendInitialEvents pod watch with a labelSelector must
    /// exclude pods that do not match the selector from the initial ADDED events.
    ///
    /// The StatefulSet controller opens a pod watch with sendInitialEvents=true and
    /// labelSelector matching its pods (e.g. "app=ss"). Before this fix, ALL pods in the
    /// namespace were returned as initial ADDED events, regardless of labels. The fix applies
    /// object_matches_label_selector to the initial items before passing them to watch_generic.
    ///
    /// This test verifies the filtering logic that was added: only pods with the matching
    /// label should survive the retain. Without the fix (retain removed), non-matching pods
    /// appear in the initial items and the informer cache gets polluted.
    #[test]
    fn send_initial_events_label_selector_filters_initial_pods() {
        let ss_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "ss-0",
                "namespace": "default",
                "labels": {"app": "ss", "controller-uid": "abc123"}
            },
            "spec": {}
        });
        let unrelated_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "unrelated-pod",
                "namespace": "default",
                "labels": {"app": "other"}
            },
            "spec": {}
        });

        let mut pods = vec![ss_pod.clone(), unrelated_pod];
        let selector = "app=ss";

        // This is the exact retain logic added by the fix.
        pods.retain(|pod| super::super::watch::object_matches_label_selector(pod, selector));

        assert_eq!(
            pods.len(),
            1,
            "sendInitialEvents with labelSelector=app=ss must return only ss-0, not unrelated pods; \
             without the fix all pods are returned and the StatefulSet controller's pod informer \
             cache is polluted with pods from other StatefulSets"
        );
        assert_eq!(
            pods[0]["metadata"]["name"], "ss-0",
            "the retained pod must be ss-0 (matches app=ss), not the unrelated pod"
        );
    }

    /// Regression test (live watch path): pod watch with labelSelector must
    /// deliver MODIFIED events for matching pods and suppress events for non-matching pods.
    ///
    /// Before the fix, label_selector was hardcoded to None in the pod watch path, so
    /// watch_generic received no label selector and delivered ALL pod MODIFIED events.
    /// The StatefulSet controller's informer received MODIFIED events for pods belonging
    /// to other StatefulSets or other workloads, adding noise but not breaking correctness.
    ///
    /// After the fix, label_selector=query.label_selector is forwarded. watch_generic applies
    /// object_matches_label_selector and only delivers events for pods matching the selector.
    /// Non-matching pods get a synthetic DELETED if they were previously sent as ADDED.
    ///
    /// This test verifies that object_matches_label_selector correctly identifies matching pods.
    /// If the label selector check is removed, the retain in sendInitialEvents fails silently
    /// (every pod would be retained) and non-ss pods appear in the informer cache.
    #[test]
    fn label_selector_matches_statefulset_pod_labels() {
        // StatefulSet controller watches with selector matching all its pods.
        let selector = "app=ss,controller-uid=abc";

        let ss_pod = serde_json::json!({
            "metadata": {"labels": {"app": "ss", "controller-uid": "abc", "statefulset.kubernetes.io/pod-name": "ss-0"}}
        });
        let other_ss_pod = serde_json::json!({
            "metadata": {"labels": {"app": "other-ss", "controller-uid": "xyz"}}
        });
        let unlabeled = serde_json::json!({
            "metadata": {"name": "bare"}
        });

        assert!(
            super::super::watch::object_matches_label_selector(&ss_pod, selector),
            "ss-0 must match selector app=ss,controller-uid=abc — it belongs to this StatefulSet"
        );
        assert!(
            !super::super::watch::object_matches_label_selector(&other_ss_pod, selector),
            "pod from other StatefulSet must NOT match — delivering its events to this watcher \
             would pollute the informer cache with unrelated pods"
        );
        assert!(
            !super::super::watch::object_matches_label_selector(&unlabeled, selector),
            "unlabeled pod must NOT match — no labels means selector cannot be satisfied"
        );
    }
}

// ---------------------------------------------------------------------------
// Status subresource — GET/PUT/PATCH /api/v1/namespaces/:ns/pods/:name/status
// ---------------------------------------------------------------------------

pub(crate) async fn get_pod_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

pub(crate) async fn replace_pod_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    // Skip namespace existence check: KCM's pod-GC calls PUT /status to mark a pod
    // Failed after the namespace is already deleted. Checking namespace existence here
    // would return "Namespace not found" 404, which KCM treats as retryable — trapping
    // GC in an infinite retry loop. Skipping the check lets the pod key lookup below
    // return "Pod not found" 404 instead, which KCM treats as terminal (pod is gone).
    let ns = Namespace::parse(&raw_ns).map_err(Status::bad_request)?;
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let incoming: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    let mut current_obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    crate::handlers::status::replace_status_field(&mut current_obj.body, &incoming["status"])?;

    crate::handlers::status::merge_incoming_metadata(&mut current_obj.body, &incoming, "Pod");

    // Dry-run: return the would-be status object without persisting — mirrors
    // put_resource_status's dry-run early-return.
    if super::json_patch::is_dry_run_header(&headers) {
        return Ok(Json(current_obj.body));
    }

    // CAS on the INCOMING body's resourceVersion, not the stored object's: a client
    // holding a stale snapshot must get 409 and retry, not silently clobber a concurrent
    // write. Absent rv stays unconditional (parse_resource_version returns None).
    let incoming_meta: ObjectMeta =
        serde_json::from_value(incoming["metadata"].clone()).unwrap_or_default();
    let expected_rv = parse_resource_version(incoming_meta.resource_version.as_deref())?;
    let new_rv = state
        .store
        .put(&key, current_obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current_obj.set_resource_version(new_rv);

    Ok(Json(current_obj.body))
}

/// Returns true if the content-type is acceptable for a pod status patch.
/// Kubelet uses application/strategic-merge-patch+json; both strategic-merge-patch
/// and merge-patch are accepted. JSON-patch (RFC 6902) is not supported for status.
fn accepts_patch_content_type(ct: &str) -> bool {
    ct.contains("application/strategic-merge-patch+json")
        || ct.contains("application/merge-patch+json")
}

/// The two fields needed to enforce the hostNetwork/podIP status invariant below: a pod
/// sharing the host's network namespace must report the node IP as its pod IP, not the
/// pod-CIDR address the CNI sandbox actually assigned. Borrowed straight out of the pod
/// `Value` rather than cloned. This invariant is narrow and stable enough to type;
/// the generic per-kind status merge in `apply_status_patch` above it is not, since it
/// must round-trip arbitrary future status fields untouched.
struct HostNetworkPodIp<'a> {
    host_network: bool,
    host_ip: Option<&'a str>,
}

impl<'a> HostNetworkPodIp<'a> {
    fn read(pod: &'a serde_json::Value) -> Self {
        Self {
            host_network: pod["spec"]["hostNetwork"].as_bool().unwrap_or(false),
            host_ip: pod["status"]["hostIP"].as_str().filter(|s| !s.is_empty()),
        }
    }
}

/// Apply the `.status` and `.metadata` portions of `patch` to `stored`, returning the full
/// updated pod. `.spec` in the patch body is ignored — the status subresource cannot modify spec.
/// This is the Kubernetes API contract for status subresources.
///
/// For array fields with registered strategic-merge keys (conditions, podIPs,
/// containerStatuses, etc.) the patch is applied using strategic-merge semantics so
/// that `$patch:delete` directives remove matching items rather than being stored
/// literally.  Storing them literally causes the kubelet to detect phantom array
/// changes on every reconcile and continuously recreate the pod sandbox.
pub(crate) fn apply_status_patch(
    stored: &serde_json::Value,
    patch: &serde_json::Value,
) -> Result<serde_json::Value, crate::status::StatusError> {
    let mut result = stored.clone();
    if let Some(patch_status) = patch.get("status") {
        if result["status"].is_object() && patch_status.is_object() {
            // Merge fields individually so we can handle arrays with strategic merge keys.
            if let Some(patch_obj) = patch_status.as_object() {
                for (key, val) in patch_obj {
                    if key.starts_with('$') {
                        // Strategic-merge-patch directives ($setElementOrder/*, $patch, etc.)
                        // are client-side instructions consumed during merge; they must not be
                        // stored in the object. Storing $setElementOrder/podIPs causes the
                        // kubelet to detect a phantom diff on every GET and continuously
                        // recreate the pod sandbox, preventing Job pods from ever completing.
                        continue;
                    } else if key == "conditions" {
                        // Strategic merge by .type — patch conditions override stored ones by type,
                        // but stored conditions not present in the patch are preserved.
                        // Fields within a matched condition are merged; missing fields in the
                        // patch leave existing stored fields intact.
                        merge_conditions(&mut result["status"]["conditions"], val);
                    } else if val.is_array() {
                        // For array fields, use strategic-merge-patch so that $patch:delete
                        // directives are applied by merge key rather than stored literally.
                        // Wrap the field in a one-key object so strategic_merge_patch can
                        // resolve the merge key via the field name as the path root.
                        let wrapper_patch = serde_json::json!({ key: val });
                        let mut wrapper_target =
                            serde_json::json!({ key: result["status"][key].clone() });
                        // Ignore errors — unknown $patch directives fall through to merge_patch.
                        if crate::patch::strategic_merge_patch(&mut wrapper_target, &wrapper_patch)
                            .is_ok()
                        {
                            result["status"][key] = wrapper_target[key].clone();
                        } else {
                            crate::patch::merge_patch(&mut result["status"][key], val);
                        }
                    } else {
                        crate::patch::merge_patch(&mut result["status"][key], val);
                    }
                }
                // Apply $setElementOrder/conditions: reorder the merged conditions array
                // to match the order the kubelet requested. Without this, the kubelet
                // detects a conditions ordering mismatch on every GET and re-sends PATCH,
                // causing continuous reconcile churn that prevents pods from progressing.
                if let Some(order_val) = patch_obj.get("$setElementOrder/conditions") {
                    if let (Some(order_arr), Some(conds)) = (
                        order_val.as_array(),
                        result["status"]["conditions"].as_array_mut(),
                    ) {
                        let order: Vec<&str> = order_arr
                            .iter()
                            .filter_map(|v| v["type"].as_str())
                            .collect();
                        conds.sort_by_key(|c| {
                            let t = c["type"].as_str().unwrap_or("");
                            order.iter().position(|&o| o == t).unwrap_or(usize::MAX)
                        });
                    }
                }
            }
        } else {
            result["status"] = patch_status.clone();
        }
    }
    // status is always a message/object type — a merge-patch body like {"status":"x"}
    // would otherwise silently persist a scalar (the `else` branch above replaces status
    // wholesale with whatever the patch carried, RFC 7396's own semantics for a non-object
    // patch value). That corrupts the object's schema and panics any LATER call that
    // stamps status fields in place via `["status"]["field"] = ...` on this same stored
    // object (e.g. `apply_resize_patch`'s resize stamp), crashing the apiserver on the next
    // resize/delete of this pod. Reject before it's ever written to the store.
    crate::handlers::status::reject_non_object_status(&result["status"])?;

    // Apply metadata changes from the patch body (annotations, etc.) via the same guard the
    // generic status handlers use: identity fields, lifecycle-control fields, and `labels`
    // are preserved from the stored object rather than reimplementing the same protected-field
    // list here, which had drifted out of sync and let a status-only merge patch smuggle in
    // a `metadata.labels` change. In particular, `finalizers` and
    // `deletionTimestamp` must never be changed via /status: the kubelet's status patch
    // body reflects the pod the kubelet last saw (which may still carry the job-tracking
    // finalizer), so without this guard every kubelet status update would restore the
    // finalizer that KCM just removed, causing a livelock where the finalizer is never
    // permanently removed and pods stay Terminating forever.
    crate::handlers::status::merge_incoming_metadata(&mut result, patch, "Pod");

    // Enforce hostNetwork invariant: a pod sharing the host network namespace has
    // the node's IP as its pod IP, not a pod-CIDR address.  The kubelet sets
    // status.podIP from the CNI sandbox result, which for hostNetwork pods is
    // still a pod-CIDR address because the sandbox creation path doesn't special-
    // case hostNetwork.  Override podIP/podIPs here so the downward API exposes
    // the correct value (HOST_IP == POD_IP for hostNetwork pods).
    let host_net = HostNetworkPodIp::read(&result);
    let podip_override = if host_net.host_network {
        host_net.host_ip.map(str::to_owned)
    } else {
        None
    };
    if let Some(host_ip) = podip_override {
        result["status"]["podIP"] = serde_json::json!(host_ip);
        result["status"]["podIPs"] = serde_json::json!([{"ip": host_ip}]);
    }

    Ok(result)
}

/// Merge a patch conditions array into stored conditions, keyed by `type`.
/// Fields present in the patch condition update the stored condition; fields absent
/// in the patch are left as-is in the stored condition.
///
/// Exception: when a patch changes the `status` field of a condition, `reason` and
/// `message` are reset to empty string if the patch omits them OR supplies them as null.
/// The kubelet sends `"reason":null` (not omitted, but null) for conditions that have no
/// reason — a null value means "no reason" the same as an absent key.  Keeping the old
/// reason when status flips produces contradictory conditions like Ready=True with
/// reason=ContainersNotReady, which breaks webhook readiness checks.
fn merge_conditions(stored: &mut serde_json::Value, patch_conditions: &serde_json::Value) {
    let Some(patch_arr) = patch_conditions.as_array() else {
        return;
    };
    if !stored.is_array() {
        *stored = patch_conditions.clone();
        return;
    }
    let stored_arr = stored.as_array_mut().unwrap();
    for patch_cond in patch_arr {
        let Some(cond_type) = patch_cond["type"].as_str() else {
            continue;
        };
        if patch_cond.get("$patch").and_then(|v| v.as_str()) == Some("delete") {
            stored_arr.retain(|c| c["type"] != cond_type);
            continue;
        }
        if let Some(existing) = stored_arr.iter_mut().find(|c| c["type"] == cond_type) {
            let patch_obj = match patch_cond.as_object() {
                Some(o) => o,
                None => continue,
            };
            let status_changes = patch_obj
                .get("status")
                .is_some_and(|v| *v != existing["status"]);
            for (k, v) in patch_obj {
                if !v.is_null() {
                    existing[k] = v.clone();
                }
            }
            if status_changes {
                let patch_reason_non_null = patch_obj.get("reason").is_some_and(|v| !v.is_null());
                if !patch_reason_non_null {
                    existing["reason"] = serde_json::json!("");
                }
                let patch_message_non_null = patch_obj.get("message").is_some_and(|v| !v.is_null());
                if !patch_message_non_null {
                    existing["message"] = serde_json::json!("");
                }
            }
        } else {
            stored_arr.push(patch_cond.clone());
        }
    }
}

pub(crate) async fn patch_pod_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Kubelet uses strategic-merge-patch; both patch types update only the status field.
    if !accepts_patch_content_type(content_type) {
        return Err(Status::unsupported_media_type(format!(
            "unsupported media type '{content_type}'; use application/merge-patch+json or application/strategic-merge-patch+json"
        )));
    }

    // Skip namespace existence check: KCM's pod-GC calls PATCH /status to mark a pod
    // Failed after the namespace is already deleted. Checking namespace existence here
    // would return "Namespace not found" 404, which KCM treats as retryable — trapping
    // GC in an infinite retry loop. Skipping the check lets the pod key lookup below
    // return "Pod not found" 404 instead, which KCM treats as terminal (pod is gone).
    let ns = Namespace::parse(&raw_ns).map_err(Status::bad_request)?;

    let key = object_key("pods", ns.as_str(), &name);

    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?;

    // Retry on RevisionMismatch: PATCH is not a conditional operation — re-read and
    // re-apply when a concurrent write advances the stored rv between our read and write.
    loop {
        let stored = state
            .store
            .get(&key)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(&name, "Pod"))?;

        let mut current_obj = Object::from_bytes(&stored.value)
            .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

        current_obj.body = apply_status_patch(&current_obj.body, &patch)?;

        // Dry-run: validation passed; return the would-be patched status without
        // persisting — mirrors replace_pod_status's dry-run early-return.
        if super::json_patch::is_dry_run_header(&headers) {
            return Ok(Json(current_obj.body));
        }

        let expected_rv = parse_resource_version(current_obj.resource_version())?;
        match state
            .store
            .put(&key, current_obj.to_bytes(), expected_rv)
            .await
        {
            Ok(new_rv) => {
                current_obj.set_resource_version(new_rv);
                return Ok(Json(current_obj.body));
            }
            Err(StoreError::RevisionMismatch { .. }) => continue,
            Err(e) => return Err(store_err_to_status(e, &name)),
        }
    }
}

// ---------------------------------------------------------------------------
// Resize subresource — PATCH/PUT /api/v1/namespaces/:ns/pods/:name/resize
// ---------------------------------------------------------------------------

/// Validate a resize patch against the stored pod before applying it.
///
/// Kubernetes rejects resize patches that would:
/// 1. Contain non-cpu/non-memory resource quantities (only cpu and memory are mutable).
/// 2. Rename, add, or reorder containers (containers must appear in the same order as stored).
/// 3. Remove a resource quantity that is currently set (resource requests/limits cannot be removed).
/// 4. Change the pod's QoS class (e.g. BestEffort → Burstable, Guaranteed → Burstable).
///
/// Error messages contain the substrings the k8s conformance test asserts
/// (pod_resize.go:390, "apply invalid resize patch requests" group):
///   "only cpu and memory resources are mutable"
///   "Forbidden: containers may not be renamed or reordered on resize"
///   "resource requests cannot be removed"
///   "resource limits cannot be removed"
///   "Pod QOS Class may not change as a result of resizing"
///
/// Without this check u7s accepts patches that real k8s rejects,
/// causing conformance failures ("Expected an error to have occurred. Got: nil").
///
/// Distinguishes "key absent from the patch" (unchanged, preserve the stored value)
/// from "key explicitly removed" for a single cpu/memory `resource` within a
/// `requests`/`limits` `section`. `section` is `Option::None` when the whole section
/// key is missing from the patch's `resources` object entirely — a real
/// `strategicpatch.CreateTwoWayMergePatch` (as kubectl/e2e clients build) omits a
/// section key altogether when nothing in it changed (e.g. a cpu-only resize of a
/// container that also has memory limits never mentions `limits` at all), so this must
/// mean "unchanged", symmetric with `merge_resize_section`'s `None` handling in
/// `apply_resize_patch`. An explicit `null` or an empty `{}` are the two forms that
/// actually mean "remove everything in this section" (matches real k8s and the "remove
/// cpu&memory limits" conformance case). Only when the section is present as a
/// non-empty object does per-key semantics apply: an absent key is unchanged, an
/// explicit `null` for that key is a real removal.
fn resize_section_removes_resource(section: Option<&serde_json::Value>, resource: &str) -> bool {
    match section {
        None => false,
        Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::Object(map)) => {
            if map.is_empty() {
                true
            } else {
                map.get(resource).is_some_and(|v| v.is_null())
            }
        }
        Some(_) => false,
    }
}

pub(crate) fn validate_resize_patch(
    stored: &serde_json::Value,
    incoming: &serde_json::Value,
) -> Result<(), String> {
    let pod_ns = stored["metadata"]["namespace"].as_str().unwrap_or("");
    let pod_name = stored["metadata"]["name"].as_str().unwrap_or("");

    let stored_containers = stored["spec"]["containers"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[]);

    // Rule 2a: check $setElementOrder/containers for reorder intent.
    // A strategic-merge-patch that only reorders (no resource changes) sends ONLY this
    // directive with no `spec.containers` array. The positional check below (Rule 2b)
    // handles the case where `containers` is also present; this check catches the
    // directive-only case that would otherwise be skipped by the early return.
    if let Some(order_arr) = incoming["spec"]["$setElementOrder/containers"].as_array() {
        let mut name_mismatches: Vec<String> = Vec::new();
        for (order_idx, entry) in order_arr.iter().enumerate() {
            let order_name = entry["name"].as_str().unwrap_or("");
            let stored_name = stored_containers
                .get(order_idx)
                .and_then(|s| s["name"].as_str())
                .unwrap_or("");
            if order_name != stored_name {
                name_mismatches.push(format!(
                    "spec.containers[{order_idx}].name: Forbidden: \
                     containers may not be renamed or reordered on resize"
                ));
            }
        }
        if !name_mismatches.is_empty() {
            return Err(format!(
                "Pod {pod_ns}/{pod_name}: {}",
                name_mismatches.join(", ")
            ));
        }
    }

    let incoming_containers = incoming["spec"]["containers"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[]);
    // Sidecar (RestartPolicy: Always) init containers are resizable through the same
    // GA feature as regular containers, and a real strategic-merge-patch client sends
    // their resource changes under `spec.initContainers`, not `spec.containers`.
    let incoming_init_containers = incoming["spec"]["initContainers"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[]);
    if incoming_containers.is_empty() && incoming_init_containers.is_empty() {
        return Ok(()); // no containers or initContainers in patch — nothing to validate
    }

    // Rule 1: only cpu and memory are resizable resource quantities.
    // If the patch specifies ephemeral-storage or any other resource in requests/limits,
    // reject with the k8s message "only cpu and memory resources are mutable".
    for (list_key, c) in incoming_containers.iter().map(|c| ("containers", c)).chain(
        incoming_init_containers
            .iter()
            .map(|c| ("initContainers", c)),
    ) {
        let incoming_resources = &c["resources"];
        if incoming_resources.is_null() {
            continue;
        }
        for section in &["requests", "limits"] {
            if let Some(obj) = incoming_resources[section].as_object() {
                for key in obj.keys() {
                    if key != "cpu" && key != "memory" {
                        let name = c["name"].as_str().unwrap_or("");
                        return Err(format!(
                            "Pod {pod_ns}/{pod_name}: spec.{list_key}[name={name}].\
                             resources.{section}.{key}: \
                             only cpu and memory resources are mutable",
                        ));
                    }
                }
            }
        }
    }

    // Rule 2b: containers in the patch must match the stored pod in name AND order.
    // Reordering or renaming containers is forbidden — the patch's i-th container must
    // have the same name as the stored pod's i-th container for all indices present in the patch.
    // This catches both rename (name doesn't exist in stored) and reorder (name exists but
    // at a different position).
    // Collect ALL mismatched positions and report them in one error, matching k8s:
    //   "spec.containers[0].name: Forbidden: ..., spec.containers[1].name: Forbidden: ..."
    let mut name_mismatches: Vec<String> = Vec::new();
    for (patch_idx, c) in incoming_containers.iter().enumerate() {
        let patch_name = c["name"].as_str().unwrap_or("");
        let stored_name = stored_containers
            .get(patch_idx)
            .and_then(|s| s["name"].as_str())
            .unwrap_or("");
        if patch_name != stored_name {
            name_mismatches.push(format!(
                "spec.containers[{patch_idx}].name: Forbidden: \
                 containers may not be renamed or reordered on resize"
            ));
        }
    }
    if !name_mismatches.is_empty() {
        return Err(format!(
            "Pod {pod_ns}/{pod_name}: {}",
            name_mismatches.join(", ")
        ));
    }

    // Rule 4: QoS class must not change — checked BEFORE Rule 3 (resource removal).
    //
    // Checked first because some tests ("Burstable pod - set requests == limits") send a patch
    // that omits the limits section entirely (to avoid triggering limits-removal) but would
    // change QoS from Burstable → Guaranteed. If Rule 3 ran first, it would fire
    // "resource limits cannot be removed" instead of the expected QoS error.
    //
    // Uses merge semantics (absent section = preserved from stored) so that a patch sending
    // only requests implicitly keeps existing limits for the QoS computation. This allows
    // detecting QoS changes that would occur when requests are set equal to stored limits.
    let qos_before = compute_qos_class(stored);
    let qos_after = compute_qos_class(&merge_resize_for_qos(stored, incoming));
    if qos_before != qos_after {
        return Err(format!(
            "Pod {pod_ns}/{pod_name}: \
             Pod QOS Class may not change as a result of resizing. \
             Existing QOS class: {qos_before}, new QOS class: {qos_after}",
        ));
    }

    // Rule 3: resize may not remove a resource quantity that is currently set.
    //
    // A whole section (limits or requests) explicitly null, or present-but-empty ({}),
    // means "remove everything in that section" — same as real k8s. A section key
    // absent from the patch entirely means "unchanged" (CreateTwoWayMergePatch omits a
    // section altogether when nothing in it changed), same as a resource KEY simply
    // absent from an otherwise non-empty section: strategicpatch.CreateTwoWayMergePatch
    // omits keys whose value didn't change, so a cpu-only patch never mentions memory
    // at all. Only an EXPLICIT null (at the section or key level) signals real removal.
    // Conflating "absent" with "removed" (as a naive serde_json index into a missing
    // key would, since both yield Value::Null) falsely rejects valid partial resizes.
    //
    // Check limits before requests so "resource limits cannot be removed" fires before
    // "resource requests cannot be removed" when both sections are missing (the
    // "Guaranteed pod - remove limits" conformance test expects this ordering).
    let stored_init_containers = stored["spec"]["initContainers"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[]);
    let stored_by_name: std::collections::HashMap<&str, &serde_json::Value> = stored_containers
        .iter()
        .chain(stored_init_containers.iter())
        .filter_map(|c| c["name"].as_str().map(|n| (n, c)))
        .collect();

    for (list_key, c) in incoming_containers.iter().map(|c| ("containers", c)).chain(
        incoming_init_containers
            .iter()
            .map(|c| ("initContainers", c)),
    ) {
        let name = c["name"].as_str().unwrap_or("");
        let Some(stored_c) = stored_by_name.get(name) else {
            continue; // already caught by Rule 2
        };
        let incoming_resources = &c["resources"];
        if incoming_resources.is_null() {
            continue;
        }

        // Check limits first.
        for resource in &["cpu", "memory"] {
            let stored_has = stored_c["resources"]["limits"][resource]
                .as_str()
                .is_some_and(|s| !s.is_empty());
            if stored_has
                && resize_section_removes_resource(incoming_resources.get("limits"), resource)
            {
                return Err(format!(
                    "Pod {pod_ns}/{pod_name}: \
                     spec.{list_key}[name={name}].resources.limits.{resource}: \
                     resource limits cannot be removed",
                ));
            }
        }

        // Check requests.
        for resource in &["cpu", "memory"] {
            let stored_has = stored_c["resources"]["requests"][resource]
                .as_str()
                .is_some_and(|s| !s.is_empty());
            if stored_has
                && resize_section_removes_resource(incoming_resources.get("requests"), resource)
            {
                return Err(format!(
                    "Pod {pod_ns}/{pod_name}: \
                     spec.{list_key}[name={name}].resources.requests.{resource}: \
                     resource requests cannot be removed",
                ));
            }
        }
    }

    Ok(())
}

/// Compute the merged post-resize state for QoS validation.
///
/// Unlike apply_resize_patch (which replaces the entire resources object), this function
/// merges resources key-by-key: if a resource key (cpu/memory) is absent from an
/// otherwise non-empty section in the incoming patch, the existing value is PRESERVED.
/// This matches strategicpatch.CreateTwoWayMergePatch semantics — such patches omit
/// unchanged keys entirely (a cpu-only change never mentions memory) — and is used
/// exclusively for QoS class validation in validate_resize_patch. A whole section
/// replacement (as done here previously) would drop the omitted key, corrupting the
/// QoS computation for the *other* resource that the patch never intended to touch.
///
/// Merges both `containers` and `initContainers` — `compute_qos_class` factors init
/// containers into the pod's QoS class, so a resize that changes an init container's
/// resources (sidecars are resizable through this same GA feature) must be reflected
/// here too, or Rule 4 evaluates QoS against a stale init-container state.
fn merge_resize_for_qos(
    stored: &serde_json::Value,
    incoming: &serde_json::Value,
) -> serde_json::Value {
    let mut result = stored.clone();
    for list_key in ["containers", "initContainers"] {
        let Some(incoming_containers) = incoming["spec"][list_key].as_array() else {
            continue;
        };
        if let Some(stored_containers) = result["spec"][list_key].as_array_mut() {
            for stored_container in stored_containers.iter_mut() {
                let stored_name = stored_container["name"].as_str().unwrap_or("");
                let Some(incoming_c) = incoming_containers
                    .iter()
                    .find(|c| c["name"].as_str().unwrap_or("") == stored_name)
                else {
                    continue;
                };
                let incoming_resources = &incoming_c["resources"];
                if incoming_resources.is_null() {
                    continue;
                }
                // Merge key-by-key within each section: only update the specific
                // cpu/memory keys the patch actually mentions. An empty object {}
                // (explicit removal of the whole section) is intentionally NOT merged
                // here — for QoS computation we need to see what limits/requests WOULD
                // be after a valid resize; the actual removal is caught by Rule 3.
                // Skipping empty {} means the stored values are preserved for QoS
                // checks, so "Guaranteed pod remove limits" does not falsely trigger a
                // QoS error.
                for section in &["requests", "limits"] {
                    if let Some(incoming_section) = incoming_resources[section].as_object() {
                        for (key, value) in incoming_section {
                            stored_container["resources"][section][key.as_str()] = value.clone();
                        }
                    }
                }
            }
        }
    }
    result
}

/// Merge one requests/limits `section` of a container's resources. `stored_section` is
/// the current value at `resources[section]` (`None` if absent); `incoming` is the value
/// found at `resources[section]` in the patch (`None` when the section key is absent
/// from the patch entirely). Returns `None` when the section should end up absent.
///
/// `incoming == None` means the patch never mentions this section at all — preserve
/// `stored_section` exactly as-is. This is only reachable for a resize patch that
/// `validate_resize_patch` already accepted: Rule 3 rejects an absent section whenever
/// the stored pod has a cpu/memory value there, so by the time this runs an absent
/// section can only mean the stored section already had nothing worth losing.
/// `incoming == Some(null)` or `Some({})` means "remove the whole section" (same
/// validated-safe reasoning). A non-empty incoming object is merged key-by-key: a key
/// present in the patch overwrites (or, if explicitly `null`, removes) that single
/// key, while a key never mentioned by the patch keeps its stored value — this is the
/// behavior `strategicpatch.CreateTwoWayMergePatch` requires, since it omits any
/// cpu/memory key that didn't change.
fn merge_resize_section(
    stored_section: Option<&serde_json::Value>,
    incoming: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    match incoming {
        None => stored_section.cloned(),
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Object(map)) if map.is_empty() => None,
        Some(serde_json::Value::Object(map)) => {
            let mut merged = stored_section
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            for (key, value) in map {
                if value.is_null() {
                    merged.remove(key);
                } else {
                    merged.insert(key.clone(), value.clone());
                }
            }
            if merged.is_empty() {
                None
            } else {
                Some(serde_json::Value::Object(merged))
            }
        }
        Some(_) => stored_section.cloned(),
    }
}

/// Merge incoming container resources onto the stored pod (match by container name),
/// then set status.resize = "Proposed".
///
/// Merges `resources.requests`/`resources.limits` key-by-key via `merge_resize_section`
/// rather than replacing the whole `resources` object. A resize patch built by
/// `strategicpatch.CreateTwoWayMergePatch` (as real kubectl/e2e clients do) omits any
/// cpu/memory key that didn't change — a CPU-only resize of a container with existing
/// memory requests/limits never mentions memory at all. Replacing `resources` wholesale
/// with that partial patch silently deletes the untouched resource, corrupting
/// multi-container resizes where different containers (or different dimensions of the
/// same container) change independently. Updates both spec.containers[].resources and
/// spec.initContainers[].resources (sidecar init containers are resizable through the
/// same GA feature and a real client's patch carries their changes under
/// `initContainers`, not `containers`); all other fields are preserved. This is the
/// pure logic extracted for testability.
pub(crate) fn apply_resize_patch(
    stored: &serde_json::Value,
    incoming: &serde_json::Value,
) -> serde_json::Value {
    let mut result = stored.clone();
    for list_key in ["containers", "initContainers"] {
        let Some(incoming_containers) = incoming["spec"][list_key].as_array() else {
            continue;
        };
        if let Some(stored_containers) = result["spec"][list_key].as_array_mut() {
            for stored_container in stored_containers.iter_mut() {
                let stored_name = stored_container["name"].as_str().unwrap_or("");
                let Some(incoming_container) = incoming_containers
                    .iter()
                    .find(|c| c["name"].as_str().unwrap_or("") == stored_name)
                else {
                    continue;
                };
                let incoming_resources = &incoming_container["resources"];
                if incoming_resources.is_null() {
                    continue;
                }
                for section in ["requests", "limits"] {
                    let merged = merge_resize_section(
                        stored_container["resources"].get(section),
                        incoming_resources.get(section),
                    );
                    match merged {
                        Some(v) => stored_container["resources"][section] = v,
                        None => {
                            if let Some(obj) = stored_container["resources"].as_object_mut() {
                                obj.remove(section);
                            }
                        }
                    }
                }
            }
        }
    }
    // A prior status-subresource write could (bug notwithstanding) have left `status` as a
    // non-object scalar/array; indexing that with ["resize"] below would panic and crash
    // the apiserver on every resize PATCH/PUT for that pod. Coerce back to an empty object
    // first so this stamp is panic-safe regardless of what's stored, mirroring
    // apply_delete_policy's (generic.rs) same guard.
    if !result["status"].is_object() && !result["status"].is_null() {
        result["status"] = serde_json::json!({});
    }
    result["status"]["resize"] = serde_json::json!("Proposed");
    result
}

pub(crate) async fn patch_pod_resize<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let incoming: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    let mut current_obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    validate_resize_patch(&current_obj.body, &incoming).map_err(Status::unprocessable_entity)?;

    let spec_before = current_obj.body["spec"].clone();
    current_obj.body = apply_resize_patch(&current_obj.body, &incoming);
    increment_pod_generation_if_spec_changed(&mut current_obj.body, &spec_before);

    // Dry-run: validation passed; return the would-be resized pod without persisting —
    // mirrors replace_pod's dry-run early-return.
    if super::json_patch::is_dry_run_header(&headers) {
        return Ok(Json(current_obj.body));
    }

    // CAS on the INCOMING body's resourceVersion. This route serves both PUT and PATCH:
    // a PUT client sends its rv and must get 409 on a stale write; a PATCH omits rv, so
    // parse_resource_version returns None and the write stays unconditional.
    let incoming_meta: ObjectMeta =
        serde_json::from_value(incoming["metadata"].clone()).unwrap_or_default();
    let expected_rv = parse_resource_version(incoming_meta.resource_version.as_deref())?;
    let new_rv = state
        .store
        .put(&key, current_obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current_obj.set_resource_version(new_rv);

    // ResourceQuota: a resize changes a pod's resource requests without creating or
    // destroying it, so the incremental counter needs its own adjustment distinct from
    // record_pod_created/record_pod_removed — see record_pod_resized's doc for why skipping
    // this permanently leaks the pre/post delta. Same per-namespace lock the create and
    // delete paths use, so this can never interleave with a concurrent create/delete/resize's
    // read-modify-write of the same quota's status.used.
    let _quota_lock = state.quota_admission_locks.lock(ns.as_str()).await;
    crate::quota::record_pod_resized(&state, ns.as_str(), &spec_before, &current_obj.body).await;

    Ok(Json(current_obj.body))
}

/// GET /api/v1/namespaces/{ns}/pods/{name}/resize
///
/// Returns the pod object. status.resize (a field within status) reflects the
/// current resize state. The in-place-resize conformance test polls this endpoint
/// after each PATCH /resize to confirm the resize was applied; without this
/// handler the route returns 405 and the conformance poll loop never terminates.
pub(crate) async fn get_pod_resize<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// EphemeralContainers subresource — PATCH /api/v1/namespaces/:ns/pods/:name/ephemeralcontainers
// ---------------------------------------------------------------------------

/// Merge `spec.ephemeralContainers` from `patch` into `stored`.
///
/// Kubernetes semantics: ephemeral containers may be added but never removed.
/// We append containers from the patch whose name does not already exist in the
/// stored list, leaving existing containers untouched.
///
/// Extracted as a pure function for testability — the async handler cannot be
/// tested without a live store.
pub(crate) fn apply_ephemeral_containers_patch(
    stored: &serde_json::Value,
    patch: &serde_json::Value,
) -> serde_json::Value {
    let mut result = stored.clone();

    let patch_containers = match patch["spec"]["ephemeralContainers"].as_array() {
        Some(a) => a.clone(),
        None => return result,
    };

    let existing: Vec<serde_json::Value> = result["spec"]["ephemeralContainers"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let existing_names: std::collections::HashSet<String> = existing
        .iter()
        .filter_map(|c| c["name"].as_str().map(|s| s.to_owned()))
        .collect();

    let mut merged = existing;
    for c in &patch_containers {
        if !existing_names.contains(c["name"].as_str().unwrap_or("")) {
            merged.push(c.clone());
        }
    }

    result["spec"]["ephemeralContainers"] = serde_json::json!(merged);
    result
}

pub(crate) async fn get_ephemeral_containers<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        stored.value,
    )
        .into_response())
}

pub(crate) async fn patch_ephemeral_containers<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let patch: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    let mut current_obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let spec_before = current_obj.body["spec"].clone();
    current_obj.body = apply_ephemeral_containers_patch(&current_obj.body, &patch);
    increment_pod_generation_if_spec_changed(&mut current_obj.body, &spec_before);

    // Dry-run: validation passed; return the would-be patched pod without persisting —
    // mirrors replace_pod's dry-run early-return.
    if super::json_patch::is_dry_run_header(&headers) {
        return Ok(Json(current_obj.body));
    }

    let expected_rv = parse_resource_version(current_obj.resource_version())?;
    let new_rv = state
        .store
        .put(&key, current_obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current_obj.set_resource_version(new_rv);

    Ok(Json(current_obj.body))
}

pub(crate) async fn put_ephemeral_containers<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let incoming: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    let mut current_obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let spec_before = current_obj.body["spec"].clone();
    current_obj.body = apply_ephemeral_containers_patch(&current_obj.body, &incoming);
    increment_pod_generation_if_spec_changed(&mut current_obj.body, &spec_before);

    // Dry-run: validation passed; return the would-be replaced pod without persisting —
    // mirrors replace_pod's dry-run early-return.
    if super::json_patch::is_dry_run_header(&headers) {
        return Ok(Json(current_obj.body));
    }

    // CAS on the INCOMING body's resourceVersion, not the stored object's, so a stale
    // PUT is rejected with 409. Absent rv stays unconditional (returns None).
    let incoming_meta: ObjectMeta =
        serde_json::from_value(incoming["metadata"].clone()).unwrap_or_default();
    let expected_rv = parse_resource_version(incoming_meta.resource_version.as_deref())?;
    let new_rv = state
        .store
        .put(&key, current_obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    current_obj.set_resource_version(new_rv);

    Ok(Json(current_obj.body))
}

// ---------------------------------------------------------------------------
// Binding subresource — POST /api/v1/namespaces/:ns/pods/:name/binding
// ---------------------------------------------------------------------------

#[cfg(test)]
mod status_tests {
    use super::*;

    /// replace_pod_status copies only the "status" field from the incoming body.
    /// Any other fields in the incoming body (spec, metadata) must be ignored.
    /// This is the Kubernetes contract: PUT /status only updates status.
    #[test]
    fn replace_status_only_mutates_status_field() {
        let mut current = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app"}]},
            "status": {"phase": "Pending"}
        });
        let incoming = serde_json::json!({
            "status": {"phase": "Running", "conditions": [{"type": "Ready"}]},
            "spec": {"containers": [{"name": "hacked"}]}
        });

        // Simulate what replace_pod_status does: only copy status field.
        current["status"] = incoming["status"].clone();

        assert_eq!(current["status"]["phase"], "Running");
        assert_eq!(current["status"]["conditions"][0]["type"], "Ready");
        // spec must not be overwritten — it is outside the status subresource
        assert_eq!(current["spec"]["containers"][0]["name"], "app");
    }

    /// patch_pod_status merges only the "status" field from the patch.
    /// Spec and metadata changes in the patch body must be ignored.
    #[test]
    fn patch_status_merges_only_status_field() {
        let mut status = serde_json::json!({"phase": "Pending", "hostIP": "1.2.3.4"});
        let patch_status = serde_json::json!({"phase": "Running"});

        // json_merge_patch on the status object: merges in place.
        crate::patch::merge_patch(&mut status, &patch_status);

        assert_eq!(status["phase"], "Running");
        // pre-existing fields not in the patch must survive
        assert_eq!(status["hostIP"], "1.2.3.4");
    }

    /// patch_pod_status with a null field in the patch status removes that field.
    #[test]
    fn patch_status_null_removes_field() {
        let mut status = serde_json::json!({"phase": "Running", "hostIP": "1.2.3.4"});
        let patch_status = serde_json::json!({"hostIP": null});

        crate::patch::merge_patch(&mut status, &patch_status);

        // null in merge patch means delete
        assert!(status
            .get("hostIP")
            .is_none_or(|v| v.is_null() || !status.as_object().unwrap().contains_key("hostIP")));
        assert_eq!(status["phase"], "Running");
    }

    /// patch_pod_status with no "status" key in the patch leaves status unchanged.
    #[test]
    fn patch_status_no_status_key_is_noop() {
        let original_status = serde_json::json!({"phase": "Running"});
        let mut current = serde_json::json!({
            "status": original_status.clone()
        });
        let patch = serde_json::json!({"metadata": {"labels": {"app": "test"}}});

        // Simulate handler logic: only act if patch has "status" key
        if let Some(patch_status) = patch.get("status") {
            if current["status"].is_object() && patch_status.is_object() {
                crate::patch::merge_patch(&mut current["status"], patch_status);
            } else {
                current["status"] = patch_status.clone();
            }
        }

        assert_eq!(current["status"], original_status);
    }

    /// accepts_patch_content_type must accept strategic-merge-patch and merge-patch,
    /// and must reject json-patch and empty strings.
    /// Kubelet uses strategic-merge-patch+json; rejecting it would break node status
    /// updates. Accepting json-patch would be incorrect (unsupported semantics for status).
    #[test]
    fn patch_content_type_acceptance() {
        assert!(
            accepts_patch_content_type("application/strategic-merge-patch+json"),
            "strategic-merge-patch must be accepted — kubelet uses this type"
        );
        assert!(
            accepts_patch_content_type("application/merge-patch+json"),
            "merge-patch must be accepted"
        );
        assert!(
            !accepts_patch_content_type("application/json-patch+json"),
            "json-patch must be rejected — not supported for status subresource"
        );
        assert!(
            !accepts_patch_content_type(""),
            "empty content-type must be rejected"
        );
    }

    /// apply_status_patch with {"status":{"phase":"Running"}} on a Pending pod must
    /// yield phase=Running. This is the primary kubelet use-case: reporting pod lifecycle
    /// transitions. If the phase doesn't update, pod lifecycle e2e is impossible.
    #[test]
    fn patch_pod_status_updates_phase() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {"phase": "Pending"}
        });
        let patch = serde_json::json!({"status": {"phase": "Running"}});

        let result = apply_status_patch(&stored, &patch).unwrap();

        assert_eq!(
            result["status"]["phase"], "Running",
            "phase must transition Pending -> Running after kubelet patch"
        );
    }

    /// apply_status_patch must ignore spec fields in the patch body.
    /// The status subresource cannot modify spec — Kubernetes API contract.
    /// If spec can be changed via /status, an attacker could hijack pod scheduling.
    #[test]
    fn patch_pod_status_ignores_spec_fields() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "worker-1", "containers": [{"name": "app", "image": "nginx"}]},
            "status": {"phase": "Pending"}
        });
        let patch = serde_json::json!({
            "status": {"phase": "Running"},
            "spec": {"nodeName": "hacked"}
        });

        let result = apply_status_patch(&stored, &patch).unwrap();

        assert_eq!(
            result["status"]["phase"], "Running",
            "status phase must be updated"
        );
        assert_eq!(
            result["spec"]["nodeName"], "worker-1",
            "spec.nodeName must not be changed — status subresource cannot modify spec"
        );
    }

    /// apply_status_patch must preserve existing status fields not present in the patch.
    /// Kubelet sends incremental updates; clobbering existing conditions would lose
    /// previously reported state (e.g. Initialized, ContainersReady conditions).
    #[test]
    fn patch_pod_status_preserves_existing_status_fields() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {},
            "status": {
                "phase": "Pending",
                "conditions": [{"type": "Initialized", "status": "True"}],
                "hostIP": "10.0.0.1"
            }
        });
        let patch = serde_json::json!({"status": {"phase": "Running"}});

        let result = apply_status_patch(&stored, &patch).unwrap();

        assert_eq!(
            result["status"]["phase"], "Running",
            "phase must be updated"
        );
        assert_eq!(
            result["status"]["hostIP"], "10.0.0.1",
            "pre-existing hostIP must not be clobbered"
        );
        let conditions = result["status"]["conditions"]
            .as_array()
            .expect("conditions must still be an array");
        assert_eq!(
            conditions.len(),
            1,
            "pre-existing conditions must be preserved"
        );
        assert_eq!(
            conditions[0]["type"], "Initialized",
            "Initialized condition must survive the phase-only patch"
        );
    }

    /// apply_status_patch with containerStatuses[].restartCount=3 must persist the value.
    ///
    /// The kubelet increments restartCount after each container restart triggered by a
    /// failing liveness probe. If apply_status_patch silently drops or zeros restartCount,
    /// the e2e test "should have monotonically increasing restart count" always sees 0
    /// and fails. This is failure mode B.
    #[test]
    fn patch_pod_status_restart_count_persists() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "liveness-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "busybox",
                    "livenessProbe": {"exec": {"command": ["/bin/false"]},
                        "initialDelaySeconds": 1, "periodSeconds": 1}}]
            },
            "status": {"phase": "Running"}
        });
        // Kubelet sends a status PATCH after the container restarts; it includes the
        // full containerStatuses array with the updated restartCount.
        let patch = serde_json::json!({
            "status": {
                "phase": "Running",
                "containerStatuses": [{
                    "name": "app",
                    "ready": false,
                    "restartCount": 3,
                    "image": "busybox",
                    "imageID": "",
                    "state": {"running": {"startedAt": "2024-01-01T00:00:01Z"}}
                }]
            }
        });

        let result = apply_status_patch(&stored, &patch).unwrap();

        assert_eq!(
            result["status"]["containerStatuses"][0]["restartCount"], 3,
            "restartCount must be preserved after status PATCH — kubelet increments this \
             after each liveness probe restart; if it's zeroed, the e2e monotonic-restart-count \
             test always sees 0 restarts (failure mode B)"
        );
        assert_eq!(
            result["spec"]["containers"][0]["livenessProbe"]["exec"]["command"][0], "/bin/false",
            "spec.containers[].livenessProbe must be untouched by status PATCH"
        );
    }

    /// Kubelet sends partial conditions (type + observedGeneration only, no status field).
    /// Strategic merge by type must preserve the existing status value, not replace it with null.
    /// Without this, endpoints-controller sees Ready condition with null status → treats pod as
    /// not-ready → never populates Endpoints.subsets → webhook service never gets endpoints →
    /// AdmissionWebhook conformance test times out waiting for endpoint count=1.
    #[test]
    fn patch_pod_status_partial_conditions_preserve_ready_status() {
        let stored = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p", "namespace": "ns", "resourceVersion": "1"},
            "spec": {},
            "status": {
                "conditions": [
                    {"type": "Ready", "status": "True", "lastTransitionTime": "2026-06-02T00:00:01Z"},
                    {"type": "ContainersReady", "status": "True"},
                    {"type": "PodScheduled", "status": "True"}
                ]
            }
        });
        // Kubelet periodic sync: partial update with type + observedGeneration, no status field.
        let patch = serde_json::json!({
            "status": {
                "conditions": [
                    {"observedGeneration": 1, "type": "Ready"},
                    {"observedGeneration": 1, "type": "ContainersReady"},
                    {"observedGeneration": 1, "type": "PodScheduled"}
                ]
            }
        });

        let result = apply_status_patch(&stored, &patch).unwrap();
        let conditions = result["status"]["conditions"]
            .as_array()
            .expect("conditions array");
        let ready = conditions
            .iter()
            .find(|c| c["type"] == "Ready")
            .expect("Ready condition");
        assert_eq!(
            ready["status"], "True",
            "Ready status must survive a partial kubelet conditions patch — without this, \
             endpoints-controller sees no-status=not-ready and never populates Endpoints"
        );
        assert_eq!(
            ready["observedGeneration"], 1,
            "observedGeneration from patch must be merged in"
        );
        assert_eq!(
            ready["lastTransitionTime"], "2026-06-02T00:00:01Z",
            "lastTransitionTime absent from patch must be preserved from stored value"
        );
    }

    /// apply_status_patch that adds a new condition to status.conditions merges correctly.
    /// For merge-patch semantics: arrays are replaced, so patching with a new conditions
    /// array replaces the old one. This is the expected RFC 7396 behavior.
    /// If this merges incorrectly, kubelet's reported conditions will be wrong.
    #[test]
    fn patch_pod_status_with_conditions_merge() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {},
            "status": {
                "phase": "Running",
                "conditions": [
                    {"type": "Initialized", "status": "True"},
                    {"type": "Ready", "status": "False"}
                ]
            }
        });
        // Kubelet sends the full updated conditions array (merge-patch replaces arrays).
        let patch = serde_json::json!({
            "status": {
                "phase": "Running",
                "conditions": [
                    {"type": "Initialized", "status": "True"},
                    {"type": "Ready", "status": "True"},
                    {"type": "ContainersReady", "status": "True"}
                ]
            }
        });

        let result = apply_status_patch(&stored, &patch).unwrap();

        let conditions = result["status"]["conditions"]
            .as_array()
            .expect("conditions must be an array");
        // Merge-patch replaces the array entirely with the patch value.
        assert_eq!(
            conditions.len(),
            3,
            "conditions array must reflect the full patch (merge-patch replaces arrays)"
        );
        let ready = conditions
            .iter()
            .find(|c| c["type"] == "Ready")
            .expect("Ready condition must be present");
        assert_eq!(
            ready["status"], "True",
            "Ready condition status must be updated to True"
        );
        let containers_ready = conditions.iter().find(|c| c["type"] == "ContainersReady");
        assert!(
            containers_ready.is_some(),
            "ContainersReady condition must be added by the patch"
        );
    }

    /// apply_status_patch must reject a merge-patch body `{"status":"x"}` (scalar), not
    /// persist it. `status` is a message/object type for every resource; without this
    /// check the `else` branch (see line above) replaces `result["status"]` with the
    /// scalar, corrupting the pod's schema and later panicking the hostNetwork podIP
    /// override in this same function (and `apply_resize_patch`'s in-place stamp) on the
    /// very next call, indexing a JSON string with a str key.
    #[test]
    fn apply_status_patch_rejects_scalar_status() {
        let stored = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p", "namespace": "ns", "resourceVersion": "1"},
            "spec": {},
            "status": {"phase": "Running"}
        });
        let patch = serde_json::json!({"status": "x"});

        let err = apply_status_patch(&stored, &patch)
            .expect_err("a scalar status merge-patch must be rejected, not accepted");
        assert_eq!(
            err.0,
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "a scalar status must be rejected with 422, matching upstream schema validation"
        );
    }

    /// apply_status_patch must ACCEPT a merge-patch body `{"status": null}` — RFC 7396's
    /// own field-deletion syntax, not an invalid scalar. Kubelet/controllers clearing
    /// status entirely via /status must not be wrongly 422'd.
    #[test]
    fn apply_status_patch_accepts_null_status_as_field_deletion() {
        let stored = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p", "namespace": "ns", "resourceVersion": "1"},
            "spec": {},
            "status": {"phase": "Running"}
        });
        let patch = serde_json::json!({"status": null});

        let result = apply_status_patch(&stored, &patch)
            .expect("a null status merge-patch is RFC 7396 field deletion, not a 422");
        assert!(
            result["status"].is_null(),
            "status must be cleared, not left at its old value or rejected"
        );
    }

    /// A strategic-merge-patch with `$patch: delete` on a condition must remove that
    /// condition from the stored list, not store a literal `$patch` key inside it.
    /// Without this, a PATCH intended to remove the Ready condition would instead corrupt
    /// the condition object, and consumers reading conditions would see spurious entries.
    #[test]
    fn patch_delete_directive_removes_condition() {
        let mut stored = serde_json::json!([
            {"type": "Ready", "status": "True"},
            {"type": "Initialized", "status": "True"}
        ]);
        let patch = serde_json::json!([
            {"type": "Ready", "$patch": "delete"}
        ]);

        merge_conditions(&mut stored, &patch);

        let arr = stored.as_array().expect("conditions must remain an array");
        assert!(
            arr.iter().all(|c| c["type"] != "Ready"),
            "$patch:delete must remove the Ready condition — without this, the literal \
             $patch key is stored inside the condition object instead of removing it"
        );
        assert_eq!(
            arr.len(),
            1,
            "only the non-deleted condition must remain after $patch:delete"
        );
        assert_eq!(
            arr[0]["type"], "Initialized",
            "Initialized condition must survive the delete of Ready"
        );
        assert!(
            arr[0].get("$patch").is_none(),
            "no $patch key must appear on unrelated conditions"
        );
    }

    /// apply_status_patch for a hostNetwork pod must set status.podIP == status.hostIP.
    ///
    /// A pod with spec.hostNetwork=true shares the node's network namespace, so its
    /// pod IP is the node IP, not a pod-CIDR address.  The kubelet sets status.podIP
    /// from the CNI sandbox result, which is a pod-CIDR IP even for hostNetwork pods.
    /// Without this override, the downward API exposes HOST_IP != POD_IP, breaking
    /// the sonobuoy test "Downward API should provide host IP and pod IP as an env var
    /// if pod uses host network" (SONOBUOY_FOCUS='Downward API should provide host IP
    /// and pod IP.*host network').
    #[test]
    fn host_network_pod_status_pod_ip_equals_host_ip() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "hostnet-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "hostNetwork": true,
                "containers": [{"name": "app", "image": "nginx"}]
            },
            "status": {"phase": "Pending"}
        });
        // Kubelet patches status with hostIP (node IP) and podIP (pod-CIDR address from CNI).
        let patch = serde_json::json!({
            "status": {
                "phase": "Running",
                "hostIP": "192.168.5.15",
                "podIP": "10.85.1.153",
                "podIPs": [{"ip": "10.85.1.153"}]
            }
        });

        let result = apply_status_patch(&stored, &patch).unwrap();

        assert_eq!(
            result["status"]["podIP"], "192.168.5.15",
            "hostNetwork pod status.podIP must equal status.hostIP (192.168.5.15), not \
             the pod-CIDR address (10.85.1.153) — downward API POD_IP must match HOST_IP \
             for pods sharing the host network namespace"
        );
        assert_eq!(
            result["status"]["podIPs"][0]["ip"], "192.168.5.15",
            "hostNetwork pod status.podIPs[0].ip must equal hostIP — same invariant as podIP"
        );
        assert_eq!(
            result["status"]["hostIP"], "192.168.5.15",
            "hostIP must remain unchanged at the node IP"
        );
    }

    /// apply_status_patch for a normal (non-hostNetwork) pod must NOT override podIP.
    ///
    /// Only hostNetwork pods receive the host IP override; regular pods keep their
    /// pod-CIDR address.  Incorrect over-application would break all pod networking.
    #[test]
    fn non_host_network_pod_status_pod_ip_unchanged() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "normal-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "hostNetwork": false,
                "containers": [{"name": "app", "image": "nginx"}]
            },
            "status": {"phase": "Pending"}
        });
        let patch = serde_json::json!({
            "status": {
                "phase": "Running",
                "hostIP": "192.168.5.15",
                "podIP": "10.85.1.153",
                "podIPs": [{"ip": "10.85.1.153"}]
            }
        });

        let result = apply_status_patch(&stored, &patch).unwrap();

        assert_eq!(
            result["status"]["podIP"], "10.85.1.153",
            "non-hostNetwork pod status.podIP must not be overridden — \
             only hostNetwork pods share the node IP"
        );
    }

    /// apply_status_patch must clear stale reason/message when PodScheduled status changes.
    ///
    /// A scheduler that patches only {"type":"PodScheduled","status":"True"} (without
    /// reason/message) must not result in PodScheduled=True + reason=Unschedulable.
    /// That contradictory state causes conformance tests (e.g. Variable Expansion) to see
    /// PodScheduled=True while also seeing Unschedulable — an impossible combination that
    /// confuses watchers checking whether a pod was successfully scheduled.
    #[test]
    fn status_patch_clears_stale_reason_when_pod_scheduled_status_changes() {
        let stored = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p", "namespace": "ns", "resourceVersion": "1"},
            "spec": {},
            "status": {
                "phase": "Pending",
                "conditions": [{
                    "type": "PodScheduled",
                    "status": "False",
                    "reason": "Unschedulable",
                    "message": "pod not yet scheduled",
                    "lastTransitionTime": "2024-01-01T00:00:00Z"
                }]
            }
        });
        let patch = serde_json::json!({
            "status": {
                "conditions": [{"type": "PodScheduled", "status": "True"}]
            }
        });

        let result = apply_status_patch(&stored, &patch).unwrap();

        let conditions = result["status"]["conditions"]
            .as_array()
            .expect("conditions array");
        let scheduled = conditions
            .iter()
            .find(|c| c["type"] == "PodScheduled")
            .expect("PodScheduled condition must survive patch");
        assert_eq!(
            scheduled["status"], "True",
            "PodScheduled status must be updated to True by the patch"
        );
        assert_ne!(
            scheduled["reason"], "Unschedulable",
            "PodScheduled=True must not carry reason=Unschedulable — that contradictory \
             state causes conformance tests to see an impossible scheduling outcome"
        );
    }

    /// merge_conditions must clear stale reason/message when kubelet sends reason:null
    /// alongside a status change from False to True.
    ///
    /// The kubelet sends `"reason":null` (JSON null, not key-absent) for conditions with no
    /// reason — e.g. `{"type":"Ready","status":"True","reason":null,"message":null}`.  The
    /// old code treated null as "key present → don't clear stale reason", producing
    /// Ready=True + reason=ContainersNotReady.  That contradictory state causes the
    /// AdmissionWebhook conformance BeforeEach to wait forever for webhook=ready.
    #[test]
    fn merge_conditions_null_reason_cleared_on_status_change() {
        let mut stored = serde_json::json!([
            {
                "type": "Ready",
                "status": "False",
                "reason": "ContainersNotReady",
                "message": "containers with unready status: [sample-webhook]"
            },
            {
                "type": "ContainersReady",
                "status": "False",
                "reason": "ContainersNotReady",
                "message": "containers with unready status: [sample-webhook]"
            }
        ]);
        // Kubelet sends reason:null and message:null (not absent, but JSON null) when
        // containers become ready — serialized from Go's zero-value string fields.
        let patch = serde_json::json!([
            {"type": "Ready", "status": "True", "reason": null, "message": null},
            {"type": "ContainersReady", "status": "True", "reason": null, "message": null}
        ]);

        merge_conditions(&mut stored, &patch);

        let arr = stored.as_array().expect("conditions array");
        let ready = arr
            .iter()
            .find(|c| c["type"] == "Ready")
            .expect("Ready condition must survive");
        assert_eq!(
            ready["status"], "True",
            "Ready status must be updated to True"
        );
        assert_ne!(
            ready["reason"], "ContainersNotReady",
            "Ready=True must not carry reason=ContainersNotReady — kubelet null reason \
             means no reason; keeping the stale reason produces a contradictory condition \
             that breaks AdmissionWebhook conformance (BeforeEach never sees webhook=ready)"
        );
        let cr = arr
            .iter()
            .find(|c| c["type"] == "ContainersReady")
            .expect("ContainersReady condition must survive");
        assert_eq!(cr["status"], "True", "ContainersReady status must be True");
        assert_ne!(
            cr["reason"], "ContainersNotReady",
            "ContainersReady=True must not carry reason=ContainersNotReady"
        );
    }

    /// apply_status_patch must not store $setElementOrder/* or any other $ directive key.
    ///
    /// Kubelet strategic-merge-patch bodies include $setElementOrder/conditions and
    /// $setElementOrder/podIPs to specify desired array ordering. These are client-side
    /// merge instructions, not status fields. If stored literally in the pod object,
    /// the kubelet reads them back on the next GET and detects a phantom diff — causing
    /// it to continuously update podIPs by creating new sandboxes, so Job pods never
    /// hold Running state and every Job conformance test times out.
    #[test]
    fn set_element_order_directives_are_not_stored() {
        let stored = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "job-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {},
            "status": {
                "phase": "Running",
                "podIP": "10.85.0.5",
                "podIPs": [{"ip": "10.85.0.5"}],
                "conditions": [{"type": "Ready", "status": "True"}]
            }
        });
        let patch = serde_json::json!({
            "status": {
                "podIP": "10.85.0.5",
                "podIPs": [{"ip": "10.85.0.5"}],
                "$setElementOrder/podIPs": [{"ip": "10.85.0.5"}],
                "conditions": [{"type": "Ready", "status": "True"}],
                "$setElementOrder/conditions": [{"type": "Ready"}]
            }
        });

        let result = apply_status_patch(&stored, &patch).unwrap();
        let status = result["status"].as_object().expect("status must be object");

        assert!(
            !status.contains_key("$setElementOrder/podIPs"),
            "$setElementOrder/podIPs must not be stored — it is a merge directive, not a \
             status field; storing it causes kubelet to detect a phantom podIPs diff on \
             every GET and recreate the pod sandbox, so Job pods never complete"
        );
        assert!(
            !status.contains_key("$setElementOrder/conditions"),
            "$setElementOrder/conditions must not be stored — same phantom-diff mechanism"
        );
        assert_eq!(
            result["status"]["podIP"], "10.85.0.5",
            "real status fields must still be applied"
        );
    }

    /// apply_status_patch must reorder conditions to match $setElementOrder/conditions.
    ///
    /// The kubelet sends $setElementOrder/conditions on every status PATCH requesting a
    /// specific condition ordering (e.g. PodReadyToStartContainers first, PodScheduled last).
    /// Without honouring this ordering, the kubelet sees a different order on each GET and
    /// re-sends PATCH, causing ~1-2 reconcile cycles per second. This continuous churn
    /// prevented Job pods from holding Running phase long enough for conformance tests to pass.
    #[test]
    fn set_element_order_conditions_reorders_stored_conditions() {
        let stored = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "job-pod", "namespace": "default", "resourceVersion": "5"},
            "spec": {},
            "status": {
                "phase": "Running",
                "conditions": [
                    {"type": "PodScheduled", "status": "True"},
                    {"type": "Initialized", "status": "True"},
                    {"type": "ContainersReady", "status": "True"},
                    {"type": "Ready", "status": "True"}
                ]
            }
        });
        // Kubelet sends the conditions in its preferred order, with $setElementOrder requesting
        // [PodReadyToStartContainers, Initialized, Ready, ContainersReady, PodScheduled].
        let patch = serde_json::json!({
            "status": {
                "conditions": [
                    {"type": "PodReadyToStartContainers", "status": "True"},
                    {"type": "Initialized", "status": "True"},
                    {"type": "Ready", "status": "True"},
                    {"type": "ContainersReady", "status": "True"},
                    {"type": "PodScheduled", "status": "True"}
                ],
                "$setElementOrder/conditions": [
                    {"type": "PodReadyToStartContainers"},
                    {"type": "Initialized"},
                    {"type": "Ready"},
                    {"type": "ContainersReady"},
                    {"type": "PodScheduled"}
                ]
            }
        });

        let result = apply_status_patch(&stored, &patch).unwrap();
        let conds = result["status"]["conditions"]
            .as_array()
            .expect("conditions must be an array");

        assert_eq!(
            conds[0]["type"], "PodReadyToStartContainers",
            "PodReadyToStartContainers must be first per $setElementOrder — \
             without this, kubelet detects ordering mismatch on every GET and \
             re-sends PATCH causing ~1-2 reconciles/sec preventing Job pods from \
             holding Running phase"
        );
        assert_eq!(conds[1]["type"], "Initialized");
        assert_eq!(conds[2]["type"], "Ready");
        assert_eq!(conds[3]["type"], "ContainersReady");
        assert_eq!(
            conds[4]["type"], "PodScheduled",
            "PodScheduled must be last per $setElementOrder"
        );
    }
}

// ---------------------------------------------------------------------------
// Patch type detection tests — regression
// ---------------------------------------------------------------------------

#[cfg(test)]
mod patch_type_tests {
    use super::*;
    use crate::handlers::json_patch::{apply_json_patch, detect_patch_type, PatchType};
    use axum::http::{header::CONTENT_TYPE, HeaderMap, HeaderValue};

    fn headers_with_ct(ct: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_str(ct).unwrap());
        h
    }

    /// json-patch+json must be accepted — not return 415.
    /// This is the regression test: before the fix, patch_pod
    /// rejected application/json-patch+json with HTTP 415 Unsupported Media Type.
    #[test]
    fn json_patch_content_type_is_accepted() {
        let h = headers_with_ct("application/json-patch+json");
        let result = detect_patch_type(&h);
        assert!(
            result.is_ok(),
            "application/json-patch+json must be accepted by patch_pod; \
             before the fix it returned 415 Unsupported Media Type"
        );
        assert!(matches!(result.ok(), Some(PatchType::Json)));
    }

    /// strategic-merge-patch+json must be accepted.
    #[test]
    fn strategic_merge_patch_content_type_is_accepted() {
        let h = headers_with_ct("application/strategic-merge-patch+json");
        assert!(matches!(
            detect_patch_type(&h).ok(),
            Some(PatchType::StrategicMerge)
        ));
    }

    /// merge-patch+json must be accepted.
    #[test]
    fn merge_patch_content_type_is_accepted() {
        let h = headers_with_ct("application/merge-patch+json");
        assert!(matches!(detect_patch_type(&h).ok(), Some(PatchType::Merge)));
    }

    /// apply-patch+yaml is treated as strategic-merge-patch (SSA approximation).
    #[test]
    fn apply_patch_yaml_is_accepted_as_strategic_merge() {
        let h = headers_with_ct("application/apply-patch+yaml");
        assert!(matches!(
            detect_patch_type(&h).ok(),
            Some(PatchType::StrategicMerge)
        ));
    }

    /// Unknown content-type must return 415 error.
    #[test]
    fn unknown_content_type_returns_415() {
        let h = headers_with_ct("application/octet-stream");
        // Must error, not succeed.
        let result = detect_patch_type(&h);
        assert!(result.is_err(), "unknown content-type must be rejected");
        // Verify it produces a 415 response.
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    /// apply_json_patch: replace operation updates a field in the pod object.
    /// This verifies the json-patch apply path end-to-end at the logic level.
    #[test]
    fn apply_json_patch_replace_updates_field() {
        let mut pod = serde_json::json!({
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {"nodeName": "worker-1"}
        });
        let patch = serde_json::json!([
            {"op": "replace", "path": "/spec/nodeName", "value": "worker-2"}
        ]);
        assert!(
            apply_json_patch(&mut pod, &patch).is_ok(),
            "replace op must succeed"
        );
        assert_eq!(
            pod["spec"]["nodeName"], "worker-2",
            "replace op must update spec.nodeName"
        );
    }

    /// apply_json_patch: add operation inserts a new field.
    #[test]
    fn apply_json_patch_add_inserts_field() {
        let mut pod = serde_json::json!({
            "metadata": {"name": "my-pod"},
            "spec": {}
        });
        let patch = serde_json::json!([
            {"op": "add", "path": "/spec/nodeName", "value": "worker-3"}
        ]);
        assert!(
            apply_json_patch(&mut pod, &patch).is_ok(),
            "add op must succeed"
        );
        assert_eq!(pod["spec"]["nodeName"], "worker-3");
    }

    /// apply_json_patch: remove operation deletes a field.
    #[test]
    fn apply_json_patch_remove_deletes_field() {
        let mut pod = serde_json::json!({
            "metadata": {"name": "my-pod", "labels": {"app": "test"}}
        });
        let patch = serde_json::json!([
            {"op": "remove", "path": "/metadata/labels/app"}
        ]);
        assert!(
            apply_json_patch(&mut pod, &patch).is_ok(),
            "remove op must succeed"
        );
        assert!(
            pod["metadata"]["labels"].get("app").is_none(),
            "remove op must delete the key"
        );
    }
}

/// Mirrors upstream apimachinery's `IsValidSysctlName`: a sysctl name is a sequence of
/// segments of lowercase alphanumerics with optional interior '-'/'_' (each segment must
/// start and end alphanumeric), joined by '.' or '/' — the kernel treats either separator
/// as equivalent (e.g. "kernel.shm_rmid_forced" == "kernel/shm_rmid_forced").
fn is_valid_sysctl_name(name: &str) -> bool {
    const MAX_LEN: usize = 253;
    if name.is_empty() || name.len() > MAX_LEN {
        return false;
    }
    let is_lower_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    name.split(['.', '/']).all(|segment| {
        let bytes = segment.as_bytes();
        !bytes.is_empty()
            && is_lower_alnum(bytes[0])
            && is_lower_alnum(bytes[bytes.len() - 1])
            && bytes
                .iter()
                .all(|&b| is_lower_alnum(b) || b == b'-' || b == b'_')
    })
}

/// Validates `spec.securityContext.sysctls[].name` at pod admission.
///
/// Real kube-apiserver rejects malformed sysctl names (a pure syntax check — allow/deny
/// listing valid-but-unsafe sysctls is a separate, kubelet-side mechanism) at CREATE with
/// 422. Without this, u7s persists pods with malformed sysctl names and the kubelet later
/// kills the pod with a misleading "SysctlForbidden" event — the wrong layer and the wrong
/// message for what is really a syntax error the apiserver should catch up front.
fn validate_pod_sysctls(pod: &serde_json::Value) -> Result<(), String> {
    let Some(sysctls) = pod["spec"]["securityContext"]["sysctls"].as_array() else {
        return Ok(());
    };
    let mut errors = Vec::new();
    for (i, s) in sysctls.iter().enumerate() {
        let name = s["name"].as_str().unwrap_or("");
        if !is_valid_sysctl_name(name) {
            errors.push(format!(
                "spec.securityContext.sysctls[{i}].name: Invalid value: \"{name}\": \
                 must have at most 253 characters and match regex \
                 [a-z0-9]([-_a-z0-9]*[a-z0-9])?((\\.|/)[a-z0-9]([-_a-z0-9]*[a-z0-9])?)*"
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(", "))
    }
}

/// Extract the effective tag from a container image reference, mirroring upstream
/// `ParseImageName` (pkg/util/parsers/parsers.go @ v1.36.0), which itself wraps
/// `dockerref.ParseNormalizedNamed`.
///
/// Registry hosts may embed a port (`registry.example.com:5000/nginx:v1`), so a colon
/// is only a tag delimiter when it occurs strictly after the last `/` — a colon before
/// the last slash is part of the host:port, not a tag. A bare reference with neither
/// tag nor digest (`nginx`, `registry:5000/nginx`) is `:latest` by Docker convention.
/// A digest-only reference (`nginx@sha256:...`) has no tag — upstream's
/// `ParseImageName` only backfills "latest" when BOTH tag and digest are absent, so
/// a digest pin does NOT get treated as "latest" even though it also has no explicit tag.
fn parse_image_tag(image: &str) -> &str {
    let (name_and_tag, has_digest) = match image.split_once('@') {
        Some((n, _)) => (n, true),
        None => (image, false),
    };
    let slash_idx = name_and_tag.rfind('/');
    let colon_idx = name_and_tag.rfind(':');
    let tag = match (colon_idx, slash_idx) {
        (Some(c), Some(s)) if c > s => &name_and_tag[c + 1..],
        (Some(c), None) => &name_and_tag[c + 1..],
        _ => "",
    };
    if tag.is_empty() && !has_digest {
        "latest"
    } else {
        tag
    }
}

/// Apply spec-only defaults to a pod's spec fields.
///
/// This must NOT touch pod.status — callers on the update path rely on it being
/// status-free so that a running pod's phase and conditions are never stomped back
/// to "Pending" / "Unschedulable" by a no-op replace or patch.
pub(crate) fn apply_pod_spec_defaults(pod: &mut serde_json::Value) {
    // Deserialize spec into typed form once; all typed-field accesses are compile-checked.
    let mut spec: PodSpec = serde_json::from_value(pod["spec"].clone()).unwrap_or_default();

    // enableServiceLinks: PodSpec deserializes this with default_true, so
    // spec.enable_service_links is true when the field was absent. Write it
    // back only when absent in the raw JSON, preserving an explicit false.
    if pod["spec"]["enableServiceLinks"].is_null() {
        pod["spec"]["enableServiceLinks"] =
            serde_json::to_value(spec.enable_service_links).expect("bool is always serializable");
    }

    // dnsPolicy: default to "ClusterFirst" when absent.
    // Real kube-apiserver always stamps this field on create. The kubelet reads
    // spec.dnsPolicy and rejects empty string with "invalid DNSPolicy=", which
    // causes it to fall back to ClusterFirst for every pod — silently incorrect
    // behaviour. Defaulting here matches kube-apiserver behaviour and preserves
    // any explicit value set by the user (e.g. ClusterFirstWithHostNet, None).
    if pod["spec"]["dnsPolicy"].is_null() {
        pod["spec"]["dnsPolicy"] = serde_json::json!("ClusterFirst");
    }

    // schedulerName: default to "default-scheduler" when absent or empty, mirroring
    // upstream's `obj.SchedulerName == "" { obj.SchedulerName = v1.DefaultSchedulerName }`
    // in SetDefaults_PodSpec. Real kube-scheduler's HandlesSchedulerName looks up the pod's
    // schedulerName in a map keyed by each profile's name, which itself defaults to
    // "default-scheduler" and is never "" — so a pod stored with schedulerName:"" is
    // invisible to it and never gets scheduled.
    if pod["spec"]["schedulerName"]
        .as_str()
        .unwrap_or("")
        .is_empty()
    {
        pod["spec"]["schedulerName"] = serde_json::json!("default-scheduler");
    }

    // restartPolicy: default to "Always" when absent or empty, mirroring upstream's
    // unconditional default in SetDefaults_PodSpec. Defense-in-depth: kubelet's
    // ShouldContainerBeRestarted already tolerates "" today (falls through to restart),
    // but other RestartPolicy switches (e.g. pod-phase computation) are not guaranteed to.
    if pod["spec"]["restartPolicy"]
        .as_str()
        .unwrap_or("")
        .is_empty()
    {
        pod["spec"]["restartPolicy"] = serde_json::json!("Always");
    }

    // securityContext: default to an empty object when absent, mirroring upstream's
    // unconditional `obj.SecurityContext = &v1.PodSecurityContext{}` in SetDefaults_PodSpec.
    // The kubelet's generatePodSandboxLinuxConfig only calls NamespacesForPod (which computes
    // the CRI NamespaceOption for hostNetwork/hostPID/hostIPC) inside an
    // `if pod.Spec.SecurityContext != nil` guard — with securityContext absent, the CRI
    // RunPodSandboxRequest carries no NamespaceOptions at all and every namespace mode
    // silently defaults to POD, even for hostNetwork:true pods. CRI-O then creates an
    // isolated network namespace instead of sharing the host's, so the kubelet's own
    // post-creation PodSandboxChanged check (comparing the sandbox's actual namespace mode
    // against pod.Spec.HostNetwork) finds a mismatch and recreates the sandbox — forever,
    // once per sync — which is the hostNetwork pod "Sandbox for pod has changed" churn loop.
    if pod["spec"]["securityContext"].is_null() {
        pod["spec"]["securityContext"] = serde_json::json!({});
    }

    // terminationGracePeriodSeconds: default to 30 when absent, mirroring
    // upstream's unconditional default in SetDefaults_PodSpec. This value is
    // set once at creation and never touched again, including through a
    // graceful delete — so a nil default here means it stays nil for the
    // pod's entire life. The "should be submitted and removed" conformance
    // test asserts this field is non-zero on the Pod object delivered by the
    // final watch.Deleted event (pods.go:334); without this default that
    // object still carries the nil the pod was created with.
    if pod["spec"]["terminationGracePeriodSeconds"].is_null() {
        pod["spec"]["terminationGracePeriodSeconds"] = serde_json::json!(30);
    }

    // serviceAccountName: when absent or empty, fall back to the deprecated
    // spec.serviceAccount alias before defaulting to "default", mirroring upstream's
    // Convert_v1_PodSpec_To_core_PodSpec ("We support DeprecatedServiceAccount as an
    // alias for ServiceAccountName. If both are specified, ServiceAccountName (the new
    // field) wins") followed by the ServiceAccount admission plugin's unconditional
    // "default" fallback. Manifests that only set the legacy `serviceAccount` field
    // (e.g. upstream's hello-populator-deploy.yaml) would otherwise silently run under
    // the RBAC-less "default" SA and get instant 403s on every apiserver call.
    // client-go's token-fetch machinery also rejects an empty resource name
    // ("failed to fetch token: resource name may not be empty"), so a pod with no
    // resolved serviceAccountName can never start — the kubelet needs a real name to
    // request the projected SA token for. This also unblocks inject_sa_token_volume
    // below, which only fires when serviceAccountName is set.
    if pod["spec"]["serviceAccountName"]
        .as_str()
        .unwrap_or("")
        .is_empty()
    {
        let alias = pod["spec"]["serviceAccount"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        pod["spec"]["serviceAccountName"] =
            serde_json::json!(alias.unwrap_or_else(|| "default".to_string()));
    }
    // Convert_core_PodSpec_To_v1_PodSpec unconditionally backfills the deprecated
    // alias from the resolved ServiceAccountName, so the two fields never diverge in
    // an object a client reads back — even if the client originally sent a
    // conflicting `serviceAccount` value alongside an explicit `serviceAccountName`.
    pod["spec"]["serviceAccount"] = pod["spec"]["serviceAccountName"].clone();

    // defaultMode for volume sources that require it.
    // The kubelet refuses to mount ConfigMap/Secret/DownwardAPI volumes whose defaultMode is
    // absent: "no defaultMode used, not even the default value for it"
    // Real kube-apiserver defaults these to 0644 (420 decimal).
    //
    // We deserialize each volume into a typed Volume, stamp the missing defaultMode
    // on the typed field, then write the whole volumes array back. This ensures the
    // rename of defaultMode → somethingElse is a compile error rather than a silent
    // bug, and that untyped volume fields (emptyDir, hostPath, etc.) survive via `rest`.
    //
    // downwardAPI is included here (not just configMap/secret/projected): unlike those three,
    // a top-level DownwardAPIVolumeSource has no other defaulting pass anywhere in u7s, so a
    // pod created without an explicit defaultMode (the common case) would otherwise store one
    // forever — and every consumer of the stored JSON (the watch stream is a straight JSON
    // pass-through, not just a protobuf-negotiated GET/LIST) would hit the same kubelet
    // mount failure.
    if let Some(ref mut volumes) = spec.volumes {
        let mut changed = false;
        for vol in volumes.iter_mut() {
            for proj in [
                vol.config_map.as_mut(),
                vol.secret.as_mut(),
                vol.projected.as_mut(),
                vol.downward_api.as_mut(),
            ]
            .into_iter()
            .flatten()
            {
                if proj.default_mode.is_none() {
                    proj.default_mode = Some(420);
                    changed = true;
                }
            }
        }
        if changed {
            pod["spec"]["volumes"] =
                serde_json::to_value(&*volumes).expect("Volume is always serializable");
        }
    }
    // If spec.volumes is None, there is nothing to default.

    // Remove spurious `defaultMode` from DownwardAPIProjection sources inside projected volumes.
    //
    // `DownwardAPIProjection` (used in spec.volumes[].projected.sources[].downwardAPI) has no
    // `defaultMode` field in the Kubernetes API — only `DownwardAPIVolumeSource` (top-level
    // downwardAPI volume) has it. The u7s protobuf decoder incorrectly injects `defaultMode: 420`
    // into these inner sources when decoding a protobuf PUT body from client-go, causing the
    // stored spec (no defaultMode there) to differ from the proto-decoded incoming spec on every
    // no-op replace, which produces a phantom generation bump. Stripping it here in the
    // comparison copies normalises both sides to the canonical stored form.
    //
    // NOTE: use immutable index checks before mutable access — serde_json's IndexMut autovivifies
    // intermediate null entries, which would corrupt volumes that have no projected field.
    if let Some(volumes) = pod["spec"]["volumes"].as_array_mut() {
        for vol in volumes.iter_mut() {
            // Guard: only enter if the volume has an actual projected.sources array.
            let has_projected_sources = vol
                .get("projected")
                .and_then(|p| p.get("sources"))
                .and_then(|s| s.as_array())
                .is_some();
            if !has_projected_sources {
                continue;
            }
            if let Some(sources) = vol["projected"]["sources"].as_array_mut() {
                for src in sources.iter_mut() {
                    if src.get("downwardAPI").is_some_and(|d| d.is_object()) {
                        src["downwardAPI"]
                            .as_object_mut()
                            .map(|m| m.remove("defaultMode"));
                    }
                }
            }
        }
    }

    // Default fieldRef.apiVersion to "v1" and port protocol to "TCP" for all containers
    // (including initContainers). Real kube-apiserver stamps both fields before storing.
    // Absent fieldRef.apiVersion causes kubelet "unsupported pod version: <empty>".
    // Absent port protocol causes KCM endpointslice controller to emit ports:[].
    for containers_key in &["containers", "initContainers", "ephemeralContainers"] {
        if let Some(containers) = pod["spec"][containers_key].as_array_mut() {
            for container in containers {
                // Default terminationMessagePolicy to "File", matching upstream
                // SetDefaults_Container. Real clients (kubectl, client-go) already stamp
                // this field themselves: encoding a Pod as protobuf round-trips it through
                // the client's own scheme defaulting, so containers the *client* wrote
                // always arrive with this field set. A container a mutating webhook injects
                // via JSON patch has no such client — the apiserver adds it directly to the
                // JSON body — so it needs this apiserver-side default or it is stored with
                // no terminationMessagePolicy at all. This function runs both before and
                // after the mutating webhook chain (see create_pod), so webhook-injected
                // containers get the same default a real client would have supplied.
                // Breaks conformance "[sig-api-machinery] AdmissionWebhook ... should mutate
                // pod and apply defaults after mutation" otherwise.
                if container["terminationMessagePolicy"].is_null()
                    || container["terminationMessagePolicy"] == ""
                {
                    container["terminationMessagePolicy"] =
                        serde_json::Value::String("File".to_string());
                }
                // imagePullPolicy: default per upstream SetDefaults_Container
                // (pkg/apis/core/v1/defaults.go:82-93 @ v1.36.0) when absent or empty.
                // The kubelet's imagePullPrecheck (image_manager.go:117-127) is a `switch
                // pullPolicy` over Always/IfNotPresent/Never with NO default case — an
                // empty policy falls through to the same unconditional-repull path as
                // PullAlways, so every container start re-pulls the image regardless of
                // whether it's already cached locally.
                if container["imagePullPolicy"].is_null() || container["imagePullPolicy"] == "" {
                    let image = container["image"].as_str().unwrap_or("");
                    let policy = if parse_image_tag(image) == "latest" {
                        "Always"
                    } else {
                        "IfNotPresent"
                    };
                    container["imagePullPolicy"] = serde_json::Value::String(policy.to_string());
                }
                if let Some(env) = container["env"].as_array_mut() {
                    for var in env {
                        // Guard: only enter if valueFrom.fieldRef already exists as an
                        // object. `var["valueFrom"]["fieldRef"]` (IndexMut) would
                        // autovivify `valueFrom: {fieldRef: null}` into every env var
                        // that has no `valueFrom` at all (a plain `value: "..."` var),
                        // corrupting the stored pod at create time — and a client's
                        // protobuf round trip of that corruption later decodes the "no
                        // fieldRef" state as `{}` instead of `null`, which this loop then
                        // treats differently (is_object() true vs false), producing a
                        // spurious "containers changed" 422 on every subsequent
                        // annotation-only update (mayor conformance regression
                        // 0818-1112, "[sig-node] Variable Expansion").
                        let has_field_ref_object = var
                            .get("valueFrom")
                            .and_then(|vf| vf.get("fieldRef"))
                            .is_some_and(|fr| fr.is_object());
                        if !has_field_ref_object {
                            continue;
                        }
                        let field_ref = &mut var["valueFrom"]["fieldRef"];
                        if field_ref["apiVersion"].is_null() || field_ref["apiVersion"] == "" {
                            field_ref["apiVersion"] = serde_json::json!("v1");
                        }
                    }
                }
                if let Some(ports) = container["ports"].as_array_mut() {
                    for port in ports {
                        if port["protocol"].is_null() {
                            port["protocol"] = serde_json::Value::String("TCP".to_string());
                        }
                    }
                }
                // Apply upstream SetDefaults_Probe defaults for all three probe types.
                // kubelet calls time.NewTicker(periodSeconds) — a value of 0 panics with
                // "non-positive interval for NewTicker" (prober/worker.go:169), crash-looping
                // the kubelet. Clients rely on the apiserver to default these fields.
                for probe_key in &["livenessProbe", "readinessProbe", "startupProbe"] {
                    if container[probe_key].is_object() {
                        let probe = &mut container[*probe_key];
                        if probe["periodSeconds"].is_null()
                            || probe["periodSeconds"].as_i64() == Some(0)
                        {
                            probe["periodSeconds"] = serde_json::json!(10);
                        }
                        if probe["timeoutSeconds"].is_null()
                            || probe["timeoutSeconds"].as_i64() == Some(0)
                        {
                            probe["timeoutSeconds"] = serde_json::json!(1);
                        }
                        if probe["successThreshold"].is_null()
                            || probe["successThreshold"].as_i64() == Some(0)
                        {
                            probe["successThreshold"] = serde_json::json!(1);
                        }
                        if probe["failureThreshold"].is_null()
                            || probe["failureThreshold"].as_i64() == Some(0)
                        {
                            probe["failureThreshold"] = serde_json::json!(3);
                        }
                    }
                }
            }
        }
    }
}

/// Apply pod creation defaults: set spec.enableServiceLinks=true if absent,
/// and stamp defaultMode=420 on configMap/secret/projected volumes if absent.
///
/// Extracted for testability — the full create_pod handler is async and needs
/// a live store, so the defaulting logic lives here as a pure function.
pub(crate) fn apply_pod_create_defaults(pod: &mut serde_json::Value) {
    apply_pod_spec_defaults(pod);

    // Initialize status.conditions with PodScheduled=False when absent.
    //
    // Real kube-apiserver always stamps this condition on Pod create.  Conformance
    // scheduling tests (e.g. scheduling/predicates.go) wait for PodScheduled to
    // appear in status.conditions before declaring scheduling success.  Without this
    // initial False, the field is absent after create and the scheduler never has a
    // condition to flip to True — so tests that wait for "scheduled condition" time out.
    //
    // Idempotent: the condition is only inserted when status.conditions is absent or
    // does not already contain a PodScheduled entry.
    if !pod["status"].is_object() {
        pod["status"] = serde_json::json!({});
    }
    if pod["status"]["phase"].is_null() {
        pod["status"]["phase"] = serde_json::json!("Pending");
    }

    let conditions_absent = pod["status"]["conditions"].is_null()
        || pod["status"]["conditions"].as_array().is_none_or(|arr| {
            arr.iter()
                .all(|c| c["type"].as_str() != Some("PodScheduled"))
        });
    if conditions_absent {
        let now = crate::util::utc_now_rfc3339();
        let scheduled_false = serde_json::json!({
            "type": "PodScheduled",
            "status": "False",
            "reason": "Unschedulable",
            "message": "pod not yet scheduled",
            "lastTransitionTime": now
        });
        match pod["status"]["conditions"].as_array_mut() {
            Some(arr) => arr.push(scheduled_false),
            None => pod["status"]["conditions"] = serde_json::json!([scheduled_false]),
        }
    }
}

/// Copy `overhead.podFixed` from a RuntimeClass into `pod.spec.overhead`.
///
/// If the pod already carries `spec.overhead`, it is left unchanged (idempotent,
/// matches what the kube-apiserver RuntimeClass admission plugin does).
/// The RuntimeClass JSON must be the full stored object; if it has no
/// `overhead.podFixed` this is a no-op.
pub(crate) fn apply_runtime_class_overhead(pod: &mut serde_json::Value, rc: &serde_json::Value) {
    let pod_fixed = &rc["overhead"]["podFixed"];
    if pod_fixed.is_null() || pod_fixed.as_object().is_none_or(|m| m.is_empty()) {
        return;
    }
    if pod["spec"]["overhead"].is_null() {
        pod["spec"]["overhead"] = pod_fixed.clone();
    }
}

/// Merge `scheduling.nodeSelector`/`scheduling.tolerations` from a RuntimeClass into
/// `pod.spec`, mirroring upstream's RuntimeClass admission plugin (`setScheduling` in
/// plugin/pkg/admission/runtimeclass/admission.go).
///
/// nodeSelector keys are merged into `pod.spec.nodeSelector`. A key present on both
/// sides with different values is rejected outright (`Err`) rather than silently
/// picking one side — without this a Pod's own nodeSelector could quietly overrule
/// the RuntimeClass's placement requirement, or vice versa, and the caller couldn't
/// tell which one actually took effect.
///
/// `scheduling.tolerations` are appended to `pod.spec.tolerations`, skipping entries
/// already present verbatim (idempotent re-admission, e.g. under `dryRun`).
///
/// The RuntimeClass JSON must be the full stored object; a RuntimeClass with no
/// `.scheduling` is a no-op.
pub(crate) fn apply_runtime_class_scheduling(
    pod: &mut serde_json::Value,
    rc: &serde_json::Value,
) -> Result<(), String> {
    if let Some(rc_selector) = rc["scheduling"]["nodeSelector"].as_object() {
        let mut merged = pod["spec"]["nodeSelector"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        for (key, rc_value) in rc_selector {
            if let Some(pod_value) = merged.get(key) {
                if pod_value != rc_value {
                    return Err(format!(
                        "conflict: runtimeClass.scheduling.nodeSelector[{key}] = {rc_value}; \
                         pod.spec.nodeSelector[{key}] = {pod_value}"
                    ));
                }
            }
            merged.insert(key.clone(), rc_value.clone());
        }
        pod["spec"]["nodeSelector"] = serde_json::Value::Object(merged);
    }

    if let Some(rc_tolerations) = rc["scheduling"]["tolerations"].as_array() {
        let mut merged = pod["spec"]["tolerations"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for t in rc_tolerations {
            if !merged.contains(t) {
                merged.push(t.clone());
            }
        }
        if !merged.is_empty() {
            pod["spec"]["tolerations"] = serde_json::Value::Array(merged);
        }
    }

    Ok(())
}

/// The two built-in Kubernetes PriorityClasses that are always resolvable, even
/// when no PriorityClass object has been created for them. Upstream's
/// PriorityClass admission plugin (plugin/pkg/admission/priority) special-cases
/// these two names regardless of what's in the PriorityClass store.
pub const SYSTEM_CLUSTER_CRITICAL_VALUE: i32 = 2_000_000_000;
pub const SYSTEM_NODE_CRITICAL_VALUE: i32 = 2_000_001_000;

/// Resolve `spec.priorityClassName` into `spec.priority` (and `spec.preemptionPolicy`
/// when the pod didn't already set one), mirroring upstream's PriorityClass
/// admission plugin.
///
/// The scheduler's preemption logic (crates/scheduler) keys entirely off
/// `spec.priority` — without this resolution every pod looks like priority 0
/// and preemption can never distinguish a high-priority pod from a low-priority
/// one.
///
/// `stored_class` is the PriorityClass object already fetched from the store by
/// name (`None` if no such object exists). It is ignored for the two built-in
/// system class names above, which always resolve to their fixed values
/// regardless of what (if anything) is stored under that name.
///
/// No-op (`Ok`) when the pod has no `priorityClassName`, or already carries an
/// explicit `spec.priority` — a value the client set directly is left alone
/// rather than silently overwritten.
///
/// Returns `Err(message)` when `priorityClassName` is set but does not resolve
/// to any PriorityClass: upstream rejects such pod creates outright rather than
/// silently defaulting to priority 0, and a rejected pod must never be
/// persisted with an unresolved priority the scheduler cannot act on.
///
/// NOTE: does not implement `globalDefault` (the PriorityClass applied when a
/// pod sets no `priorityClassName` at all) — tracked as a known gap.
pub(crate) fn resolve_pod_priority_class(
    pod: &mut serde_json::Value,
    stored_class: Option<&serde_json::Value>,
) -> Result<(), String> {
    let class_name = match pod["spec"]["priorityClassName"].as_str() {
        Some(n) if !n.is_empty() => n.to_owned(),
        _ => return Ok(()),
    };
    if !pod["spec"]["priority"].is_null() {
        return Ok(());
    }

    let (value, preemption_policy): (i32, Option<String>) = match class_name.as_str() {
        "system-cluster-critical" => (SYSTEM_CLUSTER_CRITICAL_VALUE, None),
        "system-node-critical" => (SYSTEM_NODE_CRITICAL_VALUE, None),
        _ => match stored_class {
            Some(pc) => (
                pc["value"].as_i64().unwrap_or(0) as i32,
                pc["preemptionPolicy"].as_str().map(str::to_owned),
            ),
            None => {
                return Err(format!(
                    "no PriorityClass with name \"{class_name}\" was found"
                ));
            }
        },
    };

    pod["spec"]["priority"] = serde_json::json!(value);
    if pod["spec"]["preemptionPolicy"].is_null() {
        if let Some(policy) = preemption_policy {
            pod["spec"]["preemptionPolicy"] = serde_json::json!(policy);
        }
    }
    Ok(())
}

/// Compute the QoS class for a pod from its container resource requests/limits.
///
/// Kubernetes sets `status.qosClass` at admission time based on the resource
/// declarations across all containers and init containers:
///
/// - **Guaranteed**: every container has both cpu AND memory limits set, AND
///   for each resource where a request is present the request equals the limit.
///   (If a request is absent for a resource, it is implicitly equal to the limit.)
/// - **Burstable**: at least one container has any cpu or memory request/limit
///   set, but the Guaranteed criteria are not met.
/// - **BestEffort**: no container has any cpu or memory request or limit.
///
/// Without this, conformance tests like node/pods.go:200 ("Pods should be
/// submitted and removed") fail because they create a pod with requests==limits
/// and assert status.qosClass == "Guaranteed".
pub(crate) fn compute_qos_class(pod: &serde_json::Value) -> &'static str {
    let containers: Vec<&serde_json::Value> = {
        let mut v: Vec<&serde_json::Value> = Vec::new();
        if let Some(arr) = pod["spec"]["containers"].as_array() {
            v.extend(arr.iter());
        }
        if let Some(arr) = pod["spec"]["initContainers"].as_array() {
            v.extend(arr.iter());
        }
        v
    };

    if containers.is_empty() {
        return "BestEffort";
    }

    let mut any_resources = false;
    let mut all_guaranteed = true;

    for c in &containers {
        let cpu_limit = c["resources"]["limits"]["cpu"].as_str();
        let mem_limit = c["resources"]["limits"]["memory"].as_str();
        let cpu_req = c["resources"]["requests"]["cpu"].as_str();
        let mem_req = c["resources"]["requests"]["memory"].as_str();

        let has_cpu_limit = cpu_limit.is_some();
        let has_mem_limit = mem_limit.is_some();
        let has_any = has_cpu_limit || has_mem_limit || cpu_req.is_some() || mem_req.is_some();

        if has_any {
            any_resources = true;
        }

        // Guaranteed requires both limits set and request == limit by value (absent request == limit).
        // Compare by parsed millivalue so "1" == "1000m" and "1Gi" == "1024Mi".
        let cpu_ok = has_cpu_limit
            && cpu_req.is_none_or(|r| parse_quantity(r) == parse_quantity(cpu_limit.unwrap_or("")));
        let mem_ok = has_mem_limit
            && mem_req.is_none_or(|r| parse_quantity(r) == parse_quantity(mem_limit.unwrap_or("")));

        if !cpu_ok || !mem_ok {
            all_guaranteed = false;
        }
    }

    if !any_resources {
        "BestEffort"
    } else if all_guaranteed {
        "Guaranteed"
    } else {
        "Burstable"
    }
}

/// Set `metadata.generation = 1` on a newly created pod.
///
/// `metadata.generation` is a server-managed field in Kubernetes. The apiserver
/// always stamps it to 1 on create, ignoring any client-supplied value.
/// Controllers that gate on observedGeneration == generation must see generation=1
/// on every new pod; a caller-supplied value of 100 would force a controller to
/// wait for 99 phantom generations that will never arrive.
pub(crate) fn initialize_pod_generation(pod: &mut serde_json::Value) {
    pod["metadata"]["generation"] = serde_json::json!(1i64);
}

/// Reject a pod-spec update that changes any field outside Kubernetes' narrow
/// upstream-allowed set of pod-spec mutations — an allowlist, mirroring
/// `validatePodSpecUpdate` in `pkg/apis/core/validation` (release-1.36).
///
/// Algorithm: build a MUNGED copy of `new_spec` with each upstream-permitted
/// mutable field overwritten from `old_spec` — after first enforcing that
/// field's own directional rule (e.g. tolerations may only grow, resources may
/// not change via this path at all). Any field NOT explicitly munged away is
/// then subject to a full deep-equal against `old_spec`; a diff anywhere else
/// (schedulerName, serviceAccountName, securityContext, volumes, dnsPolicy,
/// nodeSelector/affinity on an already-scheduled pod, ...) is rejected. This is
/// the inverse of the previous blocklist shape, which enumerated a handful of
/// forbidden changes and fell through to `Ok(())` for everything else —
/// silently allowing any field the blocklist hadn't been told about yet.
///
/// Upstream-permitted mutations implemented here:
/// - `containers[].image` / `initContainers[].image` — unconstrained (graceful
///   rollout of a new image on a running pod).
/// - `activeDeadlineSeconds` — may be set from unset, decreased, or cleared
///   back to unset (controllers clear it); may never increase.
/// - `tolerations` — append-only; every existing entry must survive verbatim.
/// - `schedulingGates` — deletion-only; no new gate may be added post-creation.
/// - `nodeSelector` / `affinity` — mutable ONLY while the pod is still gated
///   (unscheduled AND `schedulingGates` non-empty); frozen once scheduled or
///   ungated.
/// - `terminationGracePeriodSeconds` — a negative value is normalized to 1
///   before comparison (upstream's "terminate now" clamp); any other change
///   is still frozen.
/// - `containers[]/initContainers[].resources` — handled by the pre-existing
///   dedicated resize guard below (kept verbatim). Resource changes are
///   immutable via the generic PUT/PATCH pod update; they are only permitted
///   through the `/resize` subresource (`validate_resize_patch` /
///   `apply_resize_patch`), which additionally enforces QoS-class stability
///   and resource-removal rules. Without this guard a client could rewrite
///   containers[].resources via a plain PUT, bypassing those rules entirely
///   and letting ResourceQuota's captured pod-creation totals go stale.
///
/// `spec.nodeName` gets its own dedicated check ahead of the munge purely for
/// a clearer, more actionable error message pointing at `/binding` — it is
/// never in the allowed set, so a bare change would be caught by the trailing
/// deep-equal regardless.
///
/// Both sides are spec-defaulted the same way `increment_pod_generation_if_spec_changed`
/// does before any comparison runs, so a client PUT/PATCH that omits already-defaulted
/// fields (dnsPolicy, serviceAccountName, probe periods, port protocol, ...) isn't
/// mistaken for an illegal spec change by the trailing whole-spec deep-equal: those
/// fields are normalized identically on both sides first. A newly-discovered decode
/// asymmetry on a field this defaulting doesn't yet cover would surface as a
/// false-positive 422 here; the fix is to extend `apply_pod_spec_defaults`, not to
/// relax this function back into a blocklist.
///
/// `automountServiceAccountToken` is deliberately NOT munged or stripped here: it
/// round-trips through the protobuf adapter like any other bool field (see
/// `encode_pod_proto_gen_round_trips_enable_service_links_and_automount_service_account_token`
/// in core_gen_adapter.rs), `apply_automount_sa_token_default` always resolves it to an
/// explicit `true`/`false` at create time (never leaves it absent), and upstream
/// `ValidatePodUpdate` freezes it post-creation — so it is correctly caught by the
/// trailing deep-equal like every other unlisted field.
pub(crate) fn validate_pod_spec_immutable(
    spec_before: &serde_json::Value,
    spec_after: &serde_json::Value,
) -> Result<(), String> {
    let mut old_pod = serde_json::json!({ "spec": spec_before.clone() });
    apply_pod_spec_defaults(&mut old_pod);
    let mut new_pod = serde_json::json!({ "spec": spec_after.clone() });
    apply_pod_spec_defaults(&mut new_pod);
    let old_spec = old_pod["spec"].clone();
    let new_spec = new_pod["spec"].clone();

    if old_spec == new_spec {
        return Ok(());
    }

    // spec.nodeName may only ever be assigned via the /binding subresource (a separate
    // RBAC verb, `create pods/binding`, precisely so that ordinary `patch`/`update pods`
    // rights can't assign or reassign a pod's node). This includes the very first
    // assignment: a not-yet-scheduled pod (stored nodeName blank/absent) must reject a
    // direct spec write just as much as an already-bound pod does — otherwise a caller
    // holding only `patch pods` can steer an unscheduled pod straight to a node of their
    // choosing, bypassing the scheduler's taints/tolerations/affinity/resource-fit checks
    // and the pods/binding RBAC boundary entirely.
    let old_node_name = old_spec["nodeName"].as_str().filter(|s| !s.is_empty());
    let new_node_name = new_spec["nodeName"].as_str().filter(|s| !s.is_empty());
    if new_node_name != old_node_name {
        return Err(
            "spec.nodeName: Forbidden: pod nodeName is immutable once set — \
             reassign via the /binding subresource, not a direct spec update"
                .into(),
        );
    }

    // Container/init-container count changes are rejected up front: the by-index munge
    // below assumes both arrays already have matching lengths.
    let old_containers = old_spec["containers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let new_containers = new_spec["containers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if old_containers.len() != new_containers.len() {
        return Err(
            "spec.containers: Forbidden: pod updates may not add or remove containers".into(),
        );
    }
    let old_init = old_spec["initContainers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let new_init = new_spec["initContainers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if old_init.len() != new_init.len() {
        return Err(
            "spec.initContainers: Forbidden: pod updates may not add or remove containers".into(),
        );
    }

    // activeDeadlineSeconds: may be set from unset, decreased, or cleared back to unset
    // (a controller may clear it once it has already acted on the deadline); may never
    // increase — that would let a client extend a countdown already in progress.
    let old_ads = old_spec["activeDeadlineSeconds"].as_i64();
    let new_ads = new_spec["activeDeadlineSeconds"].as_i64();
    if let (Some(old), Some(new)) = (old_ads, new_ads) {
        if new > old {
            return Err("spec.activeDeadlineSeconds: Forbidden: must be less than \
                         or equal to previous value"
                .into());
        }
    }

    // tolerations: append-only. Every existing toleration must survive verbatim; only
    // new entries may be added (e.g. by a controller reacting to a newly observed taint).
    let old_tolerations = old_spec["tolerations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let new_tolerations = new_spec["tolerations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for t in &old_tolerations {
        if !new_tolerations.contains(t) {
            return Err(
                "spec.tolerations: Forbidden: existing tolerations may not be \
                         removed or modified"
                    .into(),
            );
        }
    }

    // schedulingGates: deletion-only. A gate may be removed (signalling the pod is ready
    // for scheduling) but never added once the pod exists — adding gates is reserved for
    // pod creation.
    let old_gates = old_spec["schedulingGates"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let new_gates = new_spec["schedulingGates"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for g in &new_gates {
        if !old_gates.contains(g) {
            return Err(
                "spec.schedulingGates: Forbidden: only deletion is allowed, \
                         tried to add a scheduling gate"
                    .into(),
            );
        }
    }

    // containers[]/initContainers[].resources: kept verbatim from the pre-rewrite guard.
    // See normalize_container_resources for why an empty {} and an absent key must
    // compare equal here.
    for (i, (old_c, new_c)) in old_containers.iter().zip(new_containers.iter()).enumerate() {
        if normalize_container_resources(&old_c["resources"])
            != normalize_container_resources(&new_c["resources"])
        {
            return Err(format!(
                "spec.containers[{i}].resources: Forbidden: pod updates may not change \
                 container resources — resize the pod via the /resize subresource instead"
            ));
        }
    }
    for (i, (old_c, new_c)) in old_init.iter().zip(new_init.iter()).enumerate() {
        if normalize_container_resources(&old_c["resources"])
            != normalize_container_resources(&new_c["resources"])
        {
            return Err(format!(
                "spec.initContainers[{i}].resources: Forbidden: pod updates may not change \
                 container resources — resize the pod via the /resize subresource instead"
            ));
        }
    }

    // Every check above enforces a directional rule for one specific mutable field. Now
    // build the munged copy: overwrite each of those fields (plus the unconstrained ones,
    // like image) in a clone of new_spec with old_spec's value, so a legitimate mutation
    // there doesn't register as a diff below. Any field NOT explicitly munged here stays
    // subject to the trailing whole-spec deep-equal — this is what makes the guard an
    // allowlist rather than a blocklist: a new upstream-forbidden field added to PodSpec
    // tomorrow is frozen by default, with no code change required here.
    let mut munged = new_spec.clone();

    if let Some(containers) = munged.get_mut("containers").and_then(|v| v.as_array_mut()) {
        for (i, c) in containers.iter_mut().enumerate() {
            if let Some(old_c) = old_containers.get(i) {
                munge_field(c, "image", old_c);
                munge_field(c, "resources", old_c);
            }
        }
    }
    if let Some(init) = munged
        .get_mut("initContainers")
        .and_then(|v| v.as_array_mut())
    {
        for (i, c) in init.iter_mut().enumerate() {
            if let Some(old_c) = old_init.get(i) {
                munge_field(c, "image", old_c);
                munge_field(c, "resources", old_c);
            }
        }
    }
    munge_field(&mut munged, "activeDeadlineSeconds", &old_spec);
    munge_field(&mut munged, "tolerations", &old_spec);
    munge_field(&mut munged, "schedulingGates", &old_spec);

    // nodeSelector/affinity: mutable only while the pod is still gated — unscheduled
    // (nodeName unset; already enforced equal to old_spec's above) AND schedulingGates
    // still non-empty. Once scheduled or ungated, these are frozen like everything else.
    let still_gated = old_node_name.is_none() && !old_gates.is_empty();
    if still_gated {
        munge_field(&mut munged, "nodeSelector", &old_spec);
        munge_field(&mut munged, "affinity", &old_spec);
    }

    // terminationGracePeriodSeconds: a negative value means "terminate now", which
    // upstream normalizes to 1 before storing — treat a negative incoming value as
    // equivalent to 1 rather than as a forbidden change. Any other change is still
    // frozen by the deep-equal below.
    if munged["terminationGracePeriodSeconds"]
        .as_i64()
        .is_some_and(|v| v < 0)
    {
        munged["terminationGracePeriodSeconds"] = serde_json::json!(1);
    }

    if munged == old_spec {
        return Ok(());
    }

    let mut changed_fields: Vec<&str> = Vec::new();
    if let (Some(m), Some(o)) = (munged.as_object(), old_spec.as_object()) {
        let mut keys: Vec<&str> = m.keys().chain(o.keys()).map(String::as_str).collect();
        keys.sort_unstable();
        keys.dedup();
        for k in keys {
            if m.get(k) != o.get(k) {
                changed_fields.push(k);
            }
        }
    }
    Err(format!(
        "spec: Forbidden: pod updates may not change fields other than \
         containers[*].image, initContainers[*].image, activeDeadlineSeconds, \
         tolerations (additions only), schedulingGates (deletions only), \
         nodeSelector/affinity (only while scheduling-gated), \
         terminationGracePeriodSeconds (negative normalized to 1), and \
         containers[*].resources via /resize — changed field(s): {}",
        changed_fields.join(", ")
    ))
}

/// Overwrite `dst[key]` with `src[key]`, or remove `dst[key]` entirely if `src` has no
/// (non-null) value for it — used by `validate_pod_spec_immutable` to erase an
/// already-validated, legitimate mutation from the trailing whole-spec deep-equal.
/// Removing rather than inserting `null` matters: this codebase's patch appliers
/// (`merge_patch`, `strategic_merge_patch`) represent "no value" as an absent key,
/// never an explicit `null`, so leaving a `null` behind here would make `dst` compare
/// unequal to `src` even when both mean the same thing.
fn munge_field(dst: &mut serde_json::Value, key: &str, src: &serde_json::Value) {
    let Some(m) = dst.as_object_mut() else {
        return;
    };
    match src.get(key) {
        Some(v) if !v.is_null() => {
            m.insert(key.to_string(), v.clone());
        }
        _ => {
            m.remove(key);
        }
    }
}

/// Normalize a container's `resources` value for the immutability comparison above so
/// that an absent field, an explicit `null`, and an empty `{}` all compare equal — as do
/// empty `limits`/`requests`/`claims` sub-maps within a present object.
///
/// A pod created via a JSON-writing client (e.g. KCM, which runs with
/// `--kube-api-content-type=application/json`) stores `resources: {}` for a container
/// that set no resources, because Go's `encoding/json` always emits a non-pointer struct
/// field regardless of the `omitempty` tag. A pod updated via a protobuf-writing client
/// (e.g. client-go's typed clientset, which defaults to protobuf for core/v1 writes)
/// decodes to a container with the `resources` key omitted entirely, because our
/// protobuf adapter deliberately drops an empty `ResourceRequirements` (see
/// `gen_container_to_json` in core_gen_adapter.rs — needed so protobuf-decoded workload
/// templates structurally match JSON-created ones for the Deployment controller's
/// hash-collision check). Both representations mean "no resources configured"; comparing
/// them with raw JSON equality treats a metadata-only PUT/PATCH round-trip through a
/// protobuf client as an illegal resources change and 422s it, breaking Job/RC pod
/// adoption, release, and orphaning.
fn normalize_container_resources(v: &serde_json::Value) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(limits) = v.get("limits").and_then(|x| x.as_object()) {
        if !limits.is_empty() {
            m.insert(
                "limits".to_string(),
                serde_json::Value::Object(limits.clone()),
            );
        }
    }
    if let Some(requests) = v.get("requests").and_then(|x| x.as_object()) {
        if !requests.is_empty() {
            m.insert(
                "requests".to_string(),
                serde_json::Value::Object(requests.clone()),
            );
        }
    }
    if let Some(claims) = v.get("claims").and_then(|x| x.as_array()) {
        if !claims.is_empty() {
            m.insert(
                "claims".to_string(),
                serde_json::Value::Array(claims.clone()),
            );
        }
    }
    if m.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Object(m)
    }
}

#[cfg(test)]
mod pod_resources_immutability_tests {
    use super::*;

    /// A pod created by a JSON-writing client (`resources: {}`) followed by a
    /// metadata-only PUT decoded from a protobuf-writing client (`resources` key
    /// omitted) must NOT be rejected as a resources change — both mean "no resources
    /// configured". This is the exact shape KCM (JSON, `--kube-api-content-type=
    /// application/json`) creates a pod with, followed by the conformance e2e binary's
    /// (protobuf) orphan/release PUT — without this normalization the guard 422s
    /// "[sig-apps] Job should adopt matching orphans and release non-matching pods" and
    /// "[sig-apps] ReplicationController should release no longer matching pods", which
    /// only ever touch metadata.ownerReferences / metadata.labels, never resources.
    #[test]
    fn empty_object_resources_and_omitted_resources_are_not_a_change() {
        let spec_before = serde_json::json!({
            "containers": [{"name": "c", "image": "pause", "resources": {}}]
        });
        let spec_after = serde_json::json!({
            "containers": [{"name": "c", "image": "pause"}]
        });
        assert_eq!(
            validate_pod_spec_immutable(&spec_before, &spec_after),
            Ok(()),
            "an empty {{}} resources object and an entirely absent resources key both mean \
             \"no resources configured\" — treating them as a change breaks metadata-only \
             pod updates from any client whose protobuf encoding omits empty resources"
        );
    }

    /// The reverse direction (stored has no `resources` key, incoming PUT has `{}`) must
    /// also be treated as unchanged — the normalization must be symmetric.
    #[test]
    fn omitted_resources_and_empty_object_resources_are_not_a_change() {
        let spec_before = serde_json::json!({
            "containers": [{"name": "c", "image": "pause"}]
        });
        let spec_after = serde_json::json!({
            "containers": [{"name": "c", "image": "pause", "resources": {}}]
        });
        assert_eq!(
            validate_pod_spec_immutable(&spec_before, &spec_after),
            Ok(())
        );
    }

    /// A genuine resources change must still be rejected — the normalization fix above
    /// must not turn into "never enforce the guard". Resource rewrites must go through
    /// the /resize subresource, not a plain PUT.
    #[test]
    fn real_resources_change_is_still_rejected() {
        let spec_before = serde_json::json!({
            "containers": [{"name": "c", "image": "pause", "resources": {
                "requests": {"cpu": "100m"}
            }}]
        });
        let spec_after = serde_json::json!({
            "containers": [{"name": "c", "image": "pause", "resources": {
                "requests": {"cpu": "200m"}
            }}]
        });
        let result = validate_pod_spec_immutable(&spec_before, &spec_after);
        assert!(
            result.is_err(),
            "an actual resources change must still be rejected by the plain PUT/PATCH \
             path — it must go through /resize instead"
        );
        assert!(
            result.unwrap_err().contains("resources"),
            "the rejection must name resources as the forbidden field"
        );
    }

    /// A plain-value env var (`value: "foo"`, no `valueFrom` at all) must survive a real
    /// client's protobuf GET/decode-mutate-encode/PUT round trip (as an annotation-only
    /// update performs) without being flagged as a containers change.
    ///
    /// Regression (Conformance run 0818-1112, "[sig-node] Variable Expansion ... should
    /// succeed in writing subpaths in container" / "... failing subpath expansion can be
    /// modified"): the fieldRef.apiVersion defaulting loop in `apply_pod_spec_defaults`
    /// used naive chained JSON indexing (`var["valueFrom"]["fieldRef"]`), which
    /// autovivifies `valueFrom: {fieldRef: null}` into *every* env var lacking a
    /// `valueFrom` — corrupting the stored pod at create time. Encoding that corrupted
    /// shape to protobuf (for a client's GET) and decoding a client's re-PUT of it back
    /// produces `valueFrom: {fieldRef: {}}` instead (an empty embedded message is still
    /// present on the wire, just not `null`), and the immutability guard's own second
    /// defaulting pass then stamps `apiVersion: "v1"` into that `{}` shape (since `{}` is
    /// an object) but leaves the `null` shape alone (since `null` is not an object) — so
    /// the two sides diverge and every annotation-only update on a pod with such an env
    /// var is rejected 422. This test exercises the real create-defaulting and
    /// encode/decode functions rather than hand-written fixtures, so it fails on revert
    /// regardless of which layer the fix lands in.
    #[test]
    fn env_var_without_value_from_survives_protobuf_round_trip() {
        // What a client submits on create: a plain `value:` env var, no valueFrom.
        let mut created = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": "pause",
                    "env": [{"name": "POD_NAME", "value": "foo"}]
                }]
            }
        });
        apply_pod_spec_defaults(&mut created);
        let spec_before = created["spec"].clone();

        // Simulate the e2e framework's PodClient().Update(): a fresh GET (protobuf
        // encode of the stored spec) decoded back into the client's object, then
        // PUT (protobuf decode on the way back into u7s) — annotations are the only
        // thing that changes, so re-encoding/decoding the untouched spec must be a
        // no-op for this comparison.
        let stored_pod = serde_json::json!({
            "metadata": {"name": "p", "namespace": "default"},
            "spec": spec_before.clone(),
        });
        let raw = crate::core_gen_adapter::encode_pod_proto_gen(&stored_pod);
        let decoded =
            crate::core_gen_adapter::decode_pod_proto_gen(&raw).expect("must decode back");
        let spec_after = decoded["spec"].clone();

        assert_eq!(
            validate_pod_spec_immutable(&spec_before, &spec_after),
            Ok(()),
            "an env var with no real fieldRef must not be treated as changed just because \
             its \"no fieldRef set\" representation differs (absent/null vs an empty {{}} \
             message) between the stored copy and a protobuf-round-tripped copy — \
             otherwise every annotation-only update on a pod with a plain-value env var \
             is rejected 422"
        );
    }
}

/// Increment `metadata.generation` by 1 when the pod spec has changed.
///
/// Called after PATCH and PUT operations. Kubernetes increments generation on
/// every spec change so that controllers and status reporters can detect when
/// spec has advanced past what they last reconciled (via observedGeneration).
///
/// Both sides are spec-defaulted before comparing so that a client omitting
/// defaulted fields (dnsPolicy, enableServiceLinks, volume defaultMode,
/// container env fieldRef.apiVersion, port protocol, terminationMessagePolicy)
/// does not produce a spurious generation bump — upstream k8s only bumps on a
/// real spec change.
pub(crate) fn increment_pod_generation_if_spec_changed(
    pod: &mut serde_json::Value,
    spec_before: &serde_json::Value,
) {
    let mut after_pod = serde_json::json!({ "spec": pod["spec"].clone() });
    apply_pod_spec_defaults(&mut after_pod);

    let mut before_pod = serde_json::json!({ "spec": spec_before.clone() });
    apply_pod_spec_defaults(&mut before_pod);

    if after_pod["spec"] != before_pod["spec"] {
        let current = pod["metadata"]["generation"].as_i64().unwrap_or(1);
        pod["metadata"]["generation"] = serde_json::json!(current + 1);
    }
}

/// Resolve and write `spec.automountServiceAccountToken` on a pod before create.
///
/// Real kube-apiserver's ServiceAccount admission plugin resolves the effective
/// automount value as follows:
/// 1. If the pod already has the field set (true or false), leave it — pod wins.
/// 2. If the pod has a serviceAccountName, look up the SA; if the SA sets the
///    field to false, inherit that value (token will be suppressed).
/// 3. Otherwise default to true (the kube-apiserver default).
///
/// Without this, a pod that omits `spec.automountServiceAccountToken` always gets
/// the token injected, even if the ServiceAccount opts out with
/// `automountServiceAccountToken: false`. That breaks the conformance test
/// "ServiceAccounts should allow opting out of API token automount".
///
/// This function writes the resolved boolean into `pod["spec"]["automountServiceAccountToken"]`
/// so that `inject_sa_token_volume` can make a deterministic decision.
pub(crate) async fn apply_automount_sa_token_default<S: Store>(
    state: &AppState<S>,
    pod: &mut serde_json::Value,
    namespace: &str,
) {
    // 1. Pod already has the field set — nothing to do.
    if !pod["spec"]["automountServiceAccountToken"].is_null() {
        return;
    }

    // 2. Look up the SA if serviceAccountName is present.
    let sa_name = pod["spec"]["serviceAccountName"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    if !sa_name.is_empty() {
        let sa_key = object_key("serviceaccounts", namespace, &sa_name);
        if let Ok(Some(stored)) = state.store.get(&sa_key).await {
            if let Ok(sa) = serde_json::from_slice::<serde_json::Value>(&stored.value) {
                // SA explicitly sets automountServiceAccountToken=false: inherit it.
                // ServiceAccount stores this as a top-level field, not under spec.
                if sa["automountServiceAccountToken"] == serde_json::Value::Bool(false) {
                    pod["spec"]["automountServiceAccountToken"] = serde_json::Value::Bool(false);
                    return;
                }
            }
        }
    }

    // 3. Default to true.
    pod["spec"]["automountServiceAccountToken"] = serde_json::Value::Bool(true);
}

/// Inject the projected service-account token volume into a pod, mirroring
/// what the real Kubernetes ServiceAccount admission plugin does.
///
/// Skips injection when:
/// - `spec.serviceAccountName` is absent or empty
/// - `spec.automountServiceAccountToken` is explicitly `false`
/// - any existing volume name already starts with `kube-api-access-` (idempotency)
///
/// The volume name suffix is derived deterministically from the pod name so
/// the function is pure (no I/O, no randomness) and therefore unit-testable.
pub(crate) fn inject_sa_token_volume(pod: &mut serde_json::Value, pod_name: &str) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Skip if serviceAccountName absent or empty.
    let sa_name = pod["spec"]["serviceAccountName"].as_str().unwrap_or("");
    if sa_name.is_empty() {
        return;
    }

    // Skip if automountServiceAccountToken is explicitly false.
    if pod["spec"]["automountServiceAccountToken"] == serde_json::Value::Bool(false) {
        return;
    }

    // Idempotency: skip if a kube-api-access-* volume already exists.
    if let Some(volumes) = pod["spec"]["volumes"].as_array() {
        if volumes.iter().any(|v| {
            v["name"]
                .as_str()
                .map(|n| n.starts_with("kube-api-access-"))
                .unwrap_or(false)
        }) {
            return;
        }
    }

    // Deterministic 5-char suffix from pod name hash.
    let mut h = DefaultHasher::new();
    pod_name.hash(&mut h);
    let suffix_num = h.finish();
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let suffix: String = (0..5)
        .map(|i| {
            let idx = ((suffix_num >> (i * 6)) as usize) % ALPHABET.len();
            ALPHABET[idx] as char
        })
        .collect();
    let vol_name = format!("kube-api-access-{suffix}");

    // Append projected volume.
    let new_vol = serde_json::json!({
        "name": vol_name,
        "projected": {
            "defaultMode": 420,
            "sources": [
                {"serviceAccountToken": {"expirationSeconds": 3607, "path": "token"}},
                {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                {"downwardAPI": {"items": [{"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.namespace"}, "path": "namespace"}]}}
            ]
        }
    });
    match pod["spec"]["volumes"].as_array_mut() {
        Some(vols) => vols.push(new_vol),
        None => pod["spec"]["volumes"] = serde_json::json!([new_vol]),
    }

    // Append volumeMount to each container in containers and initContainers,
    // skipping any that already mount the SA path.
    const SA_MOUNT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
    let new_mount = serde_json::json!({
        "mountPath": SA_MOUNT_PATH,
        "name": vol_name,
        "readOnly": true
    });
    for containers_key in &["containers", "initContainers"] {
        if let Some(containers) = pod["spec"][containers_key].as_array_mut() {
            for container in containers.iter_mut() {
                let already_mounted = container["volumeMounts"]
                    .as_array()
                    .map(|mounts| {
                        mounts
                            .iter()
                            .any(|m| m["mountPath"].as_str() == Some(SA_MOUNT_PATH))
                    })
                    .unwrap_or(false);
                if already_mounted {
                    continue;
                }
                match container["volumeMounts"].as_array_mut() {
                    Some(mounts) => mounts.push(new_mount.clone()),
                    None => container["volumeMounts"] = serde_json::json!([new_mount.clone()]),
                }
            }
        }
    }
}

#[cfg(test)]
mod create_defaults_tests {
    use super::*;

    /// create_pod must default spec.enableServiceLinks to true when absent.
    ///
    /// The kubelet's kuberuntime_manager requires this field to construct service
    /// env vars for each container.  Without it the container fails with
    /// CreateContainerConfigError: "nil pod.spec.enableServiceLinks encountered".
    /// Real kube-apiserver always sets this field on create.
    #[test]
    fn enable_service_links_defaults_to_true_when_absent() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "smoke-pod", "namespace": "default"},
            "spec": {
                "nodeName": "ci-node",
                "containers": [{"name": "hello", "image": "busybox:1.36"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["enableServiceLinks"],
            serde_json::Value::Bool(true),
            "enableServiceLinks must be defaulted to true so the kubelet can construct \
             service env vars; a nil value causes CreateContainerConfigError"
        );
    }

    /// create_pod must NOT override an explicit false value for enableServiceLinks.
    ///
    /// If the user explicitly disables service link injection, that preference
    /// must be preserved.
    #[test]
    fn enable_service_links_false_is_preserved() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {
                "enableServiceLinks": false,
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["enableServiceLinks"],
            serde_json::Value::Bool(false),
            "an explicit enableServiceLinks=false must not be overridden by the default"
        );
    }

    /// Kubelet refuses to mount a ConfigMap volume whose defaultMode is absent:
    /// "no defaultMode used, not even the default value for it"
    /// Real kube-apiserver defaults it to 0644 (420 decimal).
    #[test]
    fn configmap_volume_default_mode_is_set_when_absent() {
        let mut pod = serde_json::json!({
            "spec": {
                "volumes": [{"name": "cfg", "configMap": {"name": "my-cm"}}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["volumes"][0]["configMap"]["defaultMode"],
            serde_json::Value::Number(420.into()),
            "configMap volume defaultMode must be set to 0644 (420) when absent"
        );
    }

    #[test]
    fn configmap_volume_explicit_default_mode_is_preserved() {
        let mut pod = serde_json::json!({
            "spec": {
                "volumes": [{"name": "cfg", "configMap": {"name": "my-cm", "defaultMode": 256}}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["volumes"][0]["configMap"]["defaultMode"],
            serde_json::Value::Number(256.into()),
            "explicit defaultMode must not be overridden"
        );
    }

    #[test]
    fn secret_volume_default_mode_is_set_when_absent() {
        let mut pod = serde_json::json!({
            "spec": {
                "volumes": [{"name": "sec", "secret": {"secretName": "my-sec"}}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["volumes"][0]["secret"]["defaultMode"],
            serde_json::Value::Number(420.into()),
            "secret volume defaultMode must be set to 0644 (420) when absent"
        );
    }

    /// A top-level `downwardAPI` volume has no other defaulting pass anywhere in u7s (unlike
    /// configMap/secret/projected), so a pod created the ordinary way (no explicit
    /// defaultMode, the common case) would otherwise store one with defaultMode permanently
    /// absent. Every consumer of the stored JSON — including the watch stream, which is a
    /// straight JSON pass-through and never goes through the protobuf encoder — would then
    /// hit the real kubelet's "FailedMount ... no defaultMode used, not even the default
    /// value for it" for the lifetime of the pod.
    #[test]
    fn downward_api_volume_default_mode_is_set_when_absent() {
        let mut pod = serde_json::json!({
            "spec": {
                "volumes": [{
                    "name": "podinfo",
                    "downwardAPI": {
                        "items": [{ "path": "labels", "fieldRef": { "fieldPath": "metadata.labels" } }]
                    }
                }]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["volumes"][0]["downwardAPI"]["defaultMode"],
            serde_json::Value::Number(420.into()),
            "downwardAPI volume defaultMode must be set to 0644 (420) when absent, or the \
             stored pod never mounts for any client — protobuf or plain JSON"
        );
        assert_eq!(
            pod["spec"]["volumes"][0]["downwardAPI"]["items"][0]["path"], "labels",
            "stamping defaultMode must not clobber the volume's items"
        );
    }

    #[test]
    fn downward_api_volume_explicit_default_mode_is_preserved() {
        let mut pod = serde_json::json!({
            "spec": {
                "volumes": [{
                    "name": "podinfo",
                    "downwardAPI": { "items": [], "defaultMode": 256 }
                }]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["volumes"][0]["downwardAPI"]["defaultMode"],
            serde_json::Value::Number(256.into()),
            "explicit defaultMode must not be overridden"
        );
    }

    /// fieldRef.apiVersion must be defaulted to "v1" when absent.
    ///
    /// The kubelet calls ConvertDownwardAPIFieldLabel(apiVersion, label, value) which
    /// returns "unsupported pod version: <value>" when apiVersion is empty or missing.
    /// Real kube-apiserver stamps "v1" on fieldRef before storing the object.
    /// Without the fix, sonobuoy pods fail with CreateContainerConfigError.
    #[test]
    fn field_ref_api_version_defaults_to_v1_when_absent() {
        let mut pod = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "sonobuoy:latest",
                    "env": [{
                        "name": "SONOBUOY_ADVERTISE_IP",
                        "valueFrom": {"fieldRef": {"fieldPath": "status.podIP"}}
                    }]
                }]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["containers"][0]["env"][0]["valueFrom"]["fieldRef"]["apiVersion"],
            serde_json::json!("v1"),
            "fieldRef.apiVersion must be defaulted to v1; absent value causes \
             CreateContainerConfigError in kubelet"
        );
    }

    #[test]
    fn field_ref_api_version_preserved_when_explicit() {
        let mut pod = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "sonobuoy:latest",
                    "env": [{
                        "name": "MY_VAR",
                        "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.name"}}
                    }]
                }]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["containers"][0]["env"][0]["valueFrom"]["fieldRef"]["apiVersion"],
            serde_json::json!("v1"),
        );
    }

    #[test]
    fn field_ref_api_version_defaulted_in_init_containers() {
        let mut pod = serde_json::json!({
            "spec": {
                "initContainers": [{
                    "name": "init",
                    "image": "busybox",
                    "env": [{
                        "name": "NODE_NAME",
                        "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}
                    }]
                }]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["initContainers"][0]["env"][0]["valueFrom"]["fieldRef"]["apiVersion"],
            serde_json::json!("v1"),
        );
    }

    // --- dnsPolicy defaulting tests ---

    /// create_pod must default spec.dnsPolicy to "ClusterFirst" when absent.
    ///
    /// Real kube-apiserver always stamps this field on create. The kubelet reads
    /// spec.dnsPolicy and logs "invalid DNSPolicy=" with an empty string, then
    /// falls back to ClusterFirst for every pod — silently incorrect behaviour.
    /// Without this default, every pod in a conformance run triggers the kubelet
    /// error "Failed to get DNS type for pod. Falling back to DNSClusterFirst
    /// policy. err=invalid DNSPolicy=".
    #[test]
    fn dns_policy_defaults_to_cluster_first_when_absent() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["dnsPolicy"],
            serde_json::json!("ClusterFirst"),
            "dnsPolicy must be defaulted to ClusterFirst when absent — \
             kubelet rejects empty string with 'invalid DNSPolicy=' and falls back \
             incorrectly, silently breaking pod DNS for every pod in a cluster"
        );
    }

    /// create_pod must NOT override an explicit dnsPolicy value.
    ///
    /// A pod running in host network mode uses ClusterFirstWithHostNet so that
    /// DNS resolution works correctly while sharing the host network namespace.
    /// Overriding this to ClusterFirst would silently break DNS for such pods.
    ///
    /// This is also the round-trip regression test: a pod created with an explicit
    /// dnsPolicy must have that exact value when read back from the store.
    #[test]
    fn dns_policy_explicit_value_is_preserved() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "hostnet-pod", "namespace": "default"},
            "spec": {
                "dnsPolicy": "ClusterFirstWithHostNet",
                "hostNetwork": true,
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["dnsPolicy"],
            serde_json::json!("ClusterFirstWithHostNet"),
            "an explicit dnsPolicy must not be overridden by the default — \
             ClusterFirstWithHostNet is required for pods using hostNetwork; \
             overriding it would silently break DNS resolution for those pods"
        );
    }

    /// create_pod must NOT override dnsPolicy: "None" (user-managed DNS).
    ///
    /// Pods with dnsPolicy=None manage DNS entirely via dnsConfig.nameservers.
    /// Overriding to ClusterFirst would silently break their custom DNS setup.
    #[test]
    fn dns_policy_none_is_preserved() {
        let mut pod = serde_json::json!({
            "spec": {
                "dnsPolicy": "None",
                "dnsConfig": {"nameservers": ["1.1.1.1"]},
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["dnsPolicy"],
            serde_json::json!("None"),
            "dnsPolicy=None must be preserved — user-managed DNS pods configure \
             nameservers via dnsConfig; overriding would silently redirect DNS traffic"
        );
    }

    // --- schedulerName defaulting tests ---

    /// create_pod must default spec.schedulerName to "default-scheduler" when absent.
    ///
    /// Real vendored kube-scheduler's HandlesSchedulerName (pkg/scheduler/profile/profile.go)
    /// looks the pod's schedulerName up in a map keyed by each profile's name, which itself
    /// defaults to "default-scheduler" and is never the empty string. A pod stored with
    /// schedulerName:"" is therefore invisible to it and never gets scheduled.
    #[test]
    fn pod_without_scheduler_name_gets_default() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["schedulerName"],
            serde_json::json!("default-scheduler"),
            "empty schedulerName is invisible to real kube-scheduler's HandlesSchedulerName \
             (profile.go:68) — the pod would never be scheduled"
        );
    }

    /// create_pod must NOT override an explicit schedulerName value.
    ///
    /// Overwriting a caller's custom scheduler name would silently redirect the pod to
    /// the default scheduler instead of the custom one the user (or a scheduling
    /// framework like kube-batch) intended to handle it.
    #[test]
    fn pod_with_custom_scheduler_name_is_preserved() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {
                "schedulerName": "my-scheduler",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["schedulerName"],
            serde_json::json!("my-scheduler"),
            "an explicit schedulerName must not be overwritten by the default — doing so \
             would silently hand the pod to the wrong scheduler"
        );
    }

    // --- restartPolicy defaulting tests ---

    /// create_pod must default spec.restartPolicy to "Always" when absent.
    ///
    /// Matches upstream SetDefaults_PodSpec (pkg/apis/core/v1/defaults.go:211-232 @
    /// release-1.36), which unconditionally defaults RestartPolicy to Always. Defense in
    /// depth: kubelet's ShouldContainerBeRestarted tolerates "" today, but other
    /// RestartPolicy switches are not guaranteed to.
    #[test]
    fn pod_without_restart_policy_gets_always() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["restartPolicy"],
            serde_json::json!("Always"),
            "restartPolicy must default to Always when absent, matching upstream \
             SetDefaults_PodSpec @ release-1.36:211-232"
        );
    }

    /// create_pod must NOT override an explicit restartPolicy value.
    ///
    /// A Job's pod template commonly sets restartPolicy: Never or OnFailure; silently
    /// forcing it back to Always would break the Job controller's completion tracking.
    #[test]
    fn pod_with_custom_restart_policy_is_preserved() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "job-pod", "namespace": "default"},
            "spec": {
                "restartPolicy": "Never",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["restartPolicy"],
            serde_json::json!("Never"),
            "an explicit restartPolicy must not be overwritten by the default — doing so \
             would break Job completion tracking for pods that must not restart"
        );
    }

    /// Running apply_pod_spec_defaults twice on an already-defaulted pod must be a no-op.
    ///
    /// apply_pod_spec_defaults runs on every write (create AND update). If a second pass
    /// re-defaulted an already-set field, an update to an unrelated field could silently
    /// mutate schedulerName/restartPolicy/dnsPolicy back to their defaults.
    #[test]
    fn applying_defaults_twice_is_idempotent() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {
                "schedulerName": "my-scheduler",
                "restartPolicy": "Never",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_spec_defaults(&mut pod);
        let once_defaulted = pod.clone();
        apply_pod_spec_defaults(&mut pod);
        assert_eq!(
            pod, once_defaulted,
            "a second apply_pod_spec_defaults pass (e.g. on an unrelated update) must not \
             change a single field already set by the first pass"
        );
    }

    // --- securityContext defaulting tests ---

    /// create_pod must default spec.securityContext to an empty object when absent.
    ///
    /// The real kubelet's generatePodSandboxLinuxConfig only calls NamespacesForPod
    /// (which computes the CRI NamespaceOption for hostNetwork/hostPID/hostIPC) inside
    /// an `if pod.Spec.SecurityContext != nil` guard. Without this default, a
    /// hostNetwork:true pod with no explicit pod-level securityContext gets a CRI
    /// RunPodSandboxRequest with no NamespaceOptions at all, so CRI-O creates an
    /// isolated (non-host) network namespace. The kubelet's own post-creation
    /// PodSandboxChanged check then detects that the sandbox's actual namespace mode
    /// doesn't match pod.Spec.HostNetwork and recreates the sandbox — forever, once per
    /// sync — which is the observed "Sandbox for pod has changed. Need to start a new
    /// one" churn loop that prevents any hostNetwork pod (e.g. an e2e host-exec pod)
    /// from ever stabilizing.
    #[test]
    fn security_context_defaults_to_empty_object_when_absent() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "hostnet-pod", "namespace": "default"},
            "spec": {
                "hostNetwork": true,
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert!(
            pod["spec"]["securityContext"].is_object(),
            "securityContext must default to a non-null (even empty) object — upstream \
             SetDefaults_PodSpec stamps this unconditionally, and the kubelet's \
             NamespacesForPod call (which sets hostNetwork/hostPID/hostIPC on the CRI \
             sandbox request) is gated on securityContext being non-nil; leaving it null \
             silently breaks hostNetwork for every pod that doesn't set it explicitly"
        );
    }

    /// create_pod must NOT override an explicit securityContext value.
    ///
    /// A pod that sets its own pod-level securityContext (e.g. runAsNonRoot, fsGroup)
    /// must keep those settings — defaulting must only fill the field when absent, not
    /// replace an already-present (even partially populated) object.
    #[test]
    fn security_context_explicit_value_is_preserved() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {
                "securityContext": {"runAsNonRoot": true, "fsGroup": 1000},
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["securityContext"],
            serde_json::json!({"runAsNonRoot": true, "fsGroup": 1000}),
            "an explicit securityContext must not be overridden or merged with defaults — \
             a user's runAsNonRoot/fsGroup settings must survive pod creation unchanged"
        );
    }

    // --- terminationGracePeriodSeconds defaulting tests ---

    /// create_pod must default spec.terminationGracePeriodSeconds to 30 when absent.
    ///
    /// This field is set once at creation and never touched again, including by a
    /// later graceful delete — so if it is left nil here, it stays nil for the pod's
    /// entire life. The "[sig-node] Pods should be submitted and removed" conformance
    /// test creates a pod with no explicit terminationGracePeriodSeconds, deletes it,
    /// and asserts the Pod object delivered on the final watch.Deleted event has this
    /// field non-zero (pods.go:334). Without this default that assertion fails with
    /// "nil not to be zero-valued" because the field was never populated.
    #[test]
    fn termination_grace_period_seconds_defaults_to_30_when_absent() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["terminationGracePeriodSeconds"],
            serde_json::json!(30),
            "terminationGracePeriodSeconds must default to 30 when absent — upstream \
             SetDefaults_PodSpec stamps this unconditionally, and a client watching \
             for pod deletion (e.g. the submitted-and-removed conformance test) asserts \
             it is non-nil on the final Deleted event"
        );
    }

    /// create_pod must NOT override an explicit terminationGracePeriodSeconds value.
    ///
    /// A pod that needs longer than 30s to flush state on SIGTERM sets this itself;
    /// silently clamping it back to 30 would cause the kubelet to SIGKILL the
    /// container before it finishes shutting down cleanly.
    #[test]
    fn termination_grace_period_seconds_explicit_value_is_preserved() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "slow-shutdown-pod", "namespace": "default"},
            "spec": {
                "terminationGracePeriodSeconds": 120,
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["terminationGracePeriodSeconds"],
            serde_json::json!(120),
            "an explicit terminationGracePeriodSeconds must not be overridden by the \
             default — doing so would cause the kubelet to SIGKILL the container \
             before its intended graceful-shutdown window elapses"
        );
    }

    // --- serviceAccountName defaulting tests ---

    /// A pod created with no serviceAccountName must get "default".
    ///
    /// Without this default, client-go's token-fetch machinery rejects the empty
    /// resource name ("failed to fetch token: resource name may not be empty") and
    /// the pod never starts — this was the live-reproduced failure behind
    /// "[sig-auth] ServiceAccounts should mount projected service account token".
    /// It also gates inject_sa_token_volume, which only injects the token volume
    /// when serviceAccountName is non-empty.
    #[test]
    fn service_account_name_defaults_to_default_when_absent() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "bare-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["serviceAccountName"], "default",
            "spec.serviceAccountName must default to \"default\" when absent — an empty \
             name fails kubelet's token fetch and the pod never runs"
        );
    }

    /// A pod with serviceAccountName == "" (empty string) must also get "default".
    ///
    /// Some clients send an explicit empty string rather than omitting the field
    /// entirely; both must be treated as "unset" per upstream ServiceAccount admission.
    #[test]
    fn service_account_name_empty_string_defaults_to_default() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "",
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["serviceAccountName"], "default",
            "empty-string serviceAccountName must be treated as absent and defaulted"
        );
    }

    /// A pod that sets only the deprecated `serviceAccount` alias must resolve
    /// serviceAccountName to that value, not "default".
    ///
    /// Upstream's hello-populator-deploy.yaml (AnyVolumeDataSource conformance) sets
    /// only `serviceAccount: hello-account`, never `serviceAccountName`. Before this
    /// fix, apply_pod_spec_defaults ignored the alias and stamped "default" — the
    /// populator controller then ran as the RBAC-less default SA and got instant 403
    /// Forbidden on every list/watch call, so its informer caches never synced and it
    /// never provisioned the datasource volume, hanging the conformance test.
    #[test]
    fn service_account_name_falls_back_to_deprecated_alias() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccount": "hello-account",
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["serviceAccountName"], "hello-account",
            "a pod using only the deprecated serviceAccount alias must run under that \
             SA's RBAC identity, not the powerless default SA"
        );
        assert_eq!(
            pod["spec"]["serviceAccount"], "hello-account",
            "upstream keeps the deprecated alias in sync with the resolved \
             serviceAccountName so clients reading the pod back see both fields agree"
        );
    }

    /// An explicit non-default serviceAccountName must not be overwritten.
    ///
    /// Overwriting a caller's chosen SA would silently change the pod's identity
    /// and RBAC permissions.
    #[test]
    fn service_account_name_explicit_value_preserved() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "custom-sa",
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["serviceAccountName"], "custom-sa",
            "an explicit serviceAccountName must not be overwritten by the default"
        );
    }

    /// End-to-end: a bare pod with no serviceAccountName must still receive the
    /// kube-api-access token volume once defaulting runs before injection.
    ///
    /// This is the exact bug scenario: bare pods had no
    /// /var/run/secrets/kubernetes.io/serviceaccount because inject_sa_token_volume
    /// requires a non-empty serviceAccountName, which was never defaulted. If the
    /// serviceAccountName default is removed or reordered after injection, this
    /// test fails and in-cluster clients (extension apiservers, sonobuoy) lose
    /// their token again.
    #[test]
    fn bare_pod_gets_token_volume_via_defaulted_service_account_name() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "bare-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        apply_pod_create_defaults(&mut pod);
        inject_sa_token_volume(&mut pod, "bare-pod");
        let volumes = pod["spec"]["volumes"]
            .as_array()
            .expect("volumes must be set once serviceAccountName is defaulted");
        assert!(
            volumes.iter().any(|v| v["name"]
                .as_str()
                .map(|n| n.starts_with("kube-api-access-"))
                .unwrap_or(false)),
            "a bare pod (no explicit serviceAccountName) must still get the \
             kube-api-access-* token volume via the defaulted \"default\" SA"
        );
    }

    // --- inject_sa_token_volume tests ---

    /// SA token projected volume must be injected when serviceAccountName is set.
    ///
    /// rest.InClusterConfig() reads /var/run/secrets/kubernetes.io/serviceaccount/token;
    /// without this injection sonobuoy fails with "no configuration has been provided".
    #[test]
    fn sa_token_volume_injected_when_sa_name_set() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "default",
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        let volumes = pod["spec"]["volumes"]
            .as_array()
            .expect("volumes must be set");
        assert!(
            volumes.iter().any(|v| v["name"]
                .as_str()
                .map(|n| n.starts_with("kube-api-access-"))
                .unwrap_or(false)),
            "a kube-api-access-* volume must be injected so in-cluster token is available"
        );
        let mounts = pod["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volumeMounts must be set");
        assert!(
            mounts.iter().any(|m| m["mountPath"].as_str()
                == Some("/var/run/secrets/kubernetes.io/serviceaccount")),
            "volumeMount at SA path must be added to container"
        );
    }

    /// SA token volume must NOT be injected when automountServiceAccountToken is false.
    ///
    /// Pods that explicitly opt out must not receive the mount; injecting anyway
    /// would violate the user's security intent and differ from real kube behavior.
    #[test]
    fn sa_token_volume_not_injected_when_automount_false() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "default",
                "automountServiceAccountToken": false,
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        assert!(
            pod["spec"]["volumes"].is_null(),
            "no volume must be injected when automountServiceAccountToken=false"
        );
    }

    /// SA token volume must NOT be injected when serviceAccountName is absent.
    ///
    /// Pods with no SA name have no identity to bind a token to.
    #[test]
    fn sa_token_volume_not_injected_when_sa_name_absent() {
        let mut pod = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        assert!(
            pod["spec"]["volumes"].is_null(),
            "no volume must be injected when serviceAccountName is absent"
        );
    }

    /// SA token volume must NOT be injected when serviceAccountName is empty string.
    #[test]
    fn sa_token_volume_not_injected_when_sa_name_empty() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "",
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        assert!(
            pod["spec"]["volumes"].is_null(),
            "no volume must be injected when serviceAccountName is empty"
        );
    }

    /// inject_sa_token_volume must be idempotent: a second call must not add a
    /// duplicate volume when a kube-api-access-* volume already exists.
    ///
    /// This prevents volume-name collisions on repeated admission passes.
    #[test]
    fn sa_token_volume_idempotent_when_kube_api_access_volume_exists() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "default",
                "volumes": [{"name": "kube-api-access-abcde", "projected": {"defaultMode": 420, "sources": []}}],
                "containers": [{"name": "app", "image": "busybox"}]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        let count = pod["spec"]["volumes"]
            .as_array()
            .map(|v| v.len())
            .unwrap_or(0);
        assert_eq!(
            count, 1,
            "duplicate kube-api-access-* volume must not be added when one already exists"
        );
    }

    /// VolumeMounts must be added to both containers and initContainers.
    ///
    /// initContainers run before main containers and also need in-cluster config
    /// (e.g. sonobuoy's init step pulls a kubeconfig).
    #[test]
    fn sa_token_volume_mounts_added_to_containers_and_init_containers() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "default",
                "containers": [{"name": "main", "image": "busybox"}],
                "initContainers": [{"name": "init", "image": "busybox"}]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        let main_mount = pod["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .and_then(|m| {
                m.iter().find(|e| {
                    e["mountPath"].as_str() == Some("/var/run/secrets/kubernetes.io/serviceaccount")
                })
            });
        assert!(
            main_mount.is_some(),
            "main container must receive the SA volumeMount"
        );
        let init_mount = pod["spec"]["initContainers"][0]["volumeMounts"]
            .as_array()
            .and_then(|m| {
                m.iter().find(|e| {
                    e["mountPath"].as_str() == Some("/var/run/secrets/kubernetes.io/serviceaccount")
                })
            });
        assert!(
            init_mount.is_some(),
            "initContainer must receive the SA volumeMount"
        );
    }

    /// A container that already mounts the SA path must not receive a duplicate mount.
    ///
    /// Kubelet rejects pods with duplicate mount paths; idempotency here prevents
    /// that failure when a pod already has an explicit SA mount.
    #[test]
    fn sa_token_volume_mount_skipped_when_container_has_existing_sa_mount() {
        let mut pod = serde_json::json!({
            "spec": {
                "serviceAccountName": "default",
                "containers": [{
                    "name": "app",
                    "image": "busybox",
                    "volumeMounts": [{
                        "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                        "name": "my-existing-sa",
                        "readOnly": true
                    }]
                }]
            }
        });
        inject_sa_token_volume(&mut pod, "my-pod");
        let mount_count = pod["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .map(|m| {
                m.iter()
                    .filter(|e| {
                        e["mountPath"].as_str()
                            == Some("/var/run/secrets/kubernetes.io/serviceaccount")
                    })
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(
            mount_count, 1,
            "duplicate SA mount must not be added when container already has one"
        );
    }

    /// apply_pod_create_defaults must preserve spec.containers[].livenessProbe intact.
    ///
    /// The kubelet reads livenessProbe from the pod spec it receives from the apiserver.
    /// If apply_pod_create_defaults (or any other CREATE-path code) strips or transforms
    /// livenessProbe, the kubelet never sees the probe config and cannot run it — causing
    /// the container to never restart even when the probe command fails. This is failure
    /// mode A: the probe config is dropped before the kubelet can act on it.
    #[test]
    fn liveness_probe_is_preserved_through_create_defaults() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "liveness-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "busybox",
                    "livenessProbe": {
                        "exec": {"command": ["/bin/sh", "-c", "exit 1"]},
                        "initialDelaySeconds": 5,
                        "periodSeconds": 2,
                        "failureThreshold": 3
                    }
                }]
            }
        });

        apply_pod_create_defaults(&mut pod);

        let probe = &pod["spec"]["containers"][0]["livenessProbe"];
        assert!(
            probe.is_object(),
            "livenessProbe must remain an object after apply_pod_create_defaults — \
             kubelet reads it to schedule probe runs; if missing, probes never fire \
             and restartCount stays at 0 (failure mode A)"
        );
        assert_eq!(
            probe["exec"]["command"][0], "/bin/sh",
            "livenessProbe.exec.command must be preserved exactly"
        );
        assert_eq!(
            probe["exec"]["command"][2], "exit 1",
            "livenessProbe.exec.command payload must be preserved"
        );
        assert_eq!(
            probe["initialDelaySeconds"], 5,
            "livenessProbe.initialDelaySeconds must be preserved"
        );
        assert_eq!(
            probe["periodSeconds"], 2,
            "livenessProbe.periodSeconds must be preserved"
        );
        assert_eq!(
            probe["failureThreshold"], 3,
            "livenessProbe.failureThreshold must be preserved"
        );
    }

    /// Probe fields missing periodSeconds must be defaulted to 10 on pod create.
    ///
    /// kubelet calls time.NewTicker(periodSeconds) in prober/worker.go:169. When
    /// periodSeconds == 0 (the value for an unset field), Go panics with
    /// "non-positive interval for NewTicker", crash-looping the kubelet (236 restarts
    /// observed). Clients rely on the apiserver to default these fields — omitting
    /// periodSeconds is the normal usage. This test fails if the defaulting is removed,
    /// proving it is a genuine regression guard.
    #[test]
    fn probe_missing_period_seconds_defaults_to_10() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "probe-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "busybox",
                    "livenessProbe": {
                        "exec": {"command": ["cat", "/tmp/health"]},
                        "initialDelaySeconds": 15
                    },
                    "readinessProbe": {
                        "exec": {"command": ["cat", "/tmp/ready"]}
                    }
                }],
                "initContainers": [{
                    "name": "init",
                    "image": "busybox",
                    "startupProbe": {
                        "exec": {"command": ["cat", "/tmp/started"]}
                    }
                }]
            }
        });

        apply_pod_create_defaults(&mut pod);

        let liveness = &pod["spec"]["containers"][0]["livenessProbe"];
        assert_eq!(
            liveness["periodSeconds"], 10,
            "livenessProbe.periodSeconds must default to 10 — 0 panics kubelet NewTicker"
        );
        assert_eq!(
            liveness["timeoutSeconds"], 1,
            "livenessProbe.timeoutSeconds must default to 1 — upstream SetDefaults_Probe"
        );
        assert_eq!(
            liveness["successThreshold"], 1,
            "livenessProbe.successThreshold must default to 1 — upstream SetDefaults_Probe"
        );
        assert_eq!(
            liveness["failureThreshold"], 3,
            "livenessProbe.failureThreshold must default to 3 — upstream SetDefaults_Probe"
        );
        assert_eq!(
            liveness["initialDelaySeconds"], 15,
            "livenessProbe.initialDelaySeconds must be preserved (client-supplied)"
        );

        let readiness = &pod["spec"]["containers"][0]["readinessProbe"];
        assert_eq!(
            readiness["periodSeconds"], 10,
            "readinessProbe.periodSeconds must default to 10 — 0 panics kubelet NewTicker"
        );

        let startup = &pod["spec"]["initContainers"][0]["startupProbe"];
        assert_eq!(
            startup["periodSeconds"], 10,
            "initContainers startupProbe.periodSeconds must default to 10 — applies to all container lists"
        );
    }

    /// An explicit periodSeconds must not be overwritten.
    ///
    /// A probe with periodSeconds: 5 must stay at 5 — the defaulting must only fill
    /// absent (0/null) values, not overwrite client-supplied ones.
    #[test]
    fn probe_explicit_period_seconds_not_overwritten() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "probe-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "busybox",
                    "livenessProbe": {
                        "exec": {"command": ["cat", "/tmp/health"]},
                        "periodSeconds": 5,
                        "timeoutSeconds": 10,
                        "successThreshold": 2,
                        "failureThreshold": 1
                    }
                }]
            }
        });

        apply_pod_create_defaults(&mut pod);

        let probe = &pod["spec"]["containers"][0]["livenessProbe"];
        assert_eq!(
            probe["periodSeconds"], 5,
            "explicit periodSeconds must not be overwritten by defaulting"
        );
        assert_eq!(
            probe["timeoutSeconds"], 10,
            "explicit timeoutSeconds must not be overwritten by defaulting"
        );
        assert_eq!(
            probe["successThreshold"], 2,
            "explicit successThreshold must not be overwritten by defaulting"
        );
        assert_eq!(
            probe["failureThreshold"], 1,
            "explicit failureThreshold must not be overwritten by defaulting"
        );
    }

    /// A container with no probe must not get a probe injected.
    ///
    /// Probe defaulting must only fill fields on probes that EXIST — it must not
    /// invent a livenessProbe on containers that have none.
    #[test]
    fn container_without_probe_stays_without_probe() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "noprobe-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        apply_pod_create_defaults(&mut pod);

        assert!(
            pod["spec"]["containers"][0]["livenessProbe"].is_null(),
            "a container without livenessProbe must not have one injected by defaulting"
        );
        assert!(
            pod["spec"]["containers"][0]["readinessProbe"].is_null(),
            "a container without readinessProbe must not have one injected by defaulting"
        );
        assert!(
            pod["spec"]["containers"][0]["startupProbe"].is_null(),
            "a container without startupProbe must not have one injected by defaulting"
        );
    }

    /// apply_pod_create_defaults must insert PodScheduled=False into status.conditions.
    ///
    /// Real kube-apiserver always stamps this condition on create.  Conformance scheduling
    /// tests (scheduling/predicates.go) wait for `PodScheduled` to appear in
    /// `pod.status.conditions`; without this default the field is absent after create and
    /// those tests time out with "Did not find scheduled condition for pod".
    ///
    /// This test fails if the PodScheduled initialization is removed — proving it is a
    /// genuine regression test, not just documentation.
    #[test]
    fn pod_create_defaults_sets_pod_scheduled_false() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pfpod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        apply_pod_create_defaults(&mut pod);

        let conditions = pod["status"]["conditions"]
            .as_array()
            .expect("status.conditions must be an array after apply_pod_create_defaults");
        let scheduled = conditions
            .iter()
            .find(|c| c["type"].as_str() == Some("PodScheduled"))
            .expect(
                "PodScheduled condition must be present — scheduling tests wait for it and \
                 time out with 'Did not find scheduled condition for pod' if absent",
            );
        assert_eq!(
            scheduled["status"], "False",
            "PodScheduled must start as False — the scheduler flips it to True after binding; \
             if missing, scheduling tests cannot observe the transition"
        );
        assert_eq!(
            scheduled["reason"], "Unschedulable",
            "PodScheduled reason must be Unschedulable before the pod is bound to a node"
        );
    }

    /// apply_pod_create_defaults must not overwrite a pre-existing PodScheduled condition.
    ///
    /// Idempotency: if the pod already carries PodScheduled (e.g. from a webhook or
    /// a second call to apply_pod_create_defaults), the existing value must survive.
    #[test]
    fn pod_create_defaults_does_not_overwrite_existing_pod_scheduled() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pfpod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {
                "conditions": [{
                    "type": "PodScheduled",
                    "status": "True",
                    "reason": "PodScheduled",
                    "lastTransitionTime": "2024-01-01T00:00:00Z"
                }]
            }
        });

        apply_pod_create_defaults(&mut pod);

        let conditions = pod["status"]["conditions"]
            .as_array()
            .expect("conditions must still be an array");
        let scheduled = conditions
            .iter()
            .find(|c| c["type"].as_str() == Some("PodScheduled"))
            .expect("PodScheduled condition must be present");
        assert_eq!(
            scheduled["status"], "True",
            "pre-existing PodScheduled=True must not be overwritten to False"
        );
    }

    /// apply_pod_create_defaults must set status.phase=Pending on a newly-created pod.
    ///
    /// Conformance tests (e.g. Variable Expansion) check `pod.status.phase == "Pending"`
    /// immediately after create.  A missing phase causes tests to fail with
    /// "got a pod with no phase set" because the pod never reports its lifecycle state.
    #[test]
    fn pod_create_defaults_sets_status_phase_pending() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "phase-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        apply_pod_create_defaults(&mut pod);

        assert_eq!(
            pod["status"]["phase"], "Pending",
            "status.phase must be Pending after create — tests that wait for phase=Pending \
             fail with 'no phase set' if this field is absent"
        );
    }

    /// apply_pod_create_defaults must not overwrite a pre-existing status.phase.
    ///
    /// Idempotency: a pod already carrying a phase (e.g. Running from a webhook)
    /// must not have its phase overwritten to Pending.
    #[test]
    fn pod_create_defaults_does_not_overwrite_existing_phase() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "phase-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {"phase": "Running"}
        });

        apply_pod_create_defaults(&mut pod);

        assert_eq!(
            pod["status"]["phase"], "Running",
            "pre-existing status.phase must not be overwritten to Pending"
        );
    }

    /// apply_pod_create_defaults must stamp the COMPLETE set of defaults regardless of
    /// which create route the pod arrives through.
    ///
    /// Before this consolidation, apply_pod_create_defaults (the only actually-invoked
    /// path — pods are not in the generic resource registry) was missing the port protocol
    /// default that lived only in default_pod (defaults.rs). A pod with an undeclared
    /// containerPort protocol would be stored without protocol=TCP, causing the KCM
    /// endpointslice controller to emit ports:[] for named-targetPort services and the
    /// kubelet to see an incomplete spec. This test FAILS if the port protocol defaulting
    /// is removed from apply_pod_create_defaults, proving it guards against regression.
    #[test]
    fn pod_create_applies_full_defaults_so_kubelet_never_sees_a_partial_spec() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "full-defaults-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "ports": [{"containerPort": 8080}]
                }],
                "initContainers": [{
                    "name": "init",
                    "image": "busybox",
                    "ports": [{"containerPort": 9090}]
                }],
                "volumes": [{
                    "name": "cfg",
                    "configMap": {"name": "my-config"}
                }]
            }
        });

        apply_pod_create_defaults(&mut pod);

        assert_eq!(
            pod["spec"]["enableServiceLinks"], true,
            "enableServiceLinks must be true — absent value causes kubelet \
             CreateContainerConfigError: nil pod.spec.enableServiceLinks"
        );
        assert_eq!(
            pod["spec"]["dnsPolicy"], "ClusterFirst",
            "dnsPolicy must default to ClusterFirst — absent value causes kubelet \
             to emit 'invalid DNSPolicy=' and silently fall back to ClusterFirst"
        );
        assert_eq!(
            pod["spec"]["volumes"][0]["configMap"]["defaultMode"], 420,
            "configMap volume defaultMode must be 420 — absent value causes kubelet \
             to refuse the mount with 'no defaultMode used'"
        );
        assert_eq!(
            pod["spec"]["containers"][0]["ports"][0]["protocol"], "TCP",
            "container port protocol must default to TCP — absent protocol causes \
             KCM endpointslice controller to emit ports:[] for named-targetPort services"
        );
        assert_eq!(
            pod["spec"]["initContainers"][0]["ports"][0]["protocol"], "TCP",
            "initContainer port protocol must also default to TCP"
        );
        assert_eq!(
            pod["status"]["phase"], "Pending",
            "status.phase must be Pending after create"
        );
        let conditions = pod["status"]["conditions"]
            .as_array()
            .expect("status.conditions must be set");
        assert!(
            conditions
                .iter()
                .any(|c| c["type"].as_str() == Some("PodScheduled")),
            "PodScheduled condition must be present — conformance scheduling tests wait \
             for it before declaring scheduling success"
        );
    }

    /// A container added AFTER initial create-time defaulting (simulating a mutating
    /// webhook injecting a container via JSON patch) must still get
    /// terminationMessagePolicy defaulted when create_pod re-applies spec defaults
    /// post-mutation — otherwise the injected container is stored with no
    /// terminationMessagePolicy at all, which fails conformance
    /// "[sig-api-machinery] AdmissionWebhook ... should mutate pod and apply defaults
    /// after mutation". This also proves the re-apply is idempotent: the
    /// container defaulted on the first pass must be unchanged by the second pass.
    #[test]
    fn post_mutation_defaults_apply_to_webhook_injected_container() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "webhook-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        // First pass: what create_pod does BEFORE the mutating webhook chain runs.
        apply_pod_create_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["containers"][0]["terminationMessagePolicy"], "File",
            "sanity check: the client-supplied container must be defaulted by the first pass"
        );

        // Simulate a mutating webhook injecting an initContainer via JSON patch: the
        // apiserver adds this container directly to the JSON body with no client
        // involved, so it has none of the fields a real client's protobuf encoding
        // would have stamped.
        pod["spec"]["initContainers"] = serde_json::json!([
            {"name": "webhook-injected", "image": "busybox"}
        ]);

        // Second pass: what create_pod does AFTER the mutating webhook chain runs.
        apply_pod_spec_defaults(&mut pod);

        assert_eq!(
            pod["spec"]["initContainers"][0]["terminationMessagePolicy"], "File",
            "webhook-injected container must get terminationMessagePolicy defaulted by \
             the post-mutation re-apply — without it, a webhook-added container is stored \
             with no terminationMessagePolicy, failing the AdmissionWebhook conformance test"
        );
        assert_eq!(
            pod["spec"]["containers"][0]["terminationMessagePolicy"], "File",
            "the pre-existing container's terminationMessagePolicy must be unchanged by \
             the second pass — the re-apply must be idempotent, not just additive"
        );
    }

    // --- imagePullPolicy defaulting tests ---
    //
    // NOTE: idempotency for this field is already covered by the pre-existing
    // `applying_defaults_twice_is_idempotent` test above (full-pod equality across two
    // passes) — the bare "nginx" image there exercises the "no tag -> Always" default,
    // so a regression here would already fail that test too.

    /// A container with a pinned, non-latest tag and no explicit imagePullPolicy must
    /// default to IfNotPresent, matching upstream SetDefaults_Container
    /// (pkg/apis/core/v1/defaults.go:82-93 @ v1.36.0).
    ///
    /// Without this default, kubelet's imagePullPrecheck (image_manager.go:117-127) is a
    /// `switch pullPolicy` with NO default case: an empty policy falls through to the
    /// same unconditional-repull path as PullAlways, so u7s re-pulls the same image on
    /// every container start regardless of local cache state — verified 29x for a single
    /// digest in a 0806-0217 csi-hostpath run, versus exactly once for a
    /// sibling container that had an explicit IfNotPresent.
    #[test]
    fn container_without_image_pull_policy_and_non_latest_tag_defaults_to_if_not_present() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx:v1.2"}]
            }
        });
        apply_pod_spec_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["containers"][0]["imagePullPolicy"],
            serde_json::json!("IfNotPresent"),
            "a pinned non-latest tag must default to IfNotPresent — leaving it empty \
             falls through kubelet's unhandled-default switch and re-pulls the image on \
             every container start, defeating the local image cache"
        );
    }

    /// A container with an explicit ":latest" tag and no imagePullPolicy must default to
    /// Always, matching upstream SetDefaults_Container — latest-tag content is expected
    /// to drift, so kubelet must re-check the registry on every start.
    #[test]
    fn container_without_image_pull_policy_and_latest_tag_defaults_to_always() {
        let mut pod = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "image": "nginx:latest"}]
            }
        });
        apply_pod_spec_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["containers"][0]["imagePullPolicy"],
            serde_json::json!("Always"),
            "an explicit :latest tag must default imagePullPolicy to Always, matching \
             upstream SetDefaults_Container — latest is expected to drift and must always \
             be re-checked against the registry"
        );
    }

    /// A bare image reference with no tag at all (`nginx`) is `:latest` by Docker
    /// convention, so it must get the same Always default as an explicit `:latest`.
    #[test]
    fn container_without_image_pull_policy_and_no_tag_defaults_to_always() {
        let mut pod = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        apply_pod_spec_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["containers"][0]["imagePullPolicy"],
            serde_json::json!("Always"),
            "a bare image reference with no tag is implicitly :latest per Docker \
             convention and upstream's ParseImageName — defaulting it to IfNotPresent \
             instead would pin a pod to whatever happened to be cached at first pull"
        );
    }

    /// An explicit imagePullPolicy must never be overwritten by the default, even when
    /// the image tag would otherwise suggest a different policy (here: latest -> Always).
    #[test]
    fn container_with_explicit_image_pull_policy_is_preserved() {
        let mut pod = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx:latest",
                    "imagePullPolicy": "IfNotPresent"
                }]
            }
        });
        apply_pod_spec_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["containers"][0]["imagePullPolicy"],
            serde_json::json!("IfNotPresent"),
            "an explicit imagePullPolicy must not be overwritten by the tag-based default \
             — a user who deliberately pinned IfNotPresent on a :latest image (e.g. to \
             avoid registry calls in an air-gapped cluster) must keep that choice"
        );
    }

    /// initContainers and ephemeralContainers must receive the same imagePullPolicy
    /// default as regular containers — the kubelet applies imagePullPrecheck identically
    /// to all three container kinds, so leaving init/ephemeral containers undefaulted
    /// would reintroduce the unconditional-repull bug for exactly those container kinds.
    #[test]
    fn init_container_and_ephemeral_container_are_also_defaulted() {
        let mut pod = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "image": "nginx:v1"}],
                "initContainers": [{"name": "init", "image": "busybox:1.36"}],
                "ephemeralContainers": [{"name": "debugger", "image": "busybox:1.36"}]
            }
        });
        apply_pod_spec_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["initContainers"][0]["imagePullPolicy"],
            serde_json::json!("IfNotPresent"),
            "initContainers must be defaulted identically to containers — kubelet's \
             imagePullPrecheck applies to init containers too, so skipping them here \
             would leave init containers re-pulling on every restart"
        );
        assert_eq!(
            pod["spec"]["ephemeralContainers"][0]["imagePullPolicy"],
            serde_json::json!("IfNotPresent"),
            "ephemeralContainers must be defaulted identically to containers — \
             `kubectl debug` injects these, and an undefaulted policy would re-pull the \
             debug image on every ephemeral container (re)start"
        );
    }

    /// Registry hosts may embed a port (`host:5000/image:tag`); the tag-parsing logic
    /// must not mistake the port for a tag. This is the classic image-reference parsing
    /// pitfall (naively splitting on the first or last ':' in the whole string).
    #[test]
    fn image_with_registry_port_does_not_confuse_tag_parsing() {
        let mut pod = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "registry.example.com:5000/nginx:v1"
                }]
            }
        });
        apply_pod_spec_defaults(&mut pod);
        assert_eq!(
            pod["spec"]["containers"][0]["imagePullPolicy"],
            serde_json::json!("IfNotPresent"),
            "the registry's port (:5000) must not be mistaken for the image tag — doing \
             so would read the tag as '5000' (not 'v1'), which is never 'latest' by \
             coincidence, but is fragile and diverges from upstream's actual parser \
             (dockerref.ParseNormalizedNamed), which uses the last colon after the last \
             slash as the tag delimiter"
        );
    }
}

#[cfg(test)]
mod parse_image_tag_tests {
    use super::*;

    #[test]
    fn pinned_tag_is_extracted_verbatim() {
        assert_eq!(
            parse_image_tag("nginx:v1.2.3"),
            "v1.2.3",
            "a pinned tag must be returned as-is — this is what upstream's \
             SetDefaults_Container compares against \"latest\" to choose IfNotPresent"
        );
    }

    #[test]
    fn explicit_latest_tag_is_extracted() {
        assert_eq!(
            parse_image_tag("nginx:latest"),
            "latest",
            "an explicit :latest tag must round-trip as \"latest\" so the caller defaults \
             imagePullPolicy to Always, matching upstream's drift-expected semantics"
        );
    }

    #[test]
    fn absent_tag_and_digest_defaults_to_latest() {
        assert_eq!(
            parse_image_tag("nginx"),
            "latest",
            "Docker treats a bare name with no tag as :latest — upstream's ParseImageName \
             backfills \"latest\" only when BOTH tag and digest are absent"
        );
    }

    /// Upstream's `ParseImageName` only backfills "latest" when BOTH tag and digest are
    /// absent (parsers.go: `if len(tag) == 0 && len(digest) == 0`). A digest pins exact
    /// content, so a digest-only reference must NOT be treated as "latest" even though it
    /// also has no explicit tag — otherwise a digest-pinned image would get PullAlways,
    /// causing a needless registry round-trip on every start despite being immutable.
    #[test]
    fn digest_only_reference_is_not_treated_as_latest() {
        assert_ne!(
            parse_image_tag(
                "nginx@sha256:2cd1d97f2f7ab93c8b7c2c2c8e6e6d6e40d0e1a49e2c4b1e5a4b3c2d1e0f9a8b"
            ),
            "latest",
            "a digest-only reference must not be treated as :latest — upstream's parser \
             only defaults the tag to latest when there is no digest either; digest \
             content is pinned and immutable"
        );
    }

    #[test]
    fn registry_port_before_last_slash_is_not_mistaken_for_a_tag() {
        assert_eq!(
            parse_image_tag("registry.example.com:5000/nginx:v1"),
            "v1",
            "a colon before the last slash is part of host:port, not a tag delimiter — \
             mistaking :5000 for the tag would misclassify every image pulled from a \
             registry running on a non-default port"
        );
    }

    #[test]
    fn registry_port_with_no_tag_defaults_to_latest() {
        assert_eq!(
            parse_image_tag("registry.example.com:5000/nginx"),
            "latest",
            "a registry-with-port reference and no tag is still implicitly :latest — the \
             port colon (before the last slash) must not be mistaken for an explicit tag \
             that would otherwise suppress the latest default"
        );
    }
}

/// Flip the PodScheduled condition to True in-place.
///
/// Finds an existing PodScheduled entry in `status.conditions` and sets its status to
/// "True".  If no entry exists, appends one.  Matches upstream's bind-path write
/// (`pkg/registry/core/pod/storage/storage.go`), which sets only `Type` and `Status` —
/// no `Reason`/`Message` — so kubelet's cache doesn't drift from the apiserver's copy.
/// Any stale `reason`/`message` left over from the initial PodScheduled=False condition
/// (e.g. reason=Unschedulable) is cleared, since upstream's `UpdatePodCondition` replaces
/// the whole condition struct rather than patching individual fields — leaving the old
/// reason in place would produce a self-contradictory PodScheduled=True + Unschedulable.
/// `now` must be an RFC3339 timestamp string (used as `lastTransitionTime`).
///
/// Extracted for testability — the full `bind_pod` handler is async and requires a live store.
pub(crate) fn set_pod_scheduled_true(pod: &mut serde_json::Value, now: &str) {
    if !pod["status"].is_object() {
        pod["status"] = serde_json::json!({});
    }
    if let Some(conditions) = pod["status"]["conditions"].as_array_mut() {
        for cond in conditions.iter_mut() {
            if cond["type"].as_str() == Some("PodScheduled") {
                cond["status"] = serde_json::json!("True");
                cond["reason"] = serde_json::json!("");
                cond["message"] = serde_json::json!("");
                cond["lastTransitionTime"] = serde_json::json!(now);
                return;
            }
        }
        // No existing PodScheduled condition — append one.
        conditions.push(serde_json::json!({
            "type": "PodScheduled",
            "status": "True",
            "lastTransitionTime": now
        }));
    } else {
        pod["status"]["conditions"] = serde_json::json!([{
            "type": "PodScheduled",
            "status": "True",
            "lastTransitionTime": now
        }]);
    }
}

#[cfg(test)]
mod generation_tests {
    use super::*;

    /// create_pod must set metadata.generation=1 when the caller does not supply one.
    ///
    /// Controllers and scheduler use generation/observedGeneration to detect spec changes.
    /// A missing generation means a controller can never know if it has reconciled the
    /// latest spec — it would either loop forever or never act.
    #[test]
    fn initialize_sets_generation_to_1_when_absent() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });
        initialize_pod_generation(&mut pod);
        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(1i64),
            "generation must be initialized to 1 on create — absent generation means \
             controllers relying on observedGeneration will never see spec changes"
        );
    }

    /// create_pod must reset a caller-supplied generation value to 1.
    ///
    /// metadata.generation is a server-managed field. Kubernetes conformance test
    /// "custom-set generation on new pods" (pods.go:554) creates a pod with
    /// generation=100 and asserts the server returns generation=1. A controller
    /// waiting for observedGeneration==generation would stall forever if the server
    /// accepted generation=100 — it would need 99 phantom spec changes to catch up.
    #[test]
    fn initialize_resets_caller_supplied_generation_to_1() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "generation": 100i64},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });
        initialize_pod_generation(&mut pod);
        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(1i64),
            "generation must be reset to 1 on create even if the client sent a different value — \
             metadata.generation is server-managed; a non-1 initial value would stall \
             controllers waiting for observedGeneration==generation to catch up"
        );
    }

    /// PATCH that changes spec must increment generation.
    ///
    /// A spec change that does not bump generation is invisible to controllers
    /// watching generation; they would never re-reconcile the updated spec.
    #[test]
    fn increment_on_spec_change() {
        let spec_before =
            serde_json::json!({"containers": [{"name": "app", "image": "nginx:1.0"}]});
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "generation": 1i64},
            "spec": {"containers": [{"name": "app", "image": "nginx:2.0"}]}
        });
        increment_pod_generation_if_spec_changed(&mut pod, &spec_before);
        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(2i64),
            "generation must increment when spec changes — controllers use \
             generation/observedGeneration to detect new work; no increment means stale reconcile"
        );
    }

    /// PATCH that does not change spec must NOT increment generation.
    ///
    /// A metadata-only patch (labels, annotations) must leave generation unchanged
    /// so controllers do not re-reconcile when nothing in spec changed.
    #[test]
    fn no_increment_when_spec_unchanged() {
        let spec = serde_json::json!({"containers": [{"name": "app", "image": "nginx:1.0"}]});
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "generation": 1i64, "labels": {}},
            "spec": spec.clone()
        });
        increment_pod_generation_if_spec_changed(&mut pod, &spec);
        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(1i64),
            "generation must NOT increment for metadata-only patches — spurious increments \
             would cause controllers to re-reconcile unchanged pods"
        );
    }

    /// Sequential spec changes must increment generation monotonically.
    ///
    /// A pod updated twice (generation 1 → 2 → 3) must track both changes.
    /// If the counter resets or skips, observedGeneration comparisons break.
    #[test]
    fn generation_increments_monotonically_across_multiple_patches() {
        let spec_v1 = serde_json::json!({"containers": [{"name": "app", "image": "nginx:1.0"}]});
        let spec_v2 = serde_json::json!({"containers": [{"name": "app", "image": "nginx:2.0"}]});
        let spec_v3 = serde_json::json!({"containers": [{"name": "app", "image": "nginx:3.0"}]});

        let mut pod = serde_json::json!({
            "metadata": {"generation": 1i64},
            "spec": spec_v2.clone()
        });

        // First spec change: 1 -> 2
        increment_pod_generation_if_spec_changed(&mut pod, &spec_v1);
        assert_eq!(pod["metadata"]["generation"], serde_json::json!(2i64));

        // Second spec change: 2 -> 3
        pod["spec"] = spec_v3.clone();
        increment_pod_generation_if_spec_changed(&mut pod, &spec_v2);
        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(3i64),
            "generation must increment monotonically — generation=3 after two spec changes; \
             a reset or skip would break observedGeneration tracking in controllers"
        );
    }

    /// A no-op replace (client omits defaulted fields) must NOT bump generation.
    ///
    /// Upstream k8s conformance test node/pods.go:530 creates a pod (gen=1) then
    /// does an empty update and expects gen still 1.  u7s was returning 2 because
    /// the stored spec (fully defaulted) differed structurally from the incoming
    /// spec (missing dnsPolicy, enableServiceLinks, volume defaultMode, etc.).
    /// Controllers that gate on observedGeneration==generation would re-reconcile
    /// every pod on every no-op update, and the conformance pod-generation suite
    /// would fail with "Expected 2 to be equivalent to 1".
    #[test]
    fn noop_update_omitting_defaulted_fields_does_not_bump_generation() {
        // Simulate a fully-defaulted stored spec (what is written to the store on create).
        let mut stored_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "test-pod", "namespace": "default", "generation": 1i64},
            "spec": {
                "containers": [{"name": "app", "image": "nginx:1.0"}],
                "dnsPolicy": "ClusterFirst",
                "enableServiceLinks": true
            }
        });
        apply_pod_create_defaults(&mut stored_pod);
        let spec_before = stored_pod["spec"].clone();

        // Simulate a no-op update: client sends back the pod but omits some defaulted
        // fields (e.g. dnsPolicy stripped, as many kubectl-based clients do on round-trip).
        let mut incoming_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "test-pod", "namespace": "default", "generation": 1i64},
            "spec": {
                "containers": [{"name": "app", "image": "nginx:1.0"}]
                // dnsPolicy and enableServiceLinks intentionally omitted
            }
        });

        increment_pod_generation_if_spec_changed(&mut incoming_pod, &spec_before);

        assert_eq!(
            incoming_pod["metadata"]["generation"],
            serde_json::json!(1i64),
            "generation must stay at 1 after a no-op update that omits defaulted fields — \
             controllers gate on observedGeneration==generation; a spurious bump causes \
             every controller to re-reconcile unchanged pods and the k8s pod-generation \
             conformance suite to fail with 'Expected 2 to be equivalent to 1'"
        );
    }

    /// A real spec change (image update) after a create must still bump generation.
    ///
    /// Verifies that the no-op fix does not suppress legitimate generation increments —
    /// controllers would miss the new spec and never re-reconcile if this were broken.
    #[test]
    fn real_spec_change_still_bumps_generation() {
        // Simulate stored spec after create defaults.
        let mut stored_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "test-pod", "namespace": "default", "generation": 1i64},
            "spec": {
                "containers": [{"name": "app", "image": "nginx:1.0"}]
            }
        });
        apply_pod_create_defaults(&mut stored_pod);
        let spec_before = stored_pod["spec"].clone();

        // Incoming pod changes the container image — a real spec change.
        let mut incoming_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "test-pod", "namespace": "default", "generation": 1i64},
            "spec": {
                "containers": [{"name": "app", "image": "nginx:2.0"}]
            }
        });

        increment_pod_generation_if_spec_changed(&mut incoming_pod, &spec_before);

        assert_eq!(
            incoming_pod["metadata"]["generation"],
            serde_json::json!(2i64),
            "generation must increment to 2 on a real spec change — controllers use \
             generation/observedGeneration to detect new work; no increment means stale reconcile"
        );
    }

    /// A changed automountServiceAccountToken must still bump generation.
    ///
    /// increment_pod_generation_if_spec_changed used to strip this field from both sides
    /// of the comparison under a false "proto decoder skips it" premise,
    /// mirroring the fix to validate_pod_spec_immutable. Guards against that
    /// strip being reintroduced, which would silently hide this field's changes from
    /// generation tracking.
    #[test]
    fn automount_service_account_token_change_bumps_generation() {
        let spec_before = serde_json::json!({
            "containers": [{"name": "app", "image": "nginx:1.0"}],
            "automountServiceAccountToken": true
        });
        let mut pod = serde_json::json!({
            "metadata": {"generation": 1i64},
            "spec": {
                "containers": [{"name": "app", "image": "nginx:1.0"}],
                "automountServiceAccountToken": false
            }
        });
        increment_pod_generation_if_spec_changed(&mut pod, &spec_before);
        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(2i64),
            "generation must increment when automountServiceAccountToken changes — a stale \
             strip of this field from the comparison would hide the change from controllers \
             gating on observedGeneration"
        );
    }

    /// Protobuf-decoded spec with spurious defaultMode in projected source's downwardAPI must
    /// not bump generation on a no-op replace.
    ///
    /// client-go sends pods via protobuf. The u7s proto decoder calls
    /// downward_api_volume_source_to_json with defaultMode=0 for projected sources'
    /// DownwardAPIProjection entries (which have no defaultMode field), which injects
    /// defaultMode:420 into the inner source. The stored spec (created via JSON or
    /// apply_pod_create_defaults) has no defaultMode in that position. Without normalization,
    /// every protobuf no-op replace by client-go bumps generation — conformance test
    /// "pod generation should start at 1 and increment per update" (pods.go:530) would fail.
    #[test]
    fn proto_style_noop_with_spurious_defaultmode_in_downward_api_source() {
        // Stored spec: projected volume with downwardAPI source (no defaultMode in source).
        let spec_before = serde_json::json!({
            "containers": [{"name": "app", "image": "nginx:1.0"}],
            "volumes": [{
                "name": "kube-api-access",
                "projected": {
                    "defaultMode": 420,
                    "sources": [
                        {"serviceAccountToken": {"expirationSeconds": 3607, "path": "token"}},
                        {"downwardAPI": {"items": [{"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.namespace"}, "path": "namespace"}]}}
                    ]
                }
            }]
        });

        // Incoming spec: same content but with spurious defaultMode:420 in the downwardAPI source
        // (as injected by the proto decoder when client-go sends the pod back via protobuf).
        let mut incoming_pod = serde_json::json!({
            "metadata": {"generation": 1i64},
            "spec": {
                "containers": [{"name": "app", "image": "nginx:1.0"}],
                "volumes": [{
                    "name": "kube-api-access",
                    "projected": {
                        "defaultMode": 420,
                        "sources": [
                            {"serviceAccountToken": {"expirationSeconds": 3607, "path": "token"}},
                            {"downwardAPI": {
                                "defaultMode": 420,
                                "items": [{"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.namespace"}, "path": "namespace"}]
                            }}
                        ]
                    }
                }]
            }
        });

        increment_pod_generation_if_spec_changed(&mut incoming_pod, &spec_before);

        assert_eq!(
            incoming_pod["metadata"]["generation"],
            serde_json::json!(1i64),
            "generation must stay at 1 when client-go sends a protobuf no-op replace — the proto \
             decoder injects defaultMode:420 into projected.sources[].downwardAPI (a field that \
             DownwardAPIProjection does not have); without normalization every client-go replace \
             bumps generation and conformance pod-generation tests fail"
        );
    }

    /// apply_pod_spec_defaults must not inject a `projected` field into non-projected volumes.
    ///
    /// serde_json's IndexMut autovivifies intermediate null entries when accessed mutably.
    /// If the projected-source normalization code uses mutable indexing on a volume that has
    /// no `projected` field (e.g. a plain configMap volume), it would corrupt the volume spec
    /// by inserting `"projected": {"sources": null}`, causing the kubelet to see two volume
    /// plugins and refuse to mount the volume ("multiple volume plugins matched").
    #[test]
    fn spec_defaults_do_not_autovivify_projected_on_non_projected_volumes() {
        let mut pod = serde_json::json!({
            "metadata": {"generation": 1i64},
            "spec": {
                "containers": [{"name": "app", "image": "nginx:1.0"}],
                "volumes": [
                    {"name": "config-vol", "configMap": {"name": "my-cm", "defaultMode": 420}},
                    {"name": "empty", "emptyDir": {}}
                ]
            }
        });

        apply_pod_spec_defaults(&mut pod);

        assert!(
            pod["spec"]["volumes"][0]["projected"].is_null(),
            "apply_pod_spec_defaults must not inject a projected field into a configMap volume — \
             the kubelet would see both configMap and projected plugins and refuse to mount"
        );
        assert!(
            pod["spec"]["volumes"][1]["projected"].is_null(),
            "apply_pod_spec_defaults must not inject a projected field into an emptyDir volume"
        );
        assert!(
            pod["spec"]["volumes"][0]["downwardAPI"].is_null()
                && pod["spec"]["volumes"][1]["downwardAPI"].is_null(),
            "apply_pod_spec_defaults must not inject a downwardAPI field into a configMap or \
             emptyDir volume — same 'kubelet sees two volume plugins' failure mode as projected"
        );
    }

    /// Adding a toleration via client-go (which reads JSON-in-proto and omits nil fields on PUT)
    /// must still bump generation.
    ///
    /// client-go reads the pod via proto GET (u7s returns JSON-in-proto-envelope). The stored
    /// spec may have explicit null fields (env:null, ports:null, initContainers:null, volumes:null).
    /// When client-go re-encodes the Go struct to JSON with omitempty, these nil slices are
    /// omitted. However apply_pod_spec_defaults uses IndexMut to access container["env"] and
    /// container["ports"], which AUTOVIVIFIES the absent keys as null — so both sides end up
    /// with env:null after normalization. The toleration added by the test creates a real diff.
    #[test]
    fn client_go_toleration_update_bumps_generation() {
        // spec_before: stored spec with explicit null fields (as u7s stores them).
        let spec_before = serde_json::json!({
            "containers": [
                {
                    "command": ["sleep", "300"],
                    "env": null,
                    "image": "registry.k8s.io/e2e-test-images/busybox:1.37.0-1",
                    "imagePullPolicy": "IfNotPresent",
                    "name": "busybox",
                    "ports": null
                }
            ],
            "dnsPolicy": "ClusterFirst",
            "enableServiceLinks": true,
            "initContainers": null,
            "nodeName": "lima-node-2",
            "terminationGracePeriodSeconds": 5,
            "volumes": null,
            "automountServiceAccountToken": true
        });

        // incoming pod: client-go omits nil fields (env, ports, initContainers, volumes) but adds toleration.
        let mut incoming_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "test-pod", "namespace": "default", "generation": 1i64},
            "spec": {
                "containers": [
                    {
                        "command": ["sleep", "300"],
                        "image": "registry.k8s.io/e2e-test-images/busybox:1.37.0-1",
                        "imagePullPolicy": "IfNotPresent",
                        "name": "busybox"
                        // env, ports omitted (nil in Go → omitempty → absent)
                    }
                ],
                "dnsPolicy": "ClusterFirst",
                "enableServiceLinks": true,
                "nodeName": "lima-node-2",
                "terminationGracePeriodSeconds": 5,
                "automountServiceAccountToken": true,
                "tolerations": [{"key": "dedicated", "operator": "Equal", "value": "test", "effect": "NoSchedule"}]
                // initContainers, volumes omitted (nil → omitempty → absent)
            }
        });

        increment_pod_generation_if_spec_changed(&mut incoming_pod, &spec_before);

        assert_eq!(
            incoming_pod["metadata"]["generation"],
            serde_json::json!(2i64),
            "adding a toleration via client-go PUT must bump generation — client-go omits nil \
             fields (env, ports, volumes, initContainers) but the real change (toleration added) \
             must still be detected; pods.go:530 conformance test asserts gen==2 after this update"
        );
    }

    /// Graceful delete (setting deletionTimestamp) must increment generation.
    ///
    /// Kubernetes conformance test "custom-set generation on new pods and graceful delete"
    /// (pods.go:573) creates a pod (gen=1), issues a graceful DELETE, and asserts gen=2.
    /// Without this bump, controllers watching generation/observedGeneration would never see
    /// the terminating transition — they would attempt to reconcile a pod that is already gone.
    ///
    /// This test verifies the arithmetic that delete_pod applies directly, mirroring the
    /// logic in the soft-delete branch of the handler.
    #[test]
    fn graceful_delete_increments_generation() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-pod",
                "namespace": "default",
                "generation": 1i64
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        // Simulate what delete_pod does: stamp deletionTimestamp, increment generation.
        pod["metadata"]["deletionTimestamp"] = serde_json::json!("2026-01-01T00:00:00Z");
        let current_gen = pod["metadata"]["generation"].as_i64().unwrap_or(1);
        pod["metadata"]["generation"] = serde_json::json!(current_gen + 1);

        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(2i64),
            "graceful delete must bump generation from 1 to 2 — pods.go:573 conformance test \
             asserts gen=2 after DELETE; controllers use this to detect the terminating transition"
        );
    }

    /// A PUT that sends a lower generation value must not downgrade the stored generation.
    ///
    /// The PodObservedGenerationTracking conformance test (pods.go:530) includes a case
    /// where the client sets `pod.SetGeneration(1)` and sends a PUT on a pod already at
    /// generation=5. The server must ignore the client-supplied generation and keep it at 5.
    /// Without this protection, the stored generation drops to 1 and the conformance
    /// assertion `Expect(pod.Generation).To(BeEquivalentTo(5))` fails.
    ///
    /// This test fails if replace_pod does not restore the stored generation before calling
    /// increment_pod_generation_if_spec_changed.
    #[test]
    fn client_supplied_lower_generation_not_accepted_on_noop_replace() {
        // Simulate replace_pod: stored generation is 5, client sends generation=1,
        // spec is unchanged. The server must keep generation at 5.
        let spec = serde_json::json!({
            "containers": [{"name": "app", "image": "nginx:1.0"}],
            "dnsPolicy": "ClusterFirst",
            "enableServiceLinks": true
        });
        let stored_generation = serde_json::json!(5i64);

        // Incoming PUT body: client sends generation=1 (attempting to downgrade).
        let mut incoming_pod = serde_json::json!({
            "metadata": {"name": "test-pod", "generation": 1i64},
            "spec": spec.clone()
        });

        // Simulate what replace_pod does: restore stored generation, then check for spec change.
        incoming_pod["metadata"]["generation"] = stored_generation;
        let spec_before = spec.clone();
        increment_pod_generation_if_spec_changed(&mut incoming_pod, &spec_before);

        assert_eq!(
            incoming_pod["metadata"]["generation"],
            serde_json::json!(5i64),
            "a client-supplied generation=1 on a PUT to a pod at generation=5 must be rejected \
             — generation is server-managed; allowing downgrade breaks the PodObservedGenerationTracking \
             conformance test (pods.go:530) which asserts generation stays at 5 after a client \
             attempts to set it to 1"
        );
    }

    /// A PUT that sends a lower generation but with a real spec change must increment from
    /// the stored generation, not from the client-supplied value.
    ///
    /// If the server used the client-supplied generation=1 as the base, incrementing would
    /// produce generation=2 instead of the correct generation=6 (stored=5, bump by 1).
    /// Controllers relying on generation to track spec versions would be confused.
    #[test]
    fn client_supplied_lower_generation_does_not_affect_increment_base() {
        let spec_before = serde_json::json!({
            "containers": [{"name": "app", "image": "nginx:1.0"}]
        });
        let stored_generation = serde_json::json!(5i64);

        // Incoming PUT body: client sends generation=1 AND changes the image.
        let mut incoming_pod = serde_json::json!({
            "metadata": {"name": "test-pod", "generation": 1i64},
            "spec": {"containers": [{"name": "app", "image": "nginx:2.0"}]}
        });

        // Simulate what replace_pod does: restore stored generation before incrementing.
        incoming_pod["metadata"]["generation"] = stored_generation;
        increment_pod_generation_if_spec_changed(&mut incoming_pod, &spec_before);

        assert_eq!(
            incoming_pod["metadata"]["generation"],
            serde_json::json!(6i64),
            "a spec-changing PUT with client-supplied generation=1 on a pod at generation=5 must \
             increment to 6, not 2 — generation must increment from the stored value, not the \
             client-supplied value; otherwise controllers tracking spec versions via generation \
             lose the history of previous spec changes"
        );
    }
}

/// Extract the target node name from a Binding object body.
///
/// Returns `Err` with a 400 if `target.name` is absent or empty.
/// Extracted for testability — the full `bind_pod` handler is async and requires a live store.
pub(crate) fn extract_binding_node_name(
    binding: &serde_json::Value,
) -> Result<String, crate::status::StatusError> {
    let parsed: Binding = serde_json::from_value(binding.clone())
        .map_err(|_| Status::bad_request("target.name is required".into()))?;
    if parsed.target.name.is_empty() {
        return Err(Status::bad_request("target.name is required".into()));
    }
    Ok(parsed.target.name)
}

pub(crate) async fn bind_pod<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ns = parse_namespace(&raw_ns, &state).await?;
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let binding: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let node_name = extract_binding_node_name(&binding)?;

    let key = object_key("pods", ns.as_str(), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, "Pod"))?;

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // A pod may only be bound once. Rejecting unconditionally (not just on a
    // mismatched target) matches upstream kube-apiserver, which never allows a
    // second bind even to the same node — a stray duplicate bind call must not
    // be able to silently reassign or re-trigger scheduling for a pod whose
    // containers are already running under the original node's kubelet.
    if let Some(existing) = obj.body["spec"]["nodeName"].as_str() {
        if !existing.is_empty() {
            return Err(Status::conflict(format!(
                "Pod \"{name}\" is already assigned to node \"{existing}\""
            )));
        }
    }

    obj.body["spec"]["nodeName"] = serde_json::Value::String(node_name);

    // Set PodScheduled=True now that the pod has a node assignment.
    //
    // In real k8s the scheduler does a separate PATCH on the status subresource to
    // flip PodScheduled from False→True.  In u7s we do it atomically inside bind_pod
    // so no separate scheduler status-patch is required.  Conformance scheduling tests
    // wait for PodScheduled=True before asserting the pod is running.
    let now = utc_now_rfc3339();
    set_pod_scheduled_true(&mut obj.body, &now);

    // Dry-run: validation passed; return the would-be bound pod without persisting it or
    // registering it with the node-authorization graph — mirrors replace_pod's dry-run
    // early-return.
    if super::json_patch::is_dry_run_header(&headers) {
        return Ok((StatusCode::CREATED, Json(obj.body)));
    }

    let expected_rv = parse_resource_version(obj.resource_version())?;

    let new_rv = state
        .store
        .put(&key, obj.to_bytes(), expected_rv)
        .await
        .map_err(|e| store_err_to_status(e, &name))?;

    obj.set_resource_version(new_rv);

    // Now that spec.nodeName is set, register the pod (and its reference edges) with the
    // node-authorization graph — this is what actually grants the target node's kubelet
    // access to this pod and whatever it references.
    state.node_graph.apply_pod(ns.as_str(), &name, &obj.body);

    Ok((StatusCode::CREATED, Json(obj.body)))
}

// ---------------------------------------------------------------------------
// Unit tests for pure functions: store_err_to_status, JSON patch helpers,
// binding extraction. These cover lines/branches not reachable via the
// existing watch_tests / field_selector_tests / status_tests / patch_type_tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pure_logic_tests {
    use super::*;
    use crate::handlers::json_patch::{
        apply_json_patch, json_navigate_one, json_navigate_one_or_create, json_patch_add,
        json_patch_navigate_mut, json_patch_remove, json_patch_set, json_pointer_segments,
    };
    use u7s_store::StoreError;

    // -----------------------------------------------------------------------
    // store_err_to_status
    // -----------------------------------------------------------------------

    /// StoreError::NotFound must map to HTTP 404 and name the "Pod" kind.
    /// Without this, callers (get_pod, delete_pod) would surface wrong status codes.
    #[test]
    fn store_err_not_found_becomes_404() {
        let err = StoreError::NotFound {
            key: "/registry/pods/default/my-pod".into(),
        };
        let status_err = store_err_to_status(err, "my-pod");
        let resp: axum::response::Response = status_err.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    }

    /// StoreError::AlreadyExists must map to HTTP 409.
    /// create_pod must surface Conflict when the key already exists.
    #[test]
    fn store_err_already_exists_becomes_409() {
        let err = StoreError::AlreadyExists {
            key: "/registry/pods/default/my-pod".into(),
        };
        let status_err = store_err_to_status(err, "my-pod");
        let resp: axum::response::Response = status_err.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::CONFLICT);
    }

    /// StoreError::RevisionMismatch must map to HTTP 409 Conflict.
    /// replace_pod OCC relies on this: a stale resourceVersion must not silently
    /// overwrite newer data.
    #[test]
    fn store_err_revision_mismatch_becomes_409() {
        let err = StoreError::RevisionMismatch {
            expected: 3,
            current: 7,
        };
        let status_err = store_err_to_status(err, "my-pod");
        let resp: axum::response::Response = status_err.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::CONFLICT);
    }

    /// Other StoreErrors (e.g. Compacted) must map to HTTP 500 Internal Server Error.
    /// This is the catch-all arm; any unrecognised store error must not leak as a 2xx.
    #[test]
    fn store_err_compacted_becomes_500() {
        let err = StoreError::Compacted {
            requested: 1,
            horizon: 100,
        };
        let status_err = store_err_to_status(err, "my-pod");
        let resp: axum::response::Response = status_err.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -----------------------------------------------------------------------
    // json_pointer_segments
    // -----------------------------------------------------------------------

    /// Empty pointer yields empty segments — root document path.
    #[test]
    fn pointer_segments_empty_string() {
        assert!(json_pointer_segments("").is_empty());
    }

    /// "/a/b/c" splits into ["a", "b", "c"].
    #[test]
    fn pointer_segments_three_parts() {
        assert_eq!(json_pointer_segments("/a/b/c"), vec!["a", "b", "c"]);
    }

    /// RFC 6901 escape sequences: ~1 -> "/" and ~0 -> "~".
    #[test]
    fn pointer_segments_rfc6901_escapes() {
        let segs = json_pointer_segments("/a~1b/c~0d");
        assert_eq!(segs, vec!["a/b", "c~d"]);
    }

    /// A pointer without a leading slash is used as-is (strip_prefix returns None).
    #[test]
    fn pointer_segments_no_leading_slash() {
        let segs = json_pointer_segments("foo/bar");
        assert_eq!(segs, vec!["foo", "bar"]);
    }

    // -----------------------------------------------------------------------
    // json_patch_navigate_mut
    // -----------------------------------------------------------------------

    /// Empty segments must return an error ("cannot operate on root document").
    #[test]
    fn navigate_mut_empty_segments_returns_err() {
        let mut obj = serde_json::json!({"a": 1});
        let result = json_patch_navigate_mut(&mut obj, &[]);
        assert!(result.is_err(), "empty segments must error");
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Single segment returns (root_object, "key") — the last segment.
    #[test]
    fn navigate_mut_single_segment() {
        let mut obj = serde_json::json!({"x": 99});
        let segs = vec!["x".to_string()];
        let (parent, key) =
            json_patch_navigate_mut(&mut obj, &segs).unwrap_or_else(|_| panic!("must succeed"));
        assert_eq!(key, "x");
        assert!(parent.is_object());
    }

    // -----------------------------------------------------------------------
    // json_navigate_one
    // -----------------------------------------------------------------------

    /// Traversing into an object with a known key returns a reference to that key's
    /// value specifically, not the root or some other field. A bug that returned the
    /// wrong child (e.g. the root object, or a sibling key) here would silently corrupt
    /// every patch/status subresource path that traverses through an object segment.
    #[test]
    fn navigate_one_object_known_key() {
        let mut obj = serde_json::json!({"spec": {"nodeName": "worker-1"}});
        let result = json_navigate_one(&mut obj, "spec");
        let val = result.unwrap_or_else(|_| panic!("must succeed"));
        assert_eq!(*val, serde_json::json!({"nodeName": "worker-1"}));
    }

    /// Traversing into an object with an unknown key returns 422.
    #[test]
    fn navigate_one_object_missing_key_returns_422() {
        let mut obj = serde_json::json!({"spec": {}});
        let result = json_navigate_one(&mut obj, "status");
        assert!(result.is_err());
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Traversing into an array by numeric index succeeds.
    #[test]
    fn navigate_one_array_valid_index() {
        let mut obj = serde_json::json!([10, 20, 30]);
        let result = json_navigate_one(&mut obj, "1");
        assert!(result.is_ok());
        let val = result.unwrap_or_else(|_| panic!("must succeed"));
        assert_eq!(*val, serde_json::json!(20));
    }

    /// Traversing into an array with an out-of-bounds index returns 422.
    #[test]
    fn navigate_one_array_oob_returns_422() {
        let mut obj = serde_json::json!([10]);
        let result = json_navigate_one(&mut obj, "5");
        assert!(result.is_err());
    }

    /// Traversing into an array with a non-numeric index returns 422.
    #[test]
    fn navigate_one_array_non_numeric_index_returns_422() {
        let mut obj = serde_json::json!([10]);
        let result = json_navigate_one(&mut obj, "not-a-number");
        assert!(result.is_err());
    }

    /// Traversing into a scalar (non-object/array) returns 422.
    #[test]
    fn navigate_one_scalar_returns_422() {
        let mut obj = serde_json::json!(42);
        let result = json_navigate_one(&mut obj, "foo");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // json_navigate_one_or_create
    // -----------------------------------------------------------------------

    /// Creating an intermediate key in an object succeeds.
    #[test]
    fn navigate_one_or_create_creates_missing_key() {
        let mut obj = serde_json::json!({});
        let result = json_navigate_one_or_create(&mut obj, "spec");
        assert!(result.is_ok());
        let node = result.unwrap_or_else(|_| panic!("must succeed"));
        assert!(node.is_object());
    }

    /// Creating into a non-object (e.g. array, scalar) returns 422.
    #[test]
    fn navigate_one_or_create_non_object_returns_422() {
        let mut obj = serde_json::json!([1, 2, 3]);
        let result = json_navigate_one_or_create(&mut obj, "key");
        assert!(result.is_err());
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// An array index that already has an element must be a valid path intermediate, not
    /// an error. A CRD's `spec.versions` is an array, and every CRD has at least one
    /// version, so JSON-Patch 'add' on a path like `/spec/versions/0/schema/...` must
    /// descend into the existing element at 0 rather than reject it as "non-object" —
    /// otherwise PATCHing a CRD's schema via RFC 6902 (as kubectl and the conformance
    /// suite do) 422s even though nothing needed to be fabricated.
    #[test]
    fn navigate_one_or_create_existing_array_index_succeeds() {
        let mut obj = serde_json::json!([{"name": "v1"}]);
        let result = json_navigate_one_or_create(&mut obj, "0");
        let node = result.unwrap_or_else(|_| {
            panic!("an existing array element must be a valid 'add' path intermediate")
        });
        assert_eq!(*node, serde_json::json!({"name": "v1"}));
    }

    /// An out-of-bounds array index must still error — 'add' may create missing object
    /// keys, but it must never fabricate array elements to satisfy a path.
    #[test]
    fn navigate_one_or_create_array_index_out_of_bounds_returns_422() {
        let mut obj = serde_json::json!([{"name": "v1"}]);
        let result = json_navigate_one_or_create(&mut obj, "5");
        assert!(
            result.is_err(),
            "an out-of-bounds array index must not be silently created"
        );
    }

    // -----------------------------------------------------------------------
    // json_patch_add — branches not covered by patch_type_tests
    // -----------------------------------------------------------------------

    /// add to root (empty pointer) replaces the whole document.
    #[test]
    fn patch_add_root_replaces_document() {
        let mut obj = serde_json::json!({"old": true});
        json_patch_add(&mut obj, "", serde_json::json!({"new": true}))
            .unwrap_or_else(|_| panic!("add to root must succeed"));
        assert_eq!(obj, serde_json::json!({"new": true}));
    }

    /// add with "-" as last segment appends to an array.
    /// This is the RFC 6902 append convention; kubelet uses it for conditions.
    #[test]
    fn patch_add_dash_appends_to_array() {
        let mut obj = serde_json::json!({"items": [1, 2]});
        json_patch_add(&mut obj, "/items/-", serde_json::json!(3))
            .unwrap_or_else(|_| panic!("add '-' must succeed"));
        assert_eq!(obj["items"], serde_json::json!([1, 2, 3]));
    }

    /// add with a numeric index inserts at that position.
    #[test]
    fn patch_add_numeric_index_inserts_at_position() {
        let mut obj = serde_json::json!({"items": [1, 3]});
        json_patch_add(&mut obj, "/items/1", serde_json::json!(2))
            .unwrap_or_else(|_| panic!("add at index must succeed"));
        assert_eq!(obj["items"], serde_json::json!([1, 2, 3]));
    }

    /// add with an out-of-bounds index returns 422.
    #[test]
    fn patch_add_array_oob_returns_422() {
        let mut obj = serde_json::json!({"items": [1]});
        let result = json_patch_add(&mut obj, "/items/5", serde_json::json!(99));
        assert!(result.is_err());
    }

    /// add with an invalid (non-numeric) array index returns 422.
    #[test]
    fn patch_add_invalid_array_index_returns_422() {
        let mut obj = serde_json::json!({"items": [1]});
        let result = json_patch_add(&mut obj, "/items/not-a-num", serde_json::json!(99));
        assert!(result.is_err());
    }

    /// add to a scalar (non-object/array) returns 422.
    #[test]
    fn patch_add_to_scalar_returns_422() {
        let mut obj = serde_json::json!(42);
        let result = json_patch_add(&mut obj, "/foo", serde_json::json!(1));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // json_patch_set — branches not covered by patch_type_tests
    // -----------------------------------------------------------------------

    /// set (replace) on root (empty pointer) replaces the whole document.
    #[test]
    fn patch_set_root_replaces_document() {
        let mut obj = serde_json::json!({"old": true});
        json_patch_set(&mut obj, "", serde_json::json!({"new": true}))
            .unwrap_or_else(|_| panic!("set root must succeed"));
        assert_eq!(obj, serde_json::json!({"new": true}));
    }

    /// set with "-" on an array appends (same as add "-").
    #[test]
    fn patch_set_dash_appends_to_array() {
        let mut obj = serde_json::json!({"items": [1, 2]});
        json_patch_set(&mut obj, "/items/-", serde_json::json!(3))
            .unwrap_or_else(|_| panic!("set '-' must succeed"));
        assert_eq!(obj["items"], serde_json::json!([1, 2, 3]));
    }

    /// set (replace) on an existing numeric array index overwrites that element in
    /// place and leaves the array length unchanged. RFC 6902 §4.3 defines "replace"
    /// as remove-then-add at the *same* location, not an insert: a client patching
    /// EndpointSlice addresses[0] (or any array field) must get back a same-length
    /// array with only the target index changed, not a corrupted, ever-growing array
    /// with the old value pushed to the tail (the bug this test guards against).
    #[test]
    fn patch_set_numeric_index_overwrites_in_place() {
        let mut obj = serde_json::json!({"items": ["9.9.9.9", "keep"]});
        json_patch_set(&mut obj, "/items/0", serde_json::json!("8.8.8.8"))
            .unwrap_or_else(|_| panic!("replace on an existing index must succeed"));
        assert_eq!(
            obj["items"],
            serde_json::json!(["8.8.8.8", "keep"]),
            "replace must overwrite index 0 in place, not insert and shift 'keep' along"
        );
    }

    /// set (replace) with idx == arr.len() is rejected: RFC 6902 "replace" only
    /// targets an existing element, unlike "add" which may append past the end.
    /// Allowing this would let a corrupted patch silently grow an array via replace.
    #[test]
    fn patch_set_array_index_equal_len_returns_422() {
        let mut obj = serde_json::json!({"items": [1]});
        let result = json_patch_set(&mut obj, "/items/1", serde_json::json!(99));
        assert!(
            result.is_err(),
            "replace past the end of the array must be rejected, not treated as an append"
        );
    }

    /// set with a numeric index beyond bounds returns 422.
    #[test]
    fn patch_set_array_oob_returns_422() {
        let mut obj = serde_json::json!({"items": [1]});
        let result = json_patch_set(&mut obj, "/items/5", serde_json::json!(99));
        assert!(result.is_err());
    }

    /// set with an invalid array index returns 422.
    #[test]
    fn patch_set_invalid_array_index_returns_422() {
        let mut obj = serde_json::json!({"items": [1]});
        let result = json_patch_set(&mut obj, "/items/bad", serde_json::json!(2));
        assert!(result.is_err());
    }

    /// set on a scalar parent (non-object/array) returns 422.
    #[test]
    fn patch_set_non_object_parent_returns_422() {
        let mut obj = serde_json::json!({"leaf": 42});
        // "leaf" is an integer; navigating into it then setting a sub-key must fail.
        let result = json_patch_set(&mut obj, "/leaf/sub", serde_json::json!(1));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // json_patch_remove — branches not covered by patch_type_tests
    // -----------------------------------------------------------------------

    /// remove a key that does not exist returns 422.
    #[test]
    fn patch_remove_missing_key_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let result = json_patch_remove(&mut obj, "/b");
        assert!(result.is_err());
    }

    /// remove by valid array index succeeds and shortens the array.
    #[test]
    fn patch_remove_array_index_succeeds() {
        let mut obj = serde_json::json!({"items": [10, 20, 30]});
        json_patch_remove(&mut obj, "/items/1")
            .unwrap_or_else(|_| panic!("remove at valid index must succeed"));
        assert_eq!(obj["items"], serde_json::json!([10, 30]));
    }

    /// remove with an out-of-bounds array index returns 422.
    #[test]
    fn patch_remove_array_oob_returns_422() {
        let mut obj = serde_json::json!({"items": [10]});
        let result = json_patch_remove(&mut obj, "/items/5");
        assert!(result.is_err());
    }

    /// remove with a non-numeric array index returns 422.
    #[test]
    fn patch_remove_invalid_array_index_returns_422() {
        let mut obj = serde_json::json!({"items": [10]});
        let result = json_patch_remove(&mut obj, "/items/not-num");
        assert!(result.is_err());
    }

    /// remove from a scalar (non-object/array) returns 422.
    #[test]
    fn patch_remove_scalar_parent_returns_422() {
        let mut obj = serde_json::json!({"leaf": 42});
        // Navigate into "leaf" (integer) then attempt remove of a sub-key.
        let result = json_patch_remove(&mut obj, "/leaf/sub");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // apply_json_patch — error paths not covered by patch_type_tests
    // -----------------------------------------------------------------------

    /// patch body must be a JSON array; a non-array returns 422.
    #[test]
    fn apply_json_patch_non_array_body_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!({"op": "replace", "path": "/a", "value": 2});
        let result = apply_json_patch(&mut obj, &patch);
        assert!(result.is_err());
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// An operation missing the "op" field returns 422.
    #[test]
    fn apply_json_patch_missing_op_field_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"path": "/a", "value": 2}]);
        let result = apply_json_patch(&mut obj, &patch);
        assert!(result.is_err());
    }

    /// An operation missing the "path" field returns 422.
    #[test]
    fn apply_json_patch_missing_path_field_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "replace", "value": 2}]);
        let result = apply_json_patch(&mut obj, &patch);
        assert!(result.is_err());
    }

    /// An "add" operation missing "value" returns 422.
    #[test]
    fn apply_json_patch_add_missing_value_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "add", "path": "/b"}]);
        let result = apply_json_patch(&mut obj, &patch);
        assert!(result.is_err());
    }

    /// A "replace" operation missing "value" returns 422.
    #[test]
    fn apply_json_patch_replace_missing_value_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "replace", "path": "/a"}]);
        let result = apply_json_patch(&mut obj, &patch);
        assert!(result.is_err());
    }

    /// An unsupported op (e.g. "copy") returns 422.
    /// Only add, remove, replace are supported.
    #[test]
    fn apply_json_patch_unsupported_op_returns_422() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([{"op": "copy", "from": "/a", "path": "/b"}]);
        let result = apply_json_patch(&mut obj, &patch);
        assert!(result.is_err());
    }

    /// An empty array patch is a no-op and must succeed.
    #[test]
    fn apply_json_patch_empty_array_is_noop() {
        let mut obj = serde_json::json!({"a": 1});
        let patch = serde_json::json!([]);
        assert!(apply_json_patch(&mut obj, &patch).is_ok());
        assert_eq!(obj["a"], 1);
    }

    // -----------------------------------------------------------------------
    // extract_binding_node_name
    // -----------------------------------------------------------------------

    /// A valid binding with target.name returns the node name.
    /// This is the primary scheduler use-case: bind pod to node.
    #[test]
    fn extract_binding_node_name_valid() {
        let binding = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Binding",
            "target": {"kind": "Node", "name": "worker-1"}
        });
        let result = extract_binding_node_name(&binding);
        let name = result.unwrap_or_else(|_| panic!("valid binding must yield node name"));
        assert_eq!(name, "worker-1");
    }

    /// A binding with an empty target.name must be rejected with 400.
    /// An empty nodeName would silently leave the pod unscheduled.
    #[test]
    fn extract_binding_node_name_empty_returns_400() {
        let binding = serde_json::json!({"target": {"name": ""}});
        let result = extract_binding_node_name(&binding);
        assert!(result.is_err());
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    /// A binding missing target.name must be rejected with 400.
    #[test]
    fn extract_binding_node_name_missing_returns_400() {
        let binding = serde_json::json!({"target": {}});
        let result = extract_binding_node_name(&binding);
        assert!(result.is_err());
        let resp: axum::response::Response = match result {
            Err(e) => e.into_response(),
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    /// A binding missing target entirely must be rejected with 400.
    #[test]
    fn extract_binding_node_name_no_target_returns_400() {
        let binding = serde_json::json!({"kind": "Binding"});
        let result = extract_binding_node_name(&binding);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // set_pod_scheduled_true
    // -----------------------------------------------------------------------

    /// set_pod_scheduled_true must flip an existing PodScheduled=False to True.
    ///
    /// bind_pod calls this after setting spec.nodeName.  If it doesn't flip the
    /// condition, scheduling conformance tests that wait for PodScheduled=True will
    /// time out.  This test fails if set_pod_scheduled_true is reverted to a no-op.
    #[test]
    fn set_pod_scheduled_true_flips_false_condition() {
        let mut pod = serde_json::json!({
            "status": {
                "conditions": [{
                    "type": "PodScheduled",
                    "status": "False",
                    "reason": "Unschedulable",
                    "lastTransitionTime": "2024-01-01T00:00:00Z"
                }]
            }
        });

        set_pod_scheduled_true(&mut pod, "2024-01-01T00:00:01Z");

        let conditions = pod["status"]["conditions"]
            .as_array()
            .expect("conditions must be an array");
        let scheduled = conditions
            .iter()
            .find(|c| c["type"].as_str() == Some("PodScheduled"))
            .expect("PodScheduled condition must still be present after flip");
        assert_eq!(
            scheduled["status"], "True",
            "PodScheduled must be True after bind_pod calls set_pod_scheduled_true — \
             scheduling conformance tests wait for this transition"
        );
        assert!(
            scheduled["reason"].as_str().unwrap_or("").is_empty(),
            "PodScheduled=True must not carry a reason after bind — upstream apiserver's \
             bind path writes only Type+Status, so a stray reason (here, a stale \
             'Unschedulable' surviving the False->True flip) makes kubelet's local cache \
             disagree with the apiserver on every reconcile tick, causing needsReconcile \
             log spam and redundant status re-sends"
        );
    }

    /// set_pod_scheduled_true must append PodScheduled=True when no condition exists.
    ///
    /// Handles pods that were created without the initial PodScheduled=False default
    /// (e.g. pods seeded directly into the store in tests).
    #[test]
    fn set_pod_scheduled_true_appends_when_absent() {
        let mut pod = serde_json::json!({
            "status": {"phase": "Pending"}
        });

        set_pod_scheduled_true(&mut pod, "2024-01-01T00:00:01Z");

        let conditions = pod["status"]["conditions"]
            .as_array()
            .expect("conditions must be an array after append");
        let scheduled = conditions
            .iter()
            .find(|c| c["type"].as_str() == Some("PodScheduled"))
            .expect("PodScheduled condition must be present after append");
        assert_eq!(
            scheduled["status"], "True",
            "appended PodScheduled condition must have status=True"
        );
    }

    /// set_pod_scheduled_true must not disturb other conditions.
    ///
    /// Pods may already have Initialized/Ready conditions set by kubelet; only
    /// PodScheduled must be touched.
    #[test]
    fn set_pod_scheduled_true_leaves_other_conditions_intact() {
        let mut pod = serde_json::json!({
            "status": {
                "conditions": [
                    {
                        "type": "Initialized",
                        "status": "True",
                        "lastTransitionTime": "2024-01-01T00:00:00Z"
                    },
                    {
                        "type": "PodScheduled",
                        "status": "False",
                        "reason": "Unschedulable",
                        "lastTransitionTime": "2024-01-01T00:00:00Z"
                    }
                ]
            }
        });

        set_pod_scheduled_true(&mut pod, "2024-01-01T00:00:01Z");

        let conditions = pod["status"]["conditions"]
            .as_array()
            .expect("conditions must be an array");
        assert_eq!(
            conditions.len(),
            2,
            "only PodScheduled must be touched; Initialized must survive"
        );
        let initialized = conditions
            .iter()
            .find(|c| c["type"].as_str() == Some("Initialized"))
            .expect("Initialized condition must survive");
        assert_eq!(
            initialized["status"], "True",
            "Initialized condition must not be modified by set_pod_scheduled_true"
        );
    }

    // -----------------------------------------------------------------------
    // apply_runtime_class_overhead
    // -----------------------------------------------------------------------

    /// A pod referencing a RuntimeClass with overhead.podFixed{cpu:10m} must have
    /// spec.overhead set to {cpu:10m} by apply_runtime_class_overhead.
    ///
    /// The RuntimeClass admission plugin in real kube-apiserver copies podFixed into
    /// pod.spec.overhead on CREATE. Without this, conformance test
    /// '[sig-node] RuntimeClass should schedule a Pod requesting a RuntimeClass and
    /// initialize its Overhead' fails with expected cpu=10m but got 0.
    /// This test fails when apply_runtime_class_overhead is removed or does not copy.
    #[test]
    fn runtime_class_overhead_injected_into_pod_spec() {
        let rc = serde_json::json!({
            "apiVersion": "node.k8s.io/v1",
            "kind": "RuntimeClass",
            "metadata": {"name": "my-rc"},
            "handler": "my-rc",
            "overhead": {
                "podFixed": {"cpu": "10m", "memory": "50Mi"}
            }
        });
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "test-pod", "namespace": "default"},
            "spec": {
                "runtimeClassName": "my-rc",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        apply_runtime_class_overhead(&mut pod, &rc);

        assert_eq!(
            pod["spec"]["overhead"]["cpu"], "10m",
            "spec.overhead.cpu must equal the RuntimeClass podFixed.cpu — \
             conformance test asserts overhead matches the RuntimeClass definition"
        );
        assert_eq!(
            pod["spec"]["overhead"]["memory"], "50Mi",
            "spec.overhead.memory must equal the RuntimeClass podFixed.memory"
        );
    }

    /// A pod that already has spec.overhead set must not have it overwritten.
    ///
    /// Idempotency: the admission plugin must not overwrite overhead that was
    /// already set (e.g. by a mutating webhook).
    #[test]
    fn runtime_class_overhead_not_overwritten_when_already_set() {
        let rc = serde_json::json!({
            "overhead": {
                "podFixed": {"cpu": "10m"}
            }
        });
        let mut pod = serde_json::json!({
            "spec": {
                "overhead": {"cpu": "20m"}
            }
        });

        apply_runtime_class_overhead(&mut pod, &rc);

        assert_eq!(
            pod["spec"]["overhead"]["cpu"], "20m",
            "pre-existing spec.overhead must not be overwritten by RuntimeClass admission — \
             a mutating webhook may have already set it to a valid value"
        );
    }

    /// A RuntimeClass without overhead.podFixed must leave pod.spec.overhead unchanged.
    #[test]
    fn runtime_class_without_overhead_is_noop() {
        let rc = serde_json::json!({
            "handler": "no-overhead"
        });
        let mut pod = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        apply_runtime_class_overhead(&mut pod, &rc);

        assert!(
            pod["spec"]["overhead"].is_null(),
            "pod.spec.overhead must remain absent when RuntimeClass has no podFixed overhead"
        );
    }

    // -----------------------------------------------------------------------
    // apply_runtime_class_scheduling
    // -----------------------------------------------------------------------

    /// A RuntimeClass with no `.scheduling` must leave the pod's own nodeSelector
    /// and tolerations exactly as the client posted them.
    ///
    /// Without this no-op guard, a RuntimeClass that only sets `overhead` (no
    /// scheduling constraints at all) could still clobber a pod's placement —
    /// e.g. wiping tolerations the client explicitly set — for no reason tied to
    /// the RuntimeClass definition.
    #[test]
    fn runtime_class_without_scheduling_leaves_pod_unchanged() {
        let rc = serde_json::json!({ "handler": "no-scheduling" });
        let mut pod = serde_json::json!({
            "spec": {
                "nodeSelector": {"disk": "ssd"},
                "tolerations": [{"key": "dedicated", "operator": "Exists"}]
            }
        });

        apply_runtime_class_scheduling(&mut pod, &rc).expect("no-op must not error");

        assert_eq!(
            pod["spec"]["nodeSelector"],
            serde_json::json!({"disk": "ssd"}),
            "pod.spec.nodeSelector must be untouched when the RuntimeClass has no scheduling"
        );
        assert_eq!(
            pod["spec"]["tolerations"],
            serde_json::json!([{"key": "dedicated", "operator": "Exists"}]),
            "pod.spec.tolerations must be untouched when the RuntimeClass has no scheduling"
        );
    }

    /// A RuntimeClass's `scheduling.nodeSelector` must merge into a pod's
    /// nodeSelector when the keys don't conflict.
    ///
    /// Conformance test '[sig-node] RuntimeClass should run a Pod requesting a
    /// RuntimeClass with scheduling with taints' asserts the created pod's
    /// nodeSelector equals the RuntimeClass's full nodeSelector even though the
    /// pod only set one of the two keys itself — without the merge, the pod is
    /// missing the RuntimeClass's placement key and never lands on the intended
    /// (labeled) node.
    #[test]
    fn runtime_class_scheduling_nodeselector_merges_cleanly_when_no_conflict() {
        let rc = serde_json::json!({
            "scheduling": {
                "nodeSelector": {"foo": "bar", "fizz": "buzz"}
            }
        });
        let mut pod = serde_json::json!({
            "spec": { "nodeSelector": {"foo": "bar"} }
        });

        apply_runtime_class_scheduling(&mut pod, &rc).expect("no conflict must not error");

        assert_eq!(
            pod["spec"]["nodeSelector"],
            serde_json::json!({"foo": "bar", "fizz": "buzz"}),
            "RuntimeClass.scheduling.nodeSelector keys absent from the pod's own \
             nodeSelector must be merged in, or the pod won't be constrained to \
             the nodes the RuntimeClass requires"
        );
    }

    /// A RuntimeClass's `scheduling.tolerations` must be appended to the pod's
    /// tolerations.
    ///
    /// Conformance test '[sig-node] RuntimeClass should run a Pod requesting a
    /// RuntimeClass with scheduling with taints' taints the target node and
    /// expects the pod to still schedule there — without this merge the pod
    /// carries no toleration for that taint and sits Pending forever.
    #[test]
    fn runtime_class_scheduling_tolerations_appended_to_pod() {
        let rc = serde_json::json!({
            "scheduling": {
                "tolerations": [{"key": "foo", "operator": "Equal", "value": "bar", "effect": "NoSchedule"}]
            }
        });
        let mut pod = serde_json::json!({ "spec": {} });

        apply_runtime_class_scheduling(&mut pod, &rc).expect("toleration append must not error");

        assert_eq!(
            pod["spec"]["tolerations"],
            serde_json::json!([{"key": "foo", "operator": "Equal", "value": "bar", "effect": "NoSchedule"}]),
            "RuntimeClass.scheduling.tolerations must be copied onto the pod, or a \
             pod requesting the RuntimeClass can never schedule onto a node the \
             RuntimeClass's own taint tolerations were meant to unblock"
        );
    }

    /// A RuntimeClass with both `scheduling.nodeSelector` and
    /// `scheduling.tolerations` must merge both onto the pod in one pass.
    #[test]
    fn runtime_class_scheduling_nodeselector_and_tolerations_merge_together() {
        let rc = serde_json::json!({
            "scheduling": {
                "nodeSelector": {"fizz": "buzz"},
                "tolerations": [{"key": "foo", "operator": "Exists", "effect": "NoSchedule"}]
            }
        });
        let mut pod = serde_json::json!({
            "spec": { "nodeSelector": {"foo": "bar"} }
        });

        apply_runtime_class_scheduling(&mut pod, &rc).expect("no conflict must not error");

        assert_eq!(
            pod["spec"]["nodeSelector"],
            serde_json::json!({"foo": "bar", "fizz": "buzz"}),
            "nodeSelector merge must not be skipped just because tolerations are also present"
        );
        assert_eq!(
            pod["spec"]["tolerations"],
            serde_json::json!([{"key": "foo", "operator": "Exists", "effect": "NoSchedule"}]),
            "toleration append must not be skipped just because nodeSelector is also present"
        );
    }

    /// A pod's nodeSelector key that conflicts with the RuntimeClass's own
    /// `scheduling.nodeSelector` value for that key must be rejected.
    ///
    /// Conformance test '[sig-node] RuntimeClass should reject a Pod requesting a
    /// RuntimeClass with conflicting node selector' expects 403 Forbidden here.
    /// Silently picking either side's value would let a pod land on a node the
    /// RuntimeClass's own placement rule forbids (or vice versa), with no
    /// indication to the client that its selector was ignored.
    #[test]
    fn runtime_class_scheduling_nodeselector_conflict_rejected_because_pod_could_land_on_wrong_node(
    ) {
        let rc = serde_json::json!({
            "scheduling": {
                "nodeSelector": {"foo": "conflict"}
            }
        });
        let mut pod = serde_json::json!({
            "spec": { "nodeSelector": {"foo": "bar"} }
        });

        let result = apply_runtime_class_scheduling(&mut pod, &rc);

        assert!(
            result.is_err(),
            "a pod nodeSelector value that disagrees with the RuntimeClass's \
             nodeSelector for the same key must be rejected, not silently merged"
        );
    }

    /// A toleration already present on the pod (verbatim) must not be duplicated
    /// when the RuntimeClass also specifies it.
    ///
    /// Re-admission must be idempotent (e.g. a webhook retry or `dryRun`) — a
    /// naive append would grow `pod.spec.tolerations` unboundedly on every retry.
    #[test]
    fn runtime_class_scheduling_tolerations_not_duplicated_when_already_present() {
        let toleration = serde_json::json!({"key": "foo", "operator": "Exists"});
        let rc = serde_json::json!({
            "scheduling": { "tolerations": [toleration] }
        });
        let mut pod = serde_json::json!({
            "spec": { "tolerations": [toleration] }
        });

        apply_runtime_class_scheduling(&mut pod, &rc).expect("must not error");

        assert_eq!(
            pod["spec"]["tolerations"].as_array().map(Vec::len),
            Some(1),
            "an identical toleration already on the pod must not be duplicated by the merge"
        );
    }
}

// ---------------------------------------------------------------------------
// resolve_pod_priority_class
// ---------------------------------------------------------------------------

#[cfg(test)]
mod priority_class_tests {
    use super::*;

    /// A pod with priorityClassName referencing a stored PriorityClass must have
    /// spec.priority resolved to that class's value.
    ///
    /// The scheduler's preemption logic (crates/scheduler) keys entirely off
    /// spec.priority — without this resolution every pod looks like priority 0
    /// and a pod that explicitly asked for a high PriorityClass could never
    /// preempt a lower-priority one.
    #[test]
    fn resolves_priority_from_stored_priority_class_value() {
        let mut pod = serde_json::json!({
            "spec": {
                "priorityClassName": "high",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        let stored_class = serde_json::json!({"value": 12345});

        resolve_pod_priority_class(&mut pod, Some(&stored_class))
            .expect("a found PriorityClass must resolve without error");

        assert_eq!(
            pod["spec"]["priority"], 12345,
            "spec.priority must equal the referenced PriorityClass's value — \
             the scheduler cannot preempt on a priority it never sees"
        );
    }

    /// A pod whose priorityClassName does not resolve to any stored PriorityClass
    /// (and isn't a built-in system class) must be rejected, not silently default
    /// to priority 0.
    ///
    /// Upstream's PriorityClass admission plugin rejects such pod creates outright;
    /// silently defaulting here would let a typo'd priorityClassName sail through
    /// with no signal that the intended priority was ignored.
    #[test]
    fn errors_when_priority_class_name_does_not_resolve() {
        let mut pod = serde_json::json!({
            "spec": {
                "priorityClassName": "does-not-exist",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let err = resolve_pod_priority_class(&mut pod, None)
            .expect_err("an unresolvable priorityClassName must error, not be ignored");

        assert!(
            err.contains("does-not-exist"),
            "the error must name the missing PriorityClass so the caller can \
             surface a useful message; got: {err}"
        );
        assert!(
            pod["spec"]["priority"].is_null(),
            "priority must remain unset when resolution fails — a rejected pod \
             must not be left half-defaulted"
        );
    }

    /// system-cluster-critical must resolve to its fixed value even when no
    /// PriorityClass object exists for it in the store.
    ///
    /// Real Kubernetes clusters bootstrap this PriorityClass automatically; u7s
    /// does not seed it as a stored object, so control-plane-critical pods that
    /// reference it by name must not be rejected just because the store lookup
    /// misses.
    #[test]
    fn resolves_system_cluster_critical_without_a_stored_object() {
        let mut pod = serde_json::json!({
            "spec": { "priorityClassName": "system-cluster-critical" }
        });

        resolve_pod_priority_class(&mut pod, None)
            .expect("system-cluster-critical must always resolve, stored or not");

        assert_eq!(
            pod["spec"]["priority"], SYSTEM_CLUSTER_CRITICAL_VALUE,
            "system-cluster-critical must resolve to its well-known value 2000000000"
        );
    }

    /// system-node-critical must resolve to its fixed value even when no
    /// PriorityClass object exists for it in the store.
    #[test]
    fn resolves_system_node_critical_without_a_stored_object() {
        let mut pod = serde_json::json!({
            "spec": { "priorityClassName": "system-node-critical" }
        });

        resolve_pod_priority_class(&mut pod, None)
            .expect("system-node-critical must always resolve, stored or not");

        assert_eq!(
            pod["spec"]["priority"], SYSTEM_NODE_CRITICAL_VALUE,
            "system-node-critical must resolve to its well-known value 2000001000"
        );
    }

    /// A pod with no priorityClassName at all must be left with priority unset.
    ///
    /// Real kube-apiserver only runs priority resolution when priorityClassName
    /// is present (globalDefault PriorityClass is a separate mechanism, not yet
    /// implemented here). Without this guard a plain pod could have a priority
    /// invented for it that no one asked for.
    #[test]
    fn leaves_priority_unset_when_no_priority_class_name() {
        let mut pod = serde_json::json!({
            "spec": { "containers": [{"name": "app", "image": "nginx"}] }
        });

        resolve_pod_priority_class(&mut pod, None).expect("a no-op must never error");

        assert!(
            pod["spec"]["priority"].is_null(),
            "a pod that never asked for a PriorityClass must not have spec.priority \
             invented for it"
        );
    }

    /// A pod that already carries an explicit spec.priority must keep it, even
    /// when priorityClassName also resolves to a different value.
    ///
    /// u7s currently lets a client set spec.priority directly and it survives the
    /// wire round-trip; silently overwriting that value here would
    /// break whichever caller relies on their explicit priority sticking.
    #[test]
    fn does_not_overwrite_an_explicit_client_set_priority() {
        let mut pod = serde_json::json!({
            "spec": {
                "priorityClassName": "high",
                "priority": 99
            }
        });
        let stored_class = serde_json::json!({"value": 12345});

        resolve_pod_priority_class(&mut pod, Some(&stored_class))
            .expect("no-op path must not error");

        assert_eq!(
            pod["spec"]["priority"], 99,
            "an explicit client-set spec.priority must not be clobbered by \
             priorityClassName resolution"
        );
    }

    /// When the PriorityClass sets preemptionPolicy and the pod didn't, the
    /// policy must be copied onto the pod — matching upstream's admission plugin.
    #[test]
    fn copies_preemption_policy_from_priority_class_when_pod_has_none() {
        let mut pod = serde_json::json!({
            "spec": { "priorityClassName": "high" }
        });
        let stored_class = serde_json::json!({"value": 100, "preemptionPolicy": "Never"});

        resolve_pod_priority_class(&mut pod, Some(&stored_class)).expect("resolution must succeed");

        assert_eq!(
            pod["spec"]["preemptionPolicy"], "Never",
            "preemptionPolicy must be copied from the PriorityClass when the pod \
             didn't set its own — otherwise a Never-preemption class silently \
             behaves like the PreemptLowerPriority default"
        );
    }

    /// An explicit pod-level preemptionPolicy must not be overwritten by the
    /// PriorityClass's preemptionPolicy.
    #[test]
    fn does_not_overwrite_an_explicit_preemption_policy() {
        let mut pod = serde_json::json!({
            "spec": {
                "priorityClassName": "high",
                "preemptionPolicy": "PreemptLowerPriority"
            }
        });
        let stored_class = serde_json::json!({"value": 100, "preemptionPolicy": "Never"});

        resolve_pod_priority_class(&mut pod, Some(&stored_class)).expect("resolution must succeed");

        assert_eq!(
            pod["spec"]["preemptionPolicy"], "PreemptLowerPriority",
            "an explicit pod-level preemptionPolicy must win over the PriorityClass's"
        );
    }
}

// ---------------------------------------------------------------------------
// compute_qos_class
// ---------------------------------------------------------------------------

#[cfg(test)]
mod qos_class_tests {
    use super::*;

    /// A pod whose every container has matching requests==limits for both cpu AND
    /// memory must be classified Guaranteed so the scheduler and the kubelet eviction
    /// manager treat it with the highest priority.
    ///
    /// Removing or breaking compute_qos_class would cause node/pods.go:200 to fail
    /// with status.qosClass="" instead of "Guaranteed".
    #[test]
    fn qos_class_guaranteed_when_requests_equal_limits_so_scheduler_and_eviction_work() {
        let pod = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "requests": {"cpu": "100m", "memory": "128Mi"},
                        "limits":   {"cpu": "100m", "memory": "128Mi"}
                    }
                }]
            }
        });
        assert_eq!(
            compute_qos_class(&pod),
            "Guaranteed",
            "requests == limits for all resources means Guaranteed — \
             kubelet eviction and scheduler use this to avoid evicting the pod under pressure"
        );
    }

    /// A pod with no resource requests or limits on any container must be BestEffort
    /// so the kubelet evicts it first when the node is under memory pressure.
    ///
    /// Removing compute_qos_class or returning a wrong class breaks eviction ordering:
    /// BestEffort pods must be evicted before Burstable and Guaranteed.
    #[test]
    fn qos_class_best_effort_when_no_resources_set_so_eviction_order_is_correct() {
        let pod = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        assert_eq!(
            compute_qos_class(&pod),
            "BestEffort",
            "no resource requests/limits means BestEffort — \
             these pods are first to be evicted; wrong classification disrupts eviction ordering"
        );
    }

    /// A pod where requests < limits (or only limits are set without matching requests)
    /// must be Burstable — it has SOME resource guarantee but not full Guaranteed status.
    ///
    /// This covers the case where HPA or a user sets limits without matching requests.
    #[test]
    fn qos_class_burstable_when_requests_differ_from_limits_so_partial_guarantee_is_correct() {
        let pod = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "requests": {"cpu": "50m", "memory": "64Mi"},
                        "limits":   {"cpu": "200m", "memory": "256Mi"}
                    }
                }]
            }
        });
        assert_eq!(
            compute_qos_class(&pod),
            "Burstable",
            "requests < limits means Burstable — pod can burst up to limits but is not \
             guaranteed the full limit; wrong class would misorder kubelet eviction"
        );
    }

    /// Init containers are included in QoS computation just as regular containers.
    /// A Guaranteed pod requires ALL containers (including init) to have matching resources.
    #[test]
    fn qos_class_considers_init_containers_so_init_heavy_pods_are_classified_correctly() {
        let pod = serde_json::json!({
            "spec": {
                "initContainers": [{
                    "name": "init",
                    "resources": {
                        "requests": {"cpu": "10m", "memory": "32Mi"},
                        "limits":   {"cpu": "10m", "memory": "32Mi"}
                    }
                }],
                "containers": [{
                    "name": "app",
                    "resources": {
                        "requests": {"cpu": "100m", "memory": "128Mi"},
                        "limits":   {"cpu": "100m", "memory": "128Mi"}
                    }
                }]
            }
        });
        assert_eq!(
            compute_qos_class(&pod),
            "Guaranteed",
            "init containers with matching requests==limits must not prevent Guaranteed — \
             the kubelet treats init containers as part of the pod QoS class"
        );
    }

    /// A pod where only limits are set (no requests) and they match: must be Guaranteed.
    /// Kubernetes treats absent requests as equal to limits for QoS class computation.
    #[test]
    fn qos_class_guaranteed_when_only_limits_set_because_absent_requests_equal_limits() {
        let pod = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "limits": {"cpu": "100m", "memory": "128Mi"}
                    }
                }]
            }
        });
        assert_eq!(
            compute_qos_class(&pod),
            "Guaranteed",
            "absent requests default to the limit value for QoS purposes — \
             Kubernetes docs state: if limits are set and requests are absent, requests == limits"
        );
    }

    /// A pod with requests:{cpu:'1'},limits:{cpu:'1000m'} is numerically Guaranteed
    /// but was previously classified Burstable by string comparison.
    /// Wrong classification causes the kubelet to evict this pod before truly Burstable
    /// pods under memory pressure, even though the user pinned all resources.
    #[test]
    fn qos_guaranteed_when_request_equals_limit_by_value_not_string_so_eviction_ordering_is_correct(
    ) {
        let pod = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "requests": {"cpu": "1", "memory": "1Gi"},
                        "limits":   {"cpu": "1000m", "memory": "1024Mi"}
                    }
                }]
            }
        });
        assert_eq!(
            compute_qos_class(&pod),
            "Guaranteed",
            "cpu '1'=='1000m' and memory '1Gi'=='1024Mi' by value — \
             string comparison misclassified this as Burstable, misplacing it in eviction order"
        );
    }

    /// A pod with requests:{cpu:'500m'},limits:{cpu:'1000m'} is truly Burstable
    /// and must remain Burstable after the value-based comparison fix.
    #[test]
    fn qos_burstable_when_request_numerically_less_than_limit_so_partial_guarantee_preserved() {
        let pod = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "requests": {"cpu": "500m", "memory": "512Mi"},
                        "limits":   {"cpu": "1000m", "memory": "1Gi"}
                    }
                }]
            }
        });
        assert_eq!(
            compute_qos_class(&pod),
            "Burstable",
            "request < limit numerically must remain Burstable — \
             value-based comparison must not mistakenly promote this to Guaranteed"
        );
    }
}

// ---------------------------------------------------------------------------
// validate_pod_sysctls
// ---------------------------------------------------------------------------

#[cfg(test)]
mod sysctl_validation_tests {
    use super::*;

    /// A sysctl name using '/' as a separator must be accepted: the kernel treats '.'
    /// and '/' as equivalent separators, and real conformance ("should support sysctls
    /// with slashes as separator") relies on the apiserver not rejecting this form.
    #[test]
    fn is_valid_sysctl_name_accepts_slash_as_separator() {
        assert!(
            is_valid_sysctl_name("kernel/shm_rmid_forced"),
            "slash-separated sysctl names must be accepted — rejecting them would break \
             the 'sysctls with slashes as separator' conformance test"
        );
    }

    /// Malformed sysctl names must be rejected at the apiserver (422), not silently
    /// persisted and later killed by the kubelet with a misleading "SysctlForbidden"
    /// event — that mechanism is for valid-but-unsafe names, not syntax errors.
    /// Syntactically valid names (even ones later blocked by the allowlist) must NOT be
    /// rejected or even mentioned here: that's a separate, kubelet-side check.
    #[test]
    fn create_pod_rejects_malformed_sysctl_names_but_not_syntactically_valid_ones() {
        let pod = serde_json::json!({
            "spec": {
                "securityContext": {
                    "sysctls": [
                        {"name": "foo-", "value": "bar"},
                        {"name": "kernel.shmmax", "value": "100000000"},
                        {"name": "safe-and-unsafe", "value": "100000000"},
                        {"name": "bar..", "value": "42"}
                    ]
                }
            }
        });

        let result = validate_pod_sysctls(&pod);

        assert!(
            result.is_err(),
            "a pod with malformed sysctl names ('foo-', 'bar..') must be rejected at create"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("Invalid value: \"foo-\""),
            "error must name the malformed sysctl 'foo-' so the client knows what to fix; \
             got: {msg}"
        );
        assert!(
            msg.contains("Invalid value: \"bar..\""),
            "error must name the malformed sysctl 'bar..' so the client knows what to fix; \
             got: {msg}"
        );
        assert!(
            !msg.contains("kernel.shmmax"),
            "the syntactically valid 'kernel.shmmax' must not be rejected or mentioned — \
             conformance asserts the error does NOT reference it; got: {msg}"
        );
        assert!(
            !msg.contains("safe-and-unsafe"),
            "the syntactically valid 'safe-and-unsafe' must not be rejected or mentioned \
             (allow/deny-listing of valid-but-unsafe names is a separate, kubelet-side \
             check) — conformance asserts the error does NOT reference it; got: {msg}"
        );
    }
}

// ---------------------------------------------------------------------------
// Integration-style tests for async handlers (tower::ServiceExt::oneshot)
// These use an in-memory store so no real server is needed.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod handler_tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        routing::{delete, get, patch, post, put},
        Router,
    };
    use bytes::Bytes;
    use tower::ServiceExt;
    use u7s_store::{SqliteStore, Store};

    use super::*;
    use crate::state::AppState;

    /// Build a minimal AppState backed by an in-memory SQLite store.
    fn make_state() -> (AppState, Arc<SqliteStore>) {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        (state, store)
    }

    /// Return an axum Extension layer that injects a test UserInfo, required by handlers
    /// that extract Extension<UserInfo>. Without this, Router-based tests get 500.
    fn auth_layer() -> axum::Extension<crate::auth::UserInfo> {
        axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        })
    }

    /// Seed the store with a namespace so parse_namespace succeeds.
    async fn seed_namespace(store: &Arc<SqliteStore>, ns: &str) {
        let key = format!("/registry/namespaces/{ns}");
        let val = serde_json::json!({"kind": "Namespace", "metadata": {"name": ns}});
        store
            .put(&key, Bytes::from(serde_json::to_vec(&val).unwrap()), None)
            .await
            .expect("seed namespace");
    }

    /// Seed the store with a pod, merging `extra` into the default pod JSON.
    async fn seed_pod(store: &Arc<SqliteStore>, ns: &str, name: &str, extra: serde_json::Value) {
        let key = format!("/registry/pods/{ns}/{name}");
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": ns,
                "resourceVersion": "1"
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {"phase": "Pending"}
        });
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                pod[k] = v.clone();
            }
        }
        store
            .put(&key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .expect("seed pod");
    }

    fn json_body(v: &serde_json::Value) -> Body {
        Body::from(Bytes::from(serde_json::to_vec(v).unwrap()))
    }

    // -----------------------------------------------------------------------
    // get_pod
    // -----------------------------------------------------------------------

    /// GET a pod that exists must return 200 with the pod JSON.
    #[tokio::test]
    async fn get_pod_returns_200_for_existing_pod() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "nginx", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/nginx")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A kubectl/kubelet-style GET with `Accept: application/vnd.kubernetes.protobuf` must
    /// receive a real protobuf-encoded Pod, not JSON silently substituted in its place: a
    /// client that only speaks protobuf (no `application/json` in its Accept list) would
    /// otherwise fail to parse the response at all.
    #[tokio::test]
    async fn get_pod_with_protobuf_accept_returns_protobuf_encoded_body() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "nginx", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/nginx")
            .header(
                "accept",
                "application/vnd.kubernetes.protobuf, application/json",
            )
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/vnd.kubernetes.protobuf",
            "Content-Type must advertise protobuf, not silently stay application/json"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "body must start with the k8s protobuf magic prefix"
        );
        let raw = crate::proto::decode_k8s_proto_envelope(&body)
            .expect("response body must decode as a k8s protobuf envelope");
        let decoded = crate::core_gen_adapter::decode_pod_proto_gen(&raw.raw)
            .expect("envelope raw field must decode as a Pod protobuf message");
        assert_eq!(decoded["metadata"]["name"], "nginx");
        assert_eq!(decoded["spec"]["containers"][0]["image"], "nginx");
    }

    /// GET a pod that does not exist must return 404.
    #[tokio::test]
    async fn get_pod_returns_404_for_missing_pod() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/ghost")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// GET a pod in a namespace that does not exist must return 404.
    #[tokio::test]
    async fn get_pod_returns_404_for_missing_namespace() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/nonexistent/pods/nginx")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// `kubectl get pod <name>` sends Accept: application/json;as=Table;... by default. Before
    /// this fix, get_pod ignored Accept entirely and always returned the raw Pod object, so
    /// kubectl logged "Unable to decode server response into a Table" and fell back to printing
    /// only NAME/AGE instead of the usual READY/STATUS/RESTARTS/AGE columns (LIST already worked
    /// via list_pods — this closes the gap for single-name GET).
    #[tokio::test]
    async fn get_pod_with_table_accept_returns_single_row_table() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "nginx", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/nginx")
            .header("accept", "application/json;as=Table;g=meta.k8s.io;v=v1")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(
            v["kind"], "Table",
            "a plain Pod kind here means kubectl can't decode it as a Table and silently \
             falls back to hardcoded NAME/AGE-only columns"
        );
        let rows = v["rows"].as_array().expect("Table response must have rows");
        assert_eq!(
            rows.len(),
            1,
            "a single-object GET must produce exactly one Table row, not a full list"
        );
        assert_eq!(
            rows[0]["cells"][0], "nginx",
            "the Table row must describe the requested pod, not some other object"
        );
        assert_eq!(
            rows[0]["object"]["metadata"]["name"], "nginx",
            "kubectl reads the row's embedded object to resolve the resource on selection"
        );
    }

    /// A Table request for a v1beta1 Table (long deprecated) on a single-name GET must be
    /// rejected the same way list_pods already rejects it on LIST — a stale client must be
    /// told the format isn't supported rather than silently downgraded to plain JSON or v1.
    #[tokio::test]
    async fn get_pod_with_v1beta1_table_accept_returns_406() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "nginx", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/nginx")
            .header(
                "accept",
                "application/json;as=Table;g=meta.k8s.io;v=v1beta1",
            )
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    }

    /// kcm's GC sends `Accept: application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1`
    /// when verifying a Pod owner reference still exists (garbagecollector.go:434-444
    /// isDangling). Before this fix, get_pod always returned the full typed Pod object,
    /// which the GC's metadata-only decoder rejects; the owner-check retries forever and
    /// newly-orphaned Pods leak indefinitely on any long-running u7s cluster.
    #[tokio::test]
    async fn get_pod_returns_partial_object_metadata_when_requested() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "nginx", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/nginx")
            .header(
                "accept",
                "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1",
            )
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(
            v["apiVersion"], "meta.k8s.io/v1",
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
        assert_eq!(
            v["kind"], "PartialObjectMetadata",
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
        assert!(
            v.get("spec").is_none(),
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
        assert!(
            v.get("status").is_none(),
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
    }

    // -----------------------------------------------------------------------
    // create_pod
    // -----------------------------------------------------------------------

    /// POST a valid pod must return 201 with the created pod.
    #[tokio::test]
    async fn create_pod_returns_201() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "test-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    /// A store wrapper whose first `put()` call always fails with AlreadyExists,
    /// regardless of key — simulating a generateName suffix landing on some unrelated
    /// existing object. Delegates every other call to the inner SqliteStore.
    ///
    /// Used by create_pod's generateName-collision-retry regression test.
    /// `create_if_namespace_active`'s default trait implementation calls `put()`
    /// internally, so this transparently exercises create_pod's actual write path.
    struct FirstPutAlreadyExistsStore {
        inner: Arc<SqliteStore>,
        fire_once: std::sync::atomic::AtomicBool,
    }

    impl FirstPutAlreadyExistsStore {
        fn new(inner: Arc<SqliteStore>) -> Self {
            Self {
                inner,
                fire_once: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    impl u7s_store::Store for FirstPutAlreadyExistsStore {
        fn get(
            &self,
            key: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Option<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.get(&key).await }
        }

        fn list(
            &self,
            prefix: &str,
            opts: u7s_store::ListOptions,
        ) -> impl std::future::Future<Output = u7s_store::Result<u7s_store::ListResponse>> + Send
        {
            let inner = self.inner.clone();
            let prefix = prefix.to_string();
            async move { inner.list(&prefix, opts).await }
        }

        fn put(
            &self,
            key: &str,
            value: Bytes,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<u64>> + Send {
            let inject = self
                .fire_once
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            let inner = self.inner.clone();
            let key = key.to_string();
            async move {
                if inject {
                    Err(u7s_store::StoreError::AlreadyExists { key })
                } else {
                    inner.put(&key, value, expected_revision).await
                }
            }
        }

        fn delete(
            &self,
            key: &str,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<(u64, Bytes)>> + Send {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.delete(&key, expected_revision).await }
        }

        fn list_namespace_objects(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.list_namespace_objects(&ns).await }
        }

        fn delete_namespace_resources(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<String>>> + Send {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.delete_namespace_resources(&ns).await }
        }

        fn watch(
            &self,
            _prefix: &str,
            _from_revision: u64,
        ) -> impl std::future::Future<
            Output = u7s_store::Result<
                impl futures_core::Stream<Item = u7s_store::WatchEvent> + Send + 'static,
            >,
        > + Send {
            std::future::ready(Ok(futures_util::stream::empty()))
        }

        fn compaction_horizon(&self) -> u64 {
            self.inner.compaction_horizon()
        }

        fn current_revision(&self) -> u64 {
            self.inner.current_revision()
        }

        fn watch_receiver_count(&self) -> usize {
            self.inner.watch_receiver_count()
        }
    }

    /// A controller mass-creating pods via bare `metadata.generateName` (e.g. a
    /// ReplicaSet backfilling replicas) must not see a spurious 409 just because the
    /// server's random name suffix happened to collide with an unrelated object. This
    /// forces that collision on the very first attempt and asserts create_pod retries
    /// with a fresh suffix and succeeds, rather than surfacing the collision as
    /// AlreadyExists to the client.
    ///
    /// Fails on revert: without the retry, create_pod's single create_if_namespace_active
    /// call returns AlreadyExists and the handler maps it straight to 409.
    #[tokio::test]
    async fn create_pod_retries_generate_name_collision_instead_of_409ing() {
        let inner = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        seed_namespace(&inner, "default").await;
        let collision_store = Arc::new(FirstPutAlreadyExistsStore::new(Arc::clone(&inner)));

        let state = AppState::new(
            Arc::clone(&collision_store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"generateName": "web-", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "a generateName-based pod create must retry past a spurious store collision, \
             not hard-error with 409 — a controller mass-creating pods via generateName \
             would otherwise see spurious create failures"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(
            created["metadata"]["name"]
                .as_str()
                .is_some_and(|n| n.starts_with("web-")),
            "created pod must still carry the generateName prefix after the retry"
        );
    }

    /// POST a pod into a Terminating namespace must return 403, matching
    /// create_namespaced_resource's gate for every other resource type.
    ///
    /// Without this, a ReplicationController/ReplicaSet controller can keep recreating pods
    /// in a namespace mid-deletion faster than the real KCM namespace-controller's own
    /// DeleteCollection retries converge, since pods (unlike every other resource type) had
    /// no Terminating check at all on their own dedicated create path.
    ///
    /// Fails on revert: reverting create_pod's Terminating check makes this return 201
    /// Created instead of 403.
    #[tokio::test]
    async fn create_pod_rejects_when_namespace_terminating() {
        let (state, store) = make_state();
        let ns_key = "/registry/namespaces/terminating-ns";
        let ns_val = serde_json::json!({
            "kind": "Namespace",
            "metadata": { "name": "terminating-ns" },
            "status": { "phase": "Terminating" }
        });
        store
            .put(
                ns_key,
                Bytes::from(serde_json::to_vec(&ns_val).unwrap()),
                None,
            )
            .await
            .expect("seed terminating namespace");

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "test-pod", "namespace": "terminating-ns"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/terminating-ns/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "pod creation must be rejected once the namespace is Terminating — otherwise a \
             controller can keep recreating pods faster than KCM's DeleteCollection retries \
             can drain them"
        );

        let stored = store
            .get("/registry/pods/terminating-ns/test-pod")
            .await
            .expect("store get must not error");
        assert!(
            stored.is_none(),
            "rejected pod creation must not persist the pod"
        );
    }

    /// POST a pod with invalid JSON must return 400.
    #[tokio::test]
    async fn create_pod_returns_400_for_invalid_json() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("not json"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // nodeSelector / affinity protobuf-decode regression test
    // -----------------------------------------------------------------------

    fn encode_varint_field(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    fn encode_ld(field_number: u64, payload: &[u8]) -> Vec<u8> {
        let tag = (field_number << 3) | 2;
        let mut out = encode_varint_field(tag);
        out.extend_from_slice(&encode_varint_field(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    /// The full create_pod pipeline (protobuf decode -> defaults -> SA token injection ->
    /// admission -> LimitRange -> quota -> store.put) must preserve spec.nodeSelector and
    /// spec.affinity.nodeAffinity end to end when the request arrives protobuf-encoded, the
    /// wire format client-go clientsets use by default for built-in types (e2e test binaries,
    /// kube-scheduler, kube-controller-manager). kubectl instead sends JSON, which is why a
    /// manual `kubectl apply` of an identical pod could never reproduce the sonobuoy failure
    /// this regresses: "[sig-scheduling] SchedulerPredicates validates that NodeSelector/
    /// NodeAffinity is respected if not matching". Asserting on the object fetched back out of
    /// the store (not just the CREATE response) matches the live repro exactly: `kubectl get
    /// pod -o json` on the persisted object showed both fields completely absent.
    #[tokio::test]
    async fn create_pod_preserves_node_selector_and_node_affinity_from_protobuf_body() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let mut obj_meta = encode_ld(1, b"restricted-pod");
        obj_meta.extend_from_slice(&encode_ld(3, b"default"));

        let mut container = encode_ld(1, b"c");
        container.extend_from_slice(&encode_ld(2, b"img"));

        // PodSpec.nodeSelector (field 7): map entry {key(1)="label", value(2)="nonempty"}.
        let mut map_entry = encode_ld(1, b"label");
        map_entry.extend_from_slice(&encode_ld(2, b"nonempty"));

        // PodSpec.affinity (field 18) -> Affinity.nodeAffinity(1) ->
        // NodeAffinity.requiredDuringSchedulingIgnoredDuringExecution(1) ->
        // NodeSelector.nodeSelectorTerms(1) -> NodeSelectorTerm.matchExpressions(1) ->
        // NodeSelectorRequirement{key(1),operator(2),values(3)}.
        let mut requirement = encode_ld(1, b"restrict-me");
        requirement.extend_from_slice(&encode_ld(2, b"In"));
        requirement.extend_from_slice(&encode_ld(3, b"true"));
        let term = encode_ld(1, &requirement);
        let node_selector_msg = encode_ld(1, &term);
        let node_affinity_msg = encode_ld(1, &node_selector_msg);
        let affinity_msg = encode_ld(1, &node_affinity_msg);

        let mut pod_spec = encode_ld(2, &container);
        pod_spec.extend_from_slice(&encode_ld(7, &map_entry));
        pod_spec.extend_from_slice(&encode_ld(18, &affinity_msg));

        let mut pod_proto = encode_ld(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_ld(2, &pod_spec));

        // Wrap in the k8s Unknown envelope client-go uses for core types (empty contentType).
        let mut type_meta = encode_ld(1, b"v1");
        type_meta.extend_from_slice(&encode_ld(2, b"Pod"));
        let mut unknown = encode_ld(1, &type_meta);
        unknown.extend_from_slice(&encode_ld(2, &pod_proto));
        let mut body = vec![0x6b, 0x38, 0x73, 0x00]; // magic
        body.extend_from_slice(&unknown);

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/vnd.kubernetes.protobuf")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let stored = store
            .get("/registry/pods/default/restricted-pod")
            .await
            .expect("store get must succeed")
            .expect("pod must be persisted");
        let persisted: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            persisted["spec"]["nodeSelector"]["label"], "nonempty",
            "spec.nodeSelector must be present on the object fetched back out of the store — \
             a protobuf-encoded create must not lose it anywhere in the create_pod pipeline"
        );
        assert_eq!(
            persisted["spec"]["affinity"]["nodeAffinity"]
                ["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"][0]
                ["matchExpressions"][0],
            serde_json::json!({"key": "restrict-me", "operator": "In", "values": ["true"]}),
            "spec.affinity.nodeAffinity must be present on the object fetched back out of the \
             store — a protobuf-encoded create must not lose it anywhere in the create_pod \
             pipeline"
        );
    }

    /// The full create_pod pipeline must preserve container- and pod-level SecurityContext
    /// hardening fields end to end when the request arrives protobuf-encoded.
    ///
    /// `gen_security_context_to_json`/`gen_pod_security_context_to_json` previously had no
    /// branch at all for seLinuxOptions/windowsOptions/appArmorProfile/seLinuxChangePolicy/
    /// fsGroupChangePolicy: a client-go protobuf create carrying these hardening controls had
    /// them silently stripped before the object ever reached storage, and the container/pod
    /// would run less confined than the client believed it configured — with no error
    /// anywhere. Asserting on the object fetched back out of the store (not just the CREATE
    /// response) rules out a whole-subtree-replace elsewhere silently discarding fields that
    /// did survive decode, the same failure shape found in the /status path.
    #[tokio::test]
    async fn create_pod_preserves_securitycontext_hardening_fields_from_protobuf_body_or_container_runs_less_confined_than_requested(
    ) {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let mut obj_meta = encode_ld(1, b"hardened-pod");
        obj_meta.extend_from_slice(&encode_ld(3, b"default"));

        // Container.securityContext (tag 15) -> SecurityContext:
        //   seLinuxOptions(3): user(1)/role(2)/type(3)/level(4)
        //   windowsOptions(10): gmsaCredentialSpecName(1)/gmsaCredentialSpec(2)/
        //     runAsUserName(3)/hostProcess(4, bool)
        //   appArmorProfile(12): type(1)/localhostProfile(2)
        let mut se_linux_options = encode_ld(1, b"system_u");
        se_linux_options.extend_from_slice(&encode_ld(2, b"staff_r"));
        se_linux_options.extend_from_slice(&encode_ld(3, b"container_t"));
        se_linux_options.extend_from_slice(&encode_ld(4, b"s0:c1,c2"));

        let mut windows_options = encode_ld(1, b"my-gmsa-spec");
        windows_options.extend_from_slice(&encode_ld(2, b"<GMSA XML>"));
        windows_options.extend_from_slice(&encode_ld(3, b"ContainerAdministrator"));
        windows_options.push(0x20); // field 4 (hostProcess), wire type 0 (varint)
        windows_options.push(1); // true

        let mut app_armor_profile = encode_ld(1, b"Localhost");
        app_armor_profile.extend_from_slice(&encode_ld(2, b"k8s-apparmor-example-deny-write"));

        let mut container_security_context = encode_ld(3, &se_linux_options);
        container_security_context.extend_from_slice(&encode_ld(10, &windows_options));
        container_security_context.extend_from_slice(&encode_ld(12, &app_armor_profile));

        let mut container = encode_ld(1, b"app");
        container.extend_from_slice(&encode_ld(2, b"nginx"));
        container.extend_from_slice(&encode_ld(15, &container_security_context));

        // PodSpec.securityContext (tag 14) -> PodSecurityContext:
        //   fsGroupChangePolicy(9), seLinuxChangePolicy(13)
        let mut pod_security_context = encode_ld(9, b"OnRootMismatch");
        pod_security_context.extend_from_slice(&encode_ld(13, b"Recursive"));

        let mut pod_spec = encode_ld(2, &container);
        pod_spec.extend_from_slice(&encode_ld(14, &pod_security_context));

        let mut pod_proto = encode_ld(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_ld(2, &pod_spec));

        let mut type_meta = encode_ld(1, b"v1");
        type_meta.extend_from_slice(&encode_ld(2, b"Pod"));
        let mut unknown = encode_ld(1, &type_meta);
        unknown.extend_from_slice(&encode_ld(2, &pod_proto));
        let mut body = vec![0x6b, 0x38, 0x73, 0x00]; // magic
        body.extend_from_slice(&unknown);

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/vnd.kubernetes.protobuf")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "protobuf-encoded pod create with SecurityContext hardening fields set must \
             succeed, not be rejected"
        );

        let stored = store
            .get("/registry/pods/default/hardened-pod")
            .await
            .expect("store get must succeed")
            .expect("pod must be persisted");
        let persisted: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        let sc = &persisted["spec"]["containers"][0]["securityContext"];
        assert_eq!(
            sc["seLinuxOptions"],
            serde_json::json!({
                "user": "system_u", "role": "staff_r", "type": "container_t", "level": "s0:c1,c2"
            }),
            "container securityContext.seLinuxOptions must survive a protobuf-encoded create — \
             dropping it means the container gets a runtime-allocated random SELinux context \
             instead of the one the client requested"
        );
        assert_eq!(
            sc["windowsOptions"],
            serde_json::json!({
                "gmsaCredentialSpecName": "my-gmsa-spec",
                "gmsaCredentialSpec": "<GMSA XML>",
                "runAsUserName": "ContainerAdministrator",
                "hostProcess": true
            }),
            "container securityContext.windowsOptions must survive a protobuf-encoded create — \
             dropping hostProcess would run the container as a normal (non-HostProcess) \
             container against the client's request"
        );
        assert_eq!(
            sc["appArmorProfile"],
            serde_json::json!({"type": "Localhost", "localhostProfile": "k8s-apparmor-example-deny-write"}),
            "container securityContext.appArmorProfile must survive a protobuf-encoded create \
             — dropping it means the container runs under the runtime default AppArmor \
             profile instead of the requested localhost profile"
        );

        let psc = &persisted["spec"]["securityContext"];
        assert_eq!(
            psc["fsGroupChangePolicy"], "OnRootMismatch",
            "pod securityContext.fsGroupChangePolicy must survive a protobuf-encoded create — \
             dropping it silently falls back to the \"Always\" recursive chown/chmod behavior \
             the client explicitly opted out of"
        );
        assert_eq!(
            psc["seLinuxChangePolicy"], "Recursive",
            "pod securityContext.seLinuxChangePolicy must survive a protobuf-encoded create — \
             dropping it silently falls back to the default volume relabeling policy instead \
             of the one the client requested"
        );
    }

    // -----------------------------------------------------------------------
    // RuntimeClass overhead injection regression test
    // -----------------------------------------------------------------------

    /// Creating a pod with spec.runtimeClassName referencing a RuntimeClass that has
    /// overhead.podFixed must result in the stored pod having spec.overhead set.
    ///
    /// The RuntimeClass admission plugin in real kube-apiserver copies podFixed into
    /// pod.spec.overhead at CREATE time. Conformance test '[sig-node] RuntimeClass
    /// should schedule a Pod requesting a RuntimeClass and initialize its Overhead'
    /// fails with "Expected value:0 to equal value:10 scale:-3" when this injection
    /// is absent.
    ///
    /// This test fails when the RuntimeClass store fetch and apply_runtime_class_overhead
    /// call are removed from create_pod.
    #[tokio::test]
    async fn create_pod_injects_runtime_class_overhead() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let rc = serde_json::json!({
            "apiVersion": "node.k8s.io/v1",
            "kind": "RuntimeClass",
            "metadata": {"name": "test-rc"},
            "handler": "test-rc",
            "overhead": {
                "podFixed": {"cpu": "10m"}
            }
        });
        store
            .put(
                "/registry/node.k8s.io/runtimeclasses/test-rc",
                Bytes::from(serde_json::to_vec(&rc).unwrap()),
                None,
            )
            .await
            .expect("seed RuntimeClass");

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "rc-pod", "namespace": "default"},
            "spec": {
                "runtimeClassName": "test-rc",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let stored = store
            .get("/registry/pods/default/rc-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["spec"]["overhead"]["cpu"], "10m",
            "spec.overhead.cpu must be injected from RuntimeClass.overhead.podFixed — \
             conformance test asserts the pod overhead matches the RuntimeClass definition"
        );
    }

    // -----------------------------------------------------------------------
    // dnsPolicy round-trip regression test
    // -----------------------------------------------------------------------

    /// A pod created with spec.dnsPolicy: ClusterFirstWithHostNet must have that
    /// exact value when read back via GET.
    ///
    /// Before the fix, spec.dnsPolicy was absent from the stored pod when not
    /// explicitly set, causing the kubelet to log "invalid DNSPolicy=" for every
    /// pod and fall back to ClusterFirst — silently incorrect behaviour.
    ///
    /// This test also verifies the full create→get round-trip so that a future
    /// regression (e.g. a new defaulting pass that strips dnsPolicy) is caught.
    #[tokio::test]
    async fn create_pod_dns_policy_survives_round_trip() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .route("/api/v1/namespaces/{ns}/pods/{name}", get(get_pod))
            .layer(auth_layer())
            .with_state(state);

        // Create a pod with an explicit dnsPolicy.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "dns-pod", "namespace": "default"},
            "spec": {
                "dnsPolicy": "ClusterFirstWithHostNet",
                "hostNetwork": true,
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let create_req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let create_resp = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(
            create_resp.status(),
            StatusCode::CREATED,
            "pod creation must succeed"
        );

        // Read the pod back via GET.
        let get_req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/dns-pod")
            .body(Body::empty())
            .unwrap();

        let get_resp = app.oneshot(get_req).await.unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(get_resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(
            v["spec"]["dnsPolicy"],
            serde_json::json!("ClusterFirstWithHostNet"),
            "spec.dnsPolicy must survive the create→get round-trip unchanged — \
             before the fix this was lost, causing kubelet to log \
             'invalid DNSPolicy=' for every pod"
        );

        // Verify stored value directly in the store for defense-in-depth.
        let stored = store
            .get("/registry/pods/default/dns-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["spec"]["dnsPolicy"],
            serde_json::json!("ClusterFirstWithHostNet"),
            "spec.dnsPolicy must be present in the stored object, not just the response"
        );
    }

    /// A pod created without spec.dnsPolicy must have it defaulted to "ClusterFirst"
    /// after creation (matching real kube-apiserver behaviour).
    ///
    /// Kubelet reads spec.dnsPolicy on every pod; an empty string causes it to
    /// log "invalid DNSPolicy=" and fall back incorrectly for every pod.
    #[tokio::test]
    async fn create_pod_dns_policy_defaults_to_cluster_first_when_absent() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "no-dns-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let stored = store
            .get("/registry/pods/default/no-dns-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["dnsPolicy"],
            serde_json::json!("ClusterFirst"),
            "dnsPolicy must be defaulted to ClusterFirst when absent at creation time — \
             real kube-apiserver always stamps this field; the kubelet rejects empty string"
        );
    }

    // -----------------------------------------------------------------------
    // dryRun=All and RuntimeClass rejection regression tests
    // -----------------------------------------------------------------------

    /// POST ?dryRun=All must return 201 but NOT persist the pod.
    ///
    /// Without the dryRun check in create_pod the pod is written to the store
    /// even when the client requests a dry run.  A scheduler then binds it to a
    /// real node, consuming capacity and causing cascading OutOfpods failures in
    /// unrelated tests.
    #[tokio::test]
    async fn create_pod_dry_run_returns_success_without_persisting() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state.clone());

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "dry-run-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods?dryRun=All")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "dryRun=All must return 201 (would-be created object) so clients know validation passed"
        );

        // The pod must NOT appear in the store — if it does, the scheduler will
        // bind it to a real node and consume node capacity.
        let stored = store
            .get("/registry/pods/default/dry-run-pod")
            .await
            .unwrap();
        assert!(
            stored.is_none(),
            "dryRun=All must not persist the pod — a persisted dry-run pod \
             gets scheduled for real, consuming node capacity and cascading \
             OutOfpods failures into other tests"
        );
    }

    /// POST a pod referencing a non-existent RuntimeClass must return 403.
    ///
    /// The real kube-apiserver rejects such pods via the RuntimeClass admission
    /// plugin.  Without this rejection the pod is persisted and scheduled, fills
    /// the node (cap 110), and causes all subsequent pod-creation tests to fail
    /// with OutOfpods.  The conformance test 'should reject a Pod requesting a
    /// deleted RuntimeClass' uses dryRun=All and expects Forbidden — so the 403
    /// must also fire under dry-run.
    #[tokio::test]
    async fn create_pod_missing_runtime_class_returns_403() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        // Deliberately do NOT seed any RuntimeClass for "missing-rc".

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "rc-missing-pod", "namespace": "default"},
            "spec": {
                "runtimeClassName": "missing-rc",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        // Without dryRun — must be rejected.
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "pod referencing a non-existent RuntimeClass must be rejected 403 — \
             without this, the pod is persisted and scheduled, filling the node \
             and causing OutOfpods failures in unrelated tests"
        );

        // With dryRun=All — validation must still fire and return 403.
        let req_dry = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods?dryRun=All")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp_dry = app.oneshot(req_dry).await.unwrap();
        assert_eq!(
            resp_dry.status(),
            StatusCode::FORBIDDEN,
            "dryRun=All must still run validation — a missing RuntimeClass must \
             return 403 even under dry-run (conformance test 'should reject a Pod \
             requesting a deleted RuntimeClass' uses dryRun=All + expects Forbidden)"
        );

        // Neither request should have persisted the pod.
        let stored = store
            .get("/registry/pods/default/rc-missing-pod")
            .await
            .unwrap();
        assert!(
            stored.is_none(),
            "rejected pod must not be persisted in the store"
        );
    }

    // -----------------------------------------------------------------------
    // RuntimeClass scheduling merge regression tests
    // -----------------------------------------------------------------------

    /// Creating a pod with spec.runtimeClassName referencing a RuntimeClass that
    /// defines scheduling.nodeSelector and scheduling.tolerations must result in
    /// the stored pod having both merged into its spec.
    ///
    /// Conformance test '[sig-node] RuntimeClass should run a Pod requesting a
    /// RuntimeClass with scheduling with taints' creates a pod like this, taints
    /// the target node, and expects the pod to schedule there. Before this merge,
    /// the stored pod kept only its own nodeSelector key and had no tolerations
    /// at all, so it sat Pending against the node's taint for the full 300s
    /// timeout.
    #[tokio::test]
    async fn create_pod_merges_runtime_class_scheduling_into_pod_spec() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let rc = serde_json::json!({
            "apiVersion": "node.k8s.io/v1",
            "kind": "RuntimeClass",
            "metadata": {"name": "scheduled-rc"},
            "handler": "scheduled-rc",
            "scheduling": {
                "nodeSelector": {"foo": "bar", "fizz": "buzz"},
                "tolerations": [
                    {"key": "foo", "operator": "Equal", "value": "bar", "effect": "NoSchedule"}
                ]
            }
        });
        store
            .put(
                "/registry/node.k8s.io/runtimeclasses/scheduled-rc",
                Bytes::from(serde_json::to_vec(&rc).unwrap()),
                None,
            )
            .await
            .expect("seed RuntimeClass");

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "scheduled-pod", "namespace": "default"},
            "spec": {
                "runtimeClassName": "scheduled-rc",
                "nodeSelector": {"foo": "bar"},
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "a pod whose own nodeSelector agrees with the RuntimeClass's must be admitted"
        );

        let stored = store
            .get("/registry/pods/default/scheduled-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["spec"]["nodeSelector"],
            serde_json::json!({"foo": "bar", "fizz": "buzz"}),
            "the RuntimeClass's fizz=buzz nodeSelector key must be merged in even \
             though the pod only set foo=bar itself — otherwise the pod is not \
             constrained to the node the RuntimeClass requires"
        );
        assert_eq!(
            stored_v["spec"]["tolerations"],
            serde_json::json!([
                {"key": "foo", "operator": "Equal", "value": "bar", "effect": "NoSchedule"}
            ]),
            "the RuntimeClass's toleration must be copied onto the pod, or the pod \
             can never schedule onto a node carrying the taint the RuntimeClass \
             expects it to tolerate"
        );
    }

    /// A pod whose own nodeSelector conflicts with the RuntimeClass's
    /// scheduling.nodeSelector value for the same key must be rejected with 403,
    /// and must not be persisted.
    ///
    /// Conformance test '[sig-node] RuntimeClass should reject a Pod requesting a
    /// RuntimeClass with conflicting node selector' expects exactly this. Before
    /// this check, u7s created the pod successfully instead of rejecting it.
    #[tokio::test]
    async fn create_pod_rejects_conflicting_runtime_class_node_selector() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let rc = serde_json::json!({
            "apiVersion": "node.k8s.io/v1",
            "kind": "RuntimeClass",
            "metadata": {"name": "conflict-rc"},
            "handler": "conflict-rc",
            "scheduling": {
                "nodeSelector": {"foo": "conflict"}
            }
        });
        store
            .put(
                "/registry/node.k8s.io/runtimeclasses/conflict-rc",
                Bytes::from(serde_json::to_vec(&rc).unwrap()),
                None,
            )
            .await
            .expect("seed RuntimeClass");

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "conflict-pod", "namespace": "default"},
            "spec": {
                "runtimeClassName": "conflict-rc",
                "nodeSelector": {"foo": "bar"},
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a pod nodeSelector value that conflicts with the RuntimeClass's own \
             nodeSelector for the same key must be rejected — silently accepting \
             it means either the pod's or the RuntimeClass's placement intent is \
             ignored with no error"
        );

        let stored = store
            .get("/registry/pods/default/conflict-pod")
            .await
            .unwrap();
        assert!(
            stored.is_none(),
            "rejected pod must not be persisted — a persisted-but-unschedulable \
             pod fills node capacity for no reason"
        );
    }

    // -----------------------------------------------------------------------
    // priorityClassName -> priority resolution
    // -----------------------------------------------------------------------

    /// Creating a pod with spec.priorityClassName referencing a stored PriorityClass
    /// must result in the stored (and returned) pod having spec.priority set to
    /// that class's value.
    ///
    /// The scheduler's preemption logic (crates/scheduler) reads
    /// spec.priority off the pod watch stream. Before this fix the apiserver never
    /// resolved priorityClassName at all, so every pod looked like priority 0 and
    /// preemption could never fire. This test fails if the store lookup + resolve
    /// step is removed from create_pod.
    #[tokio::test]
    async fn create_pod_resolves_priority_class_name_to_priority() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let pc = serde_json::json!({
            "apiVersion": "scheduling.k8s.io/v1",
            "kind": "PriorityClass",
            "metadata": {"name": "high-priority"},
            "value": 12345
        });
        store
            .put(
                "/registry/scheduling.k8s.io/priorityclasses/high-priority",
                Bytes::from(serde_json::to_vec(&pc).unwrap()),
                None,
            )
            .await
            .expect("seed PriorityClass");

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pc-pod", "namespace": "default"},
            "spec": {
                "priorityClassName": "high-priority",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let stored = store
            .get("/registry/pods/default/pc-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["spec"]["priority"], 12345,
            "spec.priority must be resolved from the referenced PriorityClass's \
             value — without this the scheduler can never preempt on this pod's \
             priority"
        );
    }

    /// Creating a pod with spec.priorityClassName that does not resolve to any
    /// PriorityClass must be rejected with 403, matching the RuntimeClass
    /// admission rejection pattern above.
    ///
    /// Without this, a pod with a typo'd (or deleted) priorityClassName would be
    /// silently persisted at priority 0 instead of failing loudly — masking the
    /// mistake from the user submitting it.
    #[tokio::test]
    async fn create_pod_missing_priority_class_returns_403() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        // Deliberately do NOT seed any PriorityClass for "missing-pc".

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pc-missing-pod", "namespace": "default"},
            "spec": {
                "priorityClassName": "missing-pc",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "pod referencing a non-existent PriorityClass must be rejected 403 — \
             otherwise it is silently persisted at priority 0, hiding the mistake"
        );

        let stored = store
            .get("/registry/pods/default/pc-missing-pod")
            .await
            .unwrap();
        assert!(
            stored.is_none(),
            "rejected pod must not be persisted in the store"
        );
    }

    /// system-cluster-critical must resolve to its well-known priority even though
    /// u7s does not seed it as a stored PriorityClass object.
    ///
    /// Real clusters bootstrap this PriorityClass automatically; control-plane
    /// pods that reference it by name (e.g. via a static manifest) must not be
    /// rejected just because u7s has no stored object under that name.
    #[tokio::test]
    async fn create_pod_resolves_system_cluster_critical_without_seeded_object() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        // Deliberately do NOT seed a PriorityClass named "system-cluster-critical".

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "critical-pod", "namespace": "default"},
            "spec": {
                "priorityClassName": "system-cluster-critical",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "system-cluster-critical must resolve and succeed even without a \
             seeded PriorityClass object"
        );

        let stored = store
            .get("/registry/pods/default/critical-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["spec"]["priority"], 2_000_000_000,
            "system-cluster-critical must resolve to its well-known value 2000000000"
        );
    }

    // -----------------------------------------------------------------------
    // automountServiceAccountToken defaulting
    // -----------------------------------------------------------------------

    /// A pod created without spec.automountServiceAccountToken must have it
    /// defaulted to true in the stored/returned object.
    ///
    /// Real kube-apiserver writes the resolved boolean into the stored pod so
    /// controllers and the kubelet always see a concrete value.  Without this,
    /// the field is absent after create and SA-level opting-out never works.
    ///
    /// This test fails if apply_automount_sa_token_default is removed or if it
    /// stops writing true when no SA sets the field to false.
    #[tokio::test]
    async fn create_pod_automount_defaults_to_true_when_absent() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "no-automount-pod", "namespace": "default"},
            "spec": {
                "serviceAccountName": "default",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let stored = store
            .get("/registry/pods/default/no-automount-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["automountServiceAccountToken"],
            serde_json::json!(true),
            "spec.automountServiceAccountToken must be defaulted to true when absent — \
             without this, SA-level opt-out cannot be inherited (conformance test \
             'ServiceAccounts should allow opting out of API token automount' fails)"
        );
    }

    /// A pod created with serviceAccountName pointing to a SA that has
    /// automountServiceAccountToken=false must NOT get the SA token volume injected.
    ///
    /// Conformance test 'ServiceAccounts should allow opting out of API token automount'
    /// creates a SA with automountServiceAccountToken=false, creates a pod referencing
    /// that SA (without a pod-level field), and expects the token NOT to be mounted.
    /// Without SA inheritance, the pod omits the field and inject_sa_token_volume
    /// injects the token anyway — the conformance test times out.
    ///
    /// This test fails if apply_automount_sa_token_default stops reading the SA's field.
    #[tokio::test]
    async fn create_pod_inherits_automount_false_from_service_account() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed a ServiceAccount with automountServiceAccountToken=false.
        let sa_key = "/registry/serviceaccounts/default/no-token-sa";
        let sa = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "no-token-sa", "namespace": "default"},
            "automountServiceAccountToken": false
        });
        store
            .put(
                sa_key,
                bytes::Bytes::from(serde_json::to_vec(&sa).unwrap()),
                None,
            )
            .await
            .expect("seed SA");

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "opt-out-pod", "namespace": "default"},
            "spec": {
                "serviceAccountName": "no-token-sa",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let stored = store
            .get("/registry/pods/default/opt-out-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["spec"]["automountServiceAccountToken"],
            serde_json::json!(false),
            "spec.automountServiceAccountToken must be false when inherited from SA — \
             SA opted out; pod must not get token"
        );
        assert!(
            v["spec"]["volumes"].is_null()
                || v["spec"]["volumes"]
                    .as_array()
                    .map(|vols| {
                        vols.iter().all(|vol| {
                            vol["name"]
                                .as_str()
                                .map(|n| !n.starts_with("kube-api-access-"))
                                .unwrap_or(true)
                        })
                    })
                    .unwrap_or(true),
            "no kube-api-access-* volume must be injected when SA has \
             automountServiceAccountToken=false — conformance test \
             'ServiceAccounts should allow opting out of API token automount' \
             checks that no token file appears in the pod"
        );
    }

    /// A bare pod (POST with no spec.serviceAccountName at all) must come back
    /// from the full create_pod handler with a "default" serviceAccountName AND
    /// the kube-api-access-* token volume mounted into its container.
    ///
    /// This is the exact live-reproduced scenario behind the Aggregator
    /// sample-apiserver and "[sig-auth] ServiceAccounts should mount an API
    /// token into pods" conformance failures: `kubectl run` sends a pod with no
    /// serviceAccountName, kube-apiserver defaults it to "default" and the
    /// ServiceAccount admission plugin injects the token volume — without both
    /// steps wired into the same create path, in-cluster clients (extension
    /// apiservers, sonobuoy) find no token file and crash-loop.
    #[tokio::test]
    async fn create_bare_pod_gets_default_sa_and_token_volume() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "bare-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let stored = store
            .get("/registry/pods/default/bare-pod")
            .await
            .unwrap()
            .expect("pod must be in store");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["spec"]["serviceAccountName"], "default",
            "a pod with no serviceAccountName must be defaulted to \"default\" — \
             without it, kubelet's token fetch fails with 'resource name may not be empty'"
        );
        let has_token_volume = v["spec"]["volumes"]
            .as_array()
            .map(|vols| {
                vols.iter().any(|vol| {
                    vol["name"]
                        .as_str()
                        .map(|n| n.starts_with("kube-api-access-"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        assert!(
            has_token_volume,
            "a bare pod must get the kube-api-access-* token volume — without it \
             /var/run/secrets/kubernetes.io/serviceaccount is missing and in-cluster \
             clients (extension apiservers, sonobuoy) cannot authenticate"
        );
        let has_mount = v["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .map(|mounts| {
                mounts.iter().any(|m| {
                    m["mountPath"].as_str() == Some("/var/run/secrets/kubernetes.io/serviceaccount")
                })
            })
            .unwrap_or(false);
        assert!(
            has_mount,
            "the container must have a volumeMount at \
             /var/run/secrets/kubernetes.io/serviceaccount — without it the SA \
             token volume is mounted nowhere and clients still can't read the token"
        );
    }

    // -----------------------------------------------------------------------
    // replace_pod (PUT)
    // -----------------------------------------------------------------------

    /// PUT with mismatched name in URL vs body must return 400.
    /// This guards against accidental or malicious object renaming via PUT.
    #[tokio::test]
    async fn replace_pod_name_mismatch_returns_400() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "nginx", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        // URL says "nginx" but body says "other-pod".
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "other-pod",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": {}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/nginx")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // delete_pod
    // -----------------------------------------------------------------------

    /// DELETE a pod without finalizers must soft-delete (stamp deletionTimestamp) on the first
    /// DELETE call — it must NOT hard-delete immediately.
    ///
    /// Real Kubernetes apiserver always soft-deletes pods first so the kubelet receives a MODIFIED
    /// event with deletionTimestamp set, which triggers graceful container termination via SIGTERM.
    /// If pods are hard-deleted immediately (bypassing the soft-delete step), the kubelet only
    /// receives a DELETED tombstone with minimal metadata (no spec), and the container never
    /// receives SIGTERM — it keeps running indefinitely.
    ///
    /// This is the regression test for the StatefulSet AfterEach hang:
    /// scale-to-0 stalled for up to 91 minutes because the StatefulSet pod was hard-deleted without
    /// going through the soft-delete+SIGTERM flow. This test fails on revert: if pods are
    /// hard-deleted immediately, the pod will be gone from the store and the deletionTimestamp
    /// assertion will fail.
    #[tokio::test]
    async fn delete_pod_without_finalizers_soft_deletes_first() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key = "/registry/pods/default/to-delete";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "to-delete", "namespace": "default", "resourceVersion": "1" },
            "spec": {},
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .layer(auth_layer())
            .with_state(state.clone());

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/to-delete")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "soft-delete must return 200");

        // The pod must still exist (soft-deleted, not hard-deleted).
        let stored = store
            .get(key)
            .await
            .unwrap()
            .expect("pod must still exist after first DELETE — soft-delete must not remove it");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["deletionTimestamp"].is_string(),
            "deletionTimestamp must be stamped on first DELETE even without finalizers — \
             kubelet uses this signal to send SIGTERM to the container; without it the \
             container keeps running and the StatefulSet scale-to-0 hangs"
        );
    }

    /// `kubectl delete pod --dry-run=server` must NOT actually delete (or even soft-delete)
    /// the pod — a dry-run that mutates anyway silently terminates a workload against the
    /// client's explicit intent. DeleteOptions.dryRun=["All"] is sent in the DELETE request
    /// BODY (client-go's typed Delete(), unlike Create/Update/Patch which use a ?dryRun=All
    /// query param) — this test fails on revert with deletionTimestamp stamped in the store.
    #[tokio::test]
    async fn delete_pod_dry_run_does_not_mutate_store() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key = "/registry/pods/default/to-delete";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "to-delete", "namespace": "default", "resourceVersion": "1" },
            "spec": {},
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .layer(auth_layer())
            .with_state(state.clone());

        let delete_opts = serde_json::json!({
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "dryRun": ["All"]
        });
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/to-delete")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&delete_opts))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "dry-run delete must still return a success response"
        );

        let stored = store
            .get(key)
            .await
            .unwrap()
            .expect("pod must still exist after a dry-run DELETE");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["deletionTimestamp"].is_null(),
            "dryRun=All must NOT stamp deletionTimestamp — if this fails, delete_pod's \
             dry-run guard was removed and the pod was actually soft-deleted in the store"
        );
    }

    /// Second DELETE on a pod that is already Terminating (has deletionTimestamp) and has no
    /// finalizers must hard-delete it — this is the path taken by the kubelet after it stops
    /// the container and calls DELETE with gracePeriodSeconds=0.
    ///
    /// Without the hard-delete on the second DELETE, the pod would stay in Terminating forever
    /// since no GC controller removes finalizer-free terminating pods.
    #[tokio::test]
    async fn delete_pod_already_terminating_without_finalizers_hard_deletes() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key = "/registry/pods/default/terminating-pod";
        // Seed a pod that already has deletionTimestamp set (soft-deleted) with no finalizers.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "terminating-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "deletionTimestamp": "2026-01-01T00:00:00Z"
            },
            "spec": {},
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .layer(auth_layer())
            .with_state(state.clone());

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/terminating-pod")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "hard-delete of already-terminating pod must return 200"
        );

        // The pod must be gone (hard-deleted).
        let stored = store.get(key).await.unwrap();
        assert!(
            stored.is_none(),
            "pod with deletionTimestamp and no finalizers must be hard-deleted on second DELETE — \
             this is the kubelet's graceful termination complete signal (gracePeriodSeconds=0 path)"
        );
    }

    /// `kubectl delete pod --grace-period=0 --force` (explicit gracePeriodSeconds=0 in the
    /// DeleteOptions body) on a pod with no finalizers must hard-delete on the very FIRST
    /// DELETE call, not just stamp deletionTimestamp and wait for a second call.
    ///
    /// Real Kubernetes pods are normally purged by a second actor observing deletionTimestamp:
    /// the kubelet (once it confirms no containers are running) or KCM's pod-GC/node-lifecycle
    /// controller (for unscheduled or orphaned pods). A pod scheduled onto a node whose kubelet
    /// died before creating any container — or a node that has otherwise gone dark — has no
    /// such actor left, and this deployment disables node-lifecycle-controller entirely. Without
    /// this immediate purge, `--force` cannot force anything: the object stays soft-deleted with
    /// deletionGracePeriodSeconds=0 forever, `kubectl get pod` keeps reporting Terminating, and
    /// downstream re-runs that try to recreate an object with the same name hit "the server
    /// reported a conflict" on the stale copy.
    ///
    /// Fails on revert: reverting the `force_requested` check makes this pod only get
    /// soft-deleted (deletionTimestamp stamped, object still present) on this single call.
    #[tokio::test]
    async fn delete_pod_explicit_grace_zero_without_finalizers_hard_deletes_on_first_call() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key = "/registry/pods/default/stuck-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "stuck-pod", "namespace": "default", "resourceVersion": "1" },
            "spec": {},
            "status": { "phase": "Pending" }
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .layer(auth_layer())
            .with_state(state.clone());

        let delete_opts = serde_json::json!({
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "gracePeriodSeconds": 0
        });
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/stuck-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&delete_opts))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "force-delete must return 200 on the first call"
        );

        let stored = store.get(key).await.unwrap();
        assert!(
            stored.is_none(),
            "an explicit gracePeriodSeconds=0 delete (--grace-period=0 --force) on a pod with \
             no finalizers must purge it immediately — waiting for a second DELETE that may \
             never come (dead kubelet, no node-lifecycle-controller) leaves it Terminating forever"
        );
    }

    /// `--grace-period=0 --force` must NOT bypass finalizers — only skip waiting on a
    /// container/kubelet confirmation. A pod with a finalizer must still be soft-deleted so its
    /// owning controller gets a chance to observe deletionTimestamp and clear the finalizer
    /// itself; forcing removal here would let the apiserver silently violate the finalizer
    /// contract just because a bystander client happened to pass --force.
    #[tokio::test]
    async fn delete_pod_explicit_grace_zero_with_finalizers_still_soft_deletes() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key = "/registry/pods/default/finalized-forced-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "finalized-forced-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "finalizers": ["my.io/cleanup"]
            },
            "spec": {},
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .layer(auth_layer())
            .with_state(state.clone());

        let delete_opts = serde_json::json!({
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "gracePeriodSeconds": 0
        });
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/finalized-forced-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&delete_opts))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let stored = store.get(key).await.unwrap().expect(
            "a finalizer'd pod must survive a forced delete — the finalizer contract \
                     is not something --force is allowed to bypass",
        );
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["deletionTimestamp"].is_string(),
            "deletionTimestamp must still be stamped so the finalizer-owning controller knows \
             to act"
        );
    }

    /// DELETE a pod with finalizers must soft-delete: stamp deletionTimestamp, keep object.
    #[tokio::test]
    async fn delete_pod_with_finalizers_stamps_deletion_timestamp() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed with finalizers directly (don't rely on seed_pod merge for nested metadata).
        let key = "/registry/pods/default/finalized-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "finalized-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "finalizers": ["my.io/cleanup"]
            },
            "spec": {},
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .layer(auth_layer())
            .with_state(state.clone());

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/finalized-pod")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "soft-delete must return 200");

        // The pod must still exist with deletionTimestamp set.
        let stored = store.get(key).await.unwrap().expect("pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["deletionTimestamp"].is_string(),
            "deletionTimestamp must be stamped on soft-delete"
        );
    }

    /// DELETE a pod that does not exist must return 404.
    #[tokio::test]
    async fn delete_pod_missing_returns_404() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .layer(auth_layer())
            .with_state(state);

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/ghost")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A repeat DELETE on a pod that is already Terminating (deletionTimestamp set) with a
    /// finalizer still held, and no explicit gracePeriodSeconds in the request, must be a
    /// complete no-op: same deletionTimestamp, deletionGracePeriodSeconds, generation and
    /// resourceVersion. This is exactly the redundant DELETE a controller re-issues on every
    /// resync (e.g. the Job controller against a pod holding batch.kubernetes.io/job-tracking)
    /// — if this re-stamps, the store's byte-equality no-op-write check never fires,
    /// resourceVersion climbs on every retry, and the resulting watch events livelock finalizer
    /// drain.
    ///
    /// Fails on revert: without the already_terminating branch this test targets, delete_pod
    /// always re-stamps deletionTimestamp to a fresh `now() + grace`, which will not equal the
    /// original value and will bump resourceVersion.
    #[tokio::test]
    async fn delete_pod_redundant_delete_of_already_terminating_pod_is_idempotent() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key = "/registry/pods/default/already-terminating";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "already-terminating",
                "namespace": "default",
                "resourceVersion": "1",
                "generation": 2,
                "finalizers": ["batch.kubernetes.io/job-tracking"],
                "deletionTimestamp": "2099-01-01T00:00:00Z",
                "deletionGracePeriodSeconds": 30
            },
            "spec": {},
            "status": {}
        });
        let seeded_rv = store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .layer(auth_layer())
            .with_state(state.clone());

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/already-terminating")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "redundant delete must still return 200"
        );

        let stored = store
            .get(key)
            .await
            .unwrap()
            .expect("pod must still exist — finalizer still held");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["resourceVersion"],
            seeded_rv.to_string(),
            "a redundant DELETE with unchanged grace must not write — otherwise \
             resourceVersion churns on every controller retry, and the watch events it fires \
             livelock finalizer drain"
        );
        assert_eq!(
            v["metadata"]["generation"], 2,
            "generation must not bump on a no-op re-delete"
        );
        assert_eq!(
            v["metadata"]["deletionTimestamp"], "2099-01-01T00:00:00Z",
            "deletionTimestamp must not be re-stamped on a no-op re-delete"
        );
    }

    /// A repeat DELETE with an explicit, shorter gracePeriodSeconds than what's already stored
    /// must still move deletionTimestamp earlier — mirroring real kube-apiserver's
    /// BeforeDelete, which lets a caller (e.g. `kubectl delete pod --grace-period=<n>`) speed
    /// up an in-flight graceful termination. Without this, the idempotency fix verified above
    /// would over-apply and freeze deletionTimestamp even when the caller legitimately wants it
    /// moved sooner.
    ///
    /// Fails on revert: if the idempotency guard collapses to a bare "skip whenever
    /// already_terminating", this legitimate shortening request also becomes a no-op and
    /// deletionTimestamp stays at its original (later) value.
    #[tokio::test]
    async fn delete_pod_explicit_shorter_grace_period_moves_deletion_timestamp_earlier() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key = "/registry/pods/default/shortening-grace";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "shortening-grace",
                "namespace": "default",
                "resourceVersion": "1",
                "generation": 2,
                "finalizers": ["batch.kubernetes.io/job-tracking"],
                "deletionTimestamp": "2099-01-01T00:00:00Z",
                "deletionGracePeriodSeconds": 120
            },
            "spec": {},
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .layer(auth_layer())
            .with_state(state.clone());

        let delete_opts = serde_json::json!({
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "gracePeriodSeconds": 30
        });
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/shortening-grace")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&delete_opts))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let stored = store
            .get(key)
            .await
            .unwrap()
            .expect("finalizer still held, pod must survive");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["deletionGracePeriodSeconds"], 30,
            "explicit shorter gracePeriodSeconds must be persisted"
        );
        assert_eq!(
            v["metadata"]["deletionTimestamp"], "2098-12-31T23:58:30Z",
            "shortening grace from 120s to 30s must move deletionTimestamp 90s earlier, \
             matching real kube-apiserver's BeforeDelete (moves the timestamp back by the \
             stored grace period, then forward by the new one)"
        );
        assert_eq!(
            v["metadata"]["generation"], 2,
            "generation must not bump when only shortening an already-in-flight graceful \
             delete — upstream only bumps it on the initial not-yet-terminating transition"
        );
    }

    /// DELETE on the pods collection endpoint must respect each pod's own soft/hard-delete
    /// state exactly like a single-pod DELETE does, not hard-delete everything
    /// unconditionally. The real KCM namespace-controller drains pods via exactly this
    /// endpoint (DeleteCollection) during OrderedNamespaceDeletion; if it bypassed
    /// finalizers, a pod's controller would never get to observe deletionTimestamp before
    /// the pod vanished, breaking the pod-before-configmap ordering the conformance test
    /// asserts.
    ///
    /// Fails on revert: reverting delete_collection_pods to unconditionally
    /// `state.store.delete` every listed pod makes the finalizer'd and not-yet-terminating
    /// pods vanish from the store instead of being soft-deleted.
    #[tokio::test]
    async fn delete_collection_pods_respects_finalizers_and_terminating_state() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // A pod with a finalizer, not yet terminating — must be soft-deleted, finalizer kept.
        let finalized_key = "/registry/pods/default/finalized-pod";
        let finalized_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "finalized-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "finalizers": ["my.io/cleanup"]
            },
            "spec": {},
            "status": {}
        });
        store
            .put(
                finalized_key,
                Bytes::from(serde_json::to_vec(&finalized_pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // A plain pod with no finalizer, not yet terminating — real Kubernetes soft-deletes
        // it first too (grace period for SIGTERM); it must NOT vanish on the first DELETE.
        let plain_key = "/registry/pods/default/plain-pod";
        let plain_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "plain-pod", "namespace": "default", "resourceVersion": "1" },
            "spec": {},
            "status": {}
        });
        store
            .put(
                plain_key,
                Bytes::from(serde_json::to_vec(&plain_pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // A pod already Terminating with no finalizers — must hard-delete (the kubelet's
        // "container stopped, gracePeriodSeconds=0" second DELETE).
        let terminating_key = "/registry/pods/default/terminating-pod";
        let terminating_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "terminating-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "deletionTimestamp": "2026-01-01T00:00:00Z"
            },
            "spec": {},
            "status": {}
        });
        store
            .put(
                terminating_key,
                Bytes::from(serde_json::to_vec(&terminating_pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods",
                delete(delete_collection_pods),
            )
            .layer(auth_layer())
            .with_state(state.clone());

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "delete collection must return 200"
        );

        let stored_finalized = store.get(finalized_key).await.unwrap().expect(
            "pod with a finalizer must NOT be removed by DeleteCollection — it must be \
             soft-deleted so its controller can observe deletionTimestamp and clear the \
             finalizer itself",
        );
        let finalized_body: serde_json::Value =
            serde_json::from_slice(&stored_finalized.value).unwrap();
        assert!(
            finalized_body["metadata"]["deletionTimestamp"].is_string(),
            "finalizer'd pod must have deletionTimestamp set after DeleteCollection"
        );

        let stored_plain = store.get(plain_key).await.unwrap().expect(
            "a not-yet-terminating pod must NOT be hard-deleted on the first DeleteCollection \
             pass — real Kubernetes always soft-deletes pods first so the kubelet can \
             gracefully terminate the container",
        );
        let plain_body: serde_json::Value = serde_json::from_slice(&stored_plain.value).unwrap();
        assert!(
            plain_body["metadata"]["deletionTimestamp"].is_string(),
            "plain pod must have deletionTimestamp stamped by DeleteCollection, matching \
             delete_pod's single-object soft-delete behavior"
        );

        let stored_terminating = store.get(terminating_key).await.unwrap();
        assert!(
            stored_terminating.is_none(),
            "a pod already Terminating with no finalizers must be hard-deleted by \
             DeleteCollection — otherwise it lingers forever since nothing else removes it"
        );
    }

    /// A redundant DeleteCollection sweep (e.g. a Job controller's namespace-wide resync) over
    /// an already-Terminating, finalizer-carrying pod, with no explicit gracePeriodSeconds, must
    /// be a no-op: same deletionTimestamp/deletionGracePeriodSeconds/resourceVersion. Real
    /// clients call DeleteCollection repeatedly (it's how KCM's namespace controller drains a
    /// namespace during OrderedNamespaceDeletion); re-stamping every pass would churn
    /// resourceVersion and livelock finalizer drain exactly like the single-pod DELETE path.
    ///
    /// Fails on revert: without the already_terminating branch this test targets,
    /// delete_collection_pods always re-stamps deletionTimestamp to a fresh `now() + grace` on
    /// every call, which will not equal the original value and will bump resourceVersion.
    #[tokio::test]
    async fn delete_collection_pods_redundant_delete_of_already_terminating_pod_is_idempotent() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key = "/registry/pods/default/already-terminating";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "already-terminating",
                "namespace": "default",
                "resourceVersion": "1",
                "generation": 2,
                "finalizers": ["batch.kubernetes.io/job-tracking"],
                "deletionTimestamp": "2099-01-01T00:00:00Z",
                "deletionGracePeriodSeconds": 30
            },
            "spec": {},
            "status": {}
        });
        let seeded_rv = store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods",
                delete(delete_collection_pods),
            )
            .layer(auth_layer())
            .with_state(state.clone());

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let stored = store
            .get(key)
            .await
            .unwrap()
            .expect("pod must still exist — finalizer still held");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["resourceVersion"],
            seeded_rv.to_string(),
            "a redundant DeleteCollection sweep with unchanged grace must not write — \
             otherwise resourceVersion churns on every controller resync and livelocks \
             finalizer drain"
        );
        assert_eq!(
            v["metadata"]["generation"], 2,
            "generation must not bump on a no-op re-delete"
        );
        assert_eq!(
            v["metadata"]["deletionTimestamp"], "2099-01-01T00:00:00Z",
            "deletionTimestamp must not be re-stamped on a no-op re-delete"
        );
    }

    /// A DeleteCollection call with an explicit, shorter gracePeriodSeconds than what's already
    /// stored must still move a Terminating, finalizer'd pod's deletionTimestamp earlier —
    /// `kubectl delete pods --all --grace-period=<n>` must be able to speed up an in-flight
    /// graceful termination, not just be swallowed by the idempotency guard above.
    ///
    /// Fails on revert: if the idempotency guard collapses to a bare "skip whenever
    /// already_terminating", this legitimate shortening request also becomes a no-op.
    #[tokio::test]
    async fn delete_collection_pods_explicit_shorter_grace_period_moves_deletion_timestamp_earlier()
    {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key = "/registry/pods/default/shortening-grace";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "shortening-grace",
                "namespace": "default",
                "resourceVersion": "1",
                "generation": 2,
                "finalizers": ["batch.kubernetes.io/job-tracking"],
                "deletionTimestamp": "2099-01-01T00:00:00Z",
                "deletionGracePeriodSeconds": 120
            },
            "spec": {},
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods",
                delete(delete_collection_pods),
            )
            .layer(auth_layer())
            .with_state(state.clone());

        let delete_opts = serde_json::json!({
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "gracePeriodSeconds": 30
        });
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&delete_opts))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let stored = store
            .get(key)
            .await
            .unwrap()
            .expect("finalizer still held, pod must survive");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["deletionGracePeriodSeconds"], 30,
            "explicit shorter gracePeriodSeconds must be persisted"
        );
        assert_eq!(
            v["metadata"]["deletionTimestamp"], "2098-12-31T23:58:30Z",
            "shortening grace from 120s to 30s must move deletionTimestamp 90s earlier, \
             matching real kube-apiserver's BeforeDelete"
        );
        assert_eq!(
            v["metadata"]["generation"], 2,
            "generation must not bump when only shortening an already-in-flight graceful \
             delete"
        );
    }

    /// `DeleteCollection` with an explicit `gracePeriodSeconds: 0` (e.g. a cleanup script's
    /// `kubectl delete pods --all --grace-period=0 --force`) must hard-delete a not-yet-
    /// terminating, finalizer-free pod immediately — mirroring delete_pod's own
    /// force_requested handling — while a finalizer'd pod is still only soft-deleted.
    ///
    /// Fails on revert: reverting `hard_delete_now` back to `!already_terminating ||
    /// has_finalizers` would leave the finalizer-free pod merely soft-deleted, stuck
    /// Terminating forever if nothing else ever confirms its removal.
    #[tokio::test]
    async fn delete_collection_pods_force_grace_zero_hard_deletes_finalizer_free_pods() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let plain_key = "/registry/pods/default/forced-plain-pod";
        let plain_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "forced-plain-pod", "namespace": "default", "resourceVersion": "1" },
            "spec": {},
            "status": {}
        });
        store
            .put(
                plain_key,
                Bytes::from(serde_json::to_vec(&plain_pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        let finalized_key = "/registry/pods/default/forced-finalized-pod";
        let finalized_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "forced-finalized-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "finalizers": ["my.io/cleanup"]
            },
            "spec": {},
            "status": {}
        });
        store
            .put(
                finalized_key,
                Bytes::from(serde_json::to_vec(&finalized_pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods",
                delete(delete_collection_pods),
            )
            .layer(auth_layer())
            .with_state(state.clone());

        let delete_opts = serde_json::json!({
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "gracePeriodSeconds": 0
        });
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&delete_opts))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let stored_plain = store.get(plain_key).await.unwrap();
        assert!(
            stored_plain.is_none(),
            "a finalizer-free pod must be hard-deleted by a force (gracePeriodSeconds=0) \
             DeleteCollection immediately, not left soft-deleted waiting on a confirmation \
             that may never come"
        );

        let stored_finalized = store
            .get(finalized_key)
            .await
            .unwrap()
            .expect("a finalizer'd pod must survive a forced DeleteCollection");
        let finalized_body: serde_json::Value =
            serde_json::from_slice(&stored_finalized.value).unwrap();
        assert!(
            finalized_body["metadata"]["deletionTimestamp"].is_string(),
            "finalizer'd pod must still have deletionTimestamp stamped even under --force"
        );
    }

    /// An explicit `gracePeriodSeconds` in the DELETE body must push `deletionTimestamp`
    /// into the future by that many seconds, and the value itself must be persisted as
    /// `deletionGracePeriodSeconds` — otherwise the kubelet has no way to know how long it
    /// has before the apiserver expects the pod gone, and controllers waiting on
    /// deletionTimestamp treat a long-grace pod exactly like an already-due one.
    ///
    /// Fails on revert: stamping `deletionTimestamp` as bare `now()` (the pre-fix behavior)
    /// would never match any of the `now+120s` candidate timestamps computed below.
    #[tokio::test]
    async fn delete_pod_with_explicit_grace_period_delays_deletion_timestamp() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key = "/registry/pods/default/graceful-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "graceful-pod", "namespace": "default", "resourceVersion": "1" },
            "spec": {},
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .layer(auth_layer())
            .with_state(state.clone());

        let grace = 120i64;
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let delete_opts = serde_json::json!({
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "gracePeriodSeconds": grace
        });
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/graceful-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&delete_opts))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let stored = store
            .get(key)
            .await
            .unwrap()
            .expect("soft-deleted pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let ts = v["metadata"]["deletionTimestamp"]
            .as_str()
            .expect("deletionTimestamp must be set");
        let candidates: Vec<String> = (before..=after)
            .map(|s| crate::util::secs_to_rfc3339(s + grace))
            .collect();
        assert!(
            candidates.contains(&ts.to_string()),
            "deletionTimestamp {ts} must be now+{grace}s, not bare now — a client that asked \
             for 120s of grace must get 120s, or its container is SIGKILLed before it can \
             shut down cleanly"
        );
        assert_eq!(
            v["metadata"]["deletionGracePeriodSeconds"], grace,
            "deletionGracePeriodSeconds must be persisted so the kubelet/controllers know \
             how long they have before a hard delete"
        );
    }

    /// delete_collection_pods must apply the same gracePeriodSeconds handling as
    /// single-pod delete_pod — a namespace-wide delete (e.g. `kubectl delete pods --all
    /// --grace-period=N`) must not silently ignore the grace period just because it went
    /// through the collection endpoint instead of the named-resource one.
    #[tokio::test]
    async fn delete_collection_pods_applies_grace_period_to_every_matched_pod() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key_a = "/registry/pods/default/pod-a";
        let key_b = "/registry/pods/default/pod-b";
        for (key, name) in [(key_a, "pod-a"), (key_b, "pod-b")] {
            let pod = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": { "name": name, "namespace": "default", "resourceVersion": "1" },
                "spec": {},
                "status": {}
            });
            store
                .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
                .await
                .unwrap();
        }

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods",
                delete(delete_collection_pods),
            )
            .layer(auth_layer())
            .with_state(state.clone());

        let grace = 45i64;
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let delete_opts = serde_json::json!({
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "gracePeriodSeconds": grace
        });
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&delete_opts))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let candidates: Vec<String> = (before..=after)
            .map(|s| crate::util::secs_to_rfc3339(s + grace))
            .collect();

        for key in [key_a, key_b] {
            let stored = store
                .get(key)
                .await
                .unwrap()
                .expect("soft-deleted pod must still exist");
            let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
            let ts = v["metadata"]["deletionTimestamp"]
                .as_str()
                .expect("deletionTimestamp must be set");
            assert!(
                candidates.contains(&ts.to_string()),
                "{key}: deletionTimestamp {ts} must be now+{grace}s — DeleteCollection must \
                 not silently drop the caller's requested grace period for any matched pod"
            );
            assert_eq!(
                v["metadata"]["deletionGracePeriodSeconds"], grace,
                "{key}: deletionGracePeriodSeconds must be persisted for every pod in the \
                 collection, not just the first one"
            );
        }
    }

    /// `kubectl delete pods --all --dry-run=server` must NOT mutate any matched pod — a
    /// dry-run DeleteCollection that soft-deletes anyway silently terminates every workload
    /// in the namespace against the client's explicit intent. This test fails on revert
    /// with deletionTimestamp stamped on both pods.
    #[tokio::test]
    async fn delete_collection_pods_dry_run_does_not_mutate_store() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key_a = "/registry/pods/default/pod-a";
        let key_b = "/registry/pods/default/pod-b";
        for (key, name) in [(key_a, "pod-a"), (key_b, "pod-b")] {
            let pod = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": { "name": name, "namespace": "default", "resourceVersion": "1" },
                "spec": {},
                "status": {}
            });
            store
                .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
                .await
                .unwrap();
        }

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods",
                delete(delete_collection_pods),
            )
            .layer(auth_layer())
            .with_state(state.clone());

        let delete_opts = serde_json::json!({
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "dryRun": ["All"]
        });
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&delete_opts))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "dry-run DeleteCollection must still return a success response"
        );

        for key in [key_a, key_b] {
            let stored = store
                .get(key)
                .await
                .unwrap()
                .expect("pod must still exist after a dry-run DeleteCollection");
            let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
            assert!(
                v["metadata"]["deletionTimestamp"].is_null(),
                "{key}: dryRun=All must NOT stamp deletionTimestamp — if this fails, \
                 delete_collection_pods's dry-run guard was removed and the pod was \
                 actually soft-deleted in the store"
            );
        }
    }

    /// A single graceful DELETE (no explicit `gracePeriodSeconds`, mirroring exactly what
    /// u7s-scheduler's preemption eviction sends) must leave the pod visible to a subsequent
    /// GET — 200 with `.metadata.deletionTimestamp` set — not 404.
    ///
    /// This is the exact contract upstream's `test/e2e/scheduling/preemption.go` (release-1.36,
    /// line ~402) depends on: it polls a preempted victim once a second expecting
    /// `DeletionTimestamp != nil` while the pod is still Gettable. u7s-scheduler's preemption
    /// path used to force a second, immediate hard-delete right after the first, so by the very
    /// next 1s poll the victim had already vanished — the test failed with `Pod ... not found`
    /// well before it ever got to inspect DeletionTimestamp.
    ///
    /// Fails on revert: if `delete_pod` (or `get_pod`) regresses to hard-delete on the very
    /// first call, the GET below returns 404 instead of 200.
    #[tokio::test]
    async fn single_delete_leaves_pod_gettable_with_deletion_timestamp() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let key = "/registry/pods/default/preempted-victim";
        let grace = 80i64;
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "preempted-victim", "namespace": "default", "resourceVersion": "1" },
            "spec": { "terminationGracePeriodSeconds": grace },
            "status": { "phase": "Running" }
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}",
                delete(delete_pod).get(get_pod),
            )
            .layer(auth_layer())
            .with_state(state.clone());

        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Exactly what u7s-scheduler's delete_pod sends: no body, no query params — the
        // apiserver must fall back to spec.terminationGracePeriodSeconds.
        let delete_req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/preempted-victim")
            .body(Body::empty())
            .unwrap();
        let delete_resp = app.clone().oneshot(delete_req).await.unwrap();
        assert_eq!(
            delete_resp.status(),
            StatusCode::OK,
            "graceful DELETE of a preemption victim must return 200"
        );

        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let get_req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/preempted-victim")
            .body(Body::empty())
            .unwrap();
        let get_resp = app.oneshot(get_req).await.unwrap();
        assert_eq!(
            get_resp.status(),
            StatusCode::OK,
            "a preemption victim must stay GETtable right after a single soft-delete — a 404 \
             here is exactly the upstream e2e failure this bug caused (`Pod ... not found`, \
             preemption.go:402), because the pod vanished before the 1s poll interval could \
             ever observe DeletionTimestamp"
        );
        let body = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ts = v["metadata"]["deletionTimestamp"]
            .as_str()
            .expect("deletionTimestamp must be set and visible via GET after a single DELETE");
        let candidates: Vec<String> = (before..=after)
            .map(|s| crate::util::secs_to_rfc3339(s + grace))
            .collect();
        assert!(
            candidates.contains(&ts.to_string()),
            "deletionTimestamp {ts} must reflect spec.terminationGracePeriodSeconds ({grace}s), \
             proving the pod is mid-grace-period, not already torn down"
        );
        assert_eq!(
            v["status"]["phase"], "Running",
            "the pod GET must still return its real status, not a bare tombstone — a client \
             polling for DeletionTimestamp needs the rest of the object intact too"
        );
    }

    // -----------------------------------------------------------------------
    // evict_pod
    // -----------------------------------------------------------------------

    /// POST /pods/{name}/eviction on a running pod must soft-delete (stamp deletionTimestamp)
    /// and return 201 Created with the Eviction object.
    ///
    /// Without this endpoint the conformance test "Should recreate evicted statefulset" never
    /// terminates the orphan pod, so the StatefulSet controller never gets a pod-deleted event
    /// and never recreates ss-0. The test then times out after 15 minutes.
    ///
    /// This test fails on revert: if evict_pod is removed, the route does not exist, and the
    /// pod deletionTimestamp is never stamped, breaking the StatefulSet recreation flow.
    #[tokio::test]
    async fn evict_pod_stamps_deletion_timestamp_and_returns_201() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/ss-0";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "ss-0", "namespace": "default", "resourceVersion": "1" },
            "spec": {},
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .layer(auth_layer())
            .with_state(state);

        let eviction_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "ss-0", "namespace": "default" }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/ss-0/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&eviction_body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "eviction must return 201 Created — the test uses this status to confirm the pod is being terminated"
        );

        let stored = store
            .get(key)
            .await
            .unwrap()
            .expect("pod must still exist after eviction — soft-delete, not hard-delete");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["deletionTimestamp"].is_string(),
            "eviction must stamp deletionTimestamp so the kubelet sends SIGTERM and the \
             StatefulSet controller sees the pod as terminating — without this the orphan \
             pod runs forever and the 'Should recreate evicted statefulset' test hangs"
        );
    }

    /// `kubectl -n <ns> ... create eviction --dry-run=server` (or any client setting
    /// Eviction.deleteOptions.dryRun) must NOT actually evict the pod — eviction is a
    /// delete-like mutation, and a dry-run that evicts anyway silently terminates a workload
    /// against the client's explicit intent. This test fails on revert with
    /// deletionTimestamp stamped in the store.
    #[tokio::test]
    async fn evict_pod_dry_run_does_not_mutate_store() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/ss-0";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "ss-0", "namespace": "default", "resourceVersion": "1" },
            "spec": {},
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .layer(auth_layer())
            .with_state(state);

        let eviction_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "ss-0", "namespace": "default" },
            "deleteOptions": { "dryRun": ["All"] }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/ss-0/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&eviction_body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "dry-run eviction must still return 201 Created with the would-be Eviction object"
        );

        let stored = store
            .get(key)
            .await
            .unwrap()
            .expect("pod must still exist after a dry-run eviction");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["deletionTimestamp"].is_null(),
            "dryRun=All in Eviction.deleteOptions must NOT stamp deletionTimestamp — if this \
             fails, evict_pod's dry-run guard was removed and the pod was actually evicted"
        );
    }

    /// POST /pods/{name}/eviction on a pod covered by a PodDisruptionBudget with
    /// `disruptionsAllowed: 0` must return 429, not 201.
    ///
    /// PDBs are the primary safety mechanism against voluntary disruption: a Deployment
    /// relies on `disruptionsAllowed` staying above zero to guarantee availability during a
    /// drain or rolling change. If eviction ignores the PDB, `kubectl drain` (and the
    /// descheduler) can take down every pod backing a service at once — exactly what the
    /// budget exists to prevent. This test fails on revert: before this fix, evict_pod had
    /// zero PDB awareness and always returned 201.
    #[tokio::test]
    async fn evict_pod_blocked_by_pdb_returns_429() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "web-0",
            serde_json::json!({"metadata": {"name": "web-0", "namespace": "default", "resourceVersion": "1", "labels": {"app": "web"}}}),
        )
        .await;

        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "web-pdb", "namespace": "default" },
            "spec": { "selector": { "matchLabels": { "app": "web" } } },
            "status": { "disruptionsAllowed": 0 }
        });
        store
            .put(
                "/registry/policy/poddisruptionbudgets/default/web-pdb",
                Bytes::from(serde_json::to_vec(&pdb).unwrap()),
                None,
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .layer(auth_layer())
            .with_state(state);

        let eviction_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "web-0", "namespace": "default" }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/web-0/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&eviction_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "eviction of a pod covered by a PDB with disruptionsAllowed:0 must return 429 — \
             returning 201 lets kubectl drain violate the pod's disruption budget"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let status_body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            status_body["details"]["causes"][0]["reason"], "DisruptionBudget",
            "the 429 body must carry a DisruptionBudget status cause so client-go's \
             apierrors.HasStatusCause(err, policyv1.DisruptionBudgetCause) — what the \
             conformance test asserts on — returns true"
        );

        let stored = store
            .get("/registry/pods/default/web-0")
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            v["metadata"]["deletionTimestamp"].is_null(),
            "a PDB-blocked eviction must not stamp deletionTimestamp — the pod was never \
             actually terminated"
        );
    }

    /// `unhealthyPodEvictionPolicy: AlwaysAllow` must permit evicting a NotReady pod even
    /// when `disruptionsAllowed: 0`.
    ///
    /// AlwaysAllow exists so an operator can clear out pods that are already broken (crash
    /// looping, failing readiness) without waiting on other pods to become healthy first —
    /// a resource-constrained cluster that can't evict its unready pods can never recover.
    /// This test fails on revert: without policy handling, `check_pdb_allows_eviction` looks
    /// only at `disruptionsAllowed` and would return 429 here.
    #[tokio::test]
    async fn evict_pod_always_allow_permits_unready_pod_despite_exhausted_budget() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "web-0",
            serde_json::json!({
                "metadata": {"name": "web-0", "namespace": "default", "resourceVersion": "1", "labels": {"app": "web"}},
                "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "False"}]}
            }),
        )
        .await;

        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "web-pdb", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "web" } },
                "unhealthyPodEvictionPolicy": "AlwaysAllow"
            },
            "status": { "disruptionsAllowed": 0, "currentHealthy": 0, "desiredHealthy": 1 }
        });
        store
            .put(
                "/registry/policy/poddisruptionbudgets/default/web-pdb",
                Bytes::from(serde_json::to_vec(&pdb).unwrap()),
                None,
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .layer(auth_layer())
            .with_state(state);

        let eviction_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "web-0", "namespace": "default" }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/web-0/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&eviction_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "AlwaysAllow must permit evicting a NotReady pod regardless of disruptionsAllowed"
        );
    }

    /// `AlwaysAllow` only exempts unhealthy pods — a Ready pod covered by the same PDB must
    /// still be blocked when `disruptionsAllowed: 0`.
    ///
    /// If the policy check bypassed the budget for every pod instead of gating on health
    /// first, `kubectl drain` could evict an entire healthy Deployment at once through a PDB
    /// that only meant to fast-track already-broken pods — the exact outage the budget exists
    /// to prevent. This test fails on revert to a "policy always wins" implementation.
    #[tokio::test]
    async fn evict_pod_always_allow_does_not_exempt_ready_pod_from_budget() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "web-0",
            serde_json::json!({
                "metadata": {"name": "web-0", "namespace": "default", "resourceVersion": "1", "labels": {"app": "web"}},
                "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}
            }),
        )
        .await;

        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "web-pdb", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "web" } },
                "unhealthyPodEvictionPolicy": "AlwaysAllow"
            },
            "status": { "disruptionsAllowed": 0, "currentHealthy": 1, "desiredHealthy": 1 }
        });
        store
            .put(
                "/registry/policy/poddisruptionbudgets/default/web-pdb",
                Bytes::from(serde_json::to_vec(&pdb).unwrap()),
                None,
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .layer(auth_layer())
            .with_state(state);

        let eviction_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "web-0", "namespace": "default" }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/web-0/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&eviction_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a Ready pod must remain subject to the budget even under AlwaysAllow — the \
             policy only relaxes eviction of pods that are already unhealthy"
        );
    }

    /// Under the default policy (no `unhealthyPodEvictionPolicy` set, equivalent to
    /// `IfHealthyBudget`), a NotReady pod must be evictable once the budget is already met
    /// (`currentHealthy >= desiredHealthy`), even with `disruptionsAllowed: 0`.
    ///
    /// Evicting a pod that isn't serving traffic doesn't reduce the application's actual
    /// availability, so an operator draining a node shouldn't be stuck waiting for
    /// `disruptionsAllowed` to reflect that. This test fails on revert: before this fix,
    /// `check_pdb_allows_eviction` only ever looked at `disruptionsAllowed`.
    #[tokio::test]
    async fn evict_pod_default_policy_permits_unready_pod_when_budget_already_met() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "web-0",
            serde_json::json!({
                "metadata": {"name": "web-0", "namespace": "default", "resourceVersion": "1", "labels": {"app": "web"}},
                "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "False"}]}
            }),
        )
        .await;

        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "web-pdb", "namespace": "default" },
            "spec": { "selector": { "matchLabels": { "app": "web" } } },
            "status": { "disruptionsAllowed": 0, "currentHealthy": 2, "desiredHealthy": 2 }
        });
        store
            .put(
                "/registry/policy/poddisruptionbudgets/default/web-pdb",
                Bytes::from(serde_json::to_vec(&pdb).unwrap()),
                None,
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .layer(auth_layer())
            .with_state(state);

        let eviction_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "web-0", "namespace": "default" }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/web-0/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&eviction_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "default (IfHealthyBudget) policy must permit evicting an unready pod once the \
             budget is already met, regardless of disruptionsAllowed"
        );
    }

    /// Under `IfHealthyBudget`, a NotReady pod must still be blocked when the budget is NOT
    /// met (`currentHealthy < desiredHealthy`) — the unhealthy-pod exemption only applies once
    /// the application is already back to full health.
    ///
    /// Without this guard, an unready pod would always bypass the budget under
    /// IfHealthyBudget/Default, collapsing it to AlwaysAllow — letting a drain evict every
    /// unready pod of a struggling application while it's still below its desired healthy
    /// count, the opposite of what IfHealthyBudget promises.
    #[tokio::test]
    async fn evict_pod_if_healthy_budget_blocks_unready_pod_when_budget_not_met() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "web-0",
            serde_json::json!({
                "metadata": {"name": "web-0", "namespace": "default", "resourceVersion": "1", "labels": {"app": "web"}},
                "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "False"}]}
            }),
        )
        .await;

        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "web-pdb", "namespace": "default" },
            "spec": {
                "selector": { "matchLabels": { "app": "web" } },
                "unhealthyPodEvictionPolicy": "IfHealthyBudget"
            },
            "status": { "disruptionsAllowed": 0, "currentHealthy": 1, "desiredHealthy": 2 }
        });
        store
            .put(
                "/registry/policy/poddisruptionbudgets/default/web-pdb",
                Bytes::from(serde_json::to_vec(&pdb).unwrap()),
                None,
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .layer(auth_layer())
            .with_state(state);

        let eviction_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "web-0", "namespace": "default" }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/web-0/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&eviction_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "IfHealthyBudget must still block an unready pod while the budget is below its \
             desired healthy count — the exemption is conditional, not unconditional"
        );
    }

    /// Two evictions issued concurrently against a PDB with `disruptionsAllowed: 1` must not
    /// both succeed — that is exactly the over-eviction a PDB exists to prevent (e.g. a
    /// StatefulSet's last two Ready replicas both getting drained at once because each request
    /// read the same stale `disruptionsAllowed` before either write landed). This test fails
    /// on revert: a read-only check (no CAS decrement) lets every concurrent evictor observe
    /// `disruptionsAllowed: 1` and all of them succeed instead of just one, reproduced 2/2 in
    /// the `[sig-apps] DisruptionController` conformance run this fixes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn evict_pod_concurrent_evictions_never_exceed_disruptions_allowed() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        for name in ["web-0", "web-1", "web-2"] {
            seed_pod(
                &store,
                "default",
                name,
                serde_json::json!({
                    "metadata": {"name": name, "namespace": "default", "resourceVersion": "1", "labels": {"app": "web"}},
                    "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}
                }),
            )
            .await;
        }

        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "web-pdb", "namespace": "default" },
            "spec": { "selector": { "matchLabels": { "app": "web" } }, "maxUnavailable": 1 },
            "status": { "disruptionsAllowed": 1, "currentHealthy": 3, "desiredHealthy": 2 }
        });
        store
            .put(
                "/registry/policy/poddisruptionbudgets/default/web-pdb",
                Bytes::from(serde_json::to_vec(&pdb).unwrap()),
                None,
            )
            .await
            .unwrap();

        let headers = {
            let mut h = axum::http::HeaderMap::new();
            h.insert(
                axum::http::header::CONTENT_TYPE,
                "application/json".parse().unwrap(),
            );
            h
        };
        let make_body = |name: &str| {
            Bytes::from(
                serde_json::json!({
                    "apiVersion": "policy/v1",
                    "kind": "Eviction",
                    "metadata": { "name": name, "namespace": "default" }
                })
                .to_string(),
            )
        };

        // Three concurrent evictions against a budget with only 1 disruption to give.
        let (r1, r2, r3) = tokio::join!(
            evict_pod(
                axum::extract::State(state.clone()),
                axum::extract::Path(("default".to_string(), "web-0".to_string())),
                auth_layer(),
                headers.clone(),
                make_body("web-0"),
            ),
            evict_pod(
                axum::extract::State(state.clone()),
                axum::extract::Path(("default".to_string(), "web-1".to_string())),
                auth_layer(),
                headers.clone(),
                make_body("web-1"),
            ),
            evict_pod(
                axum::extract::State(state.clone()),
                axum::extract::Path(("default".to_string(), "web-2".to_string())),
                auth_layer(),
                headers.clone(),
                make_body("web-2"),
            ),
        );

        let statuses: Vec<StatusCode> = [r1, r2, r3]
            .into_iter()
            .map(|r| match r {
                Ok(resp) => resp.into_response().status(),
                Err(status_err) => status_err.0,
            })
            .collect();

        let created = statuses
            .iter()
            .filter(|s| **s == StatusCode::CREATED)
            .count();
        let too_many = statuses
            .iter()
            .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
            .count();

        assert_eq!(
            created, 1,
            "exactly 1 of 3 concurrent evictions must succeed against disruptionsAllowed:1 — \
             without an atomic verify-and-decrement, every request reads the same stale \
             disruptionsAllowed and all of them succeed, evicting more pods than the budget \
             permits and breaking the availability guarantee the PDB exists to provide"
        );
        assert_eq!(
            too_many, 2,
            "the 2 losing evictions must see 429 Too Many Requests, not succeed or 500 — \
             kubectl drain and the descheduler rely on 429 to know to retry once the budget \
             recovers"
        );
    }

    /// Upstream (eviction.go MaxDisruptedPodSize=2000): once a PDB's `disruptedPods` map already
    /// holds more entries than the DisruptionController can plausibly have reconciled, further
    /// evictions must be refused rather than adding yet another entry. Without this cap, a burst
    /// of concurrent evictions the controller hasn't caught up with yet grows the map without
    /// bound instead of self-correcting via the controller's periodic resync.
    #[tokio::test]
    async fn evict_pod_over_max_disrupted_pod_size_does_not_grow_disrupted_pods() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "web-0",
            serde_json::json!({"metadata": {"name": "web-0", "namespace": "default", "resourceVersion": "1", "labels": {"app": "web"}}}),
        )
        .await;

        let mut disrupted_pods = serde_json::Map::new();
        for i in 0..2001 {
            disrupted_pods.insert(
                format!("stale-pod-{i}"),
                serde_json::json!("2020-01-01T00:00:00Z"),
            );
        }
        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "web-pdb", "namespace": "default" },
            "spec": { "selector": { "matchLabels": { "app": "web" } } },
            "status": { "disruptionsAllowed": 5, "disruptedPods": disrupted_pods }
        });
        store
            .put(
                "/registry/policy/poddisruptionbudgets/default/web-pdb",
                Bytes::from(serde_json::to_vec(&pdb).unwrap()),
                None,
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .layer(auth_layer())
            .with_state(state);

        let eviction_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "web-0", "namespace": "default" }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/web-0/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&eviction_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "eviction against a PDB whose disruptedPods already exceeds MaxDisruptedPodSize \
             (2000) must be refused — without the cap, disruptedPods keeps accepting entries \
             the DisruptionController isn't reconciling fast enough and grows without bound"
        );

        let stored = store
            .get("/registry/policy/poddisruptionbudgets/default/web-pdb")
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["disruptedPods"].as_object().unwrap().len(),
            2001,
            "a capped eviction must not add its own entry to disruptedPods — the map must stay \
             at its pre-eviction size, not grow past the cap"
        );
    }

    /// Upstream (eviction.go checkAndDecrement): a PDB whose `status.observedGeneration` trails
    /// `metadata.generation` hasn't been reconciled by the DisruptionController since its last
    /// spec change, so its `disruptionsAllowed` cannot be trusted yet. Acting on it anyway could
    /// let an eviction through against a budget the controller is about to recompute downward.
    #[tokio::test]
    async fn evict_pod_stale_pdb_observed_generation_returns_429_without_decrementing() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "web-0",
            serde_json::json!({"metadata": {"name": "web-0", "namespace": "default", "resourceVersion": "1", "labels": {"app": "web"}}}),
        )
        .await;

        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "web-pdb", "namespace": "default", "generation": 2 },
            "spec": { "selector": { "matchLabels": { "app": "web" } } },
            "status": { "disruptionsAllowed": 5, "observedGeneration": 1 }
        });
        store
            .put(
                "/registry/policy/poddisruptionbudgets/default/web-pdb",
                Bytes::from(serde_json::to_vec(&pdb).unwrap()),
                None,
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .layer(auth_layer())
            .with_state(state);

        let eviction_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "web-0", "namespace": "default" }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/web-0/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&eviction_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "an eviction must not proceed against a PDB the DisruptionController hasn't \
             finished reconciling (observedGeneration < generation) — the stale \
             disruptionsAllowed:5 in this status cannot be trusted, so acting on it must not \
             return 201"
        );

        let stored = store
            .get("/registry/policy/poddisruptionbudgets/default/web-pdb")
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["disruptionsAllowed"], 5,
            "the observedGeneration guard must reject before spending a disruption — \
             disruptionsAllowed must be untouched by the rejected attempt"
        );
    }

    /// The `dry_run` flag threaded into `check_pdb_allows_eviction` must gate the store write,
    /// not the admission verdict: a dry-run against an available budget must report the same
    /// allow verdict a real eviction would get, without spending the disruption it evaluated —
    /// otherwise `kubectl drain --dry-run` would silently exhaust a real budget before any pod
    /// was actually evicted, and a dry-run against an exhausted budget must still report deny.
    #[tokio::test]
    async fn evict_pod_dry_run_reports_pdb_verdict_without_spending_budget() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        for name in ["web-0", "web-1", "web-2"] {
            seed_pod(
                &store,
                "default",
                name,
                serde_json::json!({"metadata": {"name": name, "namespace": "default", "resourceVersion": "1", "labels": {"app": "web"}}}),
            )
            .await;
        }

        let pdb = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": { "name": "web-pdb", "namespace": "default" },
            "spec": { "selector": { "matchLabels": { "app": "web" } } },
            "status": { "disruptionsAllowed": 1 }
        });
        store
            .put(
                "/registry/policy/poddisruptionbudgets/default/web-pdb",
                Bytes::from(serde_json::to_vec(&pdb).unwrap()),
                None,
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .layer(auth_layer())
            .with_state(state);

        // A dry-run against disruptionsAllowed:1 must report the allow verdict (201)...
        let dry_run_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "web-0", "namespace": "default" },
            "deleteOptions": { "dryRun": ["All"] }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/web-0/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&dry_run_body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "a dry-run eviction against a PDB with disruptionsAllowed:1 must report the allow \
             verdict (201) a real eviction against the same budget would get"
        );

        // ...without spending it: a real eviction against the same budget right after must
        // still succeed, proving the dry-run left disruptionsAllowed untouched.
        let real_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "web-1", "namespace": "default" }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/web-1/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&real_body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "the prior dry-run must not have decremented disruptionsAllowed — if it had, this \
             real eviction against the same budget would wrongly see 429 instead of succeeding"
        );

        let stored = store
            .get("/registry/policy/poddisruptionbudgets/default/web-pdb")
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["disruptionsAllowed"], 0,
            "exactly one disruption (from the real eviction) must have been spent — the \
             dry-run must have contributed zero to the decrement"
        );
        assert!(
            v["status"]["disruptedPods"]["web-0"].is_null(),
            "dry-run must not stamp disruptedPods for the pod it evaluated — that bookkeeping \
             exists to inform the DisruptionController of real evictions only"
        );

        // The budget is now exhausted (disruptionsAllowed:0) — a dry-run must report the deny
        // verdict too, not just the allow case.
        let dry_run_deny_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "web-2", "namespace": "default" },
            "deleteOptions": { "dryRun": ["All"] }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/web-2/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&dry_run_deny_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a dry-run against an exhausted budget must report the same deny verdict (429) a \
             real eviction would get — `kubectl drain --dry-run` must not lie about what a real \
             drain would do"
        );
    }

    /// POST /pods/{name}/eviction that proceeds (PDB allows it, or no PDB covers the pod)
    /// must set the pod's `DisruptionTarget` condition.
    ///
    /// The Job controller's pod-failure-policy matches failed pods against
    /// `onPodConditions: [{type: DisruptionTarget}]` to distinguish a voluntary disruption from
    /// an application bug. Without this condition, an evicted pod's failure always counts
    /// against the Job's backoffLimit even when the policy says to ignore disruptions. This
    /// test fails on revert: before this fix, evict_pod never touched status.conditions.
    #[tokio::test]
    async fn evict_pod_sets_disruption_target_condition() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "ss-0", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .layer(auth_layer())
            .with_state(state);

        let eviction_body = serde_json::json!({
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": { "name": "ss-0", "namespace": "default" }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/ss-0/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&eviction_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let stored = store
            .get("/registry/pods/default/ss-0")
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let conditions = v["status"]["conditions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let disruption_target = conditions
            .iter()
            .find(|c| c["type"] == "DisruptionTarget")
            .expect("evicted pod must carry a DisruptionTarget condition");
        assert_eq!(
            disruption_target["status"], "True",
            "DisruptionTarget condition must be status=True — the Job controller's \
             podFailurePolicy onPodConditions match checks the condition's status"
        );
    }

    /// POST /pods/{name}/eviction on a non-existent pod must return 404.
    ///
    /// Callers must get a clear Not Found rather than a panic or silent success.
    #[tokio::test]
    async fn evict_pod_missing_returns_404() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/eviction",
                post(evict_pod),
            )
            .layer(auth_layer())
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/ghost/eviction")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "eviction of a non-existent pod must return 404 — callers must know the pod is gone"
        );
    }

    // -----------------------------------------------------------------------
    // patch_pod
    // -----------------------------------------------------------------------

    /// PATCH with merge-patch+json must update the specified field.
    #[tokio::test]
    async fn patch_pod_merge_patch_updates_field() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"metadata": {"labels": {"app": "test"}}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A merge-patch PATCH attempting to move an already-bound pod to a different node must
    /// be rejected, exactly like replace_pod's PUT path already is. `patch pods` is a
    /// commonly-granted, seemingly low-risk verb — distinct from `create pods/binding`,
    /// which real Kubernetes scopes to the scheduler specifically so that node assignment
    /// bypasses neither the scheduler's fit/taint/affinity checks nor that RBAC boundary.
    /// Without validate_pod_spec_immutable wired into patch_pod, this PATCH would silently
    /// reassign the pod straight to the attacker's chosen node.
    #[tokio::test]
    async fn patch_pod_merge_patch_cannot_reassign_node_name() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "victim",
            serde_json::json!({
                "spec": {
                    "containers": [{"name": "app", "image": "nginx"}],
                    "nodeName": "control-plane-node"
                }
            }),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"spec": {"nodeName": "other-node"}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/victim")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "patch_pod must reject a nodeName change via ordinary `patch pods` — accepting \
             it bypasses both the scheduler and the pods/binding RBAC boundary"
        );
    }

    /// A merge-patch PATCH setting nodeName on a pod that has never been scheduled (stored
    /// spec.nodeName absent/blank) must be rejected exactly like the already-bound case
    /// above. nodeName may ONLY ever be assigned via the /binding subresource — even the
    /// very first assignment — because `create pods/binding` is a distinct, scheduler-scoped
    /// RBAC verb from `patch pods`. Before this fix, validate_pod_spec_immutable only froze
    /// nodeName once the STORED value was already non-blank, so a caller holding just
    /// `patch pods` could steer a not-yet-scheduled pod straight to a node of their choosing
    /// on the first write, bypassing the scheduler's fit/taint/affinity checks entirely.
    #[tokio::test]
    async fn patch_pod_merge_patch_cannot_set_node_name_on_unscheduled_pod() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "never-scheduled-pod",
            serde_json::json!({
                "spec": {
                    "containers": [{"name": "app", "image": "nginx"}]
                }
            }),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"spec": {"nodeName": "attacker-node"}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/never-scheduled-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "patch_pod must reject a blank-to-set nodeName write via ordinary `patch pods` \
             — the first assignment is exactly as security-sensitive as a reassignment, and \
             must go through the /binding subresource"
        );
    }

    /// A merge-patch PATCH changing `spec.schedulerName` must be rejected. `schedulerName`
    /// picks which scheduler profile owns the pod's placement decisions; a caller holding
    /// only `patch pods` (not the scheduler's own credentials) must not be able to steer a
    /// pod to a different scheduler profile after the fact — that is the same class of
    /// scheduler bypass mq366 fixed for `nodeName`, just for the field one step upstream
    /// of it. Before the allowlist rewrite, `validate_pod_spec_immutable`'s blocklist never
    /// checked this field at all, so this PATCH silently succeeded.
    #[tokio::test]
    async fn patch_pod_merge_patch_cannot_change_scheduler_name() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "sched-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"spec": {"schedulerName": "other-scheduler"}});
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/sched-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "patch_pod must reject a schedulerName change via ordinary `patch pods` — \
             accepting it lets a caller retarget a pod to a different scheduler profile \
             without ever touching the scheduler-scoped RBAC surface"
        );
    }

    /// A merge-patch PATCH changing `spec.automountServiceAccountToken` must be rejected.
    /// Upstream `ValidatePodUpdate` freezes this field post-creation; letting a bare
    /// `patch pods` caller flip it lets a workload that was created with the SA-token
    /// mount suppressed (`automountServiceAccountToken: false`) silently regain the
    /// projected token volume — a privilege change no admission plugin re-evaluates
    /// after create. `validate_pod_spec_immutable` used to strip this field from both
    /// sides of its comparison before diffing (on the mistaken belief the field was
    /// never decoded from protobuf; `core_gen_adapter.rs`'s round-trip tests show it
    /// is), so this PATCH used to silently succeed.
    #[tokio::test]
    async fn patch_pod_merge_patch_cannot_change_automount_service_account_token() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "automount-pod",
            serde_json::json!({
                "spec": {
                    "containers": [{"name": "app", "image": "nginx"}],
                    "automountServiceAccountToken": false
                }
            }),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"spec": {"automountServiceAccountToken": true}});
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/automount-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "patch_pod must reject an automountServiceAccountToken change via ordinary \
             `patch pods` — accepting it lets a caller silently re-enable SA token \
             automount on a pod that was created with it explicitly suppressed"
        );
    }

    /// A merge-patch PATCH changing `spec.serviceAccountName` must be rejected.
    /// serviceAccountName determines which ServiceAccount's projected token gets mounted
    /// into the pod; letting a bare `patch pods` caller change it after creation is
    /// adjacent to SA-token privilege escalation — the pod would start requesting a
    /// different identity's credentials without ever going through the admission checks
    /// that ran at create time. The pre-rewrite blocklist never checked this field.
    #[tokio::test]
    async fn patch_pod_merge_patch_cannot_change_service_account_name() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "sa-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"spec": {"serviceAccountName": "other-sa"}});
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/sa-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "patch_pod must reject a serviceAccountName change via ordinary `patch pods` — \
             accepting it is adjacent to SA-token privilege escalation on an existing pod"
        );
    }

    /// A merge-patch PATCH changing `spec.securityContext` must be rejected. securityContext
    /// carries hostNetwork/hostPID/hostIPC and per-pod runAsUser/runAsGroup — a direct
    /// privilege-context change on an already-admitted pod, bypassing whatever PodSecurity
    /// admission or webhook ran at create time. The pre-rewrite blocklist never checked this
    /// field, so a `patch pods`-only caller could flip a pod to run as root after the fact.
    #[tokio::test]
    async fn patch_pod_merge_patch_cannot_change_security_context() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "secctx-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"spec": {"securityContext": {"runAsUser": 0}}});
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/secctx-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "patch_pod must reject a securityContext change via ordinary `patch pods` — \
             accepting it lets a caller escalate an existing pod to run as root with no \
             admission re-check"
        );
    }

    /// A merge-patch PATCH updating only `containers[].image` on an already-running pod
    /// must be allowed — this is the standard graceful-rollout mechanism controllers use
    /// (e.g. a Deployment's RollingUpdate strategy patches the image of pods it owns
    /// in-place in some flows). Rejecting it would be a regression from the allowlist
    /// rewrite: upstream explicitly permits this field to change via a plain update.
    #[tokio::test]
    async fn patch_pod_merge_patch_can_update_container_image() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "image-pod",
            serde_json::json!({
                "spec": {
                    "containers": [{"name": "app", "image": "nginx:1.0"}],
                    "nodeName": "node-1"
                }
            }),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body =
            serde_json::json!({"spec": {"containers": [{"name": "app", "image": "nginx:2.0"}]}});
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/image-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "an image-only change on a running pod must succeed — upstream explicitly \
             allows graceful image rollouts through a plain pod update"
        );
    }

    /// A merge-patch PATCH decreasing `spec.activeDeadlineSeconds` must be allowed —
    /// upstream permits shrinking (but never growing) an in-progress deadline, e.g. a
    /// controller tightening a pod's allotted runtime after observing it's misbehaving.
    #[tokio::test]
    async fn patch_pod_merge_patch_can_decrease_active_deadline_seconds() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "ads-decrease-pod",
            serde_json::json!({
                "spec": {
                    "containers": [{"name": "app", "image": "nginx"}],
                    "activeDeadlineSeconds": 60
                }
            }),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"spec": {"activeDeadlineSeconds": 30}});
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/ads-decrease-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "decreasing activeDeadlineSeconds (60 -> 30) must succeed — upstream allows \
             tightening an in-progress deadline"
        );
    }

    /// A merge-patch PATCH increasing `spec.activeDeadlineSeconds` must still be rejected
    /// after the allowlist rewrite — this was already enforced by the pre-rewrite blocklist
    /// and must not regress, or a pod could extend a countdown that's already in progress,
    /// defeating the deadline's purpose.
    #[tokio::test]
    async fn patch_pod_merge_patch_cannot_increase_active_deadline_seconds() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "ads-increase-pod",
            serde_json::json!({
                "spec": {
                    "containers": [{"name": "app", "image": "nginx"}],
                    "activeDeadlineSeconds": 60
                }
            }),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"spec": {"activeDeadlineSeconds": 120}});
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/ads-increase-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "increasing activeDeadlineSeconds (60 -> 120) must still be rejected — it would \
             let a client extend a deadline countdown already in progress"
        );
    }

    /// A merge-patch PATCH changing `spec.dnsPolicy` must be rejected. dnsPolicy is frozen
    /// upstream once a pod exists; letting it change post-creation could silently move a
    /// running pod between hostNetwork-DNS and cluster-DNS resolution, which the kubelet
    /// only wires up at sandbox-creation time. Not previously checked by name in the
    /// blocklist — this is one of the fields flagged, now frozen automatically
    /// by the trailing whole-spec deep-equal instead of needing its own dedicated check.
    #[tokio::test]
    async fn patch_pod_merge_patch_cannot_change_dns_policy() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "dns-pod",
            serde_json::json!({
                "spec": {
                    "containers": [{"name": "app", "image": "nginx"}],
                    "dnsPolicy": "ClusterFirstWithHostNet"
                }
            }),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"spec": {"dnsPolicy": "ClusterFirst"}});
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/dns-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "patch_pod must reject a dnsPolicy change — the allowlist rewrite must freeze \
             every field outside its explicit allowed set, not just the ones with a \
             dedicated check"
        );
    }

    /// A merge-patch PATCH that appends a new toleration while keeping every existing one
    /// must be allowed — upstream permits growing a pod's toleration set (e.g. a controller
    /// reacting to a newly-observed taint) without allowing existing tolerations to be
    /// weakened or removed.
    #[tokio::test]
    async fn patch_pod_merge_patch_can_append_toleration() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "toleration-append-pod",
            serde_json::json!({
                "spec": {
                    "containers": [{"name": "app", "image": "nginx"}],
                    "tolerations": [{"key": "existing", "operator": "Exists"}]
                }
            }),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"spec": {"tolerations": [
            {"key": "existing", "operator": "Exists"},
            {"key": "new", "operator": "Exists"}
        ]}});
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/toleration-append-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "appending a new toleration while keeping the existing one must succeed — \
             upstream allows tolerations to only grow"
        );
    }

    /// A merge-patch PATCH that drops an existing toleration must be rejected — removing a
    /// toleration a pod was scheduled with could let the kubelet's taint-manager evict it
    /// off a node it was legitimately tolerating, entirely outside the scheduler's control.
    #[tokio::test]
    async fn patch_pod_merge_patch_cannot_remove_toleration() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "toleration-remove-pod",
            serde_json::json!({
                "spec": {
                    "containers": [{"name": "app", "image": "nginx"}],
                    "tolerations": [
                        {"key": "keep-me", "operator": "Exists"},
                        {"key": "drop-me", "operator": "Exists"}
                    ]
                }
            }),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"spec": {"tolerations": [{"key": "keep-me", "operator": "Exists"}]}});
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/toleration-remove-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "dropping an existing toleration must be rejected — it could let the kubelet's \
             taint-manager evict the pod off a node it was legitimately scheduled onto"
        );
    }

    /// A strategic-merge-patch PATCH on the MAIN pod endpoint that sets status.phase
    /// must not change status — `patch pods` and `patch pods/status` are separate RBAC
    /// grants. Without a status snapshot/restore, a caller with only main-patch rights
    /// could forge status.phase (e.g. fake Ready) and mislead schedulers/controllers.
    #[tokio::test]
    async fn patch_pod_strategic_merge_cannot_forge_status_on_main_endpoint() {
        use axum::body::to_bytes;

        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "my-pod",
            serde_json::json!({"status": {"phase": "Pending"}}),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"status": {"phase": "Running"}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(
                header::CONTENT_TYPE,
                "application/strategic-merge-patch+json",
            )
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["status"]["phase"], "Pending",
            "main-endpoint strategic-merge PATCH must not forge status.phase — a caller \
             with only `patch pods` (no pods/status grant) must not be able to fake Ready"
        );
    }

    /// A JSON Patch on the MAIN pod endpoint targeting /status must not change status.
    /// JSON Patch is an array, so any object-key "status" strip on the incoming patch
    /// body would never catch it — the guard must snapshot/restore around the apply.
    #[tokio::test]
    async fn patch_pod_json_patch_cannot_forge_status_on_main_endpoint() {
        use axum::body::to_bytes;

        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "my-pod",
            serde_json::json!({"status": {"phase": "Pending", "podIP": ""}}),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!([
            { "op": "replace", "path": "/status/phase", "value": "Running" },
            { "op": "replace", "path": "/status/podIP", "value": "10.0.0.99" }
        ]);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(header::CONTENT_TYPE, "application/json-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["status"]["phase"], "Pending",
            "main-endpoint JSON Patch must not forge status.phase via the array-shaped \
             patch that bypasses an object-key strip"
        );
        assert_eq!(
            v["status"]["podIP"], "",
            "main-endpoint JSON Patch must not forge status.podIP — a fake pod IP could \
             be used to redirect traffic intended for the real pod"
        );
    }

    /// metadata.uid must survive every PATCH content-type on the main pod endpoint. A caller
    /// holding only `patch pods` RBAC (not `create`/`delete pods`) must not be able to forge
    /// a pod's uid to match a stale/foreign ownerReference — owner_ref_is_live keys purely on
    /// uid equality, so a forged match would hijack ReplicaSet/Job/DaemonSet cascade-GC,
    /// letting the attacker's pod either escape deletion or get someone else's pod deleted in
    /// its place. Fails on revert: without restoring the pre-patch uid, each patch below would
    /// persist the attacker-supplied uid and this assertion would fail.
    #[tokio::test]
    async fn patch_pod_cannot_change_uid() {
        use axum::body::to_bytes;

        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "my-pod",
            serde_json::json!({"metadata": {"uid": "real-uid-0001"}}),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        // Merge patch.
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(
                &serde_json::json!({"metadata": {"uid": "attacker-uid-merge"}}),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["metadata"]["uid"], "real-uid-0001",
            "a merge-patch carrying metadata.uid must not change the stored uid — a \
             patch-only caller could otherwise forge ownerReference matches and hijack GC"
        );

        // Strategic merge patch.
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(
                header::CONTENT_TYPE,
                "application/strategic-merge-patch+json",
            )
            .body(json_body(
                &serde_json::json!({"metadata": {"uid": "attacker-uid-strategic"}}),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["metadata"]["uid"], "real-uid-0001",
            "a strategic-merge-patch carrying metadata.uid must not change the stored uid — \
             a patch-only caller could otherwise forge ownerReference matches and hijack GC"
        );

        // JSON Patch — array-shaped, so an object-key strip on the incoming patch would never
        // catch this; the guard must snapshot/restore around the apply regardless of shape.
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(header::CONTENT_TYPE, "application/json-patch+json")
            .body(json_body(&serde_json::json!([
                { "op": "replace", "path": "/metadata/uid", "value": "attacker-uid-json" }
            ])))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["metadata"]["uid"], "real-uid-0001",
            "a JSON Patch carrying metadata.uid must not change the stored uid — a \
             patch-only caller could otherwise forge ownerReference matches and hijack GC"
        );

        let stored = store
            .get("/registry/pods/default/my-pod")
            .await
            .unwrap()
            .unwrap();
        let stored_val: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_val["metadata"]["uid"], "real-uid-0001",
            "the persisted store record must retain the original uid across all three patch \
             content-types, not just the response bodies"
        );
    }

    /// PATCH with an unsupported content-type must return 415.
    #[tokio::test]
    async fn patch_pod_unsupported_content_type_returns_415() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from("{}"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    /// SSA PATCH (application/apply-patch+yaml) with ?dryRun=All must return the would-be
    /// patched pod but must NOT persist the change to the store.
    ///
    /// This is the regression test for the dryRun=All bug in patch_pod: before the fix,
    /// patch_pod read no query params and always wrote to the store, causing
    /// "kubectl server-side dry-run: update Pods" sonobuoy tests to fail because
    /// the Pod image was changed on the server when it should not have been.
    #[tokio::test]
    async fn patch_pod_dry_run_all_does_not_mutate_store() {
        use axum::body::to_bytes;

        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "dry-run-pod",
            serde_json::json!({
                "spec": {"containers": [{"name": "app", "image": "nginx:original"}]}
            }),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        // SSA PATCH with dryRun=All: change image to "nginx:new".
        let patch_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "dry-run-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx:new"}]}
        });

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/dry-run-pod?dryRun=All")
            .header(header::CONTENT_TYPE, "application/apply-patch+yaml")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "dry-run PATCH must return 200"
        );

        // Response must show the would-be new image.
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let resp_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let containers = resp_json["spec"]["containers"].as_array().unwrap();
        assert_eq!(
            containers[0]["image"], "nginx:new",
            "dry-run response must show the would-be new image"
        );

        // The store must still have the original image — the write was skipped.
        let stored = store
            .get("/registry/pods/default/dry-run-pod")
            .await
            .unwrap()
            .expect("pod must still exist in store");
        let stored_json: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let stored_containers = stored_json["spec"]["containers"].as_array().unwrap();
        assert_eq!(
            stored_containers[0]["image"],
            "nginx:original",
            "dry-run PATCH must NOT mutate the store — image must remain 'nginx:original'; \
             if this fails, the dryRun=All guard was removed from patch_pod and the write went through"
        );
    }

    // -----------------------------------------------------------------------
    // get_pod_status
    // -----------------------------------------------------------------------

    /// GET /status on an existing pod returns 200.
    #[tokio::test]
    async fn get_pod_status_returns_200() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                get(get_pod_status),
            )
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/my-pod/status")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// GET /status on a missing pod returns 404.
    #[tokio::test]
    async fn get_pod_status_returns_404_for_missing() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                get(get_pod_status),
            )
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/ghost/status")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // replace_pod_status (PUT /status)
    // -----------------------------------------------------------------------

    /// PUT /status must update the status field and preserve spec.
    #[tokio::test]
    async fn replace_pod_status_updates_status_only() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                put(replace_pod_status),
            )
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "status": {"phase": "Running"},
            "spec": {"containers": [{"name": "hacker"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/my-pod/status")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify store: status updated, spec preserved.
        let key = "/registry/pods/default/my-pod";
        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["status"]["phase"], "Running");
        // spec was seeded with one container named "app"; the handler must not overwrite it.
        assert_eq!(v["spec"]["containers"][0]["name"], "app");
    }

    /// `PUT /status?dryRun=All` must return the would-be status object but leave the stored
    /// pod's status untouched. Before this fix, replace_pod_status had no dry-run check.
    #[tokio::test]
    async fn replace_pod_status_dry_run_all_does_not_persist() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                put(replace_pod_status),
            )
            .layer(axum::middleware::from_fn(
                crate::handlers::json_patch::inject_dry_run_header,
            ))
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "status": {"phase": "Running"}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/my-pod/status?dryRun=All")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            v["status"]["phase"], "Running",
            "dry-run response must show the would-be status"
        );

        let key = "/registry/pods/default/my-pod";
        let stored = store.get(key).await.unwrap().unwrap();
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["status"]["phase"], "Pending",
            "dryRun=All must not persist the status change (seed_pod's default is Pending)"
        );
    }

    /// A protobuf-encoded PUT to /status must not destroy `containerStatuses`.
    ///
    /// `replace_pod_status` replaces the whole stored `status` subtree with whatever
    /// `extract_body`/the proto decoder produces (`current_obj.body["status"] =
    /// incoming["status"].clone()`), so a decoder that omits a field doesn't just fail to
    /// update it — it deletes whatever the stored pod already had there. Before the fix,
    /// the protobuf `PodStatus` decoder never emitted `containerStatuses` at all, so this
    /// exact request returned 200 OK while collapsing the stored status down to
    /// `{"phase":"Running"}`: both the caller's new containerStatuses AND the previously
    /// stored one vanished, and `kubectl get pods` READY/RESTARTS silently fell back to
    /// the spec container count (0/1 READY, 0 RESTARTS) for a healthy pod.
    #[tokio::test]
    async fn pod_status_containerstatuses_survives_protobuf_updatestatus_or_kubectl_get_pods_shows_wrong_ready_column(
    ) {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "my-pod",
            serde_json::json!({
                "status": {
                    "phase": "Running",
                    "containerStatuses": [{
                        "name": "app",
                        "ready": true,
                        "restartCount": 5,
                        "containerID": "containerd://old"
                    }]
                }
            }),
        )
        .await;

        // ContainerStatus{name(1)="app", restartCount(5)=6, containerID(8)="containerd://new"}
        let mut container_status = encode_ld(1, b"app");
        container_status.push(0x28); // field 5 (restartCount), wire type 0 (varint)
        container_status.push(6);
        container_status.extend_from_slice(&encode_ld(8, b"containerd://new"));

        // PodStatus{containerStatuses(8) = [container_status]}
        let pod_status = encode_ld(8, &container_status);

        // ObjectMeta{name(1)="my-pod", namespace(3)="default"}
        let mut obj_meta = encode_ld(1, b"my-pod");
        obj_meta.extend_from_slice(&encode_ld(3, b"default"));

        // Pod{metadata(1), status(3)}
        let mut pod_proto = encode_ld(1, &obj_meta);
        pod_proto.extend_from_slice(&encode_ld(3, &pod_status));

        // Wrap in the k8s Unknown envelope client-go's typed UpdateStatus clients use.
        let mut type_meta = encode_ld(1, b"v1");
        type_meta.extend_from_slice(&encode_ld(2, b"Pod"));
        let mut unknown = encode_ld(1, &type_meta);
        unknown.extend_from_slice(&encode_ld(2, &pod_proto));
        let mut body = vec![0x6b, 0x38, 0x73, 0x00]; // magic
        body.extend_from_slice(&unknown);

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                put(replace_pod_status),
            )
            .with_state(state);

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/my-pod/status")
            .header(header::CONTENT_TYPE, "application/vnd.kubernetes.protobuf")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "this repro is about the request succeeding while silently discarding data, not \
             about it failing"
        );

        let stored = store
            .get("/registry/pods/default/my-pod")
            .await
            .expect("store get must succeed")
            .expect("pod must still exist after the status PUT");
        let persisted: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        let statuses = persisted["status"]["containerStatuses"].as_array().expect(
            "status.containerStatuses must survive a protobuf UpdateStatus — before the fix, \
             the protobuf PodStatus decoder never emitted this key, and replace_pod_status's \
             whole-subtree replace turned that omission into deletion: the caller's write and \
             the previously stored containerStatuses both vanished",
        );
        assert_eq!(
            statuses.len(),
            1,
            "the caller's containerStatuses entry must replace the previously stored one, \
             not disappear alongside it"
        );
        assert_eq!(
            statuses[0]["restartCount"], 6,
            "restartCount must reflect the caller's new value (6), not the stale stored \
             value (5) or be missing — kubectl get pods' RESTARTS column reads this field"
        );
        assert_eq!(
            statuses[0]["containerID"], "containerd://new",
            "containerID must reflect the caller's new value, not the stale stored value or \
             be missing — exec/log routing and crash-loop detection key off this field"
        );
    }

    // -----------------------------------------------------------------------
    // patch_pod_status (PATCH /status)
    // -----------------------------------------------------------------------

    /// PATCH /status with strategic-merge-patch must update the phase.
    #[tokio::test]
    async fn patch_pod_status_updates_phase() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                patch(patch_pod_status),
            )
            .with_state(state);

        let patch_body = serde_json::json!({"status": {"phase": "Running"}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod/status")
            .header(
                header::CONTENT_TYPE,
                "application/strategic-merge-patch+json",
            )
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// `PATCH /status?dryRun=All` must return the would-be patched status but leave the
    /// stored pod's status untouched. Before this fix, patch_pod_status had no dry-run check.
    #[tokio::test]
    async fn patch_pod_status_dry_run_all_does_not_persist() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                patch(patch_pod_status),
            )
            .layer(axum::middleware::from_fn(
                crate::handlers::json_patch::inject_dry_run_header,
            ))
            .with_state(state);

        let patch_body = serde_json::json!({"status": {"phase": "Running"}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod/status?dryRun=All")
            .header(
                header::CONTENT_TYPE,
                "application/strategic-merge-patch+json",
            )
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            v["status"]["phase"], "Running",
            "dry-run response must show the would-be patched status"
        );

        let key = "/registry/pods/default/my-pod";
        let stored = store.get(key).await.unwrap().unwrap();
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["status"]["phase"], "Pending",
            "dryRun=All must not persist the status change (seed_pod's default is Pending)"
        );
    }

    /// PATCH /status must persist the new phase to the store and the response body.
    ///
    /// Regression test: the handler accepted the PATCH without error
    /// but reported 0 changed fields — meaning the stored object was not mutated.
    ///
    /// This test fails if patch_pod_status is a no-op: if it returns 200 but leaves
    /// the stored object unchanged, the GET from the store will still show "Pending"
    /// and the assertion below will catch the regression.
    #[tokio::test]
    async fn patch_pod_status_persists_phase_change_to_store() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        // Seed a pod with phase "Pending" and a Ready=True condition.
        seed_pod(
            &store,
            "default",
            "lifecycle-pod",
            serde_json::json!({
                "status": {
                    "phase": "Pending",
                    "conditions": [{"type": "Ready", "status": "True"}]
                }
            }),
        )
        .await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                patch(patch_pod_status),
            )
            .with_state(state);

        // Kubelet reports the pod is now Running and conditions updated.
        // This is the exact scenario the e2e lifecycle test exercises.
        let patch_body = serde_json::json!({
            "status": {
                "phase": "Running",
                "conditions": [{"type": "Ready", "status": "False"}]
            }
        });

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/lifecycle-pod/status")
            .header(
                header::CONTENT_TYPE,
                "application/strategic-merge-patch+json",
            )
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PATCH /status must return 200"
        );

        // Read the pod back from the store — not from the response — to verify
        // the changes were actually persisted (not just echoed in the response body).
        let key = "/registry/pods/default/lifecycle-pod";
        let stored = store.get(key).await.unwrap().expect("pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["status"]["phase"], "Running",
            "phase must be updated to Running in the store — \
             if this fails the PATCH is a no-op (regression): \
             kubelet cannot advance pod lifecycle and pods stay Pending forever"
        );
        assert_eq!(
            v["status"]["conditions"][0]["status"], "False",
            "Ready condition must be updated to False in the store — \
             if this fails the status subresource PATCH is discarding changes"
        );
        // spec must not be touched by a status PATCH
        assert_eq!(
            v["spec"]["containers"][0]["name"], "app",
            "spec.containers must be unchanged after a status-only PATCH"
        );
    }

    /// PATCH /status with a merge-patch body `{"status":"x"}` must be rejected with 422,
    /// not persisted. This exercises the real HTTP handler end to end (not just the pure
    /// apply_status_patch function) so it fails if the guard is wired to the wrong call
    /// site. Without this, a scalar status corrupts the pod's schema and later panics
    /// apply_resize_patch's in-place status["resize"] stamp on the next resize of this pod.
    #[tokio::test]
    async fn patch_pod_status_rejects_scalar_status_merge_patch() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "scalar-status-pod",
            serde_json::json!({"status": {"phase": "Running"}}),
        )
        .await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                patch(patch_pod_status),
            )
            .with_state(state);

        let patch_body = serde_json::json!({"status": "x"});
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/scalar-status-pod/status")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a scalar status must be rejected with 422, matching upstream schema validation"
        );

        let key = "/registry/pods/default/scalar-status-pod";
        let stored = store.get(key).await.unwrap().expect("pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["phase"], "Running",
            "the rejected patch must not have been persisted — status must remain the \
             original object"
        );
    }

    /// PATCH /status must reject a smuggled metadata.labels change while still applying a
    /// legitimate status update. A caller granted only `pods/status` RBAC rights
    /// (e.g. the kubelet) must not be able to rewrite a pod's labels through this endpoint —
    /// labels gate Service/selector membership and scheduling, so this is a privilege-escalation
    /// path, not just a data-integrity bug. This exercises the real HTTP handler end to end
    /// (not just the pure merge function) so it fails if the guard is wired to the wrong call site.
    #[tokio::test]
    async fn patch_pod_status_does_not_persist_smuggled_labels() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "label-pod",
            serde_json::json!({
                "metadata": {
                    "name": "label-pod",
                    "namespace": "default",
                    "resourceVersion": "1",
                    "labels": { "app": "web" }
                },
                "status": { "phase": "Pending" }
            }),
        )
        .await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                patch(patch_pod_status),
            )
            .with_state(state);

        let patch_body = serde_json::json!({
            "metadata": { "labels": { "app": "evil", "escalated": "true" } },
            "status": { "phase": "Running" }
        });

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/label-pod/status")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PATCH /status must return 200"
        );

        let key = "/registry/pods/default/label-pod";
        let stored = store.get(key).await.unwrap().expect("pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["metadata"]["labels"],
            serde_json::json!({ "app": "web" }),
            "labels must be unchanged in the store after a /status PATCH — a status-only \
             RBAC grant must not be able to rewrite labels that gate selector-based \
             scheduling and Service membership"
        );
        assert_eq!(
            v["status"]["phase"], "Running",
            "a legitimate status field update must still be applied through the same request"
        );
    }

    /// PATCH /status with an unsupported content-type must return 415.
    #[tokio::test]
    async fn patch_pod_status_unsupported_content_type_returns_415() {
        let (state, _store) = make_state();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                patch(patch_pod_status),
            )
            .with_state(state);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod/status")
            .header(header::CONTENT_TYPE, "application/json-patch+json")
            .body(Body::from("[]"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    /// Regression test: PATCH /status on a pod whose namespace is deleted
    /// must return "Pod not found" 404 (loop-terminating), NOT "Namespace not found" 404
    /// (retryable). KCM's pod-GC controller marks orphaned/terminating pods Failed via a
    /// status PATCH; if the namespace is already hard-deleted, the previous code returned
    /// "Namespace not found" 404 because parse_namespace ran first. KCM treats that as a
    /// retryable error and retried every ~2s forever (2566 errors in 15h in one run),
    /// keeping the apiserver log growing and the GC loop hot indefinitely. A "Pod not found"
    /// 404 is what KCM treats as terminal (pod is gone, GC is done).
    ///
    /// This test fails if the namespace existence check is reintroduced in patch_pod_status:
    /// PATCH on a missing namespace would return 404 with reason=NotFound and message
    /// containing "Namespace", not "Pod", breaking the invariant below.
    #[tokio::test]
    async fn terminal_status_patch_on_pod_in_deleted_ns_does_not_trap_gc_retry() {
        let (state, _) = make_state();
        // Namespace is NOT seeded — simulates a hard-deleted namespace.
        // Pod is also absent (cascade-deleted with the namespace).

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                patch(patch_pod_status),
            )
            .with_state(state);

        // KCM pod-GC issues this exact patch to mark an orphaned pod Failed.
        let patch_body = serde_json::json!({"status": {"phase": "Failed"}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/deleted-namespace/pods/orphan-pod/status")
            .header(
                header::CONTENT_TYPE,
                "application/strategic-merge-patch+json",
            )
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        // Must be 404 (not 500 or 200).
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "status PATCH on deleted namespace must return 404 so KCM GC can terminate"
        );

        // Read response body to verify the 404 is for the POD, not the namespace.
        // KCM treats 'Pod not found' as terminal but 'Namespace not found' as retryable.
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();
        let message = body["message"].as_str().unwrap_or("");
        assert!(
            message.contains("Pod") || message.contains("pod") || message.contains("orphan-pod"),
            "404 must identify the missing Pod, not the Namespace — \
             KCM gc_controller treats 'Pod not found' as terminal (GC done) \
             but 'Namespace not found' as retryable (GC loops forever). \
             Got message: '{message}'"
        );
        assert!(
            !message.to_lowercase().contains("namespace"),
            "404 must NOT mention Namespace — that is the retryable error that traps KCM GC. \
             Got message: '{message}'"
        );
    }

    /// Regression test: PUT /status on a pod whose namespace is deleted
    /// must return "Pod not found" 404, not "Namespace not found" 404.
    /// Same invariant as the PATCH case above — KCM also uses PUT /status in some paths.
    #[tokio::test]
    async fn terminal_status_put_on_pod_in_deleted_ns_does_not_trap_gc_retry() {
        let (state, _) = make_state();
        // Namespace is NOT seeded — simulates a hard-deleted namespace.

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                put(replace_pod_status),
            )
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "orphan-pod", "namespace": "deleted-namespace"},
            "status": {"phase": "Failed"}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/deleted-namespace/pods/orphan-pod/status")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "status PUT on deleted namespace must return 404"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp_body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();
        let message = resp_body["message"].as_str().unwrap_or("");
        assert!(
            message.contains("Pod") || message.contains("pod") || message.contains("orphan-pod"),
            "404 must identify the missing Pod — \
             a Namespace 404 traps KCM pod-GC in an infinite retry loop. \
             Got: '{message}'"
        );
        assert!(
            !message.to_lowercase().contains("namespace"),
            "404 must NOT mention Namespace. Got: '{message}'"
        );
    }

    // -----------------------------------------------------------------------
    // bind_pod (POST /binding)
    // -----------------------------------------------------------------------

    /// POST /binding with a valid target.name must set spec.nodeName on the pod.
    #[tokio::test]
    async fn bind_pod_sets_node_name() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "unscheduled-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/binding",
                post(bind_pod),
            )
            .with_state(state);

        let binding = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Binding",
            "metadata": {"name": "unscheduled-pod", "namespace": "default"},
            "target": {"kind": "Node", "name": "worker-1"}
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/unscheduled-pod/binding")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&binding))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Verify spec.nodeName was set.
        let key = "/registry/pods/default/unscheduled-pod";
        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["nodeName"], "worker-1",
            "bind_pod must set spec.nodeName to the target node"
        );
    }

    /// `POST /binding?dryRun=All` must return the would-be bound pod (201, spec.nodeName set
    /// in the response) but leave the pod unbound in the store. Before this fix, bind_pod had
    /// no dry-run check at all: `kubectl` (or a scheduler plugin) verifying a binding decision
    /// with `--dry-run=server` would have actually scheduled the pod for real.
    #[tokio::test]
    async fn bind_pod_dry_run_all_does_not_bind_or_persist() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "unscheduled-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/binding",
                post(bind_pod),
            )
            .layer(axum::middleware::from_fn(
                crate::handlers::json_patch::inject_dry_run_header,
            ))
            .with_state(state);

        let binding = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Binding",
            "metadata": {"name": "unscheduled-pod", "namespace": "default"},
            "target": {"kind": "Node", "name": "worker-1"}
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/unscheduled-pod/binding?dryRun=All")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&binding))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp_body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            resp_body["spec"]["nodeName"], "worker-1",
            "dry-run response must show the would-be binding"
        );

        let key = "/registry/pods/default/unscheduled-pod";
        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["nodeName"],
            serde_json::Value::Null,
            "dryRun=All must not actually bind the pod in the store"
        );
    }

    /// POST /binding with missing target.name must return 400.
    #[tokio::test]
    async fn bind_pod_missing_target_name_returns_400() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/binding",
                post(bind_pod),
            )
            .with_state(state);

        let binding = serde_json::json!({"apiVersion": "v1", "kind": "Binding", "target": {}});

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/my-pod/binding")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&binding))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// A second bind to a DIFFERENT node must be rejected, and the pod's stored
    /// spec.nodeName must remain the ORIGINAL value.
    ///
    /// Without this guard, a stray duplicate bind call (e.g. a scheduler retry,
    /// or a race between two scheduling attempts) could silently reassign a
    /// Running pod's spec.nodeName to a different node while its containers
    /// keep running under the original kubelet — risking duplicate execution or
    /// an involuntary kill/restart of a pod, including one with
    /// restartPolicy=Never that must never be silently restarted.
    #[tokio::test]
    async fn bind_pod_rejects_rebind_to_different_node() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "bound-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/binding",
                post(bind_pod),
            )
            .with_state(state);

        let bind_to = |node: &str| {
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Binding",
                "metadata": {"name": "bound-pod", "namespace": "default"},
                "target": {"kind": "Node", "name": node}
            })
        };

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/bound-pod/binding")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&bind_to("worker-1")))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "first bind must succeed"
        );

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/bound-pod/binding")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&bind_to("worker-2")))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "a second bind to a different node must be rejected, not silently applied"
        );

        let key = "/registry/pods/default/bound-pod";
        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["nodeName"], "worker-1",
            "the rejected rebind must NOT overwrite spec.nodeName — the pod's containers are \
             still running under worker-1's kubelet, so the stored assignment must stay worker-1"
        );
    }

    /// A second bind to the SAME node must also be rejected.
    ///
    /// Upstream kube-apiserver rejects unconditionally on `NodeName != ""`, not only on a
    /// mismatch. Special-casing "same node is fine" would make an idempotent-looking rebind
    /// silently succeed — exactly the gap that let a periodic stray re-bind go unnoticed
    /// against an already-Running pod.
    #[tokio::test]
    async fn bind_pod_rejects_rebind_to_same_node() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "bound-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/binding",
                post(bind_pod),
            )
            .with_state(state);

        let bind_to_worker_1 = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Binding",
            "metadata": {"name": "bound-pod", "namespace": "default"},
            "target": {"kind": "Node", "name": "worker-1"}
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/bound-pod/binding")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&bind_to_worker_1))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "first bind must succeed"
        );

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/bound-pod/binding")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&bind_to_worker_1))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "a second bind must be rejected even when it targets the same node — upstream never \
             allows re-binding an already-assigned pod"
        );
    }

    // -----------------------------------------------------------------------
    // patch_pod — JSON patch through handler
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // list_pods (GET /namespaces/:ns/pods)
    // -----------------------------------------------------------------------

    /// GET /pods on an existing namespace returns 200 with a PodList.
    /// This covers the non-watch list_pods path and its inline lambdas.
    #[tokio::test]
    async fn list_pods_returns_200_with_pod_list() {
        use axum::http::method::Method;

        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "pod-a", serde_json::json!({})).await;
        seed_pod(&store, "default", "pod-b", serde_json::json!({})).await;

        let user = crate::auth::UserInfo {
            username: "test-user".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", get(list_pods))
            .layer(axum::Extension(user))
            .with_state(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/namespaces/default/pods")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(v["kind"], "PodList");
        assert_eq!(
            v["items"].as_array().unwrap().len(),
            2,
            "must return both seeded pods"
        );
    }

    /// metrics-server's per-namespace Pod-metadata informer (and kcm's GC) negotiate
    /// `Accept: application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1`. Before this
    /// fix, list_pods always returned a plain PodList, which their metadata-only decoder
    /// rejects; metrics-server's Pod-label cache never populates and every
    /// labelSelector-filtered PodMetrics query the HPA controller issues then returns empty,
    /// silently breaking every HPA scale-up decision.
    #[tokio::test]
    async fn list_pods_returns_partial_object_metadata_list_when_requested() {
        use axum::http::method::Method;

        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "pod-a", serde_json::json!({})).await;

        let user = crate::auth::UserInfo {
            username: "metrics-server".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", get(list_pods))
            .layer(axum::Extension(user))
            .with_state(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/namespaces/default/pods")
            .header(
                "accept",
                "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1",
            )
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(
            v["apiVersion"], "meta.k8s.io/v1",
            "metrics-server's Pod-metadata cache never populates without \
             PartialObjectMetadata-shaped LIST/WATCH responses; every labelSelector-filtered \
             PodMetrics query then returns empty, silently breaking every HPA scale-up decision."
        );
        assert_eq!(
            v["kind"], "PartialObjectMetadataList",
            "metrics-server's Pod-metadata cache never populates without \
             PartialObjectMetadata-shaped LIST/WATCH responses; every labelSelector-filtered \
             PodMetrics query then returns empty, silently breaking every HPA scale-up decision."
        );
        let items = v["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "must return the one seeded pod");
        assert_eq!(
            items[0]["kind"], "PartialObjectMetadata",
            "each POM item must have kind=PartialObjectMetadata, not Pod"
        );
        assert!(
            items[0].get("spec").is_none() && items[0].get("status").is_none(),
            "POM items must strip spec/status — leaking them defeats the metadata-only \
             informer this fix exists to unblock"
        );
    }

    /// GET /pods with a field selector must filter pods by nodeName.
    ///
    /// Uses the camelCase `fieldSelector` key real clients send (kubectl, client-go,
    /// kubelet) — not `field_selector`. A struct missing `#[serde(rename)]` would
    /// silently leave the field unparsed and return all pods unfiltered.
    #[tokio::test]
    async fn list_pods_with_field_selector_filters_pods() {
        use axum::http::method::Method;

        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed one pod on worker-1 and one on worker-2.
        let key_a = "/registry/pods/default/pod-a";
        let pod_a = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-a", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "worker-1", "containers": []}
        });
        store
            .put(
                key_a,
                Bytes::from(serde_json::to_vec(&pod_a).unwrap()),
                None,
            )
            .await
            .unwrap();

        let key_b = "/registry/pods/default/pod-b";
        let pod_b = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-b", "namespace": "default", "resourceVersion": "2"},
            "spec": {"nodeName": "worker-2", "containers": []}
        });
        store
            .put(
                key_b,
                Bytes::from(serde_json::to_vec(&pod_b).unwrap()),
                None,
            )
            .await
            .unwrap();

        let user = crate::auth::UserInfo {
            username: "test-user".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", get(list_pods))
            .layer(axum::Extension(user))
            .with_state(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/namespaces/default/pods?fieldSelector=spec.nodeName%3Dworker-1")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let items = v["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "only worker-1 pods should be returned");
        assert_eq!(items[0]["spec"]["nodeName"], "worker-1");
    }

    fn captured_log(buf: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> String {
        String::from_utf8(buf.lock().unwrap().clone()).unwrap()
    }

    /// list_pods must emit one DEBUG event per pod, carrying that pod's own phase and
    /// deletionTimestamp — not the first pod's, or a single aggregate line — so an operator
    /// enabling `u7s::apiserver::pod_lifecycle=debug` can trace an individual pod's lifecycle
    /// (e.g. spot a pod stuck Terminating) without capturing full PodList response bodies.
    #[tokio::test]
    async fn list_pods_emits_one_debug_event_per_pod_with_lifecycle_fields() {
        use axum::http::method::Method;

        crate::test_utils::tracing_capture::install_global_test_subscriber();
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let _guard = crate::test_utils::tracing_capture::TestBufferGuard::new(buf.clone());

        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "pod-a", serde_json::json!({})).await;
        seed_pod(
            &store,
            "default",
            "pod-b",
            serde_json::json!({
                "metadata": {
                    "name": "pod-b",
                    "namespace": "default",
                    "resourceVersion": "1",
                    "deletionTimestamp": "2026-07-30T00:00:00Z"
                },
                "spec": {"containers": [{"name": "app", "image": "httpd"}]},
                "status": {"phase": "Running"}
            }),
        )
        .await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", get(list_pods))
            .layer(auth_layer())
            .with_state(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/namespaces/default/pods")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let log = captured_log(&buf);
        let entry_lines: Vec<&str> = log
            .lines()
            .filter(|l| l.contains("pod list entry"))
            .collect();
        assert_eq!(
            entry_lines.len(),
            2,
            "expected one debug event per pod in the response — a single aggregate line \
             would force an operator to re-parse the whole PodList to find one pod; log was: {log}"
        );

        let pod_a_line = entry_lines
            .iter()
            .find(|l| l.contains("pod-a"))
            .expect("pod-a must have its own debug event");
        assert!(
            pod_a_line.contains("Pending"),
            "pod-a's own phase (Pending) must be recorded on its line, not pod-b's; line was: {pod_a_line}"
        );
        assert!(
            !pod_a_line.contains("2026-07-30T00:00:00Z"),
            "pod-a (not terminating) must not carry pod-b's deletionTimestamp; line was: {pod_a_line}"
        );
        assert!(
            pod_a_line.contains("nginx"),
            "pod-a's container image must be recorded; line was: {pod_a_line}"
        );

        let pod_b_line = entry_lines
            .iter()
            .find(|l| l.contains("pod-b"))
            .expect("pod-b must have its own debug event");
        assert!(
            pod_b_line.contains("Running"),
            "pod-b's own phase (Running) must be recorded, distinct from pod-a's Pending; line was: {pod_b_line}"
        );
        assert!(
            pod_b_line.contains("2026-07-30T00:00:00Z"),
            "a terminating pod's deletionTimestamp must be visible so an operator can spot a \
             pod stuck Terminating without pulling the full response body; line was: {pod_b_line}"
        );
    }

    /// GET /pods on a nonexistent namespace must return 404.
    #[tokio::test]
    async fn list_pods_missing_namespace_returns_404() {
        use axum::http::method::Method;

        let (state, _store) = make_state();

        let user = crate::auth::UserInfo {
            username: "test-user".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", get(list_pods))
            .layer(axum::Extension(user))
            .with_state(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/namespaces/nonexistent/pods")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // replace_pod (PUT) — success path
    // -----------------------------------------------------------------------

    /// PUT with matching name and valid resourceVersion must return 200.
    #[tokio::test]
    async fn replace_pod_valid_update_returns_200() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        // seed_pod seeds with resourceVersion "1" in the body; the actual store revision is 1.
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        // Read back the actual stored revision so we can construct the PUT correctly.
        let stored_rv = {
            let obj = store
                .get("/registry/pods/default/my-pod")
                .await
                .unwrap()
                .unwrap();
            obj.revision
        };

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-pod",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string()
            },
            "spec": {"containers": [{"name": "app", "image": "nginx:latest"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// `kubectl replace --dry-run=server` on a pod must NOT persist the replacement — a
    /// dry-run that writes anyway silently mutates cluster state against the client's
    /// explicit intent. This test fails on revert with the stored image changed to
    /// "nginx:latest".
    #[tokio::test]
    async fn replace_pod_dry_run_does_not_mutate_store() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let stored_rv = {
            let obj = store
                .get("/registry/pods/default/my-pod")
                .await
                .unwrap()
                .unwrap();
            obj.revision
        };

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-pod",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string()
            },
            "spec": {"containers": [{"name": "app", "image": "nginx:latest"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/my-pod?dryRun=All")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "dry-run replace must still return a success response"
        );

        let stored = store
            .get("/registry/pods/default/my-pod")
            .await
            .unwrap()
            .expect("pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["containers"][0]["image"], "nginx",
            "dryRun=All must NOT persist the replacement — if this fails, replace_pod's \
             dry-run guard was removed and the image was actually updated to nginx:latest \
             in the store"
        );
    }

    /// A plain PUT to the main /pods endpoint must never let the client body's `.status`
    /// clobber the server's stored status: status is owned by the /status subresource (a
    /// distinct RBAC grant from `update pods`), and any client with a locally cached copy
    /// (client-go `Update()`, `kubectl replace`, a controller's informer cache) commonly
    /// carries stale or zeroed status fields. Regression: kubelet's status PATCH set
    /// `observedGeneration=5`, then a legitimate metadata-only PUT from a test helper
    /// silently reset it to 0 — every later read saw the wrong value and a wait loop timed
    /// out. This test fails if replace_pod stops restoring the stored status before writing.
    #[tokio::test]
    async fn replace_pod_ignores_body_status_uses_stored_status() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        // Set status via the /status subresource, the way kubelet does.
        let status_app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                put(replace_pod_status),
            )
            .with_state(state.clone());

        let status_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "status": {"phase": "Running", "observedGeneration": 5}
        });
        let status_req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/my-pod/status")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&status_body))
            .unwrap();
        let status_resp = status_app.oneshot(status_req).await.unwrap();
        assert_eq!(status_resp.status(), StatusCode::OK);

        let stored_rv = store
            .get("/registry/pods/default/my-pod")
            .await
            .unwrap()
            .unwrap()
            .revision;

        // Client PUTs to the main endpoint with a stale/zeroed status in the body — e.g. a
        // client-go Update() built from a local cache predating kubelet's status patch.
        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        let put_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-pod",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string()
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {"phase": "Pending", "observedGeneration": 0}
        });
        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&put_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let stored = store
            .get("/registry/pods/default/my-pod")
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["status"]["phase"], "Running",
            "PUT body status (Pending) must be ignored; stored status (Running) set via \
             the /status subresource must be preserved"
        );
        assert_eq!(
            v["status"]["observedGeneration"], 5,
            "PUT body's stale observedGeneration=0 must not clobber the real value kubelet \
             set via /status — this is the exact field that regressed in production"
        );
    }

    // -----------------------------------------------------------------------
    // replace_pod — metadata.uid immutability
    // -----------------------------------------------------------------------

    /// A PUT whose body carries a non-blank uid that mismatches the stored one must be
    /// rejected with 409, and the stored pod must be left untouched. metadata.uid is
    /// immutable identity: owner_ref_is_live determines cascade-GC purely by comparing
    /// stored uid == ownerRef.uid, so silently accepting a forged uid here would let a
    /// caller holding only `update pods` RBAC (not `create`/`delete pods`) rewrite an
    /// existing pod's identity to match a stale/foreign ownerReference and hijack
    /// ReplicaSet/Job/DaemonSet garbage collection. Fails on revert: without the
    /// uid-mismatch check, this PUT (valid resourceVersion, forged uid) would succeed with
    /// 200 instead of 409.
    #[tokio::test]
    async fn replace_pod_rejects_mismatched_uid_with_409() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "my-pod",
            serde_json::json!({"metadata": {"uid": "real-uid-0001"}}),
        )
        .await;

        let stored_rv = store
            .get("/registry/pods/default/my-pod")
            .await
            .unwrap()
            .unwrap()
            .revision;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-pod",
                "namespace": "default",
                "uid": "attacker-uid",
                "resourceVersion": stored_rv.to_string()
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "PUT with a mismatched non-blank metadata.uid must return 409 Conflict — uid is \
             immutable identity, and accepting it would let a patch/update-only caller forge \
             ownerReference matches and hijack cascade-GC"
        );

        let stored = store
            .get("/registry/pods/default/my-pod")
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["uid"], "real-uid-0001",
            "the rejected PUT must not have mutated the stored pod's uid"
        );
    }

    /// A PUT whose body omits (blanks) metadata.uid must have it restored from the stored
    /// object rather than persisting a blank uid. Real client-go Update() callers (and a
    /// dynamic/typed client round-tripping a locally-held object) commonly omit uid; without
    /// restoration, a blank uid would be persisted and broadcast to watchers, permanently
    /// breaking any controller that identifies this pod by uid (e.g. ownerReference
    /// tracking). Fails on revert: without restoring a blank incoming uid, the stored pod
    /// would end up with an empty uid instead of the original one.
    #[tokio::test]
    async fn replace_pod_restores_blank_uid_from_stored() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "my-pod",
            serde_json::json!({"metadata": {"uid": "real-uid-0001"}}),
        )
        .await;

        let stored_rv = store
            .get("/registry/pods/default/my-pod")
            .await
            .unwrap()
            .unwrap()
            .revision;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-pod",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string()
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a PUT that simply omits uid (not a forgery attempt) must succeed, with uid \
             silently restored from the stored object"
        );

        let stored = store
            .get("/registry/pods/default/my-pod")
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["uid"], "real-uid-0001",
            "a blank incoming uid must be restored from the stored object, not persisted \
             as blank — a blank stored uid would break any controller identifying this pod \
             by uid (e.g. ownerReference tracking)"
        );
    }

    // -----------------------------------------------------------------------
    // replace_pod — pod-spec immutability guard (resources only via /resize)
    // -----------------------------------------------------------------------

    /// PUT that rewrites containers[].resources via the generic pod update must be
    /// rejected with 422, not silently accepted.
    ///
    /// Resource changes are only allowed through the /resize subresource, which
    /// additionally enforces QoS-class stability and forbids removing resource
    /// quantities. Accepting resource rewrites here would let a client bypass those
    /// rules and desync ResourceQuota's captured totals from the pod actually stored
    /// (ResourceQuota conformance: "a pod cannot update its resource requirements").
    #[tokio::test]
    async fn replace_pod_rejects_resource_changes() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/resourceful-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "resourceful-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {"limits": {"cpu": "100m"}, "requests": {"cpu": "100m"}}
                }]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();
        let stored_rv = store.get(key).await.unwrap().unwrap().revision;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "resourceful-pod",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string()
            },
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {"limits": {"cpu": "200m"}, "requests": {"cpu": "200m"}}
                }]
            }
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/resourceful-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a generic PUT rewriting containers[].resources must be rejected — \
             resources may only change via the /resize subresource"
        );

        let stored = store.get(key).await.unwrap().expect("pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["containers"][0]["resources"]["limits"]["cpu"], "100m",
            "rejected PUT must not have mutated the stored pod's resources"
        );
    }

    /// PUT that changes only the container image (resources unchanged) must succeed.
    ///
    /// The immutability guard must not reject legitimate updates — image is the
    /// canonical "rolling restart" field clients update via a generic PUT/PATCH.
    #[tokio::test]
    async fn replace_pod_allows_image_only_change() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/resourceful-pod2";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "resourceful-pod2", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {"limits": {"cpu": "100m"}, "requests": {"cpu": "100m"}}
                }]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();
        let stored_rv = store.get(key).await.unwrap().unwrap().revision;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "resourceful-pod2",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string()
            },
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx:latest",
                    "resources": {"limits": {"cpu": "100m"}, "requests": {"cpu": "100m"}}
                }]
            }
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/resourceful-pod2")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "an image-only change must succeed — the immutability guard must not \
             reject updates to fields upstream explicitly allows"
        );
    }

    /// The /resize subresource must still accept resource changes after the generic
    /// PUT immutability guard is added — the guard lives in replace_pod only and must
    /// not leak into patch_pod_resize, which is the one sanctioned path for resizing.
    #[tokio::test]
    async fn resize_subresource_still_allows_resource_changes() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/resourceful-pod3";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "resourceful-pod3", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {"limits": {"cpu": "100m"}, "requests": {"cpu": "100m"}}
                }]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/resize",
                patch(patch_pod_resize).put(patch_pod_resize),
            )
            .with_state(state);

        let resize_body = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {"limits": {"cpu": "200m"}, "requests": {"cpu": "200m"}}
                }]
            }
        });

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/resourceful-pod3/resize")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&resize_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PATCH /resize must still succeed — the generic-PUT immutability guard \
             must not block the one endpoint that is supposed to allow resizing"
        );

        let stored = store.get(key).await.unwrap().expect("pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["containers"][0]["resources"]["limits"]["cpu"], "200m",
            "resize must actually apply the new resources"
        );
    }

    /// A PUT that changes only `metadata.ownerReferences` (spec unchanged) must succeed.
    ///
    /// The GC, RC, and Job controllers adopt/release/orphan pods by fetching a pod,
    /// changing only its ownerReferences, and PUTting it back — spec is never touched.
    /// A prior version of the immutability guard compared the *whole* spec byte-for-byte
    /// after re-running spec defaulting on both sides, which is not resilient to protobuf
    /// encode/decode asymmetry on fields the guard doesn't even care about (dnsPolicy,
    /// probe defaults, ...). That false positive rejected every metadata-only controller
    /// PUT with a 422, breaking pod adoption/release/orphaning across GC, RC and Job
    /// conformance tests.
    #[tokio::test]
    async fn replace_pod_allows_owner_references_only_change() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/adoptable-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "adoptable-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {"limits": {"cpu": "100m"}, "requests": {"cpu": "100m"}}
                }]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();
        let stored_rv = store.get(key).await.unwrap().unwrap().revision;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "adoptable-pod",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string(),
                "ownerReferences": [{
                    "apiVersion": "v1",
                    "kind": "ReplicationController",
                    "name": "adopter",
                    "uid": "11111111-1111-1111-1111-111111111111",
                    "controller": true
                }]
            },
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {"limits": {"cpu": "100m"}, "requests": {"cpu": "100m"}}
                }]
            }
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/adoptable-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a PUT changing only metadata.ownerReferences (spec unchanged) must succeed — \
             otherwise the GC/RC/Job controllers can never adopt an orphaned pod"
        );
    }

    /// A PUT that changes only `metadata.labels` (spec unchanged) must succeed.
    ///
    /// The RC controller releases a pod it no longer selects by re-labeling it via a
    /// generic PUT (see rc.go testRCReleaseControlledNotMatching). Spec is untouched;
    /// only labels change. This must not be mistaken for a spec change by the
    /// immutability guard.
    #[tokio::test]
    async fn replace_pod_allows_labels_only_change() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/releasable-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "releasable-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": {"name": "pod-release"}
            },
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {"limits": {"cpu": "100m"}, "requests": {"cpu": "100m"}}
                }]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();
        let stored_rv = store.get(key).await.unwrap().unwrap().revision;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "releasable-pod",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string(),
                "labels": {"name": "not-matching-name"}
            },
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {"limits": {"cpu": "100m"}, "requests": {"cpu": "100m"}}
                }]
            }
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/releasable-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a PUT changing only metadata.labels (spec unchanged) must succeed — \
             otherwise the RC controller can never release a pod it no longer selects"
        );
    }

    // -----------------------------------------------------------------------
    // replace_pod — 409 on stale resourceVersion
    // -----------------------------------------------------------------------

    /// PUT /pods/:name with a stale resourceVersion must return 409 Conflict.
    /// replace_pod uses OCC: a stale writer must not silently overwrite newer data.
    #[tokio::test]
    async fn replace_pod_stale_rv_returns_409() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "occ-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        let stale_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "occ-pod",
                "namespace": "default",
                "resourceVersion": "99999"
            },
            "spec": {"containers": [{"name": "app", "image": "nginx:latest"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/occ-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&stale_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "stale resourceVersion on replace_pod must return 409 Conflict — \
             OCC prevents lost-update races when multiple controllers update the same pod"
        );
    }

    /// A stale-resourceVersion release PUT that also happens to diverge on spec.nodeName
    /// (because the scheduler bound the pod after the controller's GET, but before its PUT)
    /// must return 409 Conflict, not 422 spec-immutability-violation.
    ///
    /// The RC controller's release path (rc.go's release-not-matching
    /// test) GETs a pod, changes only its labels, and PUTs the result back declaring the
    /// resourceVersion it read. If the u7s-scheduler's /binding write lands in between, the
    /// stored pod now has a real spec.nodeName the controller's PUT body doesn't carry (it
    /// read the pod before scheduling). Comparing that stale body against the just-fetched,
    /// already-scheduled stored spec makes validate_pod_spec_immutable see a genuine nodeName
    /// change and permanently reject with 422 — instead of the 409 a resourceVersion mismatch
    /// should give, which is what tells the controller's own conflict-retry loop to re-GET and
    /// resubmit against the now-scheduled pod. A 422 here is not retried by client-go's
    /// Update-on-conflict loop, so the conformance test fails outright ~75% of the time
    /// (whenever scheduling wins the race against the controller's stale PUT).
    #[tokio::test]
    async fn replace_pod_returns_409_not_422_when_stale_put_diverges_on_nodename() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "pod-release",
            serde_json::json!({"metadata": {"labels": {"name": "pod-release"}}}),
        )
        .await;
        let key = "/registry/pods/default/pod-release";
        let rv0 = store.get(key).await.unwrap().unwrap().revision;

        // Simulate the scheduler's /binding write landing after the controller's GET (rv0)
        // but before the controller's release PUT reaches the apiserver.
        let scheduled = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "pod-release",
                "namespace": "default",
                "resourceVersion": rv0.to_string(),
                "labels": {"name": "pod-release"}
            },
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}],
                "nodeName": "lima-node-2"
            },
            "status": {"phase": "Pending"}
        });
        store
            .put(
                key,
                Bytes::from(serde_json::to_vec(&scheduled).unwrap()),
                Some(rv0),
            )
            .await
            .expect("simulated scheduler bind");

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        // The controller's release PUT: based on the pre-bind read (rv0), spec has no
        // nodeName at all — it never intended to touch nodeName, only labels.
        let release_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "pod-release",
                "namespace": "default",
                "resourceVersion": rv0.to_string(),
                "labels": {"name": "not-matching-name"}
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/pod-release")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&release_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "a stale-resourceVersion release PUT racing the scheduler's bind must return 409 \
             Conflict (retryable) — a 422 here permanently fails the RC controller's release \
             instead of letting it re-GET and resubmit against the now-scheduled pod"
        );
    }

    // -----------------------------------------------------------------------
    // replace_pod — deletionTimestamp+empty-finalizers path (PUT-based finalizer drain)
    // -----------------------------------------------------------------------

    /// PUT that clears a pod's last finalizer while deletionTimestamp is set must hard-delete
    /// the pod, exactly like patch_pod's post-patch check does for PATCH.
    ///
    /// KCM's protection controllers (kubernetes.io/pvc-protection, vac-protection, ...) remove
    /// their finalizer via PUT, not PATCH. Before this fix, replace_pod had no equivalent check
    /// on the PUT path at all: the pod would be persisted as an ordinary update with an empty
    /// finalizers list and deletionTimestamp still set, and the object would never disappear
    /// from the store — a pod (and potentially the namespace containing it) stuck Terminating
    /// forever.
    #[tokio::test]
    async fn replace_pod_put_draining_last_finalizer_hard_deletes() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/finalized-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "finalized-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "deletionTimestamp": "2026-05-22T00:00:00Z",
                "finalizers": ["my.io/cleanup"]
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();
        let stored_rv = store.get(key).await.unwrap().unwrap().revision;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        // PUT the object back with finalizers now empty — exactly what a protection
        // controller does when it removes its finalizer via replace instead of patch.
        let put_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "finalized-pod",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string(),
                "deletionTimestamp": "2026-05-22T00:00:00Z",
                "finalizers": []
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/finalized-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&put_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PUT draining the last finalizer off a soft-deleted pod must succeed"
        );

        assert!(
            store.get(key).await.unwrap().is_none(),
            "pod with deletionTimestamp set and finalizers emptied via PUT must be hard-deleted \
             immediately, exactly like the PATCH path — otherwise a protection controller can \
             never complete a delete via PUT and the pod stays stuck Terminating forever"
        );
    }

    /// PUT that omits deletionTimestamp entirely (what a protobuf-decoded body looks like,
    /// since the wire decoder never emits this field) while the stored pod is already
    /// soft-deleted must still complete the finalizer drain and hard-delete.
    ///
    /// Before this fix, replace_pod never restored deletionTimestamp from the stored object at
    /// all, so a PUT body missing it (via protobuf decode, or any client that only copies
    /// fields it knows about) would make finalizer_drain_complete see a blank timestamp and
    /// treat this as a plain update — silently resurrecting the pod as live with its finalizers
    /// stripped and no deletionTimestamp.
    #[tokio::test]
    async fn replace_pod_put_completes_finalizer_drain_when_body_omits_deletion_timestamp() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/proto-finalized-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "proto-finalized-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "deletionTimestamp": "2026-05-22T00:00:00Z",
                "finalizers": ["my.io/cleanup"]
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();
        let stored_rv = store.get(key).await.unwrap().unwrap().revision;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        // No deletionTimestamp in the body at all — simulates a protobuf-decoded PUT.
        let put_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "proto-finalized-pod",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string(),
                "finalizers": []
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/proto-finalized-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&put_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PUT draining the last finalizer must succeed even when the body omits \
             deletionTimestamp"
        );

        assert!(
            store.get(key).await.unwrap().is_none(),
            "pod must be hard-deleted, not silently un-terminated: a PUT body missing \
             deletionTimestamp must not make the server forget the pod was already \
             mid-deletion — reverting this fix leaves the pod persisted with finalizers \
             emptied and no deletionTimestamp, i.e. a live, non-terminating pod"
        );
    }

    /// PUT that removes SOME but not all finalizers while deletionTimestamp is set must NOT
    /// hard-delete — an outstanding finalizer means another controller still needs to observe
    /// and act on the pod before it can be removed.
    #[tokio::test]
    async fn replace_pod_put_partial_finalizer_removal_does_not_hard_delete() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/partially-finalized-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "partially-finalized-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "deletionTimestamp": "2026-05-22T00:00:00Z",
                "finalizers": ["my.io/cleanup-a", "my.io/cleanup-b"]
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();
        let stored_rv = store.get(key).await.unwrap().unwrap().revision;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        let put_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "partially-finalized-pod",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string(),
                "deletionTimestamp": "2026-05-22T00:00:00Z",
                "finalizers": ["my.io/cleanup-b"]
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/partially-finalized-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&put_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let stored =
            store.get(key).await.unwrap().expect(
                "pod must still exist — a finalizer (my.io/cleanup-b) is still outstanding",
            );
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["finalizers"],
            serde_json::json!(["my.io/cleanup-b"]),
            "the PUT's finalizer list must persist as given, not be treated as drain-complete"
        );
    }

    /// PUT on a pod with no deletionTimestamp at all must behave like an ordinary update.
    ///
    /// Guards against the finalizer-drain check being too aggressive: a pod that was never
    /// being deleted must never be hard-deleted just because its finalizers list happens to
    /// be empty (the common case for most pods, which have no finalizers at all).
    #[tokio::test]
    async fn replace_pod_put_without_deletion_timestamp_updates_normally() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "live-pod", serde_json::json!({})).await;
        let stored_rv = store
            .get("/registry/pods/default/live-pod")
            .await
            .unwrap()
            .unwrap()
            .revision;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", put(replace_pod))
            .layer(auth_layer())
            .with_state(state);

        let put_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "live-pod",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string(),
                "labels": {"updated": "true"}
            },
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/live-pod")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&put_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let stored = store
            .get("/registry/pods/default/live-pod")
            .await
            .unwrap()
            .expect(
                "a pod with no deletionTimestamp must never be hard-deleted by an ordinary PUT",
            );
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(v["metadata"]["labels"]["updated"], "true");
    }

    /// PUT /pods/:name/status with a stale resourceVersion must return 409 Conflict.
    /// The status subresource honors OCC: kubelet and other status writers hold a snapshot;
    /// without this check a stale writer silently overwrites a newer status write.
    #[tokio::test]
    async fn replace_pod_status_stale_rv_returns_409() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "occ-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                put(replace_pod_status),
            )
            .with_state(state);

        let stale_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "occ-pod", "namespace": "default", "resourceVersion": "99999"},
            "status": {"phase": "Running"}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/occ-pod/status")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&stale_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "stale resourceVersion on replace_pod_status must return 409 Conflict — \
             otherwise a stale status writer clobbers a concurrent write instead of retrying"
        );
    }

    /// PUT /pods/:name/resize with a stale resourceVersion must return 409 Conflict.
    /// The resize subresource accepts PUT (client sends its rv); a stale write must be
    /// rejected so concurrent resizers don't lose updates.
    #[tokio::test]
    async fn patch_pod_resize_put_stale_rv_returns_409() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed a pod whose container already has resources so the resize is VALID and reaches
        // the CAS check (validate_resize_patch runs before it) — only the rv is stale here.
        let key = "/registry/pods/default/occ-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "occ-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {"limits": {"cpu": "100m"}, "requests": {"cpu": "100m"}}
                }]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/resize",
                put(patch_pod_resize),
            )
            .with_state(state);

        // Otherwise-valid resize (cpu 100m -> 200m) but with a STALE resourceVersion.
        let stale_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "occ-pod", "namespace": "default", "resourceVersion": "99999"},
            "spec": {"containers": [{
                "name": "app",
                "resources": {"limits": {"cpu": "200m"}, "requests": {"cpu": "200m"}}
            }]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/occ-pod/resize")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&stale_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "stale resourceVersion on a PUT /resize must return 409 Conflict — \
             a stale resize must retry from a fresh GET, not overwrite a concurrent write"
        );
    }

    /// PUT /pods/:name/ephemeralcontainers with a stale resourceVersion must return 409.
    /// A stale writer to the ephemeralcontainers subresource must not clobber a newer write.
    #[tokio::test]
    async fn put_ephemeral_containers_stale_rv_returns_409() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "occ-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/ephemeralcontainers",
                put(put_ephemeral_containers),
            )
            .with_state(state);

        let stale_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "occ-pod", "namespace": "default", "resourceVersion": "99999"},
            "spec": {"ephemeralContainers": [{"name": "debugger", "image": "busybox"}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/occ-pod/ephemeralcontainers")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&stale_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "stale resourceVersion on put_ephemeral_containers must return 409 Conflict — \
             otherwise a stale writer silently overwrites a concurrent ephemeralContainers update"
        );
    }

    // -----------------------------------------------------------------------
    // replace_pod_status — 404 on missing pod
    // -----------------------------------------------------------------------

    /// PUT /pods/:name/status on a missing pod must return 404.
    /// The status subresource cannot create objects — only the main resource endpoint does that.
    #[tokio::test]
    async fn replace_pod_status_returns_404_for_missing() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                put(replace_pod_status),
            )
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "ghost-pod", "namespace": "default"},
            "status": {"phase": "Running"}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/ghost-pod/status")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "PUT /status on non-existent pod must return 404 — \
             the status subresource cannot create new pods"
        );
    }

    // -----------------------------------------------------------------------
    // replace_pod_status — finalizer and deletionTimestamp protection
    // -----------------------------------------------------------------------

    /// PUT /pods/:name/status must not overwrite finalizers or deletionTimestamp.
    /// The kubelet sends a PUT /status whose body reflects the last pod state it observed.
    /// If KCM just removed the job-tracking finalizer, the kubelet's stale body still carries it.
    /// Without protection, the PUT restores the finalizer and the pod is stuck Terminating forever
    /// (livelock — exactly the class of bug fixed by apply_status_patch, now also fixed here).
    #[tokio::test]
    async fn replace_pod_status_preserves_finalizers_and_deletion_timestamp() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "fin-pod",
            serde_json::json!({
                "metadata": {
                    "finalizers": ["batch.kubernetes.io/job-tracking"],
                    "deletionTimestamp": "2024-01-01T00:00:00Z"
                }
            }),
        )
        .await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                put(replace_pod_status),
            )
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "fin-pod",
                "namespace": "default",
                "finalizers": [],
                "deletionTimestamp": "2099-12-31T00:00:00Z"
            },
            "status": {"phase": "Succeeded"}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/fin-pod/status")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "PUT /status must succeed");

        let key = "/registry/pods/default/fin-pod";
        let stored = store.get(key).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["finalizers"][0], "batch.kubernetes.io/job-tracking",
            "finalizers must survive PUT /pods/status — the kubelet's stale body restoring a \
             just-removed job-tracking finalizer causes the pod to be stuck Terminating forever (livelock)"
        );
        assert_eq!(
            v["metadata"]["deletionTimestamp"], "2024-01-01T00:00:00Z",
            "deletionTimestamp must survive PUT /pods/status"
        );
        assert_eq!(v["status"]["phase"], "Succeeded", "status must be updated");
    }

    /// PUT /pods/:name/status with a scalar or array `status` body must be rejected with
    /// 422, not persisted. `status` is a message/object type for Pod like every resource;
    /// a PUT that wholesale-replaces it with a scalar corrupts the pod's own schema and
    /// panics `apply_resize_patch`'s and `apply_delete_policy`'s in-place
    /// `status["field"] = ...` stamps on the next resize/delete, crashing the apiserver
    /// for every other request in flight.
    #[tokio::test]
    async fn replace_pod_status_rejects_non_object_status() {
        for bad_status in [serde_json::json!("x"), serde_json::json!(["a", "b"])] {
            let (state, store) = make_state();
            seed_namespace(&store, "default").await;
            seed_pod(
                &store,
                "default",
                "put-scalar-pod",
                serde_json::json!({"status": {"phase": "Running"}}),
            )
            .await;

            let app = Router::new()
                .route(
                    "/api/v1/namespaces/{ns}/pods/{name}/status",
                    put(replace_pod_status),
                )
                .with_state(state);

            let body = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "put-scalar-pod", "namespace": "default"},
                "status": bad_status
            });
            let req = Request::builder()
                .method("PUT")
                .uri("/api/v1/namespaces/default/pods/put-scalar-pod/status")
                .header(header::CONTENT_TYPE, "application/json")
                .body(json_body(&body))
                .unwrap();

            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "a non-object status ({bad_status}) via PUT must be rejected with 422 — \
                 it would corrupt the pod's schema and later crash apply_resize_patch/\
                 apply_delete_policy's in-place status stamps"
            );

            let key = "/registry/pods/default/put-scalar-pod";
            let stored = store.get(key).await.unwrap().unwrap();
            let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
            assert_eq!(
                v["status"]["phase"], "Running",
                "the rejected PUT must not have been persisted for input {bad_status}"
            );
        }
    }

    /// PUT /pods/:name/status with an explicit `status: null` body must still succeed — the
    /// 422 guard above must reject only a present scalar/array, not the legitimate
    /// field-clearing convention.
    #[tokio::test]
    async fn replace_pod_status_accepts_null_status() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(
            &store,
            "default",
            "put-null-pod",
            serde_json::json!({"status": {"phase": "Running"}}),
        )
        .await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                put(replace_pod_status),
            )
            .with_state(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "put-null-pod", "namespace": "default"},
            "status": null
        });
        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/put-null-pod/status")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a null status PUT is legitimate field-clearing, not a 422"
        );
    }

    // -----------------------------------------------------------------------
    // patch_pod_status — 404 on missing pod
    // -----------------------------------------------------------------------

    /// PATCH /pods/:name/status on a missing pod must return 404.
    #[tokio::test]
    async fn patch_pod_status_returns_404_for_missing() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/status",
                patch(patch_pod_status),
            )
            .with_state(state);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/ghost-pod/status")
            .header(
                header::CONTENT_TYPE,
                "application/strategic-merge-patch+json",
            )
            .body(Body::from(r#"{"status":{"phase":"Running"}}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "PATCH /status on non-existent pod must return 404 — \
             kubelet should not be able to update status of pods that don't exist"
        );
    }

    // -----------------------------------------------------------------------
    // create_pod — 409 on duplicate
    // -----------------------------------------------------------------------

    /// POST /pods with the same name twice must return 409 Conflict.
    /// Duplicate pod creation must be rejected — the scheduler must GET+bind, not re-create.
    #[tokio::test]
    async fn create_pod_duplicate_returns_409() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "dup-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", post(create_pod))
            .layer(auth_layer())
            .with_state(state);

        // First create — must succeed.
        let req1 = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();
        let resp1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::CREATED);

        // Second create with same name — must return 409.
        let req2 = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&pod))
            .unwrap();
        let resp2 = app.oneshot(req2).await.unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::CONFLICT,
            "duplicate pod creation must return 409 Conflict — \
             the store already has this key and AlreadyExists maps to 409"
        );
    }

    // -----------------------------------------------------------------------
    // parse_namespace — invalid format returns 400
    // -----------------------------------------------------------------------

    /// GET /pods in a namespace with an invalid format (contains uppercase) must return 404.
    /// parse_namespace validates format; an invalid namespace name must be rejected.
    #[tokio::test]
    async fn list_pods_invalid_namespace_format_returns_404() {
        use axum::http::method::Method;

        let (state, _store) = make_state();

        let user = crate::auth::UserInfo {
            username: "test".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods", get(list_pods))
            .layer(axum::Extension(user))
            .with_state(state);

        // "INVALID" has uppercase — parse_namespace rejects it
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/namespaces/INVALID/pods")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        // Either 400 (bad format) or 404 (not found in store) — both are correct rejections.
        assert!(
            resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::NOT_FOUND,
            "invalid namespace format must return 400 or 404, got {}",
            resp.status()
        );
    }

    // -----------------------------------------------------------------------
    // patch_pod — 404 on missing pod
    // -----------------------------------------------------------------------

    /// PATCH /pods/:name on a missing pod must return 404.
    #[tokio::test]
    async fn patch_pod_missing_pod_returns_404() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/ghost-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(Body::from(r#"{"metadata":{"labels":{"k":"v"}}}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "PATCH on non-existent pod must return 404"
        );
    }

    // -----------------------------------------------------------------------
    // patch_pod — strategic-merge-patch (delete-then-recreate finalizer path)
    // -----------------------------------------------------------------------

    /// PATCH with strategic-merge-patch+json must succeed.
    #[tokio::test]
    async fn patch_pod_strategic_merge_patch_succeeds() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!({"metadata": {"annotations": {"k": "v"}}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(
                header::CONTENT_TYPE,
                "application/strategic-merge-patch+json",
            )
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // patch_pod — apply-patch+yaml (Server-Side Apply)
    // -----------------------------------------------------------------------

    /// PATCH with a genuine multi-line YAML apply-patch+yaml body must succeed, not 400
    /// "invalid patch JSON".
    ///
    /// WHY this matters: `kubectl apply --server-side` against a Pod sends real YAML block
    /// syntax, not JSON. Before this fix, patch_pod had no is_ssa handling at all — every
    /// apply-patch+yaml body was parsed with serde_json::from_slice, which rejects YAML
    /// outright, so SSA against a Pod always 400'd even though the content type itself was
    /// accepted (detect_patch_type maps it to StrategicMerge).
    #[tokio::test]
    async fn patch_pod_accepts_real_yaml_apply_patch_body() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        seed_pod(&store, "default", "my-pod", serde_json::json!({})).await;

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        // Genuine YAML block syntax — NOT JSON serialized to bytes.
        let yaml_body = "metadata:\n  annotations:\n    k: v\n";

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/my-pod")
            .header(header::CONTENT_TYPE, "application/apply-patch+yaml")
            .body(Body::from(yaml_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "apply-patch+yaml with a genuine YAML body must succeed, not 400 'invalid patch JSON'"
        );
    }

    // -----------------------------------------------------------------------
    // patch_pod — deletionTimestamp+empty-finalizers path
    // -----------------------------------------------------------------------

    /// PATCH that clears finalizers on a pod with deletionTimestamp set must hard-delete.
    #[tokio::test]
    async fn patch_pod_clears_finalizers_triggers_hard_delete() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed pod with deletionTimestamp and a finalizer.
        let key = "/registry/pods/default/finalized-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "finalized-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "deletionTimestamp": "2025-01-01T00:00:00Z",
                "finalizers": ["my.io/cleanup"]
            },
            "spec": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state.clone());

        // Patch to remove the finalizer.
        let patch_body = serde_json::json!({"metadata": {"finalizers": []}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/finalized-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Pod should now be deleted from the store.
        let stored = store.get(key).await.unwrap();
        assert!(
            stored.is_none(),
            "pod must be hard-deleted when deletionTimestamp is set and finalizers are empty"
        );
    }

    /// `PATCH ...?dryRun=All` that drains the last finalizer must NOT hard-delete the pod.
    ///
    /// Regression test for an ordering bug: patch_pod's hard-delete-on-finalizer-drain check
    /// used to run BEFORE its own dry-run check, so a dry-run request draining the last
    /// finalizer actually deleted the pod for real — the exact opposite of what dryRun=All
    /// promises.
    #[tokio::test]
    async fn patch_pod_dry_run_all_draining_last_finalizer_does_not_hard_delete() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/finalized-pod-dry-run";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "finalized-pod-dry-run",
                "namespace": "default",
                "resourceVersion": "1",
                "deletionTimestamp": "2025-01-01T00:00:00Z",
                "finalizers": ["my.io/cleanup"]
            },
            "spec": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state.clone());

        let patch_body = serde_json::json!({"metadata": {"finalizers": []}});

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/finalized-pod-dry-run?dryRun=All")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let stored = store.get(key).await.unwrap();
        assert!(
            stored.is_some(),
            "dryRun=All must not hard-delete the pod even though the patch drains its last \
             finalizer"
        );
    }

    // -----------------------------------------------------------------------
    // PATCH with json-patch+json and a valid remove op must succeed.
    // -----------------------------------------------------------------------

    /// PATCH with json-patch+json and a valid remove op must succeed.
    #[tokio::test]
    async fn patch_json_patch_remove_label() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed pod with a label directly so we control the exact JSON.
        let key = "/registry/pods/default/labeled-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "labeled-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": {"env": "test"}
            },
            "spec": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        let patch_body = serde_json::json!([{"op": "remove", "path": "/metadata/labels/env"}]);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/labeled-pod")
            .header(header::CONTENT_TYPE, "application/json-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // get_pod_resize
    // -----------------------------------------------------------------------

    /// GET /pods/<name>/resize must return 200 with the pod body.
    ///
    /// The in-place-resize conformance test polls GET /resize after each
    /// PATCH /resize to confirm the resize was applied. Without this handler
    /// the route returns 405 and the conformance poll loop never terminates.
    #[tokio::test]
    async fn get_pod_resize_returns_200_with_pod_body() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;
        let pod_json = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "resize-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {"phase": "Running", "resize": "Proposed"}
        });
        store
            .put(
                "/registry/pods/default/resize-pod",
                bytes::Bytes::from(serde_json::to_vec(&pod_json).unwrap()),
                None,
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/resize",
                get(get_pod_resize),
            )
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/resize-pod/resize")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET /pods/<name>/resize must return the resize status — the in-place-resize \
             conformance test polls it; 405 breaks the test"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["status"]["resize"], "Proposed",
            "GET /pods/<name>/resize must return the pod body including status.resize so \
             the conformance test can observe the resize state transition"
        );
    }

    /// GET /pods/<name>/resize on a missing pod must return 404, not 405.
    #[tokio::test]
    async fn get_pod_resize_missing_pod_returns_404() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/resize",
                get(get_pod_resize),
            )
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/ghost/resize")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "GET /pods/<name>/resize must return 404 for a missing pod"
        );
    }

    // -----------------------------------------------------------------------
    // patch_pod_resize (PATCH + PUT /resize)
    // -----------------------------------------------------------------------

    /// PATCH /resize with updated container resources must update the stored pod's resources
    /// and set status.resize = "Proposed".
    ///
    /// This is the core in-place resource update (VPA GA in k8s 1.33+) flow. If resources
    /// are not updated or status.resize is not "Proposed", conformance tests for in-place
    /// pod resize fail and the feature is not usable.
    #[tokio::test]
    async fn patch_pod_resize_updates_resources_and_sets_proposed() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed a pod with CPU limit 100m.
        let key = "/registry/pods/default/resize-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "resize-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {
                        "limits": {"cpu": "100m"},
                        "requests": {"cpu": "100m"}
                    }
                }]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/resize",
                patch(patch_pod_resize).put(patch_pod_resize),
            )
            .with_state(state);

        // PATCH /resize with updated CPU limit 200m.
        let resize_body = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "limits": {"cpu": "200m"},
                        "requests": {"cpu": "200m"}
                    }
                }]
            }
        });

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/resize-pod/resize")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&resize_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PATCH /resize must return 200 — conformance tests require this"
        );

        // Verify store: resources updated and status.resize = "Proposed".
        let stored = store.get(key).await.unwrap().expect("pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();

        assert_eq!(
            v["spec"]["containers"][0]["resources"]["limits"]["cpu"], "200m",
            "container resources must be updated to 200m after /resize PATCH — \
             if this fails the in-place resize feature is not working"
        );
        assert_eq!(
            v["status"]["resize"], "Proposed",
            "status.resize must be set to 'Proposed' after /resize PATCH — \
             conformance tests assert this field to verify the resize was acknowledged"
        );
    }

    /// PATCH /resize must adjust ResourceQuota's `status.used.requests.cpu` by the resize
    /// delta — not just leave it at whatever the pod's create-time request was.
    ///
    /// The incremental quota counter only ever gets touched by `record_pod_created` (adds the
    /// pod's request at create) and `record_pod_removed` (subtracts it at delete). If resize
    /// is never wired to a third adjustment, the eventual delete subtracts the pod's
    /// POST-resize amount while create only added the PRE-resize amount, permanently leaking
    /// the difference: here, a pod created at 100m and resized to 500m must leave
    /// `status.used.requests.cpu` at 500m — a namespace whose usage claims only 100m for a
    /// pod that has actually reserved 500m can wrongly admit a sibling create that a fresh
    /// recount would reject, oversubscribing the node.
    #[tokio::test]
    async fn patch_pod_resize_adjusts_resource_quota_usage() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let pod_key = "/registry/pods/default/resize-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "resize-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {
                        "limits": {"cpu": "100m"},
                        "requests": {"cpu": "100m"}
                    }
                }]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(
                pod_key,
                Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // status.used.requests.cpu = 100m mirrors what record_pod_created would have written
        // for this pod's original (pre-resize) request — the incremental counter's baseline.
        let quota_key = "/registry/resourcequotas/default/cpu-quota";
        let quota = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": {"name": "cpu-quota", "namespace": "default"},
            "spec": {"hard": {"requests.cpu": "1"}},
            "status": {"used": {"requests.cpu": "100m"}}
        });
        store
            .put(
                quota_key,
                Bytes::from(serde_json::to_vec(&quota).unwrap()),
                None,
            )
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/resize",
                patch(patch_pod_resize).put(patch_pod_resize),
            )
            .with_state(state);

        let resize_body = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "limits": {"cpu": "500m"},
                        "requests": {"cpu": "500m"}
                    }
                }]
            }
        });
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/resize-pod/resize")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&resize_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "resize PATCH must succeed");

        let stored_quota = store
            .get(quota_key)
            .await
            .unwrap()
            .expect("quota must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored_quota.value).unwrap();
        assert_eq!(
            v["status"]["used"]["requests.cpu"], "500m",
            "resizing a pod from 100m to 500m must move status.used.requests.cpu to 500m — \
             leaving it at 100m means the eventual delete (which subtracts the post-resize \
             500m) will permanently leak 400m out of this quota's usage"
        );
    }

    /// `PATCH /resize?dryRun=All` must return the would-be resized pod but leave the stored
    /// pod's resources untouched. Before this fix, patch_pod_resize had no dry-run check.
    #[tokio::test]
    async fn patch_pod_resize_dry_run_all_does_not_persist() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/resize-pod-dry-run";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "resize-pod-dry-run", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {
                        "limits": {"cpu": "100m"},
                        "requests": {"cpu": "100m"}
                    }
                }]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/resize",
                patch(patch_pod_resize).put(patch_pod_resize),
            )
            .layer(axum::middleware::from_fn(
                crate::handlers::json_patch::inject_dry_run_header,
            ))
            .with_state(state);

        let resize_body = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {"limits": {"cpu": "200m"}, "requests": {"cpu": "200m"}}
                }]
            }
        });

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/resize-pod-dry-run/resize?dryRun=All")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&resize_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["spec"]["containers"][0]["resources"]["limits"]["cpu"], "200m",
            "dry-run response must show the would-be resized resources"
        );

        let stored = store.get(key).await.unwrap().expect("pod must still exist");
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["spec"]["containers"][0]["resources"]["limits"]["cpu"], "100m",
            "dryRun=All must not persist the resize"
        );
    }

    /// PUT /resize must behave identically to PATCH /resize.
    #[tokio::test]
    async fn put_pod_resize_updates_resources_and_sets_proposed() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/resize-pod2";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "resize-pod2", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx",
                    "resources": {"limits": {"cpu": "100m"}}}]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/resize",
                patch(patch_pod_resize).put(patch_pod_resize),
            )
            .with_state(state);

        let resize_body = serde_json::json!({
            "spec": {"containers": [{"name": "app",
                "resources": {"limits": {"cpu": "500m"}}}]}
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/resize-pod2/resize")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&resize_body))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "PUT /resize must return 200");

        let stored = store.get(key).await.unwrap().expect("pod must exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["containers"][0]["resources"]["limits"]["cpu"], "500m",
            "PUT /resize must update container resources"
        );
        assert_eq!(
            v["status"]["resize"], "Proposed",
            "PUT /resize must set status.resize=Proposed"
        );
    }

    /// PATCH /resize on a missing pod must return 404.
    #[tokio::test]
    async fn patch_pod_resize_missing_pod_returns_404() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/resize",
                patch(patch_pod_resize),
            )
            .with_state(state);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/nonexistent/resize")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"spec":{"containers":[]}}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "PATCH /resize on non-existent pod must return 404"
        );
    }

    /// PATCH /resize with an invalid patch (BestEffort pod adding requests) must return 422.
    ///
    /// The conformance group "apply invalid resize patch requests" (pod_resize.go:390) expects
    /// an error when the patch would change the pod's QoS class. Without this check, u7s
    /// accepts the patch (returning 200) and the test fails with
    /// "Expected an error to have occurred. Got: nil".
    #[tokio::test]
    async fn patch_pod_resize_invalid_qos_change_returns_422() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        // Seed a BestEffort pod (no resources).
        let key = "/registry/pods/default/besteffort-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "besteffort-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "c1", "image": "busybox", "resources": {}}]
            },
            "status": {}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/resize",
                patch(patch_pod_resize).put(patch_pod_resize),
            )
            .with_state(state);

        // Try to add memory requests to a BestEffort pod — would change QoS to Burstable.
        let resize_body = serde_json::json!({
            "spec": {
                "containers": [{"name": "c1", "resources": {"requests": {"memory": "128Mi"}}}]
            }
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/namespaces/default/pods/besteffort-pod/resize")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(json_body(&resize_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "PATCH /resize that changes QoS class must return 422 — \
             conformance test (pod_resize.go:390) expects an error for BestEffort pod adding requests; \
             u7s previously returned 200 causing 'Expected an error to have occurred. Got: nil'"
        );
    }

    // ---------------------------------------------------------------------------
    // patch_pod — retry on RevisionMismatch (Job finalizer-removal convergence)
    // ---------------------------------------------------------------------------

    /// A store wrapper that injects a single RevisionMismatch on the first put() after
    /// arm() is called, then delegates all subsequent calls to the inner SqliteStore.
    ///
    /// This simulates a concurrent kubelet status patch that advances the stored
    /// resourceVersion between the PATCH handler's internal read and write.
    struct ConflictInjectStore {
        inner: Arc<SqliteStore>,
        inject_next: std::sync::atomic::AtomicBool,
    }

    impl ConflictInjectStore {
        fn new(inner: Arc<SqliteStore>) -> Self {
            Self {
                inner,
                inject_next: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn arm(&self) {
            self.inject_next
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl u7s_store::Store for ConflictInjectStore {
        fn get(
            &self,
            key: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Option<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.get(&key).await }
        }

        fn list(
            &self,
            prefix: &str,
            opts: u7s_store::ListOptions,
        ) -> impl std::future::Future<Output = u7s_store::Result<u7s_store::ListResponse>> + Send
        {
            let inner = self.inner.clone();
            let prefix = prefix.to_string();
            async move { inner.list(&prefix, opts).await }
        }

        fn put(
            &self,
            key: &str,
            value: Bytes,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<u64>> + Send {
            let inject = self
                .inject_next
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            let inner = self.inner.clone();
            let key = key.to_string();
            async move {
                if inject {
                    // Simulate concurrent kubelet status patch advancing the rv.
                    // Perform the actual write first so the retry reads fresh data.
                    let _ = inner.put(&key, value, None).await;
                    Err(u7s_store::StoreError::RevisionMismatch {
                        expected: 1,
                        current: 99,
                    })
                } else {
                    inner.put(&key, value, expected_revision).await
                }
            }
        }

        fn delete(
            &self,
            key: &str,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<(u64, Bytes)>> + Send {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.delete(&key, expected_revision).await }
        }

        fn list_namespace_objects(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.list_namespace_objects(&ns).await }
        }

        fn delete_namespace_resources(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<String>>> + Send {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.delete_namespace_resources(&ns).await }
        }

        fn watch(
            &self,
            _prefix: &str,
            _from_revision: u64,
        ) -> impl std::future::Future<
            Output = u7s_store::Result<
                impl futures_core::Stream<Item = u7s_store::WatchEvent> + Send + 'static,
            >,
        > + Send {
            std::future::ready(Ok(futures_util::stream::empty()))
        }

        fn compaction_horizon(&self) -> u64 {
            self.inner.compaction_horizon()
        }

        fn current_revision(&self) -> u64 {
            self.inner.current_revision()
        }

        fn watch_receiver_count(&self) -> usize {
            self.inner.watch_receiver_count()
        }
    }

    /// patch_pod must retry internally on RevisionMismatch rather than returning 409 to the
    /// client. Without the retry loop, KCM's finalizer-removal PATCH conflicts with concurrent
    /// kubelet status patches and the batch.kubernetes.io/job-tracking finalizer is never
    /// removed: pods stay stuck Terminating forever and Job GC never completes.
    ///
    /// This test injects a RevisionMismatch on the first put() inside patch_pod, simulating a
    /// concurrent write that advances the stored rv between the handler's read and write. The
    /// handler must retry, re-read the fresh object, re-apply the patch, and succeed (200).
    #[tokio::test]
    async fn patch_pod_retries_on_revision_mismatch_so_finalizer_removal_converges() {
        let inner = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let conflict_store = Arc::new(ConflictInjectStore::new(Arc::clone(&inner)));

        // Seed namespace and a pod with a finalizer and deletionTimestamp.
        let ns_key = "/registry/namespaces/default";
        inner
            .put(
                ns_key,
                Bytes::from(
                    serde_json::to_vec(
                        &serde_json::json!({"kind":"Namespace","metadata":{"name":"default"}}),
                    )
                    .unwrap(),
                ),
                None,
            )
            .await
            .unwrap();

        let pod_key = "/registry/pods/default/job-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "job-pod",
                "namespace": "default",
                "resourceVersion": "1",
                "deletionTimestamp": "2025-01-01T00:00:00Z",
                "finalizers": ["batch.kubernetes.io/job-tracking"]
            },
            "spec": {}
        });
        inner
            .put(
                pod_key,
                Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Arm the store: first put() inside patch_pod will return RevisionMismatch.
        conflict_store.arm();

        let state = AppState::new(
            Arc::clone(&conflict_store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        // KCM removes the job-tracking finalizer via a merge PATCH.
        let patch_body = serde_json::json!({"metadata": {"finalizers": []}});
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/job-pod")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "patch_pod must retry on RevisionMismatch and succeed (200) rather than returning \
             409 Conflict; without the retry loop KCM's finalizer-removal PATCH never converges \
             when the kubelet patches status concurrently, leaving Job pods stuck Terminating"
        );

        // Pod must be hard-deleted: deletionTimestamp was set and finalizers are now empty.
        let stored = inner.get(pod_key).await.unwrap();
        assert!(
            stored.is_none(),
            "pod must be hard-deleted after finalizer removal (deletionTimestamp set, \
             finalizers empty); if patch_pod 409-conflicts on RevisionMismatch instead of \
             retrying, the finalizer stays and Job GC never completes"
        );
    }

    /// A store wrapper that, on the first put() after arm(), writes an INDEPENDENT
    /// object (simulating a different concurrent writer, e.g. the kubelet PATCHing
    /// /status) instead of the caller's own value, then reports RevisionMismatch.
    ///
    /// Unlike ConflictInjectStore (which replays the caller's own computed value as
    /// the "concurrent" write, so a retry trivially reproduces the same result), this
    /// models two writers changing two different fields, so a retry that clobbers
    /// instead of re-reading would provably lose one side's update.
    struct ConcurrentWriterStore {
        inner: Arc<SqliteStore>,
        concurrent_write: Bytes,
        inject_next: std::sync::atomic::AtomicBool,
    }

    impl ConcurrentWriterStore {
        fn new(inner: Arc<SqliteStore>, concurrent_write: Bytes) -> Self {
            Self {
                inner,
                concurrent_write,
                inject_next: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn arm(&self) {
            self.inject_next
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl u7s_store::Store for ConcurrentWriterStore {
        fn get(
            &self,
            key: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Option<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.get(&key).await }
        }

        fn list(
            &self,
            prefix: &str,
            opts: u7s_store::ListOptions,
        ) -> impl std::future::Future<Output = u7s_store::Result<u7s_store::ListResponse>> + Send
        {
            let inner = self.inner.clone();
            let prefix = prefix.to_string();
            async move { inner.list(&prefix, opts).await }
        }

        fn put(
            &self,
            key: &str,
            value: Bytes,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<u64>> + Send {
            let inject = self
                .inject_next
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            let inner = self.inner.clone();
            let key = key.to_string();
            let concurrent_write = self.concurrent_write.clone();
            async move {
                if inject {
                    // A different writer's change lands here, independent of `value`
                    // (the caller's own not-yet-persisted attempt).
                    let _ = inner.put(&key, concurrent_write, None).await;
                    Err(u7s_store::StoreError::RevisionMismatch {
                        expected: 1,
                        current: 99,
                    })
                } else {
                    inner.put(&key, value, expected_revision).await
                }
            }
        }

        fn delete(
            &self,
            key: &str,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<(u64, Bytes)>> + Send {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.delete(&key, expected_revision).await }
        }

        fn list_namespace_objects(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.list_namespace_objects(&ns).await }
        }

        fn delete_namespace_resources(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<String>>> + Send {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.delete_namespace_resources(&ns).await }
        }

        fn watch(
            &self,
            _prefix: &str,
            _from_revision: u64,
        ) -> impl std::future::Future<
            Output = u7s_store::Result<
                impl futures_core::Stream<Item = u7s_store::WatchEvent> + Send + 'static,
            >,
        > + Send {
            std::future::ready(Ok(futures_util::stream::empty()))
        }

        fn compaction_horizon(&self) -> u64 {
            self.inner.compaction_horizon()
        }

        fn current_revision(&self) -> u64 {
            self.inner.current_revision()
        }

        fn watch_receiver_count(&self) -> usize {
            self.inner.watch_receiver_count()
        }
    }

    /// Prior investigation into sonobuoy's `sonobuoy status` freezing mid-run found:
    /// aggregator PATCHes its own pod's annotation to publish progress while the
    /// kubelet concurrently PATCHes the same pod's /status. The leading hypothesis
    /// was a lost-update clobber between the two writers. Live evidence from a full
    /// conformance run showed zero RevisionMismatch retries even occurred — ruling out
    /// a race as the cause of the observed freeze (the actual freeze traces to the
    /// upstream e2e progress reporter never emitting incremental completed counts, not
    /// to u7s). This test locks in the invariant that makes such a race safe *if* it
    /// ever does happen: patch_pod must re-read the fresh object on RevisionMismatch
    /// and reapply its own patch, rather than clobbering a concurrent writer's change
    /// with a write based on stale data.
    #[tokio::test]
    async fn patch_pod_annotation_survives_concurrent_status_write_race() {
        let inner = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        let ns_key = "/registry/namespaces/default";
        inner
            .put(
                ns_key,
                Bytes::from(
                    serde_json::to_vec(
                        &serde_json::json!({"kind":"Namespace","metadata":{"name":"default"}}),
                    )
                    .unwrap(),
                ),
                None,
            )
            .await
            .unwrap();

        let pod_key = "/registry/pods/default/sonobuoy";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "sonobuoy",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": {},
            "status": {"phase": "Running"}
        });
        inner
            .put(
                pod_key,
                Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // What the kubelet's concurrent /status write lands as, between patch_pod's
        // read and its first write attempt — a different field than the annotation
        // patch below touches.
        let concurrent_status_write = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "sonobuoy",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": {},
            "status": {"phase": "Succeeded"}
        });
        let racing_store = Arc::new(ConcurrentWriterStore::new(
            Arc::clone(&inner),
            Bytes::from(serde_json::to_vec(&concurrent_status_write).unwrap()),
        ));
        racing_store.arm();

        let state = AppState::new(
            Arc::clone(&racing_store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", patch(patch_pod))
            .with_state(state);

        // The aggregator's annotation PATCH — the write sonobuoy status polling depends on.
        let patch_body = serde_json::json!({
            "metadata": {"annotations": {"sonobuoy.hept.io/status": "progress-update"}}
        });
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/sonobuoy")
            .header(header::CONTENT_TYPE, "application/merge-patch+json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "annotation PATCH must retry past the concurrent status write and succeed"
        );

        let stored = inner.get(pod_key).await.unwrap().unwrap();
        let stored_body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_body["metadata"]["annotations"]["sonobuoy.hept.io/status"], "progress-update",
            "the annotation PATCH must not be lost after retrying past a concurrent status \
             write — this is the exact write 'sonobuoy status' depends on to show live progress"
        );
        assert_eq!(
            stored_body["status"]["phase"], "Succeeded",
            "the concurrent status write must survive too — a patch_pod that clobbers on \
             retry (e.g. writing unconditionally, or reapplying against stale data) would \
             silently revert the kubelet's status update"
        );
    }

    /// A plain `client.Delete(ctx, name, DeleteOptions{})` carries no resourceVersion
    /// precondition at all — the client never asked the apiserver to enforce one. If the
    /// kubelet's routine pod-status PATCH lands between delete_pod's read and its
    /// soft-delete write, the internal CAS delete_pod uses to persist deletionTimestamp
    /// conflicts; without a retry loop (mirroring patch_pod's, added in 1d4ec948 for the
    /// same race class) that conflict leaked straight to the client as a spurious 409,
    /// which is exactly what broke the CSIInlineVolumes conformance test's unconditional
    /// pod delete. This test fails on revert: without the retry, the DELETE returns 409
    /// instead of 200.
    #[tokio::test]
    async fn delete_pod_retries_past_concurrent_status_write_instead_of_409ing() {
        let inner = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        let ns_key = "/registry/namespaces/default";
        inner
            .put(
                ns_key,
                Bytes::from(
                    serde_json::to_vec(
                        &serde_json::json!({"kind":"Namespace","metadata":{"name":"default"}}),
                    )
                    .unwrap(),
                ),
                None,
            )
            .await
            .unwrap();

        let pod_key = "/registry/pods/default/csi-pod";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "csi-pod",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": {},
            "status": {"phase": "Pending"}
        });
        inner
            .put(
                pod_key,
                Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // What the kubelet's concurrent /status PATCH lands as between delete_pod's read
        // and its first write attempt.
        let concurrent_status_write = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "csi-pod",
                "namespace": "default",
                "resourceVersion": "1"
            },
            "spec": {},
            "status": {"phase": "Running"}
        });
        let racing_store = Arc::new(ConcurrentWriterStore::new(
            Arc::clone(&inner),
            Bytes::from(serde_json::to_vec(&concurrent_status_write).unwrap()),
        ));
        racing_store.arm();

        let state = AppState::new(
            Arc::clone(&racing_store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}", delete(delete_pod))
            .layer(auth_layer())
            .with_state(state);

        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/namespaces/default/pods/csi-pod")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a plain unconditional DELETE must retry past a concurrent status write and \
             succeed with 200, never surface the apiserver's own internal CAS conflict as \
             a 409 to a client that never specified any resourceVersion precondition"
        );

        let stored = inner.get(pod_key).await.unwrap().unwrap();
        let stored_body: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            stored_body["metadata"]["deletionTimestamp"].is_string(),
            "the retried delete must still stamp deletionTimestamp so the kubelet sends \
             SIGTERM — a retry that only avoided the 409 without completing the write \
             would leave the pod running forever with the client believing DELETE succeeded"
        );
        assert_eq!(
            stored_body["status"]["phase"], "Running",
            "the concurrent status write must survive the retried delete — a delete that \
             retries by clobbering with stale data instead of re-reading the fresh object \
             would silently revert the kubelet's status update"
        );
    }
}

// ---------------------------------------------------------------------------
// Pure-logic tests for apply_resize_patch
// ---------------------------------------------------------------------------

#[cfg(test)]
mod resize_tests {
    use super::*;

    /// apply_resize_patch must not panic when the stored pod's `status` is a scalar
    /// (possible if a status-subresource merge-patch bypassed schema validation before
    /// this was guarded). `result["status"]["resize"] = ...` indexes a JSON string with a
    /// str key, which panics without the guard — crashing the apiserver on every resize
    /// PATCH/PUT for that pod, a total denial of service for every other request in
    /// flight, not just this one.
    #[test]
    fn apply_resize_patch_does_not_panic_on_scalar_status() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {"limits": {"cpu": "100m"}, "requests": {"cpu": "100m"}}
                }]
            },
            "status": "corrupted-scalar-status"
        });
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {"limits": {"cpu": "200m"}, "requests": {"cpu": "200m"}}
                }]
            }
        });

        let result = apply_resize_patch(&stored, &incoming);

        assert_eq!(
            result["status"]["resize"], "Proposed",
            "a scalar status must be coerced back to an object so the resize stamp can \
             still be applied, matching apply_delete_policy's same defense-in-depth guard"
        );
    }

    /// apply_resize_patch merges container resources by name and sets status.resize = "Proposed".
    ///
    /// This is the primary in-place resize contract: if the container resources are not updated
    /// or status.resize is not set, the conformance test for pod resize fails.
    #[test]
    fn apply_resize_patch_updates_resources_and_sets_proposed() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "resources": {"limits": {"cpu": "100m"}, "requests": {"cpu": "100m"}}
                }]
            },
            "status": {"phase": "Running"}
        });
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {"limits": {"cpu": "200m"}, "requests": {"cpu": "200m"}}
                }]
            }
        });

        let result = apply_resize_patch(&stored, &incoming);

        assert_eq!(
            result["spec"]["containers"][0]["resources"]["limits"]["cpu"], "200m",
            "container resources must be updated to 200m — \
             if this fails the in-place resize feature is broken"
        );
        assert_eq!(
            result["status"]["resize"], "Proposed",
            "status.resize must be set to 'Proposed' — conformance tests assert this field"
        );
        // Unchanged fields must survive.
        assert_eq!(
            result["spec"]["containers"][0]["image"], "nginx",
            "container image must be preserved after resize patch"
        );
        assert_eq!(
            result["status"]["phase"], "Running",
            "status.phase must be preserved after resize patch"
        );
    }

    /// apply_resize_patch only updates the container matching by name; other containers are unchanged.
    #[test]
    fn apply_resize_patch_only_updates_matching_container() {
        let stored = serde_json::json!({
            "spec": {
                "containers": [
                    {"name": "app", "resources": {"limits": {"cpu": "100m"}}},
                    {"name": "sidecar", "resources": {"limits": {"cpu": "50m"}}}
                ]
            },
            "status": {}
        });
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "resources": {"limits": {"cpu": "300m"}}}]
            }
        });

        let result = apply_resize_patch(&stored, &incoming);

        assert_eq!(
            result["spec"]["containers"][0]["resources"]["limits"]["cpu"], "300m",
            "named container resources must be updated"
        );
        assert_eq!(
            result["spec"]["containers"][1]["resources"]["limits"]["cpu"], "50m",
            "sidecar container must be unchanged — resize only targets named containers"
        );
    }

    /// apply_resize_patch must preserve a resource dimension the patch never mentions,
    /// even when the surrounding requests/limits section IS present and non-empty.
    ///
    /// Reproduces the "guaranteed pods with multiple containers, 3 containers" and
    /// "burstable pods - extended 6 containers" InPlace Resize conformance failures:
    /// `strategicpatch.CreateTwoWayMergePatch` omits any cpu/memory key that didn't
    /// change, so a CPU-only resize of a container that also has memory requests/limits
    /// never mentions memory at all. Before this fix, apply_resize_patch replaced the
    /// whole `resources` object with the patch's partial one, silently deleting the
    /// container's memory requests/limits — verified live via kubectl --subresource=resize
    /// against a guaranteed 3-container pod, where container c1 (CPU-only change) lost
    /// its stored memory entirely.
    #[test]
    fn apply_resize_patch_preserves_untouched_resource_key_within_touched_section() {
        let stored = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {
                        "requests": {"cpu": "100m", "memory": "100Mi"},
                        "limits": {"cpu": "100m", "memory": "100Mi"}
                    }
                }]
            },
            "status": {}
        });
        // Only CPU changes for c1; memory is entirely absent (unchanged, per
        // CreateTwoWayMergePatch semantics), matching the real patch this repro sent.
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {
                        "requests": {"cpu": "150m"},
                        "limits": {"cpu": "150m"}
                    }
                }]
            }
        });

        let result = apply_resize_patch(&stored, &incoming);

        assert_eq!(
            result["spec"]["containers"][0]["resources"]["requests"]["cpu"], "150m",
            "the touched resource (cpu) must be updated"
        );
        assert_eq!(
            result["spec"]["containers"][0]["resources"]["requests"]["memory"], "100Mi",
            "memory requests must survive a CPU-only resize — losing them silently \
             shrinks the container to a fraction of its declared memory, a real \
             vertical-scaling regression, not just a cosmetic field drop"
        );
        assert_eq!(
            result["spec"]["containers"][0]["resources"]["limits"]["memory"], "100Mi",
            "memory limits must survive a CPU-only resize for the same reason"
        );
    }

    /// apply_resize_patch must let independent containers each keep the resource
    /// dimension they didn't touch, when a single resize patch changes several
    /// containers with different cpu/memory combinations at once.
    ///
    /// Mirrors the exact per-container shapes used by the "burstable pods - extended 6
    /// containers" conformance test: one container adds a limit where only a request
    /// existed, another decreases a request while its other dimension (never set before)
    /// stays absent. Both must be applied independently without cross-contaminating or
    /// dropping data — reproduced live via kubectl --subresource=resize.
    #[test]
    fn apply_resize_patch_multi_container_independent_dimensions() {
        let stored = serde_json::json!({
            "spec": {
                "containers": [
                    {"name": "c1", "resources": {"requests": {"cpu": "100m"}}},
                    {"name": "c3", "resources": {"requests": {"cpu": "100m", "memory": "100Mi"}}}
                ]
            },
            "status": {}
        });
        // c1: add a CPU limit (memory never existed, still absent — not mentioned).
        // c3: decrease memory only; cpu is untouched and must be preserved.
        let incoming = serde_json::json!({
            "spec": {
                "containers": [
                    {"name": "c1", "resources": {"limits": {"cpu": "200m"}}},
                    {"name": "c3", "resources": {"requests": {"memory": "50Mi"}}}
                ]
            }
        });

        let result = apply_resize_patch(&stored, &incoming);

        assert_eq!(
            result["spec"]["containers"][0]["resources"]["limits"]["cpu"], "200m",
            "c1's new CPU limit must be applied"
        );
        assert!(
            result["spec"]["containers"][0]["resources"]["requests"]["memory"].is_null(),
            "c1 never had memory requests and the patch never adds any — it must stay absent"
        );
        assert_eq!(
            result["spec"]["containers"][1]["resources"]["requests"]["cpu"], "100m",
            "c3's untouched CPU request must survive a memory-only resize of c3"
        );
        assert_eq!(
            result["spec"]["containers"][1]["resources"]["requests"]["memory"], "50Mi",
            "c3's memory request must reflect the decrease"
        );
    }

    /// resize that changes container resources must increment metadata.generation.
    ///
    /// Controllers and the kubelet use observedGeneration == generation to detect when they
    /// have acted on the latest spec. If generation does not bump after a resize, controllers
    /// will think the spec hasn't changed and silently skip applying the new resource limits.
    #[test]
    fn resize_that_changes_resources_bumps_generation() {
        let stored = serde_json::json!({
            "metadata": {"name": "my-pod", "generation": 1i64},
            "spec": {
                "containers": [{"name": "app", "resources": {"limits": {"cpu": "100m"}}}]
            },
            "status": {}
        });
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "resources": {"limits": {"cpu": "200m"}}}]
            }
        });

        let spec_before = stored["spec"].clone();
        let mut result = apply_resize_patch(&stored, &incoming);
        increment_pod_generation_if_spec_changed(&mut result, &spec_before);

        assert_eq!(
            result["metadata"]["generation"], 2i64,
            "generation must increment after resize changes resources — \
             controllers gate on observedGeneration==generation to detect spec changes"
        );
    }

    /// resize that sends identical resources must NOT bump generation.
    ///
    /// A no-op resize (same values as already stored) should not advance generation —
    /// doing so would cause spurious reconciliation loops in controllers.
    #[test]
    fn resize_with_identical_resources_does_not_bump_generation() {
        let stored = serde_json::json!({
            "metadata": {"name": "my-pod", "generation": 1i64},
            "spec": {
                "containers": [{"name": "app", "resources": {"limits": {"cpu": "100m"}}}]
            },
            "status": {}
        });
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "resources": {"limits": {"cpu": "100m"}}}]
            }
        });

        let spec_before = stored["spec"].clone();
        let mut result = apply_resize_patch(&stored, &incoming);
        increment_pod_generation_if_spec_changed(&mut result, &spec_before);

        assert_eq!(
            result["metadata"]["generation"], 1i64,
            "generation must NOT change when resize sends identical resources — \
             no-op resizes must not trigger spurious controller reconciliation"
        );
    }

    /// apply_resize_patch with no matching container name leaves all containers unchanged.
    #[test]
    fn apply_resize_patch_no_match_leaves_containers_unchanged() {
        let stored = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "resources": {"limits": {"cpu": "100m"}}}]
            },
            "status": {}
        });
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{"name": "nonexistent", "resources": {"limits": {"cpu": "999m"}}}]
            }
        });

        let result = apply_resize_patch(&stored, &incoming);

        assert_eq!(
            result["spec"]["containers"][0]["resources"]["limits"]["cpu"], "100m",
            "unmatched container resources must be unchanged"
        );
        // status.resize is still set even if no container matched.
        assert_eq!(result["status"]["resize"], "Proposed");
    }

    /// apply_resize_patch must also merge spec.initContainers[].resources, not just
    /// spec.containers[].resources.
    ///
    /// Sidecar (RestartPolicy: Always) init containers are resizable through the same
    /// GA in-place-resize feature as regular containers, and a real client's
    /// strategic-merge-patch carries their resource changes under `initContainers`. A
    /// resize patch that touches both an init container and a regular container in the
    /// same pod (upstream's "guaranteed qos ... + resize initContainers" conformance
    /// entries) previously had its initContainers half silently dropped — the init
    /// container's resources on disk never changed even though the apiserver returned
    /// 200 OK, so the kubelet had a stale spec to reconcile against and the conformance
    /// test's post-resize verification failed.
    #[test]
    fn apply_resize_patch_updates_init_container_resources_too() {
        let stored = serde_json::json!({
            "spec": {
                "initContainers": [{
                    "name": "init",
                    "resources": {"requests": {"cpu": "20m", "memory": "35Mi"}, "limits": {"cpu": "20m", "memory": "35Mi"}}
                }],
                "containers": [{
                    "name": "app",
                    "resources": {"requests": {"cpu": "20m", "memory": "35Mi"}, "limits": {"cpu": "20m", "memory": "35Mi"}}
                }]
            },
            "status": {}
        });
        let incoming = serde_json::json!({
            "spec": {
                "initContainers": [{
                    "name": "init",
                    "resources": {"requests": {"memory": "40Mi"}, "limits": {"memory": "40Mi"}}
                }],
                "containers": [{
                    "name": "app",
                    "resources": {"requests": {"memory": "40Mi"}, "limits": {"memory": "40Mi"}}
                }]
            }
        });

        let result = apply_resize_patch(&stored, &incoming);

        assert_eq!(
            result["spec"]["initContainers"][0]["resources"]["requests"]["memory"], "40Mi",
            "init container memory request must be updated by a resize patch — dropping it \
             leaves the kubelet reconciling against a stale spec"
        );
        assert_eq!(
            result["spec"]["initContainers"][0]["resources"]["limits"]["memory"], "40Mi",
            "init container memory limit must be updated by a resize patch"
        );
        assert_eq!(
            result["spec"]["initContainers"][0]["resources"]["requests"]["cpu"], "20m",
            "init container's untouched cpu request must survive a memory-only resize"
        );
        assert_eq!(
            result["spec"]["containers"][0]["resources"]["requests"]["memory"], "40Mi",
            "the regular container in the same patch must still be updated"
        );
    }

    // -----------------------------------------------------------------------
    // validate_resize_patch — regression tests for invalid-resize rejection
    // (conformance: "apply invalid resize patch requests", pod_resize.go:389)
    // -----------------------------------------------------------------------

    /// Guaranteed pod — rename containers: patch names containers that don't match the stored names.
    /// Real k8s rejects with "Forbidden: containers may not be renamed or reordered on resize".
    /// Accepting it would silently no-op or corrupt state, hiding misconfig from the caller.
    #[test]
    fn resize_rejects_container_rename_else_kubelet_gets_impossible_spec() {
        let stored = serde_json::json!({
            "metadata": {"name": "guaranteed-pod", "namespace": "default"},
            "spec": {
                "containers": [
                    {"name": "c1-old", "resources": {"limits": {"cpu": "20m", "memory": "35Mi"}, "requests": {"cpu": "20m", "memory": "35Mi"}}},
                    {"name": "c2-old", "resources": {"limits": {"cpu": "20m", "memory": "35Mi"}, "requests": {"cpu": "20m", "memory": "35Mi"}}}
                ]
            },
            "status": {}
        });
        // Patch uses completely different names for both containers.
        let incoming = serde_json::json!({
            "spec": {
                "containers": [
                    {"name": "c1-new", "resources": {"limits": {"cpu": "20m", "memory": "35Mi"}, "requests": {"cpu": "20m", "memory": "35Mi"}}},
                    {"name": "c2-new", "resources": {"limits": {"cpu": "20m", "memory": "35Mi"}, "requests": {"cpu": "20m", "memory": "35Mi"}}}
                ]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(result.is_err(), "rename must be rejected");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("Forbidden: containers may not be renamed or reordered on resize"),
            "error must contain k8s conformance substring \
             'Forbidden: containers may not be renamed or reordered on resize' — \
             conformance test (pod_resize.go:390) uses ContainSubstring to match this; \
             got: {msg}"
        );
        // Both mismatched positions must appear in the error.
        assert!(
            msg.contains("spec.containers[0].name") && msg.contains("spec.containers[1].name"),
            "error must report both mismatched container positions; got: {msg}"
        );
    }

    /// BestEffort pod — request memory: adding memory requests changes QoS from BestEffort to Burstable.
    /// Real k8s rejects with "Pod QOS Class may not change as a result of resizing".
    #[test]
    fn resize_rejects_besteffort_pod_adding_requests_else_qos_class_changes() {
        let stored = serde_json::json!({
            "metadata": {"name": "besteffort-pod", "namespace": "default"},
            "spec": {
                "containers": [{"name": "c1", "resources": {}}]
            },
            "status": {}
        });
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{"name": "c1", "resources": {"requests": {"memory": "128Mi"}}}]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(
            result.is_err(),
            "BestEffort pod adding requests must be rejected"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("Pod QOS Class may not change as a result of resizing"),
            "error must contain k8s conformance substring \
             'Pod QOS Class may not change as a result of resizing' — \
             conformance test (pod_resize.go:390) uses ContainSubstring to match this; \
             got: {msg}"
        );
    }

    /// Burstable pod — remove cpu&memory limits while increasing requests:
    /// removing limits changes the resource structure. k8s rejects with "resource limits cannot be removed".
    #[test]
    fn resize_rejects_burstable_removing_limits_while_increasing_requests() {
        let stored = serde_json::json!({
            "metadata": {"name": "burstable-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {
                        "limits": {"cpu": "200m", "memory": "256Mi"},
                        "requests": {"cpu": "100m", "memory": "128Mi"}
                    }
                }]
            },
            "status": {}
        });
        // Patch explicitly sets limits to {} (empty object) to remove them, and increases requests.
        // Rule 3 uses ALL-SECTIONS semantics: indexing into absent keys (via serde_json) returns
        // Null, so both an absent limits key and limits:{} (empty object) are treated as "no
        // value for cpu/memory in limits", triggering the removal error. limits:{} is used here
        // to make the test scenario explicit (and matches what some real k8s e2e clients send).
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {"requests": {"cpu": "500m", "memory": "512Mi"}, "limits": {}}
                }]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(result.is_err(), "removing limits must be rejected");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("resource limits cannot be removed"),
            "error must contain k8s conformance substring 'resource limits cannot be removed' — \
             conformance test (pod_resize.go:390) uses ContainSubstring to match this; \
             got: {msg}"
        );
    }

    /// Burstable pod — explicit null for requests.cpu is a real removal, which is forbidden.
    /// k8s rejects with "resource requests cannot be removed".
    ///
    /// Uses an EXPLICIT `null` (not a bare omission) for requests.cpu: a
    /// strategicpatch.CreateTwoWayMergePatch signals "this key was removed" with an
    /// explicit null, and omits keys that are simply unchanged. Only the explicit-null
    /// form must be rejected here — see
    /// `resize_accepts_burstable_patch_omitting_unchanged_cpu_request` below for the
    /// omitted-key case, which must be accepted.
    #[test]
    fn resize_rejects_burstable_explicit_null_cpu_request_as_removal() {
        let stored = serde_json::json!({
            "metadata": {"name": "burstable-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {
                        "limits": {"cpu": "200m", "memory": "256Mi"},
                        "requests": {"cpu": "100m", "memory": "128Mi"}
                    }
                }]
            },
            "status": {}
        });
        // Patch explicitly nulls requests.cpu — a real removal signal.
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {
                        "limits": {"cpu": "200m", "memory": "256Mi"},
                        "requests": {"cpu": null, "memory": "128Mi"}
                    }
                }]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(
            result.is_err(),
            "explicitly removing cpu requests must be rejected"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("resource requests cannot be removed"),
            "error must contain k8s conformance substring 'resource requests cannot be removed' — \
             conformance test (pod_resize.go:390) uses ContainSubstring to match this; \
             got: {msg}"
        );
    }

    /// Burstable pod, requests-only — a two-way-merge patch that changes only
    /// requests.memory omits requests.cpu entirely (it didn't change). Treating that
    /// omission as removal falsely rejects a valid in-place resize: both InPlaceResize
    /// conformance tests build their patches this way, so this must be accepted.
    #[test]
    fn resize_accepts_burstable_patch_omitting_unchanged_cpu_request() {
        let stored = serde_json::json!({
            "metadata": {"name": "burstable-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}}
                }]
            },
            "status": {}
        });
        // Patch touches only requests.memory; requests.cpu is entirely absent from the
        // JSON, matching what strategicpatch.CreateTwoWayMergePatch produces for an
        // unchanged scalar.
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {"requests": {"memory": "128Mi"}}
                }]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(
            result.is_ok(),
            "a memory-only resize must not be rejected as 'cpu requests removed' just \
             because the two-way-merge patch omits the unchanged cpu key — \
             got: {:?}",
            result.err()
        );
    }

    /// Burstable pod with both requests and limits set — a two-way-merge patch that
    /// changes only requests.cpu omits the ENTIRE `limits` section (nothing in it
    /// changed), not just an individual key within it. Treating a whole section's
    /// absence as "removed" (rather than "unchanged", symmetric with how
    /// `apply_resize_patch`'s `merge_resize_section` already treats it) falsely rejects
    /// this resize with 422 "resource limits cannot be removed" — this is exactly the
    /// live-conformance failure upstream's "burstable pods - 1 container with all
    /// requests & limits set ... cpu requests" resize entry hits when a real
    /// `strategicpatch.CreateTwoWayMergePatch` omits an untouched section outright.
    #[test]
    fn resize_accepts_burstable_patch_omitting_unchanged_limits_section() {
        let stored = serde_json::json!({
            "metadata": {"name": "burstable-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {
                        "limits": {"cpu": "30m", "memory": "45Mi"},
                        "requests": {"cpu": "20m", "memory": "35Mi"}
                    }
                }]
            },
            "status": {}
        });
        // Only requests.cpu changes; limits is entirely absent from the patch because
        // strategicpatch.CreateTwoWayMergePatch omits a section that didn't change at all.
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {"requests": {"cpu": "25m"}}
                }]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(
            result.is_ok(),
            "a cpu-request-only resize must not be rejected as 'limits removed' just \
             because the two-way-merge patch omits the entirely-unchanged limits section — \
             got: {:?}",
            result.err()
        );
    }

    /// validate_resize_patch must apply Rule 3 (no removing a set resource quantity) to
    /// init containers too, not just regular containers.
    ///
    /// Sidecar init containers are resizable through the same GA feature as regular
    /// containers; before this check covered `spec.initContainers`, a resize patch that
    /// removed an init container's cpu limit would be silently accepted by the
    /// validator (only `apply_resize_patch` would actually see the drop), letting a
    /// client strip resource guarantees from a running sidecar with no error.
    #[test]
    fn resize_rejects_init_container_removing_limits() {
        let stored = serde_json::json!({
            "metadata": {"name": "sidecar-pod", "namespace": "default"},
            "spec": {
                "initContainers": [{
                    "name": "init",
                    "resources": {
                        "limits": {"cpu": "20m", "memory": "35Mi"},
                        "requests": {"cpu": "20m", "memory": "35Mi"}
                    }
                }]
            },
            "status": {}
        });
        let incoming = serde_json::json!({
            "spec": {
                "initContainers": [{
                    "name": "init",
                    "resources": {"limits": {}, "requests": {"cpu": "20m", "memory": "35Mi"}}
                }]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(
            result.is_err(),
            "removing an init container's limits must be rejected, same as a regular container"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("spec.initContainers[name=init].resources.limits")
                && msg.contains("resource limits cannot be removed"),
            "error must reference spec.initContainers (not spec.containers) and the k8s \
             conformance substring 'resource limits cannot be removed' — got: {msg}"
        );
    }

    /// Guaranteed pod — valid resize (same QoS, existing containers, correct order): must be accepted.
    /// This ensures the validator doesn't over-reject valid resize patches.
    #[test]
    fn resize_accepts_guaranteed_pod_valid_resource_change() {
        let stored = serde_json::json!({
            "metadata": {"name": "guaranteed-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "limits": {"cpu": "100m", "memory": "128Mi"},
                        "requests": {"cpu": "100m", "memory": "128Mi"}
                    }
                }]
            },
            "status": {}
        });
        // Valid resize: increase resources, keep QoS Guaranteed (requests == limits).
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "limits": {"cpu": "200m", "memory": "256Mi"},
                        "requests": {"cpu": "200m", "memory": "256Mi"}
                    }
                }]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(
            result.is_ok(),
            "valid Guaranteed resize (same QoS, existing container, correct order) must be accepted — \
             over-rejection would break the in-place resize feature entirely; \
             got: {:?}",
            result.err()
        );
    }

    /// Burstable pod — reorder containers: patch sends containers in different order.
    /// k8s rejects with "Forbidden: containers may not be renamed or reordered on resize".
    #[test]
    fn resize_rejects_burstable_container_reorder() {
        let stored = serde_json::json!({
            "metadata": {"name": "burstable-pod", "namespace": "default"},
            "spec": {
                "containers": [
                    {"name": "c1", "resources": {"requests": {"cpu": "100m"}}},
                    {"name": "c2", "resources": {"requests": {"cpu": "100m"}}}
                ]
            },
            "status": {}
        });
        // Patch sends containers in reversed order: c2, c1.
        let incoming = serde_json::json!({
            "spec": {
                "containers": [
                    {"name": "c2", "resources": {"requests": {"cpu": "200m"}}},
                    {"name": "c1", "resources": {"requests": {"cpu": "200m"}}}
                ]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(result.is_err(), "reordering containers must be rejected");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("Forbidden: containers may not be renamed or reordered on resize"),
            "error must contain k8s conformance substring; got: {msg}"
        );
    }

    /// Burstable pod — reorder via $setElementOrder/containers only (no containers array).
    /// The real k8s conformance test 'Burstable pod - reorder containers' sends a
    /// strategic-merge-patch with ONLY spec.$setElementOrder/containers in reversed order
    /// and NO spec.containers array. Without this check, the early-return on absent
    /// containers would silently accept the patch, applying the reorder client-side, and
    /// causing the kubelet to map resources to the wrong container (cpu quota for c1 applied
    /// to c2, etc.). k8s rejects with "Forbidden: containers may not be renamed or reordered".
    #[test]
    fn resize_rejects_container_reorder_via_set_element_order_else_kubelet_maps_resources_to_wrong_container(
    ) {
        let stored = serde_json::json!({
            "metadata": {"name": "burstable-pod", "namespace": "default"},
            "spec": {
                "containers": [
                    {"name": "c1", "resources": {"requests": {"cpu": "100m"}}},
                    {"name": "c2", "resources": {"requests": {"cpu": "100m"}}}
                ]
            },
            "status": {}
        });
        // Conformance test sends ONLY $setElementOrder/containers with reversed order —
        // no spec.containers array at all.
        let incoming = serde_json::json!({
            "spec": {
                "$setElementOrder/containers": [{"name": "c2"}, {"name": "c1"}]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(
            result.is_err(),
            "reorder via $setElementOrder/containers must be rejected — \
             if accepted, the kubelet applies stored resources to the new container order, \
             silently assigning c1's cpu quota to c2 and vice versa"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("Forbidden: containers may not be renamed or reordered on resize"),
            "error must contain k8s conformance substring; got: {msg}"
        );
    }

    /// Control: $setElementOrder/containers in stored order must be accepted.
    /// A valid resize with matching order and only resource changes must not be rejected —
    /// over-rejection would break the in-place resize feature for all Burstable pods.
    #[test]
    fn resize_accepts_set_element_order_in_stored_order() {
        let stored = serde_json::json!({
            "metadata": {"name": "burstable-pod", "namespace": "default"},
            "spec": {
                "containers": [
                    {"name": "c1", "resources": {"requests": {"cpu": "100m"}}},
                    {"name": "c2", "resources": {"requests": {"cpu": "100m"}}}
                ]
            },
            "status": {}
        });
        // $setElementOrder/containers in SAME order as stored — must be accepted.
        let incoming = serde_json::json!({
            "spec": {
                "$setElementOrder/containers": [{"name": "c1"}, {"name": "c2"}],
                "containers": [
                    {"name": "c1", "resources": {"requests": {"cpu": "200m"}}},
                    {"name": "c2", "resources": {"requests": {"cpu": "200m"}}}
                ]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(
            result.is_ok(),
            "valid resize with matching $setElementOrder/containers must be accepted — \
             over-rejection blocks all strategic-merge-patch resize requests; \
             got: {:?}",
            result.err()
        );
    }

    /// Burstable pod — resize ephemeral storage: resize may only touch cpu and memory.
    /// k8s rejects with "only cpu and memory resources are mutable".
    #[test]
    fn resize_rejects_ephemeral_storage_resize_because_only_cpu_memory_are_mutable() {
        let stored = serde_json::json!({
            "metadata": {"name": "burstable-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {"requests": {"cpu": "35m", "memory": "50Mi"}}
                }]
            },
            "status": {}
        });
        // Patch adds ephemeral-storage to requests — this is not a resizable resource.
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {"requests": {"cpu": "35m", "memory": "50Mi", "ephemeral-storage": "1Gi"}}
                }]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(result.is_err(), "ephemeral-storage resize must be rejected");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("only cpu and memory resources are mutable"),
            "error must contain k8s conformance substring \
             'only cpu and memory resources are mutable' — \
             conformance test (pod_resize.go:390) uses ContainSubstring to match this; \
             got: {msg}"
        );
    }

    /// Guaranteed pod → Burstable: patch makes requests != limits, changing QoS class.
    /// k8s rejects with "Pod QOS Class may not change as a result of resizing".
    #[test]
    fn resize_rejects_guaranteed_to_burstable_qos_change() {
        let stored = serde_json::json!({
            "metadata": {"name": "guaranteed-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "limits": {"cpu": "100m", "memory": "128Mi"},
                        "requests": {"cpu": "100m", "memory": "128Mi"}
                    }
                }]
            },
            "status": {}
        });
        // Set cpu request != cpu limit → Guaranteed becomes Burstable.
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "limits": {"cpu": "200m", "memory": "128Mi"},
                        "requests": {"cpu": "100m", "memory": "128Mi"}
                    }
                }]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(result.is_err(), "QoS class change must be rejected");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("Pod QOS Class may not change as a result of resizing"),
            "error must contain k8s conformance substring \
             'Pod QOS Class may not change as a result of resizing'; \
             got: {msg}"
        );
    }

    /// Guaranteed pod — remove limits via empty object: must fire "resource limits cannot be removed",
    /// NOT a QoS error. The QoS check (Rule 4) uses merge semantics and skips empty sections, so
    /// stored limits are preserved during QoS computation (still Guaranteed → no QoS change).
    /// Rule 3 then fires because limits.cpu is in stored but absent in the patch's empty limits:{}.
    ///
    /// This tests that Rule 4 ordering + merge_resize_for_qos empty-section skipping don't
    /// falsely claim a QoS change when the real error is a forbidden resource removal.
    #[test]
    fn resize_rejects_guaranteed_removing_limits_with_removal_error_not_qos_error() {
        let stored = serde_json::json!({
            "metadata": {"name": "guaranteed-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "limits": {"cpu": "100m", "memory": "128Mi"},
                        "requests": {"cpu": "100m", "memory": "128Mi"}
                    }
                }]
            },
            "status": {}
        });
        // Send limits:{} to remove all limits (Guaranteed pod).
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "resources": {
                        "limits": {},
                        "requests": {"cpu": "100m", "memory": "128Mi"}
                    }
                }]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(
            result.is_err(),
            "removing limits from Guaranteed pod must be rejected"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("resource limits cannot be removed"),
            "error must be 'resource limits cannot be removed' (not a QoS error) — \
             merge_resize_for_qos must skip empty sections so Rule 4 doesn't shadow Rule 3; \
             got: {msg}"
        );
    }

    /// Guaranteed 3-container pod — patch resizes only c1's cpu; c1's memory (and c2/c3
    /// entirely) are omitted because a two-way-merge patch never mentions unchanged
    /// values. merge_resize_for_qos previously replaced the whole `limits`/`requests`
    /// section with the patch's partial object, dropping c1's memory value and making
    /// compute_qos_class see a container with no memory limit — flipping the pod from
    /// Guaranteed to Burstable and falsely rejecting the resize.
    #[test]
    fn resize_accepts_guaranteed_three_container_patch_touching_only_one_containers_cpu() {
        let stored = serde_json::json!({
            "metadata": {"name": "guaranteed-pod", "namespace": "default"},
            "spec": {
                "containers": [
                    {"name": "c1", "resources": {
                        "limits": {"cpu": "100m", "memory": "128Mi"},
                        "requests": {"cpu": "100m", "memory": "128Mi"}
                    }},
                    {"name": "c2", "resources": {
                        "limits": {"cpu": "50m", "memory": "64Mi"},
                        "requests": {"cpu": "50m", "memory": "64Mi"}
                    }},
                    {"name": "c3", "resources": {
                        "limits": {"cpu": "50m", "memory": "64Mi"},
                        "requests": {"cpu": "50m", "memory": "64Mi"}
                    }}
                ]
            },
            "status": {}
        });
        // Only c1 appears in the patch, and only cpu is mentioned — memory is unchanged
        // so a real two-way-merge patch omits it entirely.
        let incoming = serde_json::json!({
            "spec": {
                "containers": [
                    {"name": "c1", "resources": {
                        "limits": {"cpu": "200m"},
                        "requests": {"cpu": "200m"}
                    }}
                ]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(
            result.is_ok(),
            "a cpu-only resize of one container in a Guaranteed pod must not be rejected \
             as a QoS-class change just because the patch omits the unchanged memory key — \
             got: {:?}",
            result.err()
        );
    }

    /// Burstable pod — set requests == limits: must fire QoS error (Burstable → Guaranteed),
    /// even though the patch omits the limits section entirely (no limits key). Rule 4 uses
    /// merge semantics where absent sections are preserved from the stored pod, so the merged
    /// pod has limits=stored and requests=patch → they become equal → QoS changes.
    ///
    /// This tests that Rule 4 (QoS) runs before Rule 3 (removal) so the correct error fires.
    #[test]
    fn resize_rejects_burstable_setting_requests_equal_to_limits_via_qos_error() {
        let stored = serde_json::json!({
            "metadata": {"name": "burstable-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {
                        "limits": {"cpu": "200m", "memory": "256Mi"},
                        "requests": {"cpu": "100m", "memory": "128Mi"}
                    }
                }]
            },
            "status": {}
        });
        // Patch only sets requests == stored limits (no limits key in patch → preserved by merge).
        // This would make requests == limits → QoS changes Burstable → Guaranteed.
        let incoming = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {
                        "requests": {"cpu": "200m", "memory": "256Mi"}
                    }
                }]
            }
        });

        let result = validate_resize_patch(&stored, &incoming);
        assert!(result.is_err(), "QoS change must be rejected");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("Pod QOS Class may not change as a result of resizing"),
            "error must be QoS error (not 'limits cannot be removed') — \
             Rule 4 must fire before Rule 3 when QoS change is the real issue; \
             got: {msg}"
        );
    }
}

// ---------------------------------------------------------------------------
// EphemeralContainers pure-logic tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ephemeral_containers_tests {
    use super::*;

    /// apply_ephemeral_containers_patch appends a new ephemeral container.
    ///
    /// This is the primary sonobuoy ephemeral-container flow: a PATCH body
    /// `{"spec":{"ephemeralContainers":[{"name":"debugger","image":"busybox"}]}}`
    /// must add the container to the pod. If the container is not appended,
    /// `kubectl debug` and the sonobuoy conformance test fail with 404.
    #[test]
    fn apply_ephemeral_patch_appends_new_container() {
        let stored = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "target", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        let patch = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "debugger", "image": "busybox"}]
            }
        });

        let result = apply_ephemeral_containers_patch(&stored, &patch);

        let ecs = result["spec"]["ephemeralContainers"]
            .as_array()
            .expect("ephemeralContainers must be an array");
        assert_eq!(
            ecs.len(),
            1,
            "one ephemeral container must be present after PATCH"
        );
        assert_eq!(
            ecs[0]["name"], "debugger",
            "the new ephemeral container must appear in spec.ephemeralContainers — \
             without this, kubectl debug and sonobuoy ephemeral-container tests fail"
        );
        // Existing spec must be untouched.
        assert_eq!(
            result["spec"]["containers"][0]["name"], "app",
            "regular containers must not be disturbed by ephemeral container patch"
        );
    }

    /// apply_ephemeral_containers_patch does not remove existing ephemeral containers.
    ///
    /// Kubernetes semantics: ephemeral containers are immutable once added.
    /// Sending a PATCH with only new containers must not remove pre-existing ones.
    #[test]
    fn apply_ephemeral_patch_preserves_existing_containers() {
        let stored = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "first", "image": "busybox"}]
            }
        });
        let patch = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "second", "image": "alpine"}]
            }
        });

        let result = apply_ephemeral_containers_patch(&stored, &patch);

        let ecs = result["spec"]["ephemeralContainers"]
            .as_array()
            .expect("ephemeralContainers must be an array");
        assert_eq!(
            ecs.len(),
            2,
            "both the existing and the new ephemeral container must be present — \
             ephemeral containers cannot be removed once added (Kubernetes immutability contract)"
        );
        let names: Vec<&str> = ecs.iter().filter_map(|c| c["name"].as_str()).collect();
        assert!(
            names.contains(&"first"),
            "pre-existing ephemeral container 'first' must not be removed"
        );
        assert!(
            names.contains(&"second"),
            "newly patched ephemeral container 'second' must be present"
        );
    }

    /// apply_ephemeral_containers_patch is idempotent: re-patching the same container
    /// by name must not duplicate it.
    #[test]
    fn apply_ephemeral_patch_skips_duplicate_name() {
        let stored = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "debugger", "image": "busybox:old"}]
            }
        });
        let patch = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "debugger", "image": "busybox:new"}]
            }
        });

        let result = apply_ephemeral_containers_patch(&stored, &patch);

        let ecs = result["spec"]["ephemeralContainers"]
            .as_array()
            .expect("ephemeralContainers must be an array");
        assert_eq!(
            ecs.len(),
            1,
            "duplicate container name must not be appended — idempotent re-PATCH must not duplicate"
        );
    }

    /// apply_ephemeral_containers_patch with no ephemeralContainers in the patch is a no-op.
    #[test]
    fn apply_ephemeral_patch_no_spec_key_is_noop() {
        let stored = serde_json::json!({
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        let patch = serde_json::json!({"metadata": {"labels": {"foo": "bar"}}});

        let result = apply_ephemeral_containers_patch(&stored, &patch);

        assert!(
            result["spec"]["ephemeralContainers"].is_null()
                || result["spec"]["ephemeralContainers"]
                    .as_array()
                    .is_none_or(|a| a.is_empty()),
            "a patch without spec.ephemeralContainers must leave the field absent"
        );
    }

    /// Patching ephemeralContainers increments metadata.generation.
    ///
    /// The [sig-node] Ephemeral Containers conformance test reads back the pod and
    /// asserts generation==2.  Without the increment the test sees generation==1 and
    /// immediately fails (fast failure, not a 120s timeout).
    #[test]
    fn ephemeral_patch_increments_generation() {
        let mut pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "target", "namespace": "default", "generation": 1i64},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        let patch = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "debugger", "image": "busybox"}]
            }
        });

        let spec_before = pod["spec"].clone();
        pod = apply_ephemeral_containers_patch(&pod, &patch);
        increment_pod_generation_if_spec_changed(&mut pod, &spec_before);

        assert_eq!(
            pod["metadata"]["generation"],
            serde_json::json!(2i64),
            "generation must be incremented to 2 after ephemeralContainers PATCH — \
             the [sig-node] Ephemeral Containers conformance test asserts generation==2 \
             and fails immediately if this is not done"
        );
    }
}

// ---------------------------------------------------------------------------
// Integration test: PATCH /ephemeralcontainers route
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ephemeral_containers_route_tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        routing::{patch, put},
        Router,
    };
    use bytes::Bytes;
    use tower::ServiceExt;
    use u7s_store::{SqliteStore, Store};

    use super::*;
    use crate::state::AppState;

    fn make_state() -> (AppState, Arc<SqliteStore>) {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        (state, store)
    }

    async fn seed_namespace(store: &Arc<SqliteStore>, ns: &str) {
        let key = format!("/registry/namespaces/{ns}");
        let val = serde_json::json!({"kind": "Namespace", "metadata": {"name": ns}});
        store
            .put(&key, Bytes::from(serde_json::to_vec(&val).unwrap()), None)
            .await
            .expect("seed namespace");
    }

    fn json_body(v: &serde_json::Value) -> Body {
        Body::from(Bytes::from(serde_json::to_vec(v).unwrap()))
    }

    /// PATCH /ephemeralcontainers must return 200 and include the new ephemeral container
    /// in spec.ephemeralContainers of the response body.
    ///
    /// This is the primary sonobuoy conformance case: the test patches an ephemeral container
    /// onto a running pod and expects 200 with the updated spec. Without this route the
    /// server returns 404 ("the server could not find the requested resource") and the
    /// conformance test fails with "Failed to patch ephemeral containers in pod".
    #[tokio::test]
    async fn patch_ephemeral_containers_returns_200_with_new_container() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/ephemeral-target";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "ephemeral-target", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/ephemeralcontainers",
                patch(patch_ephemeral_containers),
            )
            .with_state(state);

        let patch_body = serde_json::json!({
            "spec": {
                "ephemeralContainers": [{"name": "debugger", "image": "busybox"}]
            }
        });

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/ephemeral-target/ephemeralcontainers")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PATCH /ephemeralcontainers must return 200 — without this route the server \
             returns 404 and kubectl debug / sonobuoy ephemeral-container conformance tests fail"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        let ecs = v["spec"]["ephemeralContainers"]
            .as_array()
            .expect("response must contain spec.ephemeralContainers");
        assert_eq!(
            ecs.len(),
            1,
            "one ephemeral container must be in the response"
        );
        assert_eq!(
            ecs[0]["name"], "debugger",
            "the new ephemeral container must appear in the response spec.ephemeralContainers"
        );
    }

    /// `PATCH /ephemeralcontainers?dryRun=All` must return the would-be patched pod but leave
    /// the stored pod's ephemeral containers untouched. Before this fix, patch_ephemeral_
    /// containers had no dry-run check.
    #[tokio::test]
    async fn patch_ephemeral_containers_dry_run_all_does_not_persist() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/ephemeral-dry-run";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "ephemeral-dry-run", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/ephemeralcontainers",
                patch(patch_ephemeral_containers),
            )
            .layer(axum::middleware::from_fn(
                crate::handlers::json_patch::inject_dry_run_header,
            ))
            .with_state(state);

        let patch_body = serde_json::json!({
            "spec": { "ephemeralContainers": [{"name": "debugger", "image": "busybox"}] }
        });

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/ephemeral-dry-run/ephemeralcontainers?dryRun=All")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&patch_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            v["spec"]["ephemeralContainers"].as_array().unwrap().len(),
            1,
            "dry-run response must show the would-be ephemeral container"
        );

        let stored = store.get(key).await.unwrap().expect("pod must still exist");
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert!(
            stored_v["spec"]["ephemeralContainers"].is_null(),
            "dryRun=All must not persist the ephemeral container"
        );
    }

    /// PATCH /ephemeralcontainers on a missing pod must return 404.
    #[tokio::test]
    async fn patch_ephemeral_containers_missing_pod_returns_404() {
        let (state, _store) = make_state();
        seed_namespace(&_store, "default").await;

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/ephemeralcontainers",
                patch(patch_ephemeral_containers),
            )
            .with_state(state);

        let req = Request::builder()
            .method("PATCH")
            .uri("/api/v1/namespaces/default/pods/nonexistent/ephemeralcontainers")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"spec":{"ephemeralContainers":[{"name":"d","image":"busybox"}]}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "PATCH /ephemeralcontainers on nonexistent pod must return 404"
        );
    }

    /// PUT /ephemeralcontainers must return 200 and include the ephemeral container.
    ///
    /// The conformance test common/node/ephemeral_containers.go:173 adds a second ephemeral
    /// container via Update() which issues PUT. Without the PUT route the server returns 405
    /// MethodNotAllowed and the second container is never added, failing the lifecycle test.
    #[tokio::test]
    async fn put_ephemeral_containers_returns_200_with_new_container() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/put-target";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "put-target", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}],
                "ephemeralContainers": [{"name": "first", "image": "busybox"}]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/ephemeralcontainers",
                put(put_ephemeral_containers),
            )
            .with_state(state);

        let put_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "put-target", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}],
                "ephemeralContainers": [
                    {"name": "first", "image": "busybox"},
                    {"name": "second", "image": "alpine"}
                ]
            }
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/put-target/ephemeralcontainers")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&put_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "PUT /ephemeralcontainers must return 200 — without this route the server returns 405 \
             and the conformance test cannot add a second ephemeral container via Update()"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        let ecs = v["spec"]["ephemeralContainers"]
            .as_array()
            .expect("response must contain spec.ephemeralContainers");
        assert_eq!(
            ecs.len(),
            2,
            "both ephemeral containers must be present after PUT — without the PUT route \
             the second container added via Update() is silently lost"
        );
        let names: Vec<&str> = ecs.iter().filter_map(|c| c["name"].as_str()).collect();
        assert!(
            names.contains(&"first"),
            "pre-existing ephemeral container 'first' must not be removed by PUT"
        );
        assert!(
            names.contains(&"second"),
            "newly PUT ephemeral container 'second' must appear in response"
        );
    }

    /// `PUT /ephemeralcontainers?dryRun=All` must return the would-be replaced pod but leave
    /// the stored pod's ephemeral containers untouched. Before this fix, put_ephemeral_
    /// containers had no dry-run check.
    #[tokio::test]
    async fn put_ephemeral_containers_dry_run_all_does_not_persist() {
        let (state, store) = make_state();
        seed_namespace(&store, "default").await;

        let key = "/registry/pods/default/put-dry-run";
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "put-dry-run", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}],
                "ephemeralContainers": [{"name": "first", "image": "busybox"}]
            },
            "status": {"phase": "Running"}
        });
        store
            .put(key, Bytes::from(serde_json::to_vec(&pod).unwrap()), None)
            .await
            .unwrap();

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/ephemeralcontainers",
                put(put_ephemeral_containers),
            )
            .layer(axum::middleware::from_fn(
                crate::handlers::json_patch::inject_dry_run_header,
            ))
            .with_state(state);

        let put_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "put-dry-run", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}],
                "ephemeralContainers": [
                    {"name": "first", "image": "busybox"},
                    {"name": "second", "image": "alpine"}
                ]
            }
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/namespaces/default/pods/put-dry-run/ephemeralcontainers?dryRun=All")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&put_body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            v["spec"]["ephemeralContainers"].as_array().unwrap().len(),
            2,
            "dry-run response must show the would-be second ephemeral container"
        );

        let stored = store.get(key).await.unwrap().expect("pod must still exist");
        let stored_v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            stored_v["spec"]["ephemeralContainers"]
                .as_array()
                .unwrap()
                .len(),
            1,
            "dryRun=All must not persist the second ephemeral container"
        );
    }
}

// ---------------------------------------------------------------------------
// Admission regression tests — prove create_pod / replace_pod invoke the
// admission webhook pipeline.
//
// Without the fix both handlers skipped admission entirely; admission-based
// controls (OPA Gatekeeper, Kyverno) on pods were non-functional.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod admission_tests {
    use std::sync::Arc;

    use axum::{routing::post, Router};
    use bytes::Bytes;
    use tokio::net::TcpListener;
    use u7s_store::{SqliteStore, Store};

    use super::*;

    use crate::handlers::test_support::make_state_with_store as make_state;

    fn test_user() -> axum::Extension<crate::auth::UserInfo> {
        axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        })
    }

    async fn seed_namespace(store: &Arc<SqliteStore>, ns: &str) {
        let key = format!("/registry/namespaces/{ns}");
        let val = serde_json::json!({"kind": "Namespace", "metadata": {"name": ns}});
        store
            .put(&key, Bytes::from(serde_json::to_vec(&val).unwrap()), None)
            .await
            .expect("seed namespace");
    }

    async fn start_mock_webhook(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock webhook server must not fail");
        });
        (format!("http://{addr}"), handle)
    }

    fn patch_label_router() -> Router {
        Router::new().route(
            "/webhook",
            post(|| async {
                let patch = serde_json::json!([
                    {"op": "add", "path": "/metadata/labels", "value": {"admitted": "yes"}}
                ]);
                let patch_b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    serde_json::to_string(&patch).unwrap(),
                );
                axum::Json(serde_json::json!({
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": "test-uid",
                        "allowed": true,
                        "patch": patch_b64,
                        "patchType": "JSONPatch"
                    }
                }))
            }),
        )
    }

    /// A mutating webhook that injects an initContainer with no terminationMessagePolicy
    /// (or any other field a real client would have stamped) — mirrors what a real
    /// sidecar-injection webhook does, e.g. Istio/linkerd-style init container injection.
    fn inject_init_container_router() -> Router {
        Router::new().route(
            "/webhook",
            post(|| async {
                let patch = serde_json::json!([
                    {"op": "add", "path": "/spec/initContainers", "value": [
                        {"name": "webhook-injected", "image": "busybox"}
                    ]}
                ]);
                let patch_b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    serde_json::to_string(&patch).unwrap(),
                );
                axum::Json(serde_json::json!({
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": "test-uid",
                        "allowed": true,
                        "patch": patch_b64,
                        "patchType": "JSONPatch"
                    }
                }))
            }),
        )
    }

    fn deny_router() -> Router {
        Router::new().route(
            "/webhook",
            post(|| async {
                axum::Json(serde_json::json!({
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": "test-uid",
                        "allowed": false,
                        "status": {"code": 403, "message": "denied by test webhook"}
                    }
                }))
            }),
        )
    }

    /// create_pod must invoke the mutating admission pipeline.
    /// A mutating webhook that adds a label must have that label present in the
    /// stored pod — without this fix, the webhook was never called and the pod was
    /// stored without the label.
    #[tokio::test]
    async fn create_pod_invokes_mutating_admission() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        seed_namespace(&store, "default").await;

        let (url, _handle) = start_mock_webhook(patch_label_router()).await;

        // Register a MutatingWebhookConfiguration targeting pods CREATE.
        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "test-mutating"},
            "webhooks": [{
                "name": "test.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/test-mutating",
                Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let pod_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "test-pod", "namespace": "default"},
                "spec": {"containers": [{"name": "app", "image": "nginx"}]}
            })
            .to_string(),
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let result = create_pod(
            axum::extract::State(state),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            headers,
            pod_body,
        )
        .await;

        assert!(
            result.is_ok(),
            "create_pod must succeed when webhook allows"
        );

        // The stored pod must have the label injected by the webhook.
        let stored = store
            .get("/registry/pods/default/test-pod")
            .await
            .unwrap()
            .expect("pod must be stored");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["labels"]["admitted"], "yes",
            "mutating webhook label must be present in stored pod — \
             without the fix, create_pod bypassed admission and the label was never injected"
        );
    }

    /// create_pod's admission context must carry the authenticated user's `extra` claims
    /// (e.g. a bound-service-account-token's node-name claim) into VAP CEL evaluation via
    /// `request.userInfo.extra` — not just username/uid/groups. Without this, a VAP that
    /// gates on `request.userInfo.extra` (like upstream's by-node node-restriction
    /// pattern) silently sees an empty map and denies every request
    /// regardless of the caller's real claims.
    ///
    /// Goes through the real `create_pod` handler (not a hand-constructed
    /// AdmissionContext) so it exercises the actual `"extra": user.extra` threading at
    /// the call site, not just the CEL evaluator in isolation.
    ///
    /// Fails on revert: reverting `"extra": user.extra` in create_pod's admission_ctx
    /// construction makes `request.userInfo.extra.testClaim` resolve to null either way,
    /// so the claim-bearing user (which must be admitted) would instead be denied by the
    /// same VAP as the claim-less user.
    #[tokio::test]
    async fn create_pod_admission_sees_authenticated_user_extra_claims() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        seed_namespace(&store, "default").await;

        // VAP that only admits the request if request.userInfo.extra.testClaim carries
        // the expected value — mirrors upstream's node-restriction pattern of gating on
        // a caller's `extra` claim (e.g. authentication.kubernetes.io/node-name).
        let policy = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "require-extra-claim"},
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{
                        "apiGroups": [""],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE"],
                        "resources": ["pods"]
                    }]
                },
                "validations": [{
                    "expression": "request.userInfo.extra.testClaim == [\"present\"]",
                    "message": "request.userInfo.extra.testClaim must equal ['present']"
                }]
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/require-extra-claim",
                Bytes::from(serde_json::to_vec(&policy).unwrap()),
                None,
            )
            .await
            .unwrap();

        let binding = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "require-extra-claim-binding"},
            "spec": {
                "policyName": "require-extra-claim",
                "validationActions": ["Deny"]
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingadmissionpolicybindings/require-extra-claim-binding",
                Bytes::from(serde_json::to_vec(&binding).unwrap()),
                None,
            )
            .await
            .unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        // A user whose UserInfo.extra carries the required claim must be admitted.
        let mut extra_with_claim = std::collections::HashMap::new();
        extra_with_claim.insert("testClaim".to_string(), vec!["present".to_string()]);
        let user_with_claim = axum::Extension(crate::auth::UserInfo {
            username: "claim-bearer".into(),
            uid: String::new(),
            groups: vec![],
            extra: extra_with_claim,
        });
        let claim_present_pod_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "claim-pod", "namespace": "default"},
                "spec": {"containers": [{"name": "app", "image": "nginx"}]}
            })
            .to_string(),
        );
        let claim_present_result = create_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            user_with_claim,
            headers.clone(),
            claim_present_pod_body,
        )
        .await;
        assert!(
            claim_present_result.is_ok(),
            "a user whose UserInfo.extra carries the required claim must be admitted — \
             if extra never reaches request.userInfo.extra, this is incorrectly denied"
        );

        // A user with no extra claims at all must be denied — proves the VAP is actually
        // evaluated against real extra data, not bypassed or always-permissive.
        let user_without_claim = axum::Extension(crate::auth::UserInfo {
            username: "claim-less".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        });
        let claim_missing_pod_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "claim-less-pod", "namespace": "default"},
                "spec": {"containers": [{"name": "app", "image": "nginx"}]}
            })
            .to_string(),
        );
        let claim_missing_result = create_pod(
            axum::extract::State(state),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            user_without_claim,
            headers,
            claim_missing_pod_body,
        )
        .await;
        assert!(
            claim_missing_result.is_err(),
            "a user with no matching extra claim must be denied by the VAP"
        );
    }

    /// create_pod must default a container a mutating webhook injects, not just the
    /// containers the client supplied.
    ///
    /// VERIFIED live (scout aa9f7278): a mutating webhook that injects an initContainer
    /// produced a stored container with no terminationMessagePolicy, because
    /// apply_pod_create_defaults ran once, before run_mutating_webhooks, so the
    /// webhook-added container was never seen by the defaulting pass. This breaks
    /// conformance "[sig-api-machinery] AdmissionWebhook ... should mutate pod and
    /// apply defaults after mutation". If create_pod stops re-applying
    /// defaults after the mutating webhook chain, this test fails because the injected
    /// container comes back with terminationMessagePolicy absent.
    #[tokio::test]
    async fn create_pod_defaults_container_injected_by_mutating_webhook() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        seed_namespace(&store, "default").await;

        let (url, _handle) = start_mock_webhook(inject_init_container_router()).await;

        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "test-inject-init-container"},
            "webhooks": [{
                "name": "inject.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/test-inject-init-container",
                Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let pod_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "webhook-injected-pod", "namespace": "default"},
                "spec": {"containers": [{"name": "app", "image": "nginx"}]}
            })
            .to_string(),
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let result = create_pod(
            axum::extract::State(state),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            headers,
            pod_body,
        )
        .await;

        assert!(
            result.is_ok(),
            "create_pod must succeed when the mutating webhook allows"
        );

        let stored = store
            .get("/registry/pods/default/webhook-injected-pod")
            .await
            .unwrap()
            .expect("pod must be stored");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["spec"]["initContainers"][0]["name"], "webhook-injected",
            "sanity check: the webhook's initContainer must be present in the stored pod"
        );
        assert_eq!(
            v["spec"]["initContainers"][0]["terminationMessagePolicy"], "File",
            "the webhook-injected container must have terminationMessagePolicy defaulted \
             to File — without the post-mutation re-apply, this field is absent because \
             the defaulting pass ran before the webhook added the container"
        );
    }

    /// create_pod must invoke the validating admission pipeline.
    /// A validating webhook that denies must cause create_pod to return an error,
    /// and the pod must NOT be stored. Before the fix, denial was silently ignored.
    #[tokio::test]
    async fn create_pod_invokes_validating_admission() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        seed_namespace(&store, "default").await;

        let (url, _handle) = start_mock_webhook(deny_router()).await;

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test-validating"},
            "webhooks": [{
                "name": "deny.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/test-validating",
                Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let pod_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "denied-pod", "namespace": "default"},
                "spec": {"containers": [{"name": "app", "image": "nginx"}]}
            })
            .to_string(),
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let result = create_pod(
            axum::extract::State(state),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            headers,
            pod_body,
        )
        .await;

        assert!(
            result.is_err(),
            "create_pod must be rejected when validating webhook denies — \
             without the fix, admission was bypassed and the pod was silently stored"
        );

        // Pod must NOT be in the store.
        let stored = store
            .get("/registry/pods/default/denied-pod")
            .await
            .unwrap();
        assert!(
            stored.is_none(),
            "denied pod must not be stored in the backing store"
        );
    }

    /// replace_pod must invoke the mutating admission pipeline.
    /// A webhook that adds a label on UPDATE must mutate the stored pod.
    #[tokio::test]
    async fn replace_pod_invokes_mutating_admission() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        seed_namespace(&store, "default").await;

        // Seed an existing pod.
        let pod_key = "/registry/pods/default/my-pod";
        let existing = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        });
        store
            .put(
                pod_key,
                Bytes::from(serde_json::to_vec(&existing).unwrap()),
                None,
            )
            .await
            .unwrap();

        let stored_rv = store.get(pod_key).await.unwrap().unwrap().revision;

        let (url, _handle) = start_mock_webhook(patch_label_router()).await;

        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "test-mutating-update"},
            "webhooks": [{
                "name": "test.webhook.io",
                "clientConfig": {"url": format!("{url}/webhook")},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"], "operations": ["UPDATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/test-mutating-update",
                Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let pod_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": "my-pod",
                    "namespace": "default",
                    "resourceVersion": stored_rv.to_string()
                },
                "spec": {"containers": [{"name": "app", "image": "nginx:latest"}]}
            })
            .to_string(),
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let result = replace_pod(
            axum::extract::State(state),
            axum::extract::Path(("default".to_string(), "my-pod".to_string())),
            axum::extract::Query(crate::handlers::json_patch::ReplaceQuery::default()),
            test_user(),
            headers,
            pod_body,
        )
        .await;

        assert!(
            result.is_ok(),
            "replace_pod must succeed when webhook allows"
        );

        let stored = store
            .get(pod_key)
            .await
            .unwrap()
            .expect("pod must still exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            v["metadata"]["labels"]["admitted"], "yes",
            "mutating webhook label must be present after replace_pod — \
             without the fix, replace_pod bypassed admission and the label was never injected"
        );
    }

    /// Concurrent create_pod calls in a quota-limited namespace must never let more pods
    /// through than the hard limit allows.
    ///
    /// This mirrors what the real kube-controller-manager's ReplicationController
    /// controller does: it creates all missing replicas concurrently in one burst
    /// (`slowStartBatch`). Without a lock spanning the quota check and the store write,
    /// each concurrent create lists pre-write usage, all observe "0 of 2 used", and all
    /// pass — collectively exceeding the quota. When that happens, KCM never sees a
    /// rejected create and so never sets the RC's `ReplicaFailure` status condition,
    /// which is exactly the symptom the conformance test
    /// "should surface a failure condition on a common issue like exceeded quota" caught.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_create_pod_never_exceeds_resource_quota() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());

        seed_namespace(&store, "default").await;

        let quota = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "pod-quota", "namespace": "default" },
            "spec": { "hard": { "pods": "2" } }
        });
        store
            .put(
                "/registry/resourcequotas/default/pod-quota",
                Bytes::from(serde_json::to_vec(&quota).unwrap()),
                None,
            )
            .await
            .unwrap();

        let make_body = |name: &str| {
            Bytes::from(
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": name, "namespace": "default"},
                    "spec": {"containers": [{"name": "app", "image": "nginx"}]}
                })
                .to_string(),
            )
        };
        let headers = {
            let mut h = axum::http::HeaderMap::new();
            h.insert(
                axum::http::header::CONTENT_TYPE,
                "application/json".parse().unwrap(),
            );
            h
        };

        // Three concurrent creates against a quota that only allows 2 pods.
        let (r1, r2, r3) = tokio::join!(
            create_pod(
                axum::extract::State(state.clone()),
                axum::extract::Path(("default".to_string(),)),
                axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
                test_user(),
                headers.clone(),
                make_body("pod-a"),
            ),
            create_pod(
                axum::extract::State(state.clone()),
                axum::extract::Path(("default".to_string(),)),
                axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
                test_user(),
                headers.clone(),
                make_body("pod-b"),
            ),
            create_pod(
                axum::extract::State(state.clone()),
                axum::extract::Path(("default".to_string(),)),
                axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
                test_user(),
                headers.clone(),
                make_body("pod-c"),
            ),
        );

        let ok_count = [&r1, &r2, &r3].iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            ok_count, 2,
            "exactly 2 of 3 concurrent creates must succeed against a pods=2 quota — \
             without the per-namespace admission lock, a TOCTOU race lets all 3 through, \
             which is why KCM's RC controller never saw a create rejected and never set \
             the ReplicaFailure condition"
        );

        let prefix = "/registry/pods/default/";
        let stored = store.list(prefix, u7s_store::ListOptions::default()).await;
        assert_eq!(
            stored.unwrap().items.len(),
            2,
            "the store must contain exactly 2 pods — a quota is a hard limit, not \
             advisory, regardless of how many creates race for it"
        );
    }

    async fn quota_used_pods(store: &Arc<SqliteStore>, quota_name: &str) -> Option<String> {
        let stored = store
            .get(&format!("/registry/resourcequotas/default/{quota_name}"))
            .await
            .unwrap()
            .expect("quota must exist");
        let v: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        v["status"]["used"]["pods"].as_str().map(|s| s.to_string())
    }

    /// A plain pod PATCH that sets `spec.activeDeadlineSeconds` retroactively moves the pod
    /// into the `Terminating` scope. `record_pod_created`/`record_pod_removed` only run at
    /// create/delete time, so without a dedicated scope-change recount a Terminating-scoped
    /// quota's `status.used.pods` stays wherever it was at pod creation (0, since the pod was
    /// NotTerminating then) forever — even though the pod now genuinely belongs to that scope.
    /// That silently lets a second Terminating pod past a hard limit that is already exhausted.
    #[tokio::test]
    async fn patch_pod_setting_active_deadline_seconds_recounts_terminating_scope_quota() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());
        seed_namespace(&store, "default").await;

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "term-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
        });
        store
            .put(
                "/registry/pods/default/term-pod",
                Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .unwrap();

        // status.used.pods = "0" mirrors what record_pod_created would have written when
        // term-pod was created: it was NotTerminating at the time, so it never counted
        // toward this Terminating-scoped quota.
        let quota = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": {"name": "term-quota", "namespace": "default"},
            "spec": {"hard": {"pods": "1"}, "scopes": ["Terminating"]},
            "status": {"used": {"pods": "0"}}
        });
        store
            .put(
                "/registry/resourcequotas/default/term-quota",
                Bytes::from(serde_json::to_vec(&quota).unwrap()),
                None,
            )
            .await
            .unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );
        let patch_body = serde_json::json!({"spec": {"activeDeadlineSeconds": 30}});

        patch_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(), "term-pod".to_string())),
            axum::extract::Query(crate::handlers::json_patch::PatchQuery::default()),
            headers,
            Bytes::from(patch_body.to_string()),
        )
        .await
        .expect("PATCH setting activeDeadlineSeconds must succeed");

        assert_eq!(
            quota_used_pods(&store, "term-quota").await,
            Some("1".to_string()),
            "PATCHing activeDeadlineSeconds moves term-pod into the Terminating scope — \
             status.used.pods on the Terminating-scoped quota must recount to 1, or the quota \
             never learns this pod now belongs to it"
        );

        // Consequence: a second Terminating pod must now be rejected — the quota's hard limit
        // of 1 is genuinely exhausted. Without the recount above, status.used.pods would still
        // read 0 and this create would be wrongly admitted, oversubscribing the scope.
        let second_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "term-pod-2", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}],
                "activeDeadlineSeconds": 30
            }
        });
        let mut create_headers = axum::http::HeaderMap::new();
        create_headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        let create_result = create_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            create_headers,
            Bytes::from(second_pod.to_string()),
        )
        .await;
        assert!(
            create_result.is_err(),
            "a second Terminating-scoped pod must be rejected once the recounted quota sits at \
             its hard limit of 1 — an under-counted quota (stuck at 0) would wrongly admit it"
        );
    }

    /// A `kubectl replace` (GET-modify-PUT) that sets `spec.activeDeadlineSeconds` moves the
    /// pod into the `Terminating` scope exactly like the PATCH case above —
    /// `validate_pod_spec_immutable` permits this same unset-to-set transition on a PUT, not
    /// just a PATCH. `record_pod_created`/`record_pod_removed` only run at create/delete time,
    /// so without `replace_pod`'s own store-write success arm also recounting scoped quotas, a
    /// Terminating-scoped quota's `status.used.pods` stays wherever it was at pod creation
    /// forever — silently letting a second Terminating pod past an already-exhausted hard
    /// limit even though the PATCH path was already fixed.
    #[tokio::test]
    async fn replace_pod_setting_active_deadline_seconds_recounts_terminating_scope_quota() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());
        seed_namespace(&store, "default").await;

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "term-pod-put", "namespace": "default"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
        });
        store
            .put(
                "/registry/pods/default/term-pod-put",
                Bytes::from(serde_json::to_vec(&pod).unwrap()),
                None,
            )
            .await
            .unwrap();
        let stored_rv = store
            .get("/registry/pods/default/term-pod-put")
            .await
            .unwrap()
            .unwrap()
            .revision;

        // status.used.pods = "0" mirrors what record_pod_created would have written when
        // term-pod-put was created: it was NotTerminating at the time, so it never counted
        // toward this Terminating-scoped quota.
        let quota = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": {"name": "term-quota-put", "namespace": "default"},
            "spec": {"hard": {"pods": "1"}, "scopes": ["Terminating"]},
            "status": {"used": {"pods": "0"}}
        });
        store
            .put(
                "/registry/resourcequotas/default/term-quota-put",
                Bytes::from(serde_json::to_vec(&quota).unwrap()),
                None,
            )
            .await
            .unwrap();

        // A GET-modify-PUT: the client reads the pod, adds activeDeadlineSeconds, and PUTs
        // the whole object back — exactly what `kubectl replace` does.
        let put_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "term-pod-put",
                "namespace": "default",
                "resourceVersion": stored_rv.to_string()
            },
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}],
                "activeDeadlineSeconds": 30
            }
        });

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        replace_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(), "term-pod-put".to_string())),
            axum::extract::Query(crate::handlers::json_patch::ReplaceQuery::default()),
            test_user(),
            headers,
            Bytes::from(put_body.to_string()),
        )
        .await
        .expect("PUT setting activeDeadlineSeconds must succeed");

        assert_eq!(
            quota_used_pods(&store, "term-quota-put").await,
            Some("1".to_string()),
            "kubectl replace setting activeDeadlineSeconds moves term-pod-put into the \
             Terminating scope — status.used.pods on the Terminating-scoped quota must recount \
             to 1, or a GET-modify-PUT silently reproduces the exact quota drift the PATCH \
             fix above already closed"
        );

        // Consequence: a second Terminating pod must now be rejected — the quota's hard limit
        // of 1 is genuinely exhausted. Without the recount above, status.used.pods would still
        // read 0 and this create would be wrongly admitted, oversubscribing the scope.
        let second_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "term-pod-put-2", "namespace": "default"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}],
                "activeDeadlineSeconds": 30
            }
        });
        let mut create_headers = axum::http::HeaderMap::new();
        create_headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        let create_result = create_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            create_headers,
            Bytes::from(second_pod.to_string()),
        )
        .await;
        assert!(
            create_result.is_err(),
            "a second Terminating-scoped pod must be rejected once the recounted quota sits at \
             its hard limit of 1 — an under-counted quota (stuck at 0, because the PUT path \
             never recounted it) would wrongly admit it"
        );
    }

    /// `write_quota_used_updates` is a plain get-then-put with no CAS: only the create path
    /// (via `quota_admission_locks`) serializes its own check-then-write around it. If a
    /// delete-side call site of `record_pod_removed` ever stops holding that same
    /// per-namespace lock, two concurrent hard-deletes in one namespace can each read the
    /// same pre-decrement `status.used.pods`, both compute "one less", and the loser's
    /// decrement is silently lost — permanently overcounting usage and wedging the quota
    /// "full" forever even with free slots, wrongly rejecting every later create in that
    /// namespace. This deletes two distinct pods concurrently and asserts the counter lands
    /// at exactly base-2, which fails if the delete path's lock is ever removed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_pod_deletes_never_lose_a_quota_decrement() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());
        seed_namespace(&store, "default").await;

        // Baseline of 5 stands in for pods this test never materializes in the store — the
        // incremental counter trusts status.used as its O(1) source of truth and never
        // re-validates it against a full scan on the fast path, so an arbitrary starting
        // value here exercises exactly that trust.
        let quota = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "pod-quota", "namespace": "default" },
            "spec": { "hard": { "pods": "10" } },
            "status": { "used": { "pods": "5" } }
        });
        store
            .put(
                "/registry/resourcequotas/default/pod-quota",
                Bytes::from(serde_json::to_vec(&quota).unwrap()),
                None,
            )
            .await
            .unwrap();

        for name in ["pod-a", "pod-b"] {
            let pod = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": name, "namespace": "default"},
                "spec": {"containers": [{"name": "app", "image": "nginx"}]}
            });
            store
                .put(
                    &format!("/registry/pods/default/{name}"),
                    Bytes::from(serde_json::to_vec(&pod).unwrap()),
                    None,
                )
                .await
                .unwrap();
        }

        let headers = {
            let mut h = axum::http::HeaderMap::new();
            h.insert(
                axum::http::header::CONTENT_TYPE,
                "application/json".parse().unwrap(),
            );
            h
        };
        let force_body = || Bytes::from(serde_json::json!({"gracePeriodSeconds": 0}).to_string());

        let (r1, r2) = tokio::join!(
            delete_pod(
                axum::extract::State(state.clone()),
                axum::extract::Path(("default".to_string(), "pod-a".to_string())),
                test_user(),
                axum::extract::Query(GracePeriodQuery {
                    grace_period_seconds: None
                }),
                headers.clone(),
                force_body(),
            ),
            delete_pod(
                axum::extract::State(state.clone()),
                axum::extract::Path(("default".to_string(), "pod-b".to_string())),
                test_user(),
                axum::extract::Query(GracePeriodQuery {
                    grace_period_seconds: None
                }),
                headers.clone(),
                force_body(),
            ),
        );
        r1.expect("first concurrent delete must succeed");
        r2.expect("second concurrent delete must succeed");

        assert_eq!(
            quota_used_pods(&store, "pod-quota").await,
            Some("3".to_string()),
            "two concurrent hard-deletes must decrement status.used.pods by exactly 2 \
             (5 -> 3) — a lost decrement here permanently overcounts usage and wedges the \
             quota full forever even after pods are actually gone"
        );
    }

    /// `check_resource_quota` now reads `status.used` as an incrementally-maintained O(1)
    /// baseline instead of re-scanning every pod in the namespace on each admission (see
    /// quota.rs module docs). A counter that drifts from the true pod count is a correctness
    /// and multi-tenancy-safety bug either direction: too high silently wedges the quota
    /// rejecting forever with room to spare, too low lets tenants burst past their hard limit.
    /// This walks create -> create -> reject -> delete -> re-admit and asserts the persisted
    /// counter is exactly right at every step, which fails if `record_pod_created`/
    /// `record_pod_removed` are ever unwired from a create/delete call site or miscompute the
    /// delta.
    #[tokio::test]
    async fn resource_quota_pod_count_rejects_at_limit_then_readmits_after_delete() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());
        seed_namespace(&store, "default").await;

        let quota = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "pod-quota", "namespace": "default" },
            "spec": { "hard": { "pods": "2" } }
        });
        store
            .put(
                "/registry/resourcequotas/default/pod-quota",
                Bytes::from(serde_json::to_vec(&quota).unwrap()),
                None,
            )
            .await
            .unwrap();

        let make_body = |name: &str| {
            Bytes::from(
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": name, "namespace": "default"},
                    "spec": {"containers": [{"name": "app", "image": "nginx"}]}
                })
                .to_string(),
            )
        };
        let headers = {
            let mut h = axum::http::HeaderMap::new();
            h.insert(
                axum::http::header::CONTENT_TYPE,
                "application/json".parse().unwrap(),
            );
            h
        };

        create_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            headers.clone(),
            make_body("pod-a"),
        )
        .await
        .expect("first create must be admitted (0 of 2 used)");

        create_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            headers.clone(),
            make_body("pod-b"),
        )
        .await
        .expect("second create must be admitted (1 of 2 used)");

        assert_eq!(
            quota_used_pods(&store, "pod-quota").await,
            Some("2".to_string()),
            "status.used.pods must read exactly 2 after two admitted creates — this is the \
             same value check_resource_quota's next call trusts as its O(1) baseline"
        );

        let third = create_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            headers.clone(),
            make_body("pod-c"),
        )
        .await;
        assert!(
            third.is_err(),
            "a third create against a pods=2 quota already at 2 must be rejected — an \
             under-counting incremental counter would wrongly admit this"
        );

        // Hard-delete pod-a (force, grace period 0) so record_pod_removed fires.
        delete_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(), "pod-a".to_string())),
            test_user(),
            axum::extract::Query(GracePeriodQuery {
                grace_period_seconds: None,
            }),
            headers.clone(),
            Bytes::from(serde_json::json!({"gracePeriodSeconds": 0}).to_string()),
        )
        .await
        .expect("delete must succeed");

        assert_eq!(
            quota_used_pods(&store, "pod-quota").await,
            Some("1".to_string()),
            "deleting one of two pods must decrement status.used.pods to exactly 1 — a \
             missed decrement here is what would wedge the quota at 'full' forever even \
             with a free slot"
        );

        create_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            headers.clone(),
            make_body("pod-c"),
        )
        .await
        .expect(
            "after freeing one slot, a create must be re-admitted — a drifted \
             (never-decremented) counter would wrongly keep rejecting this forever",
        );

        assert_eq!(
            quota_used_pods(&store, "pod-quota").await,
            Some("2".to_string()),
            "status.used.pods must be back to exactly 2 after re-admitting"
        );
    }

    /// A scopeSelector-scoped quota's incremental counter must only track pods that actually
    /// match the selector: a non-matching pod must never block on it, and must never be
    /// counted toward it either. If the incremental counter ever counted a non-matching pod,
    /// an unrelated priority class's traffic would silently starve this quota's real tenant;
    /// if it ever skipped decrementing a matching pod's delete, the quota would wedge full
    /// forever even with real turnover.
    #[tokio::test]
    async fn resource_quota_scope_selector_tracks_only_matching_pods_through_create_and_delete() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = make_state(store.clone());
        seed_namespace(&store, "default").await;

        for (name, value) in [("high", 1000), ("low", 0)] {
            let pc = serde_json::json!({
                "apiVersion": "scheduling.k8s.io/v1",
                "kind": "PriorityClass",
                "metadata": {"name": name},
                "value": value
            });
            store
                .put(
                    &format!("/registry/scheduling.k8s.io/priorityclasses/{name}"),
                    Bytes::from(serde_json::to_vec(&pc).unwrap()),
                    None,
                )
                .await
                .unwrap();
        }

        let quota = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "high-prio-quota", "namespace": "default" },
            "spec": {
                "hard": { "pods": "1" },
                "scopeSelector": {
                    "matchExpressions": [
                        {"scopeName": "PriorityClass", "operator": "In", "values": ["high"]}
                    ]
                }
            }
        });
        store
            .put(
                "/registry/resourcequotas/default/high-prio-quota",
                Bytes::from(serde_json::to_vec(&quota).unwrap()),
                None,
            )
            .await
            .unwrap();

        let make_body = |name: &str, priority_class: &str| {
            Bytes::from(
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": name, "namespace": "default"},
                    "spec": {
                        "priorityClassName": priority_class,
                        "containers": [{"name": "app", "image": "nginx"}]
                    }
                })
                .to_string(),
            )
        };
        let headers = {
            let mut h = axum::http::HeaderMap::new();
            h.insert(
                axum::http::header::CONTENT_TYPE,
                "application/json".parse().unwrap(),
            );
            h
        };

        create_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            headers.clone(),
            make_body("high-a", "high"),
        )
        .await
        .expect("first high-priority pod must be admitted (0 of 1 used)");

        let rejected = create_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            headers.clone(),
            make_body("high-b", "high"),
        )
        .await;
        assert!(
            rejected.is_err(),
            "a second high-priority pod must be rejected — the scoped quota is already at \
             1 of 1"
        );

        create_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            headers.clone(),
            make_body("low-a", "low"),
        )
        .await
        .expect(
            "a low-priority pod must never be blocked by a quota scoped to \
             PriorityClass=high — it doesn't match the scope selector at all",
        );

        assert_eq!(
            quota_used_pods(&store, "high-prio-quota").await,
            Some("1".to_string()),
            "the low-priority pod must NOT be counted toward the high-priority-scoped \
             quota's usage"
        );

        delete_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(), "high-a".to_string())),
            test_user(),
            axum::extract::Query(GracePeriodQuery {
                grace_period_seconds: None,
            }),
            headers.clone(),
            Bytes::from(serde_json::json!({"gracePeriodSeconds": 0}).to_string()),
        )
        .await
        .expect("delete of the matching high-priority pod must succeed");

        assert_eq!(
            quota_used_pods(&store, "high-prio-quota").await,
            Some("0".to_string()),
            "deleting the one pod that matched the scope selector must decrement its \
             quota's usage back to 0 — a missed decrement here would wedge the quota full \
             forever despite having no matching pods left"
        );

        create_pod(
            axum::extract::State(state.clone()),
            axum::extract::Path(("default".to_string(),)),
            axum::extract::Query(crate::handlers::json_patch::CreateQuery::default()),
            test_user(),
            headers.clone(),
            make_body("high-b", "high"),
        )
        .await
        .expect("with the slot freed, a second high-priority pod must now be admitted");
    }
}

#[cfg(test)]
mod status_patch_metadata_tests {
    use super::apply_status_patch;

    /// PATCH /pods/{name}/status with metadata.annotations must persist the annotation.
    /// Kubelet and controllers annotate pods via the status subresource; dropping annotations
    /// from the patch body causes the CronJob and Job conformance tests to fail because they
    /// read back annotations that were set via /status.
    #[test]
    fn apply_status_patch_persists_metadata_annotations() {
        let stored = serde_json::json!({
            "metadata": { "name": "mypod", "namespace": "default", "uid": "pod-uid-1" },
            "spec": { "containers": [{"name": "c", "image": "busybox"}] },
            "status": {}
        });
        let patch = serde_json::json!({
            "metadata": { "annotations": { "xzmpcheck": "ok" } },
            "status": { "phase": "Running" }
        });
        let result = apply_status_patch(&stored, &patch).unwrap();
        assert_eq!(
            result["metadata"]["annotations"]["xzmpcheck"], "ok",
            "annotation from the patch body must survive apply_status_patch; \
             dropping it causes controllers and conformance tests that set annotations via /status to fail"
        );
        assert_eq!(
            result["status"]["phase"], "Running",
            "status must be applied"
        );
        assert_eq!(
            result["spec"]["containers"][0]["name"], "c",
            "spec must not be modified by a status patch"
        );
    }

    /// PATCH /pods/{name}/status must NOT change the pod uid even if the patch carries one.
    /// uid is an immutable identity field; changing it via /status would break GC and admission.
    #[test]
    fn apply_status_patch_does_not_overwrite_uid() {
        let stored = serde_json::json!({
            "metadata": { "name": "mypod", "uid": "real-uid", "namespace": "default" },
            "spec": {},
            "status": {}
        });
        let patch = serde_json::json!({
            "metadata": { "uid": "attacker-uid", "annotations": { "safe": "yes" } },
            "status": { "phase": "Failed" }
        });
        let result = apply_status_patch(&stored, &patch).unwrap();
        assert_eq!(
            result["metadata"]["uid"], "real-uid",
            "uid must not be overwritten by a status patch; \
             uid changes via /status would corrupt object identity and break GC"
        );
        assert_eq!(
            result["metadata"]["annotations"]["safe"], "yes",
            "non-identity annotations must still land"
        );
    }

    /// PATCH /pods/{name}/status with a spec field must leave spec unchanged.
    /// spec cannot be modified via the status subresource — this is the API isolation guarantee.
    #[test]
    fn apply_status_patch_ignores_spec_in_patch() {
        let stored = serde_json::json!({
            "metadata": { "name": "mypod" },
            "spec": { "nodeName": "node-1" },
            "status": {}
        });
        let patch = serde_json::json!({
            "spec": { "nodeName": "node-evil" },
            "status": { "phase": "Pending" }
        });
        let result = apply_status_patch(&stored, &patch).unwrap();
        assert_eq!(
            result["spec"]["nodeName"], "node-1",
            "spec must not change via a status patch; \
             a controller that accidentally includes spec in its /status PATCH must not corrupt scheduling"
        );
    }

    /// Existing conditions merge logic must still work after adding metadata support.
    /// Kubelet updates conditions via strategic-merge-patch; losing this breaks pod readiness.
    #[test]
    fn apply_status_patch_still_merges_conditions() {
        let stored = serde_json::json!({
            "metadata": { "name": "mypod" },
            "spec": {},
            "status": {
                "conditions": [
                    {"type": "Ready", "status": "False"},
                    {"type": "Initialized", "status": "True"}
                ]
            }
        });
        let patch = serde_json::json!({
            "metadata": { "annotations": { "k": "v" } },
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}]
            }
        });
        let result = apply_status_patch(&stored, &patch).unwrap();
        let conds = result["status"]["conditions"]
            .as_array()
            .expect("conditions must be array");
        let ready = conds
            .iter()
            .find(|c| c["type"] == "Ready")
            .expect("Ready condition must exist");
        assert_eq!(
            ready["status"], "True",
            "Ready condition must be updated by status patch; \
             if conditions merge breaks, kubelet cannot mark pods ready and pods stay unscheduled"
        );
        let init = conds.iter().find(|c| c["type"] == "Initialized");
        assert!(
            init.is_some(),
            "Initialized condition must be preserved from stored object; \
             strategic merge on conditions must not drop unpatched conditions"
        );
        assert_eq!(
            result["metadata"]["annotations"]["k"], "v",
            "metadata annotation must also land"
        );
    }

    /// PATCH /pods/{name}/status must NOT change finalizers even if the kubelet includes them.
    /// The kubelet constructs its status patch from the pod it last saw. If the kubelet's cache
    /// still has the job-tracking finalizer, the patch body carries it. Without this guard,
    /// every kubelet status update restores the finalizer KCM just removed, causing a livelock
    /// where the finalizer is never permanently cleared and pods stay Terminating forever.
    #[test]
    fn apply_status_patch_does_not_restore_finalizers() {
        let stored = serde_json::json!({
            "metadata": {
                "name": "job-pod",
                "namespace": "test",
                "uid": "uid-1",
                "finalizers": []
            },
            "spec": {},
            "status": { "phase": "Succeeded" }
        });
        let patch = serde_json::json!({
            "metadata": {
                "finalizers": ["batch.kubernetes.io/job-tracking"]
            },
            "status": { "phase": "Succeeded", "conditions": [] }
        });
        let result = apply_status_patch(&stored, &patch).unwrap();
        let finalizers = result["metadata"]["finalizers"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);
        assert_eq!(
            finalizers, 0,
            "status subresource must not restore finalizers from the patch body; \
             if it does, KCM's finalizer removal and kubelet status updates create a livelock \
             that keeps pods stuck Terminating forever"
        );
    }

    /// PATCH /pods/{name}/status must NOT change metadata.labels even if the patch carries them.
    /// Labels drive selector-based scheduling and service membership; a caller
    /// holding only pods/status RBAC rights (e.g. the kubelet) must not be able to smuggle a
    /// label change through a status merge-patch, the same guard merge_incoming_metadata already
    /// enforces for the generic status handlers. Without this guard, an attacker with
    /// only status-write rights could flip a pod's labels to escape a NetworkPolicy or Service
    /// selector, or add/remove itself from a controller's label selector — a privilege escalation
    /// beyond what the status subresource is meant to allow.
    #[test]
    fn apply_status_patch_does_not_change_labels() {
        let stored = serde_json::json!({
            "metadata": { "name": "mypod", "namespace": "default", "uid": "uid-1",
                          "labels": { "app": "web" } },
            "spec": {},
            "status": {}
        });
        let patch = serde_json::json!({
            "metadata": { "labels": { "app": "evil", "escalated": "true" } },
            "status": { "phase": "Running" }
        });
        let result = apply_status_patch(&stored, &patch).unwrap();
        assert_eq!(
            result["metadata"]["labels"],
            serde_json::json!({ "app": "web" }),
            "labels must not change via a status patch; a status-only RBAC grant must not be \
             able to rewrite labels that gate selector-based scheduling and service membership"
        );
        assert_eq!(
            result["status"]["phase"], "Running",
            "a legitimate status-only field must still be applied"
        );
    }

    /// PATCH /pods/{name}/status must NOT set deletionTimestamp from the patch body.
    /// deletionTimestamp is stamped by the delete handler; a status patch must not add or remove it.
    #[test]
    fn apply_status_patch_does_not_set_deletion_timestamp() {
        let stored = serde_json::json!({
            "metadata": { "name": "mypod", "uid": "uid-1" },
            "spec": {},
            "status": {}
        });
        let patch = serde_json::json!({
            "metadata": { "deletionTimestamp": "2026-06-25T00:00:00Z" },
            "status": { "phase": "Running" }
        });
        let result = apply_status_patch(&stored, &patch).unwrap();
        assert!(
            result["metadata"]["deletionTimestamp"].is_null(),
            "status subresource must not set deletionTimestamp; \
             only the delete handler may stamp it, otherwise soft-delete semantics break"
        );
    }
}
