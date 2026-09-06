# Typed-status migration scope for built-in types

Bead: mayor-m10di
Date: 2026-09-06
Author: worker agent-a70b4bf52433d712c (read-only investigation, Shape-3 audit)
Status: DESIGN INPUT — no product code changed, no PR. Awaiting operator prioritization.

## Answer first

Typing built-in status end-to-end is **feasible and retires roughly two-thirds
of the j1oq9 guard set** — every built-in status path (status.rs generic
built-in arm, resource.rs generic built-in arm, the dedicated pods.rs /
namespaces.rs handlers, and the read-path defense-in-depth coercions) becomes
guard-free by construction; the remaining third stays permanently on the two
**dynamic** paths (cr.rs, crd.rs) where there is no compile-time schema. The
work is ~24 hand-written minimal-field status structs plus one per-kind dispatch
table; the boundary is the `lookup()`-hit arm that already separates built-ins
from the CR-fallback delegation in both giant generic handlers. It should be
done only AFTER the current j1oq9 security churn on status.rs/resource.rs
settles, and it naturally relocates raw-JSON status code out of the giant files
(a side benefit to note for the file-split bead mayor-r871h — not scoped here).

The single non-obvious blocker: the proto-generated prost structs already exist
for every built-in status type but are **NOT** a drop-in serde boundary
(snake_case + proto-omitempty impedance; the gen_adapters do lossy manual
mapping). The right foundation is the existing hand-written `types.rs` serde
pattern (minimal reasoned-about field + `#[serde(flatten)] rest: Value`), the
same pattern the typed-struct EPIC (mayor-ds8hb / mayor-ohh8o) established.

---

## 1. Root cause recap (verified in source)

The apiserver REASONS about status — it stamps `status.phase=Terminating` on
namespace delete, `status.conditions` on CSR approval and APIService reconcile,
`status.resize` on pod resize, and coerces ResourceQuota usage in its
reconciler. Those in-place stampers index `status["phase"]` / `status["conditions"]`.
A stored scalar status (`{"status":"x"}`) therefore panics the next stamper and
crashes the apiserver for every in-flight request. This violates the standing
directive `typing-guideline-no-raw-json-for-reasoned-fields`: reasoned-about
fields must flow through typed structs, not raw `serde_json::Value` map access.

Round-5 (mayor-j1oq9) empirically confirmed the split:

- **Typed handlers were SAFE.** `put_namespace_status` round-trips through
  `NamespaceStatus` (`from_value` → struct → `to_value`), so a scalar is
  structurally impossible to store — `to_value` on a struct always yields a JSON
  object. `patch_approval` round-trips through `CertificateSigningRequestStatus`.
  The Scale subresource round-trips through `Scale`.
- **Every raw-Value handler was VULNERABLE.** `patch_namespace` (main resource,
  not `/status`), `replace_crd`, and the generic `do_patch` each persisted a
  request-body status without the object-or-null invariant.

The tactical fix (already merged) was a **guard set**, not typing. This bead
scopes replacing that guard set with typing for the built-ins.

## 2. The j1oq9 guard set as it stands today

Three distinct guard classes, all in `crates/apiserver/src/handlers/`:

**Class A — write-rejection on `/status` subresource handlers.**
`reject_non_object_status(&status)` (422 on a present-but-non-object status;
`null` allowed per RFC 7396 deletion) and `replace_status_field(current, incoming)`
(PUT convenience wrapper around the same check). Defined in `status.rs:484` /
`status.rs:503`.

**Class B — stored-status restoration on MAIN-resource (non-`/status`) write
handlers.** Capture `stored_status` before applying a patch/replace to the whole
object, restore it after, so an ordinary (non-status-subresource) writer cannot
smuggle a scalar status into the object body. The `stored_status` naming
convention originates in `resource.rs` `do_patch`.

**Class C — read/reconcile-path defense-in-depth coercions.** Before an in-place
stamp, coerce a (hypothetically corrupted) scalar status back to `{}`:
`generic.rs:720` (namespace Terminating stamp), the ResourceQuota reconciler
(`lib.rs:3494`), the APIService reconcile (`aggregation.rs`).

Plus **three completeness meta-tests** in `status.rs` (~350 LOC) that grep every
handler file and fail if a new PUT/PATCH/main-resource write handler is added
without the guard:

- `every_status_put_handler_guards_against_non_object_status` — TYPED_SAFE
  exemption already lists `put_namespace_status` (typed round-trip).
- `every_status_patch_handler_guards_non_object_status_outside_any_branch`.
- `every_main_resource_write_handler_preserves_stored_status` — SAFE exemptions
  already list `patch_approval` (typed), `patch_ephemeral_containers` /
  `patch_pod_resize` (structurally never clobber status).

Approximate production guard-call inventory (grep, excludes test modules):

| File | reject/replace calls | stored_status refs | Path type |
|---|---|---|---|
| status.rs | 11 | 8 | generic (built-in arm + CR-fallback arm) |
| resource.rs | 0 | 15 | generic (built-in arm; CR miss delegates to cr.rs) |
| namespaces.rs | 1 | 11 | dedicated built-in (Namespace) |
| pods.rs | 2 | 7 | dedicated built-in (Pod) |
| crd.rs | 2 | 9 | **dynamic** (CRD) |
| cr.rs | 2 | 10 | **dynamic** (CR) |

Read-path Class-C coercions: `generic.rs` ×1 (`generic.rs:720-721`), `aggregation.rs` ×1, `lib.rs` ×1 (`lib.rs:3494`).

## 3. Built-in status types: typed vs raw-Value today

24 built-in kinds carry a status subresource per the registry in
`state.rs` (`rm(kind, namespaced, has_status=true)`), plus Pod and Namespace via
dedicated handlers. "Reasoned-about" = the apiserver itself stamps/validates the
status; the rest are passthrough (controller/kubelet-owned) but still need the
object-or-null invariant because generic stampers coexist in the same object.

| Built-in status | Typed today? | Handler(s) touching status | Reasoned-about? | Typeable end-to-end? |
|---|---|---|---|---|
| Namespace | **Typed** (`NamespaceStatus`) | namespaces.rs `put/patch_namespace_status` (typed); `patch_namespace` (raw, Class-B); `generic.rs` Terminating stamp (Class-C) | Yes (phase, finalize conditions) | Yes — model already exists |
| CertificateSigningRequest | **Typed** (`CertificateSigningRequestStatus`) | approval.rs `patch_approval` / `merge_approval_conditions` (typed); status.rs generic (raw) | Yes (approval conditions, certificate) | Yes — model already exists |
| Scale subresource (Deployment/ReplicaSet/StatefulSet/ReplicationController) | **Typed** (`Scale`) | scale.rs (typed) | Yes (scale.status.replicas) | Yes — model already exists |
| HorizontalPodAutoscaler | Raw | status.rs generic (its own `/status`; no `/scale` route) | Passthrough (HPA controller writes status) | Yes |
| Pod | Partial | pods.rs `replace_pod_status`/`patch_pod_status`/`patch_pod_resize` (mix: resize typed, main raw Class-B) | Yes (resize, readiness conditions, phase) | Yes — high value |
| APIService | Raw | aggregation.rs reconcile `upsert_available_condition` (raw); status.rs generic | Yes (Available condition) | Yes — high value |
| ResourceQuota | Raw | status.rs generic; reconciler coercion (`lib.rs`, Class-C) | Yes (usage) | Yes — high value |
| Node | Raw | status.rs generic | Mostly passthrough (kubelet writes; scheduler reads) | Yes |
| Deployment / ReplicaSet / StatefulSet / DaemonSet | Raw | resource.rs generic + status.rs generic | Passthrough (KCM writes) | Yes |
| Job / CronJob | Raw | resource.rs + status.rs generic | Passthrough (KCM) | Yes |
| PersistentVolume / PersistentVolumeClaim | Raw | resource.rs + status.rs generic | Passthrough (phase set by controllers) | Yes |
| ReplicationController | Raw | resource.rs + status.rs generic | Passthrough | Yes |
| Ingress | Raw | resource.rs + status.rs generic | Passthrough (ingress ctrl loadBalancer) | Yes |
| VolumeAttachment | Raw | status.rs generic | Passthrough (attach/detach ctrl) | Yes |
| FlowSchema / PriorityLevelConfiguration | Raw | status.rs generic | Passthrough (APF ctrl) | Yes |
| ServiceCIDR | Raw | status.rs generic | Passthrough | Yes |
| ValidatingAdmissionPolicy / ...Binding | Raw | status.rs generic | Passthrough | Yes |
| ResourceClaim / DeviceClass / PodCertificateRequest | Raw | status.rs generic | Passthrough (DRA/cert ctrl) | Yes |

**Score: 3 typed round-trip paths today — Namespace status (`NamespaceStatus`),
CSR status (`CertificateSigningRequestStatus`), and the `Scale` subresource
(`Scale`), which exists ONLY on Deployment/ReplicaSet/StatefulSet/ReplicationController
and NOT on HorizontalPodAutoscaler. Of the built-in status subresources themselves,
only Namespace and CSR are typed; the rest — including HorizontalPodAutoscaler,
whose own `/status` is raw through the generic status handler (its only
`HorizontalPodAutoscalerStatus` type is prost-generated, not a hand-written serde
struct) — are raw. All are typeable end-to-end.** Dynamic CR/CRD status is NOT
typeable (no compile-time schema) and keeps the structural invariant.

## 4. Feasibility given the Value-based store

**Verdict: feasible, medium effort. No new dependency.**

The store persists `serde_json::Value`. Typing status means a
deserialize → typed-validate → reserialize round-trip at the **handler
boundary**, exactly the `put_namespace_status` model:

```
match &incoming["status"] {
    Null => remove status,                       // RFC 7396 deletion stays legal
    v    => current["status"] = to_value(from_value::<KindStatus>(v)?),  // scalar -> Err -> 422
}
```

**The boundary is already carved.** Both giant generic handlers dispatch on
`lookup(&state, group, version, plural)`:

- registry **hit** → built-in arm (today: raw Value + Class-A/B guard). This is
  where a per-kind typed round-trip slots in — `meta.kind` gives the concrete
  built-in kind.
- registry **miss** → delegates to `cr::replace_cr` / the CR-fallback key in
  status.rs (dynamic; keeps the structural guard).

So the typed path drops cleanly into the built-in arm without disturbing the CR
path. A per-kind dispatch table keyed on `kind` → a `fn(&Value) -> Result<Value>`
closure (deserialize+reserialize) mirrors the existing decode-map pattern in
`proto.rs` (`m.insert("Pod", core_gen_adapter::decode_pod_proto_gen)`).

**Blockers / non-obvious constraints:**

1. **Type erasure in the generic handlers.** `put_resource_status`,
   `patch_resource_status`, `do_patch`, `replace_*` serve all kinds through one
   type-erased signature. You cannot give them a single typed status parameter;
   you need the per-kind dispatch table above. This is the main structural cost.

2. **Proto-generated structs are NOT a shortcut.** `u7s-proto-generated` (prost,
   built from vendored k8s `.proto`) has typed structs for every built-in status
   (`DeploymentStatus`, `PodStatus`, ...), already used by the `*_gen_adapter.rs`
   files for the protobuf content-type. But they are snake_case with proto3
   optional semantics, so `serde_json::from_value` against a k8s JSON status does
   NOT round-trip — that is exactly why the gen_adapters do field-by-field manual
   mapping, and that mapping is **lossy** (omitempty heuristics, dropped fields),
   designed for wire compat, not preservation. Using them as the JSON status
   boundary would silently drop passthrough fields. Use hand-written `types.rs`
   serde structs instead (minimal field + `#[serde(flatten)] rest: Value`),
   extending the mayor-ds8hb / mayor-ohh8o pattern. Do NOT add k8s-openapi.

3. **`null` must stay legal.** Merge-patch `{"status":null}` is RFC 7396 field
   deletion, not an invalid scalar — the typed path must special-case null
   (model as `Option<KindStatus>` / the `match` arm above), matching the guard's
   current null-allowed semantics.

4. **Strict (422) vs lenient (silent coerce) is an unsettled semantic.** The
   current `put_namespace_status` uses `from_value(...).unwrap_or_default()`: a
   scalar deserializes-fail → falls back to an empty `NamespaceStatus` → stores
   `{}`. That is panic-safe but **under-rejects vs upstream** — the pods.rs test
   `a scalar status must be rejected with 422, matching upstream schema
   validation` shows upstream 422s. The migration should propagate the
   deserialize error (`?` → 422), and tighten `put_namespace_status` to match.

5. **~23 status structs to author.** One minimal-field struct per built-in with a
   status subresource (only the fields the apiserver reasons about; everything
   else via `flatten rest`). This is the bulk of the LOC.

## 5. Phased plan (sequenced to avoid mid-churn merge hell)

**Phase 0 — Wait.** Do NOT start while status.rs/resource.rs are still churning
under j1oq9 security follow-ups. Typing rewrites the exact lines those guards
live on; starting mid-round is guaranteed merge hell. Gate: the adjacent
security backlog on these two files is drained.

**Phase 1 — Pattern + dispatch scaffolding (one kind).** Add the per-kind status
dispatch table (kind → deserialize+reserialize closure) in a new typed module.
Wire ONE cheap built-in end-to-end through it (recommend ResourceQuota or Node).
Prove: a scalar status now 422s by construction; the Class-A/B guard for that
kind is provably dead. Keep the guard as belt-and-suspenders until Phase 4 flips
the meta-tests. Reverse-fail test: a scalar status body → 422 with the typed
path, would-panic without it.

**Phase 2 — Reasoned-about statuses first (highest guideline value).** Migrate
where the apiserver actually stamps: Namespace (tighten `put_namespace_status`
from `unwrap_or_default` to `?`→422), CSR (formalize the already-typed path),
APIService (aggregation Available condition, retire the Class-C coercion),
ResourceQuota (usage, retire the reconciler coercion), Pod (resize + readiness
conditions). These are where the typing-guideline bites hardest.

**Phase 3 — Passthrough-status built-ins (bulk).** Author minimal-field structs
for Deployment / ReplicaSet / StatefulSet / DaemonSet, Job / CronJob, PV / PVC,
ReplicationController, HorizontalPodAutoscaler, Ingress, VolumeAttachment,
FlowSchema / PLC, ServiceCIDR, ValidatingAdmissionPolicy(+Binding), ResourceClaim /
DeviceClass / PodCertificateRequest. Each is minimal field + `flatten rest`. Wire
each into the dispatch table.

**Phase 4 — Retire the guard class for built-ins.** Once every built-in path is
typed: drop `reject_non_object_status` / `replace_status_field` / `stored_status`
from the built-in arms; retire the Class-C read-path coercions for built-ins (or
keep as cheap DiD — operator call). Rewrite the three completeness meta-tests so
their SAFE/TYPED_SAFE lists cover all built-in handlers and the tests now guard
ONLY the dynamic cr.rs / crd.rs paths. The structural object-or-null invariant
stays permanent on the dynamic paths and the CR-fallback arm of the status.rs
generic handlers.

**Phase 5 — Compose with codegen (do not block).** The hand-written `types.rs`
status structs can later be superseded by the proto-generated structs IF a
serde-faithful JSON codec is added to the prost pipeline (today the gen_adapters
are manual + lossy). Note this composition point for the prost/codegen migration;
do not block Phases 1–4 on it.

**Connection to mayor-r871h (file split — noted, NOT scoped here):** typing moves
the raw-JSON status manipulation out of resource.rs / status.rs / pods.rs into
the typed dispatch module, shrinking the giants. Type-first on the built-in arms
relocates the code; then split. This is a side benefit to flag for r871h, not a
deliverable of this bead.

**Connection to the typed-struct EPIC (mayor-ohh8o, mayor-ds8hb):** this is the
same minimal-field + `flatten rest` pattern those closed beads established for
defaults.rs and discovery.rs. This bead is its natural next cluster (status),
and the largest, because the status path is where j1oq9 proved the guideline
matters for correctness, not just allocation.

## 6. Open questions for the operator

1. **Strict vs lenient on a scalar built-in status?** Recommend strict (`?`→422,
   upstream-faithful); requires tightening `put_namespace_status` (currently
   silently coerces via `unwrap_or_default`). Confirm.
2. **Retire the Class-C read-path DiD coercions after typing, or keep them?**
   They become dead for built-ins once the write path is typed, but are cheap
   defense-in-depth. Delete-for-clarity vs keep-for-belt-and-suspenders.
3. **Hand-written `types.rs` structs now, or wait for a serde-faithful prost JSON
   codec?** Recommend hand-written now (unblocks; compose with codegen in
   Phase 5). Confirm you don't want to invest in the codec first.
4. **Sequence vs mayor-r871h.** Recommend type-first (relocates code out of the
   giants), then split. Confirm ordering.

## 7. Confidence

- Guard inventory, the three completeness meta-tests, and the `lookup()`-hit
  boundary: **high** — read directly in source.
- Feasibility verdict and the proto-struct-is-not-a-shortcut finding: **high** —
  verified the prost structs are snake_case and the gen_adapters do lossy manual
  mapping.
- Effort estimate (~23 structs + dispatch): **medium** — extrapolated from the
  mayor-ds8hb 19-struct / ~250-LOC datapoint.
- Strict-vs-lenient and DiD-retirement: genuine operator decisions, deliberately
  left open rather than assumed.
