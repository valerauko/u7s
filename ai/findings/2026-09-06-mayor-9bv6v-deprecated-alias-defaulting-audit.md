# Deprecated/legacy-sibling defaulting audit

Bead: mayor-9bv6v
Date: 2026-09-06
Scope: read-only cross-reference of `crates/apiserver/src/handlers/defaults.rs` and
`pods.rs` against upstream `release-1.36` `SetDefaults_*`/conversion functions, hunting
for the serviceAccount-class bug (canonical field defaulted/left empty instead of first
falling back to a legacy/deprecated/alias sibling).

## Verdict

2 new real MISSING gaps beyond the already-known serviceAccount bug (mayor-gktrw): Node
`podCIDR`↔`podCIDRs` and PVC/PV `storageClassName` ← the deprecated
`volume.beta.kubernetes.io/storage-class` annotation. Both are low-to-moderate severity —
the real, unmodified KCM/kubelet binaries u7s runs already write the modern field
correctly in their own hot paths, so the gap only bites a raw client (kubectl/SSA/e2e
helper) that uses the legacy form directly. 1 pair already correctly HANDLED (Service
`clusterIP`↔`clusterIPs`). 1 pair is the known, already-filed bug (`serviceAccount`).
1 pair (`podIP`↔`podIPs`) is UNCERTAIN — see below.

## Pairs

| pair | upstream ref | our ref | verdict | impact |
|---|---|---|---|---|
| `spec.serviceAccount` → `spec.serviceAccountName` | `pkg/apis/core/v1/conversion.go:354-358` (`Convert_v1_PodSpec_To_core_PodSpec`) | `pods.rs` `apply_pod_spec_defaults` ~5148-5160 | MISSING (known) | Already filed as mayor-gktrw; not re-filed here. |
| Event `source`/`firstTimestamp`/`lastTimestamp`/`count` ↔ `deprecatedSource`/... | `staging/.../events/v1/conversion.go` (Convert_v1_Event_To_core_Event et al.) | `defaults.rs:674-696` `translate_event_shape`/`alias_event_field` | HANDLED | Reference implementation for the correct pattern; no gap. |
| Service `clusterIP` → `clusterIPs` | `pkg/registry/core/service/storage/alloc.go:340-393` (`allocClusterIPs` writes `ClusterIPs[i]` then mirrors `ClusterIP = ip` for `i==0`); `pkg/apis/core/validation/validation.go:9087-9102` treats the reverse (`clusterIPs` set, `clusterIP` empty) as a validation error, not a default | `defaults.rs:719-741` `default_service_ip_fields_spec` fills `clusterIps` from `clusterIp`; call-site ordering in `resource.rs:2797-2807` (create) and `resource.rs:3431-3451` (update) runs `maybe_allocate_cluster_ip` (sets `clusterIP`) *before* `apply_defaults` (derives `clusterIPs`) | HANDLED | Matches upstream's forward-only sync exactly, in the right order. |
| Node `spec.podCIDR` ↔ `spec.podCIDRs` | `pkg/apis/core/v1/conversion.go:319-347` (`Convert_core_NodeSpec_To_v1_NodeSpec` / `Convert_v1_NodeSpec_To_core_NodeSpec`) syncs bidirectionally, unconditionally, on every read/write | No `default_node`/podCIDR handling anywhere in `defaults.rs`; `resource.rs:2386-2410` and `node_authz.rs:549` treat the two fields as independent, each frozen once non-empty, with zero cross-filling | MISSING | Low real-world severity: KCM's real `rangeAllocator` (`pkg/controller/nodeipam/ipam/range_allocator.go` → `component-helpers/node/util/cidr.go:PatchNodeCIDRs`) always writes both fields in the same strategic-merge patch, so the node-ipam-controller-driven path in u7s (`--allocate-node-cidrs=true`, install.sh:998) is unaffected. Gap surfaces for any other client (kubectl patch/apply, SSA, e2e helper) that sets only one field: the other stays empty forever (frozen-once-set semantics compound this — see `resource.rs:2396-2410`), and `proxy.rs:2214` `validate_pod_ip_against_node` (the podIP-in-podCIDR SSRF check) reads only the singular `podCIDR`, so a node with `podCIDRs` set but `podCIDR` empty silently falls into the permissive "no podCIDR assigned" branch. |
| PVC/PV `spec.storageClassName` ← `volume.beta.kubernetes.io/storage-class` annotation | `pkg/apis/core/helper/helpers.go:463-476` `GetPersistentVolumeClaimClass` ("Use beta annotation first"); consumed by the real volume-expansion admission plugin `plugin/pkg/admission/storage/persistentvolume/resize/admission.go:118-120` (`apihelper.GetPersistentVolumeClaimClass(pvc)`), not `pvc.Spec.StorageClassName` directly | No annotation handling anywhere in `default_pvc`/`default_pv` (`defaults.rs:224-234`, `262-`); `resource.rs:1946-1978` `reject_disallowed_pvc_resize` and the storageClassName-immutability check (`resource.rs:1560`, `3285`) read `spec.storageClassName` directly | MISSING | A PVC created with only the deprecated annotation (no `spec.storageClassName`) resolves `old_sc_name = ""` in `reject_disallowed_pvc_resize`; `storage_class_allows_expansion(state, "")` looks up a nonexistent `""`-named StorageClass and returns `false`, so **every** resize request for such a PVC is rejected with "only dynamically provisioned pvc can be resized" — even when the annotation's real StorageClass has `allowVolumeExpansion: true`. u7s's own PV/PVC binding is delegated to the real KCM `persistentvolume-binder` controller (enabled, not in the `--controllers` disable-list), which has its own correct Go-side `GetPersistentVolumeClaimClass`, so binding/provisioning itself is unaffected — only u7s's own volume-expansion gate and the class-immutability freeze are exposed. |
| Pod `status.podIP` ↔ `status.podIPs` | `pkg/apis/core/v1/conversion.go:258-280` (`Convert_v1_PodStatus_To_core_PodStatus`) syncs bidirectionally, unconditionally | No generic sync in `defaults.rs`; `pods.rs:3286-3288` only overrides both together for the hostNetwork special case, never backfills one from the other in the general case | UNCERTAIN (not filed) | Real kubelet (`pkg/kubelet/kubelet_pods.go:2094-2097`) always constructs `PodIPs` first and then sets `apiPodStatus.PodIP = apiPodStatus.PodIPs[0].IP` in the same status build — i.e. the sole real producer in u7s's stack never sends one without the other, unlike the podCIDR case (no known SSRF-relevant single-field read site was found for podIP; `proxy.rs`/field-selector code reads singular `podIP`, which the real kubelet always populates). No concrete client/test was found that sets only one field. Flagging as uncertain rather than filing a bead — a maintainer with more context on whether any e2e helper or SSA-based tooling writes pod status directly (bypassing kubelet) should confirm before treating this as a gap. |

## Categories checked but not applicable

- `apps/v1` (`Deployment`/`DaemonSet`/`StatefulSet`/`ReplicaSet`) and `batch/v1`
  (`Job`/`CronJob`) `SetDefaults_*`: no deprecated/legacy-sibling field pairs exist in
  either file (release-1.36) — every default there is a plain zero-value default, not an
  alias fallback.
- `ServiceExternalTrafficPolicyType`/`ServiceInternalTrafficPolicyType`/`IPFamilyPolicyType`
  (`core/v1/types.go:5817-5977`): Go type aliases for the same JSON field, not separate
  wire fields — no fallback is possible or needed.
- `volume.beta.kubernetes.io/mount-options` → `PV.Spec.MountOptions`: same
  annotation-first pattern as storageClassName, but the only consumer
  (`pkg/volume/util/util.go:MountOptionFromSpec`) is in-tree-volume-plugin code that runs
  inside the real, unmodified kubelet — not in u7s's apiserver — so there is nothing for
  us to fix here.
- `NodeSpec.configSource` / `NodeSpec.externalID` (`core/v1/types.go:6573-6580`):
  genuinely deprecated with **no** replacement field to fall back to (the features they
  supported were removed) — not an instance of this bug class.

## Method note

Upstream source fetched once via `gh api` into `temp/research/` (not committed) and
grepped locally: `core_v1_defaults.go`, `core_v1_conversion.go`, `core_v1_types.go`,
`apps_v1_defaults.go`, `batch_v1_defaults.go`, `service_alloc.go`, `service_strategy.go`,
`core_validation.go`, `core_helpers.go`, `pvc_util.go`, `range_allocator.go`,
`controller_utils.go`, all pinned `ref=release-1.36`.
