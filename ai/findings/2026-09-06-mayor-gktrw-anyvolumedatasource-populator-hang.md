# AnyVolumeDataSource: hello-populator makes zero apiserver calls

Bead: mayor-gktrw
Date: 2026-09-06
Investigator: worker/agent-a6a7cce9bd2cd1354 (live repro on lima-node-4 + lima-node-3)

## Root cause (answer first)

**(c) other — apiserver pod-defaulting bug, not networking and not CRD/PVC
watch-serving.** The pod reaches the apiserver instantly and correctly; the
apiserver correctly serves Hello/VolumePopulator/PVC. The bug is that
`apply_pod_spec_defaults` in `crates/apiserver/src/handlers/pods.rs` (around
line 5148-5160) defaults `spec.serviceAccountName` straight to `"default"`
whenever it is absent, **without first falling back to the deprecated
`spec.serviceAccount` alias field** the way upstream's
`SetDefaults_PodSpec` does (`if ServiceAccountName == "" { ServiceAccountName
= DeprecatedServiceAccount }`). Upstream's own
`hello-populator-deploy.yaml` sets only the legacy `serviceAccount:
hello-account` field (never `serviceAccountName`) in its Deployment pod
template — a real-world, valid manifest shape. Our apiserver stamps the
created Pod with `serviceAccountName: default` instead of `hello-account`,
so the controller mounts the token for the namespace's bare `default`
ServiceAccount, which has zero RBAC bindings. Every single list/watch call
the controller's informers issue gets instant `403 Forbidden` — informers
never sync, `Run()`'s cache-sync gate never passes, and the reconcile loop
that would create the prime PVC/populate pod never starts. This is a general
Pod-admission bug (affects any workload using the deprecated
`spec.serviceAccount` field), not specific to CSI/populator machinery.

## Evidence trail

### 1. The populator pod IS running, healthy, and its container logs show instant 403s (not hangs)

`kubectl logs hello-populator-7b846c6d8d-9fe23 -n provisioning-81-pop-7445 --all-containers --timestamps`, starting within 6ms of the container's own startup log line:

```
2026-09-06T10:04:54.660164674+09:00 I0906 01:04:54.660064 1 controller.go:99] Starting populator controller for Hello.hello.example.com
2026-09-06T10:04:54.666380193+09:00 W0906 01:04:54.666305 1 reflector.go:324] ... failed to list *v1.Pod: system:serviceaccount:provisioning-81-pop-7445:default is not allowed to list pods
2026-09-06T10:04:54.666414110+09:00 E0906 01:04:54.666398 1 reflector.go:138] ... Failed to watch *v1.Pod: failed to list *v1.Pod: system:serviceaccount:provisioning-81-pop-7445:default is not allowed to list pods
2026-09-06T10:04:54.666439735+09:00 W0906 01:04:54.666418 1 reflector.go:324] ... failed to list *v1.PersistentVolumeClaim: system:serviceaccount:provisioning-81-pop-7445:default is not allowed to list persistentvolumeclaims
2026-09-06T10:04:54.667152399+09:00 W0906 01:04:54.667097 1 reflector.go:324] k8s.io/client-go/dynamic/dynamicinformer/informer.go:91: failed to list *unstructured.Unstructured: system:serviceaccount:provisioning-81-pop-7445:default is not allowed to list hellos
```

This same list/watch/403 cycle repeats every few seconds for the pod's
entire life (confirmed continuing past the 1-minute observation window).
The identity making these calls is `system:serviceaccount:<ns>:default` —
**not** `hello-account`, the ServiceAccount the Deployment actually
specifies.

### 2. Reachability: the log itself is the decisive proof, not a separate wget test

The container image (`registry.k8s.io/sig-storage/hello-populator:v1.0.1`)
is a minimal static Go binary with no shell/wget/nc (`exec ... -- sh`
and `exec ... -- wget` both fail with `executable file not found in $PATH`),
so the planned busybox-style in-pod probe could not run. It is unnecessary:
an RBAC `403 Forbidden` response is only possible after a full TLS
handshake, HTTP request, and an apiserver-side authn+authz decision — a
network-partition or ClusterIP-routing failure would instead manifest as a
connection timeout/reset in the reflector logs (`dial tcp ... i/o timeout`),
which never appears. The sub-10ms gap between the controller's startup log
line and its first 403 additionally rules out any DNS/routing delay.

### 3. Pod spec confirms the alias-defaulting gap directly

`kubectl get pod hello-populator-7b846c6d8d-9fe23 -n provisioning-81-pop-7445 -o yaml`:

```yaml
spec:
  serviceAccount: hello-account      # deprecated alias, verbatim from the Deployment template — untouched
  serviceAccountName: default        # should have been backfilled from the line above; wasn't
```

The owning ReplicaSet's pod template shows the same split
(`serviceAccount: hello-account`, no `serviceAccountName` key at all),
confirming the gap is in Pod creation/admission defaulting, not something
the Deployment/ReplicaSet controllers mangled.

Upstream's own manifest (`test/e2e/testing-manifests/storage-csi/any-volume-datasource/hello-populator-deploy.yaml`,
release-1.36) confirms this is not a malformed or unusual manifest:

```yaml
    spec:
      serviceAccount: hello-account   # legacy field name; no serviceAccountName key present
```

`crates/apiserver/src/handlers/pods.rs` `apply_pod_spec_defaults` (~line 5154-5160):

```rust
if pod["spec"]["serviceAccountName"]
    .as_str()
    .unwrap_or("")
    .is_empty()
{
    pod["spec"]["serviceAccountName"] = serde_json::json!("default");
}
```

This never reads `pod["spec"]["serviceAccount"]`. Grepping the whole
apiserver crate for any read of the untyped `spec.serviceAccount` field
(the deprecated alias) returns zero matches, and the typed `PodSpec` struct
in `crates/apiserver/src/types.rs` (line 828) has only `service_account_name`
— it does not model the alias field at all, so it is silently dropped from
the typed side and the raw-JSON default path never falls back to it.

### 4. RBAC objects were created correctly — the bug is which identity the pod uses, not missing RBAC setup

`hello-account` ServiceAccount, `hello-role-provisioning-81-pop-7445`
ClusterRole (list/watch/get/create/delete on pods, PVCs, PVs, storageclasses,
hellos — exactly what the controller needs), and
`hello-binding-provisioning-81-pop-7445` ClusterRoleBinding binding the role
to `hello-account` all exist and are correctly wired. The pod simply never
uses that identity.

### 5. Zero downstream effect — no prime PVC, no populate pod, datasource PVC stuck

- `kubectl get pods -A | grep -E 'pop-|prime|populate'` → only the
  controller pod itself; no prime/populate pod ever created.
- `kubectl describe pvc pvc-86d88 -n provisioning-81` → stuck in
  `ExternalProvisioning`/"Waiting for a volume to be created ... by the
  external provisioner ... or manually", repeating every ~30s with no
  progress.
- `kubectl get hellos -A` / `kubectl get volumepopulators -A` → both the
  `Hello/example-hello` CR and the `VolumePopulator/hello-populator-provisioning-81`
  object exist and are served correctly by the apiserver (ruling out CRD/PVC
  watch-serving as a contributing cause) — the controller simply never
  successfully lists them due to (1) above.

## Smallest fix locus

`crates/apiserver/src/handlers/pods.rs`, function `apply_pod_spec_defaults`
(~line 5148-5160): before defaulting `spec.serviceAccountName` to
`"default"`, fall back to `spec.serviceAccount` (the deprecated alias) when
present and non-empty — mirroring upstream `SetDefaults_PodSpec`'s
`if obj.ServiceAccountName == "" { obj.ServiceAccountName =
obj.DeprecatedServiceAccount }`. This is a pod-admission defaulting bug
affecting any pod created with only the legacy `spec.serviceAccount` field
set; it is not specific to the populator/CSI flow, though this is the first
conformance path that exercises it.
