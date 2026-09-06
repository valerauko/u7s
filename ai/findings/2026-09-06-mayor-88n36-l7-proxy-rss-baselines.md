# L7 proxy idle-RSS baselines for a 1GB/1vCPU node class (desk research)

Bead: mayor-88n36
Status: exploratory desk research, RE-SCOPED per operator 2026-09-06 to
documented baselines + a runnable methodology. Live on-hardware RSS
measurement remains PENDING an actual L7-tier prototype and a Lima VM;
this doc does NOT close mayor-88n36. Awaiting operator.

## Answer

Do not pick an L7 proxy on folklore RSS numbers. The one thing the cited
public data settles is the opposite of reassuring: Envoy Gateway's own
default sizes the Envoy data-plane container at a **512Mi memory request
— half of a 1GB node** — and the only first-party *measured* Envoy figure
(Istio, ~60MB) is for a trimmed sidecar under light load, a config an
ingress with many routes will exceed. No clean first-party *measured
idle-RSS* number exists in public docs for any of nginx/HAProxy as raw
processes; what's publishable is vendor-default resource *requests*
(sizing defaults, not RSS) plus one measured Envoy datapoint. This is the
same trap the ServiceLB ADR already hit with loxilb — "expected to fit,"
then ENOMEM crash-loop on a real 1 CPU/1GiB Lima VM
(`docs/decisions/servicelb-ebpf-geneve-dataplane.md:35`). The proxy
choice must wait on the real measurement whose method is specified below.

## Scope and why this exists

The prior L7 finding (`2026-09-03-l7-tls-source-transparency.md`, now
deleted — content in git at `59f263a4^`) cited "Envoy ~150MB", "nginx
~50–100MB", "HAProxy lightest" from operational memory, uncited, and
itself filed this bead to substantiate or refute them. The ADR's loxilb
precedent is the standing warning: a vendor/folklore RAM expectation
wrong by enough margin crash-loops on the exact 1 CPU/1GiB target class
(loxilb needs 2GiB to start; `servicelb-ebpf-geneve-dataplane.md:36-38`).
The prior finding's own viability argument rests on the L7 tier fitting a
constrained node pool, so the RSS number is load-bearing for the whole
L7 direction.

Candidates, per the prior finding: Envoy (+ Envoy Gateway), nginx OSS (+
NGINX Gateway Fabric), HAProxy.

## Per-proxy idle-RSS baselines, with provenance

Provenance labels:
- **[measured-published]** — a first-party/reputable *measurement* with a
  citable source.
- **[vendor-default]** — a resource request/limit the vendor ships in
  official config. Real and citable, but a *sizing default, not an RSS*;
  set conservatively and NOT comparable across projects as if it were RSS.
- **[behavioral]** — vendor docs describe how memory *scales*, without a
  single idle-RSS figure.
- **[folklore]** — operational memory, no source (the numbers this bead
  exists to test).

All fetched 2026-09-06 via `gh api` from each project's default branch;
raw files cached under `temp/research/`.

| Proxy | Figure | Provenance | Source |
|---|---|---|---|
| Envoy (Envoy Gateway data plane) | **512Mi memory request** (CPU 100m) — default for the Envoy proxy container (Deployment and DaemonSet) | [vendor-default] | `envoyproxy/gateway` `api/v1alpha1/shared_types.go` (`DefaultDeploymentMemoryResourceRequests="512Mi"`), applied via `kubernetes_helpers.go` `DefaultResourceRequirements()`→`DefaultKubernetesContainer` |
| Envoy (sidecar) | **~60 MB** at 1000 rps / 1KB payload / 2 worker threads (Istio 1.24) | [measured-published] | `istio/istio.io` perf doc: "a single sidecar proxy with 2 worker threads consumes about 0.20 vCPU and 60 MB of memory"; same doc: "depends on the total configuration state… a large number of listeners, clusters, and routes can increase memory usage" |
| Envoy | ~150MB idle | [folklore] | prior finding, uncited |
| nginx OSS (ingress-nginx controller) | **90Mi memory request** (CPU 100m) | [vendor-default] | `kubernetes/ingress-nginx` `charts/ingress-nginx/values.yaml` `controller.resources.requests` |
| nginx OSS (raw) | small base; scales with `worker_processes` × per-worker buffers | [behavioral] | nginx worker model; no single first-party idle-RSS MB figure found |
| nginx | ~50–100MB idle | [folklore] | prior finding, uncited |
| NGINX Gateway Fabric | data plane = **OSS nginx by default** (`plus: false`); so data-plane RSS ≈ OSS nginx. Helm sets **`resources: {}` for BOTH** control and data plane (no default) | [vendor-default: none] | `nginx/nginx-gateway-fabric` `charts/nginx-gateway-fabric/values.yaml`: `nginx.plus=false`, `nginx.resources={}`, `nginxGateway.resources={}` |
| NGINX Gateway Fabric | control plane = separate Go pod (`nginxGateway` container), off the data path — its own RSS, additive to the nginx data-plane pod | [vendor-default: none] | same values.yaml (two separate Deployments) |
| HAProxy (k8s ingress controller pod) | **400Mi memory request** (CPU 250m) — controller container bundles the Go controller + haproxy | [vendor-default] | `haproxytech/helm-charts` `kubernetes-ingress/values.yaml` `controller.resources.requests` |
| HAProxy (raw) | small base; memory scales per-connection (~`tune.bufsize`×2, default bufsize 16KB) | [behavioral] | `haproxy/haproxy` docs (`doc/management.txt` §6 memory management; `doc/configuration.txt` `tune.bufsize`) |
| HAProxy | "lightest" | [folklore] | prior finding, uncited |

Reading the table: the only cross-project figures that exist as
published data are the vendor-default *requests* (512Mi / 90Mi / 400Mi /
none-none) and Istio's single measured Envoy sidecar (~60MB). None is an
idle-RSS measurement of the artifact u7s would actually run. Vendor
requests are set with wildly different conservatism per project and must
NOT be read as RSS or compared as such — they bound expectations, not
actuals.

## Can the existing finding's uncited numbers be substantiated?

- **"Envoy ~150MB" — NOT confirmed; bracketed, not measured.** The one
  real measurement is ~60MB (Istio, trimmed sidecar, light load), and
  Envoy Gateway's vendor default is a 512Mi *request*. 150MB is plausible
  for a moderately-configured standalone Envoy and sits inside the
  60MB–512Mi bracket, but no cited measurement lands on it. Envoy memory
  is explicitly config-dependent (listeners/clusters/routes), so a single
  "idle" number is the wrong shape anyway.
- **"nginx ~50–100MB" — partially bracketed, likely overstates raw idle
  RSS.** The ingress-nginx vendor-default *request* is 90Mi, inside that
  band, but that is a request, not RSS; a raw idle nginx (master + a
  couple of workers) is typically well under that. Consistent with the
  vendor request envelope; not confirmed as measured idle RSS.
- **"HAProxy lightest" — REFUTED as stated, with a nuance.** For the
  *raw process*, HAProxy's near-zero base + per-connection buffers make
  it genuinely the lightest of the three. But at the artifact u7s would
  deploy — the k8s ingress *controller pod* — HAProxy's own chart
  requests **400Mi, more than nginx's 90Mi**. "Lightest" does not survive
  at the pod level; it holds only for the bare binary. Which one matters
  depends on whether u7s ships a controller or a hand-rolled proxy (see
  open questions).

Net: none of the three folklore numbers is substantiated as a measured
idle RSS. The cited data brackets them and refutes "HAProxy lightest" at
the pod level. This is exactly why the live measurement is still needed.

## Runnable measurement methodology (for a future worker with a Lima VM)

Goal: a defensible steady-state memory number per proxy on the target
node class, decided the way `mayor-lrbvo` decides the eBPF dataplane — by
measurement, not estimate.

1. **Node.** Provision one Lima VM matching the loxilb test rig: **1 vCPU
   / 1GiB**, cgroup v2. Same class the ADR crash-looped loxilb on, so the
   number is directly comparable to the standing precedent. Keep it
   otherwise idle — nothing else scheduled.
2. **Baseline the node first.** With NO proxy, record resident memory of
   the co-resident stack (kernel + kubelet + containerd + CNI) via
   `/proc/meminfo` `MemAvailable` and per-cgroup `memory.current`. The
   proxy's budget is **1GiB minus this**, not 1GiB. The loxilb lesson is
   precisely that "expected to fit" ignored co-resident overhead — budget
   against free memory.
3. **One proxy at a time.** Never run two candidates concurrently (they'd
   contend for the 1GiB and pollute each other's numbers). Deploy the
   artifact u7s would actually run — decide with the operator whether that
   is the full controller (Envoy Gateway / NGF / HAProxy ingress, driven
   by Gateway API) or a bare proxy binary; measure that form.
4. **Fair, fixed config (this is the crux).** L7-proxy RSS scales with
   config size — Envoy listeners/clusters/routes, nginx server
   blocks/upstreams, HAProxy frontends/backends. A "0-route" boot
   understates a real ingress; a giant config overstates it. Measure a
   **config sweep, identical across proxies**:
   - `boot` — 0 routes (pure startup floor).
   - `rep` — a representative ingress: 1 TLS `:443` listener/frontend
     terminating TLS with a real cert + explicit session-cache size, N=10
     Services × M=3 endpoints each.
   - `scaled` — 100 Services × 3 endpoints, to get the per-route slope.
   Hold N/M/cert/session-cache identical across all proxies. Report the
   slope, not just one point — the decision number is `rep` (and its slope
   toward `scaled`), never `boot`.
5. **Reach steady-state idle.** Start proxy, apply config, send a short
   warmup then quiesce (no ongoing traffic). Sample RSS every 5s until the
   delta over a 60s window is < ~1–2% (Envoy lazy-allocates — give it
   time). Record time-to-plateau.
6. **Sample all three memory views, and know why each:**
   - **RSS** (`/proc/<pid>/status` `VmRSS`, or `ps -o rss`) — resident
     set; *overcounts* shared library pages per process. Familiar
     cross-check only.
   - **PSS** (`/proc/<pid>/smaps_rollup` `Pss`) — proportional set size;
     splits shared pages fairly across processes. The right number for
     comparing a **multi-process** proxy (nginx master+workers, or a
     controller-pod's sidecars) fairly against a single-process one.
   - **cgroup `memory.current`** (v2, the pod/container cgroup), plus
     **`memory.peak`** — what the kernel actually charges the container,
     *including* page cache + kernel memory, and what the OOM killer and
     the 1GiB limit act on. **This is the decision number** — it is the
     exact axis loxilb failed on. Take the *peak* over the idle window,
     not the last sample (the kernel may reclaim file pages and understate
     steady anon growth).
   - Also record `RssAnon` vs `RssFile` from `smaps_rollup` — anon is the
     un-reclaimable part.
7. **Repeat 3× per proxy** (fresh pod each run) to catch variance; report
   min/median/max at each config point.
8. **Gate (mirror `mayor-lrbvo`).** Pass iff `rep` steady-state cgroup
   `memory.current` + step-2 node overhead leaves clear headroom under
   1GiB (suggest proxy pool node stays < ~60–70% of 1GiB, so a config or
   traffic spike doesn't OOM). If it doesn't, the L7 tier needs a larger
   node class — decide that explicitly rather than discovering it via a
   crash-loop.

## Open questions for the operator

1. **Does the L7 node pool have to fit 1GiB/1vCPU at all?** The prior
   finding assumes L7 runs as a *separately-scaled* pool, not the eBPF
   per-node DaemonSet. If the pool can be 2–4GiB nodes, Envoy's 512Mi
   default is a non-issue and this whole constraint may not bind. Confirm
   the target node class for the L7 pool *before* measuring — it changes
   whether Envoy is even disqualified.
2. **Which artifact do we measure — full controller or bare proxy?**
   Controller pods bundle a Go control plane (NGF, HAProxy ingress) that
   dominates the pod's memory and is what the vendor requests size. If
   u7s hand-rolls a minimal TPROXY proxy (the prior finding noted the
   crates already carry hyper/rustls/socket2), the relevant number is the
   bare-proxy floor, not the controller pod. Decide before measuring.
3. **Representative config size** — is N=10 Services / M=3 endpoints the
   right `rep` point for u7s's expected fleet, or larger?
4. **Is `mayor-bguco` (L3 return-path reuse) resolved?** If the L7 tier's
   backend-dial integration is not viable, RSS measurement is moot; that
   question gates this one.

## References / cached sources

- `docs/decisions/servicelb-ebpf-geneve-dataplane.md` (loxilb precedent,
  1GiB ENOMEM, needs 2GiB) — the standing warning against folklore RAM.
- Prior finding content (deleted): `git show
  59f263a4^:ai/findings/2026-09-03-l7-tls-source-transparency.md`.
- `temp/research/istio-perf.md` — `istio/istio.io`
  `content/en/docs/ops/deployment/performance-and-scalability/index.md`
  (Envoy sidecar ~60MB, Istio 1.24).
- `temp/research/ngf-values.yaml` — `nginx/nginx-gateway-fabric` Helm
  values (OSS nginx data plane; resources {}).
- `temp/research/ingress-nginx-values.yaml` — `kubernetes/ingress-nginx`
  Helm values (90Mi request).
- `temp/research/haproxy-helm-values.yaml` — `haproxytech/helm-charts`
  kubernetes-ingress values (400Mi request).
- `temp/research/haproxy-ingress-deploy.yaml` — `haproxytech/kubernetes-ingress`
  static deploy manifest (no resources set).
- Envoy Gateway 512Mi default: `envoyproxy/gateway`
  `api/v1alpha1/shared_types.go` + `api/v1alpha1/kubernetes_helpers.go`
  (fetched via `gh api`, default branch, 2026-09-06; not cached as a file).
