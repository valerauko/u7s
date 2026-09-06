# tc-bpf hook topology for a future TPROXY return-leg reuse

Bead: mayor-bguco
Date: 2026-09-06
Status: decision-input, no code changed. Options + evidence + recommendation;
operator decides. Not a commitment to build the L7 tier (epic mayor-s82zr).

## Answer

**Recommendation: separate hooks, sharing programs and maps — not one
merged hook.** Keep the current L3 topology (`uplink_ingress` on eth0
ingress, `geneve_ingress` on geneve0 ingress, `uplink_egress_return` on
eth0 egress) exactly as-is. A future TPROXY reuse splits into two
independent pieces, and neither is served by a single merged hook:

1. **Classifying a same-node proxy's connection to a local VIP** cannot use
   the existing eth0-ingress hook at all — that traffic never reaches eth0.
   It needs its own attach point on the loopback device `lo`. This is
   forced by the kernel, not a preference.
2. **Delivering the Geneve-returned reply to the local proxy socket** reuses
   the *existing* `geneve_ingress` hook; only its terminal action changes
   (local delivery instead of `bpf_redirect(uplink)`), gated on a per-flow
   "origin was local" bit.

Separate attach points are also the cheaper choice on both axes the bead
names: per-packet cost is minimized because each tc program only runs on
its own device's traffic, and kernel memory is dominated by the conntrack
maps, which are shared by name regardless of hook count. A literal "one
hook doing everything" would have to attach at a point seeing a *superset*
of traffic (there is none that sees exactly the union and nothing else), so
it can only cost more per packet, never less.

**Nothing is built now.** What is decided now is the shape the L3 dataplane
must preserve so the L7 leg can be added without a retrofit: keep maps
pinned and shareable (already true), keep the classifier logic
attach-point-agnostic (already true), and know that the one data-model
extension the return leg will need is an origin flag in `FWD_FLOW`'s value —
documented here, deliberately *not* added yet (an unused field is
speculative).

## Current topology (baseline)

From `crates/servicelb/servicelb-ebpf/src/main.rs` and
`crates/servicelb/src/main.rs`: three programs, attached at three points
(four logical roles; `geneve_ingress` multiplexes the forward-decap and
return-decap roles by VNI).

| Program | Device | Direction | Role |
|---|---|---|---|
| `uplink_ingress` | eth0 | ingress | forward-leg classify + Geneve encap |
| `geneve_ingress` | geneve0 | ingress | decap (VNI_FWD=backend DNAT, VNI_RET=ingress un-DNAT) |
| `uplink_egress_return` | eth0 | egress | backend reply → Geneve encap |

## The kernel constraint, stated precisely

**Where each tc/clsact hook actually runs** (Linux `net/core/dev.c`,
current tree):

- tc/clsact **ingress** runs in `sch_handle_ingress()`, called from
  `__netif_receive_skb_core()` (dev.c ~L6115). It fires for every skb a
  netdevice *receives*, before the IP stack, before the netfilter ingress /
  PREROUTING hooks, before any routing decision.
- tc/clsact **egress** runs in `sch_handle_egress()`, called from
  `__dev_queue_xmit()` (dev.c ~L4860). It fires for every skb a netdevice
  *transmits*, after routing and POSTROUTING, just before the driver tx
  queue.

Each hook is bound to exactly one `(device, direction)` pair and only sees
packets crossing that pair.

**Local delivery to a node-owned address does not touch eth0.** For any IP
assigned to any interface, the kernel installs an `RTN_LOCAL` route in the
`local` table. When a local process connects to such an address (the node's
own eth0 IP, or a VIP that in the node-owned-address model *is* the node's
own IP), the output-route lookup resolves the output device to the
**loopback device `lo`** (`net->loopback_dev` for `RTN_LOCAL`), not eth0.
The packet is transmitted on `lo` (`loopback_xmit`) and looped straight
back into the receive path on `lo`. It therefore traverses:

- `lo` clsact **egress**, then `lo` clsact **ingress**,
- and **never** eth0 clsact ingress or eth0 clsact egress.

### Traffic class → hook that sees it

| Traffic class | Device/direction traversed | Hook that sees it |
|---|---|---|
| Remote client → NODE_IP:SVC_PORT (forward) | eth0 ingress | `uplink_ingress` ✓ |
| Geneve packet arriving (fwd or return) | eth0 ingress (as UDP) → kernel decaps → geneve0 ingress | `geneve_ingress` ✓ |
| Backend Pod reply → remote client (return) | eth0 egress | `uplink_egress_return` ✓ |
| **Same-node proxy → local VIP (forward)** | **lo egress, then lo ingress** | **none today — needs a new lo hook** |
| Geneve return whose real client is a local proxy | eth0 ingress → geneve0 ingress | `geneve_ingress` ✓ (terminal action must change) |

The fourth row is the bead's constraint made exact: a single hook on the
physical uplink alone cannot serve a same-node proxy dialing the local VIP,
because that packet is on `lo`, not eth0, in both directions.

## The future TPROXY reuse, split into two facets

### Facet 1 — classify the proxy's outbound VIP connection into Geneve

Needs a hook that sees loopback traffic: attach a classifier to **`lo`**
(egress or ingress) that does the same VIP-match + Geneve-encap +
redirect-to-geneve0 the eth0 `uplink_ingress` already does. The
**classification logic is identical** — it keys on the packet's dst
(VIP:PORT) and reads ifindexes from `CONFIG` — so the *same compiled
program* can be attached at the additional `lo` point; only the attach point
differs. This is "separate hook, shared program," not a second program.

Caveats to validate *when built*, not now:
- **Loopback checksums and GSO.** Loopback skbs skip checksum computation
  (`drivers/net/loopback.c` header note) and can be large GSO super-packets
  exceeding MTU. The classifier's `l3/l4_csum_replace` and fixed-offset
  header reads assume a finalized, single-MTU packet. A `lo`-attached
  classifier must handle `CHECKSUM_PARTIAL`/`CHECKSUM_UNNECESSARY` and
  segmentation.
- **A `lo` hook taxes all localhost traffic** (health checks, 127.0.0.1
  IPC) with the classifier's early-exit path (eth-type, proto, VIP-map
  miss). Cheap per packet, but non-zero on potentially high localhost
  volume.
- **A cheaper alternative to a `lo` tc hook exists** and should be weighed
  then: a `BPF_CGROUP_INET4_CONNECT` (cgroup connect) hook fires once per
  `connect()` syscall, not once per packet — Cilium's socket-LB pattern. It
  rewrites the destination at socket time rather than redirecting a packet
  into a tunnel, so it is a *different* mechanism with different topology
  implications, not a drop-in for the tc classifier. Deferred.

Note: classic iptables/nft TPROXY (`-t mangle -A PREROUTING ... -j TPROXY`,
`IP_TRANSPARENT`) is a socket-steering tool for the *input* path, and it
runs *after* tc ingress (PREROUTING is downstream of `sch_handle_ingress`).
It cannot perform facet 1's "redirect an outbound connection into a Geneve
tunnel." Classic TPROXY is a facet-2 tool at most.

### Facet 2 — deliver the Geneve-returned reply to the local proxy socket

This reuses the **existing** `geneve_ingress` hook. Today `try_geneve_decap_return`
un-DNATs `src` back to the VIP and does `bpf_redirect(uplink_ifindex)` to
send the reply out to a remote client. For a *local* proxy the reply's dst
is a node-owned address and must be delivered locally instead. That is a
change to the *terminal branch only*, selected by a per-flow "origin was
local" bit — the hook, the decap, the conntrack lookup all stay. Delivery
mechanism options (decide then): `TC_ACT_OK` after `bpf_skb_change_type`
(as the forward-decap already does), `bpf_sk_assign` (`BPF_PROG_TYPE_SK_LOOKUP`
or the tc-bpf `sk_assign` helper), or redirect to `lo`. All are terminal-action
choices inside one existing hook, not new hooks.

## Kernel memory and per-packet cost: separate vs merged

**Per-packet processing.** A tc program runs only on packets crossing its
`(device, direction)`. eth0-received traffic and loopback traffic are
disjoint sets, so with separate attach points each packet pays exactly one
classifier pass. There is no attach point that sees exactly
"eth0-received ∪ loopback-originated" and nothing else; any single merged
hook would have to sit somewhere seeing a *superset*, taxing unrelated
traffic. Separate is therefore strictly ≤ merged on per-packet cost. Folding
facet 2 into `geneve_ingress` adds one branch (an origin-bit check) to a
path that already does a `FWD_FLOW` lookup — negligible.

**Kernel memory.** Per `ebpf-lb-dataplane.md`'s own sizing table, program
text is ~0 MiB (5–50 KiB JIT'd each, kernel-resident); the maps are the
real cost (~1–2 MiB, dominated by `FWD_FLOW`/`REV_FLOW`). Consequences:

- Attaching an *existing* program at an added `lo` point costs ≈ 0 (the
  program is loaded once; a link is a few bytes).
- A *new distinct* program would add one program's text — tens of KiB,
  still negligible against the maps.
- The conntrack/VIP maps are **shared by name** (`MAP_NAMES` in
  `crates/servicelb/src/main.rs`, pinned under bpffs). A `lo`-attached
  classifier and the return-leg local-delivery branch reuse the *same*
  pinned maps. Map memory is therefore invariant to the hook count.

Net: the memory axis does not favor a merged hook; if anything it mildly
favors "reuse one program at multiple attach points" (zero extra text). The
perf axis favors separate. Both point the same way.

## What to preserve now vs defer

**Preserve now (already true — verify these invariants aren't regressed):**
- Maps stay pinned and shared by name, not program-private
  (`crates/servicelb/src/main.rs` `MAP_NAMES` + `map_pin_path`).
- The classifier stays attach-point-agnostic: it derives everything from
  packet headers and `CONFIG` ifindexes, so it already works if attached to
  `lo`. Do not bake an eth0 assumption into it.

**Document now, do not build (would be speculative — Rule 2):**
- `FWD_FLOW`'s value is `u32` (backend node IP). The return leg's local
  delivery needs an additional "origin was local" flag so
  `try_geneve_decap_return` can choose local delivery over
  `bpf_redirect(uplink)`. Widening a pinned map's value is itself a
  map-version change, so there is no cost to deferring it. **Not added
  now.**

**Defer entirely until an L7 tier is scoped (epic mayor-s82zr):**
- Facet-1 mechanism: `lo` tc hook vs `BPF_CGROUP_INET4_CONNECT` vs
  `sk_lookup`.
- Facet-2 delivery: `change_type`+`TC_ACT_OK` vs `bpf_sk_assign` vs
  redirect-to-`lo`.
- Loopback `CHECKSUM_PARTIAL`/GSO handling for any `lo`-attached rewriter.
- `IP_TRANSPARENT` requirement on the proxy socket vs an all-eBPF approach.

## Open questions for the operator

1. **Will the L7 proxy reuse the L3 dataplane by dialing the VIP, or dial
   backends directly?** If it dials the VIP, facet 1 (a `lo`/connect hook)
   is required. If it dials backends directly, facet 1 may not exist at all
   and only facet 2's local-delivery branch matters. This single choice
   decides whether any new hook is ever needed.
2. **Will the proxy run hostNetwork (loopback path, as analyzed here — and
   as the servicelb DaemonSet itself runs) or as a normal Pod in its own
   netns?** A Pod's traffic to the VIP crosses its veth pair, which has
   ordinary tc ingress/egress hooks and normal (non-loopback) checksums —
   a materially different facet-1 analysis (veth hook, not `lo` hook, and no
   loopback-checksum caveat).
3. **Is requiring `IP_TRANSPARENT` on the proxy socket acceptable**, or must
   socket steering be fully eBPF-side (`sk_assign`)?

## Confidence

**High** on the kernel path facts — hook placement verified against
`net/core/dev.c` (`sch_handle_ingress`/`sch_handle_egress` call sites) and
the loopback local-delivery behavior against `RTN_LOCAL` routing +
`drivers/net/loopback.c`; TPROXY/`sk_lookup`/`sk_assign` semantics against
current kernel docs. **Medium** on the exact future L7 shape, which hinges
on the two undecided operator questions above (proxy placement and whether
it reuses the VIP). The recommendation holds under either answer: separate
hooks with shared programs/maps is the cheaper and, for facet 1, the only
kernel-feasible topology.

## References

- Code: `crates/servicelb/servicelb-ebpf/src/main.rs` (`uplink_ingress`,
  `geneve_ingress`, `uplink_egress_return`);
  `crates/servicelb/src/main.rs` (attach points, `MAP_NAMES`, pinning).
- Mechanism: `ai/extended-context/ebpf-lb-dataplane.md` ("Hooks", "Hook
  topology" note, sizing table).
- Kernel (current tree, cached under `temp/research/`): `net/core/dev.c`
  `sch_handle_ingress`/`sch_handle_egress`; `drivers/net/loopback.c` header;
  `Documentation/networking/tproxy.rst`; `Documentation/bpf/prog_sk_lookup.rst`.
- L7 tier epic: mayor-s82zr (future, unscoped). Discovered-from: mayor-98i0y.
</content>
</invoke>
