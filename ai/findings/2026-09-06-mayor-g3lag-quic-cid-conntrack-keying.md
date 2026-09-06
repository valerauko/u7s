# QUIC CID vs 4-tuple conntrack keying — L7-proxy survey + recommendation

Bead: mayor-g3lag

Status: decision-input survey, no code changed. Read-only research. Awaiting operator decision.

## Answer (recommendation)

**Ship 4-tuple pass-through keying for QUIC now; treat CID-based keying as a
later, opt-in upgrade — and specifically as draft-ietf-quic-load-balancers
self-encoding CIDs, NOT the "LB-minted fixed-length CID" the current
mechanism doc describes.** The survey's decisive finding is that
"LB-minted CID" is not realizable by u7s's non-terminating tc-bpf dataplane
at all: the connection ID a client uses to reach the server is *server*-chosen
(RFC 9000 §7.2), and post-handshake CIDs are issued inside encrypted
NEW_CONNECTION_ID frames a non-terminating LB cannot read or rewrite. The only
way an L3/L4 LB can key on a CID across CID rotation is if the *backend*
generates routable, self-describing CIDs by a scheme the LB decodes — i.e. the
QUIC-LB draft. Of the four proxies surveyed, only **Envoy** implements that
draft, and only on the *server* (CID-generator) side; nginx, HAProxy, and
Traefik all terminate QUIC and expose no routable-CID scheme for an external
stateless LB. Because u7s's backends are arbitrary user pods it does not
control — and because the 1-RTT short header omits the CID length (RFC 9000
§17.3.1), so the LB cannot even *locate* the DCID in a mid-stream packet
without a backend-agreed length — CID keying is unavailable in the default
case. 4-tuple pass-through is the only method that works with uncooperative
backends; its cost is degraded affinity across connection migration and NAT
rebinding, stated in full below.

## Context

u7s's ServiceLB is a non-terminating per-node eBPF (tc-bpf) dataplane: it
consistent-hashes a client packet to a backend, Geneve-encapsulates it, and
never terminates TLS/QUIC (`docs/decisions/servicelb-ebpf-geneve-dataplane.md`;
`ai/extended-context/ebpf-lb-dataplane.md`). For TCP/UDP it keys conntrack on
the 5-tuple. The open question is how to key QUIC, whose whole point is to
survive the client's IP/port changing — which is exactly what breaks 5-tuple
affinity.

The mechanism doc (`ebpf-lb-dataplane.md` lines 99-111) currently proposes
"a fixed-length Destination Connection ID prefix, minted by the LB (RFC 9000
§17.2's self-describing Initial-packet DCID)" and separately declines
draft-ietf-quic-load-balancers "on routing grounds" (line 108) as overkill for
a single ingress hop. This survey addresses the *keying* question the doc
flagged as open (line 164), and in doing so corrects the "minted by the LB"
framing.

## The keying methods, corrected

There are three realizable methods for a non-terminating LB, not two. The
"LB-minted CID" in the doc is a fourth that does not exist for this dataplane.

1. **4-tuple pass-through.** Ignore the CID; key on
   `(CLIENT_IP, SRC_PORT, VIP_IP, VIP_PORT, proto)` like UDP. No backend
   cooperation. Affinity breaks whenever the client tuple changes (migration
   or NAT rebind): the new tuple re-hashes independently and, with N backends,
   lands on the *same* backend only ~1/N of the time; otherwise the packet
   reaches a backend with no QUIC state for the connection and the connection
   effectively resets (client reconnects). This defeats QUIC's migration
   resilience but loses no committed application data.

2. **Opaque-DCID observe-and-pin.** Key on the DCID bytes as first seen (at a
   fixed, backend-agreed length), pin to the chosen backend. Survives NAT
   rebinding (same DCID, new 4-tuple — RFC 9000 §9.5 permits keeping the CID
   on an unintentional path change). Still breaks on *deliberate* migration:
   §9.5 requires the client to switch to a new, never-before-used CID when it
   changes local address, and that CID was issued in an encrypted
   NEW_CONNECTION_ID frame the LB never saw — so the LB has no mapping for it.
   Also still requires backend cooperation on CID length (§17.3.1: the
   short header has no length field). Half-measure: adds a stateful QUIC CID
   map but only fixes rebind, not migration.

3. **QUIC-LB self-encoding CID (draft-ietf-quic-load-balancers).** The
   *backend* generates every CID (including rotated ones) so that it
   self-encodes a routing token (server_id) the LB decodes statelessly, with
   the CID length self-described in a fixed first-octet field. Survives NAT
   rebind *and* migration, because even a freshly rotated CID still carries the
   server_id. Requires the backend to run a QUIC-LB-aware CID generator and to
   share config/keys with the LB.

4. **"LB-minted CID" (as written in the doc) — not realizable here.** For the
   LB to mint the CID the client routes on, the LB would have to choose the
   server's Source Connection ID and control every subsequent CID rotation.
   Post-handshake CIDs travel in encrypted NEW_CONNECTION_ID frames (RFC 9000
   §5.1.1, §7.2), so a non-terminating dataplane cannot mint or even observe
   them. Minting the CID requires *terminating* QUIC — which contradicts the
   tc-bpf non-terminating design. This is the survey's central correction.

Why the routing CID is server-chosen (RFC 9000 §7.2, verbatim): "the client
uses the Source Connection ID supplied by the server as the Destination
Connection ID for subsequent packets" (lines 1874-1876), and "the Destination
Connection ID is chosen by the recipient of the packet and is used to provide
consistent routing" (lines 1839-1840). RFC 9000 §5.1 blesses the cooperation
model this survey lands on — not LB minting: "Endpoints using a load balancer that routes based on
connection ID could agree with the load balancer on a fixed length for
connection IDs or agree on an encoding scheme" (lines 1306-1310) — the
endpoint (server) agrees with the LB, it does not receive a minted CID from
it — and CIDs
"MUST NOT contain any information that can be used by an external observer
(that is, one that does not cooperate with the issuer)" — a *cooperating* LB
is explicitly the exception (lines 1293-1295). The QUIC-LB draft states the
division of labor outright: "load balancers do not generate individual
connection IDs for servers. Instead, they communicate the parameters of an
algorithm to [the servers, which] generate routable connection IDs"
(draft-ietf-quic-load-balancers, Overview, lines 140-142).

## Per-proxy survey

Each verdict answers: can this proxy cooperate with routable/self-describing
QUIC CIDs for an external stateless L3/L4 LB (the u7s role)?

### Envoy — YES (server-side QUIC-LB generator), the only cooperator

Envoy ships `envoy.quic.connection_id_generator.quic_lb`, "a connection ID
generator implementation for the QUIC-LB draft RFC for routable connection
IDs" (added in Envoy 1.34.0). It generates CIDs that encode an encrypted
`server_id` + `nonce`, with the CID length self-encoded per the draft's
"length self-description," keyed by a shared 16-byte `encryption_key` and a
`configuration_version` distributed over SDS. Source:
`api/envoy/extensions/quic/connection_id_generator/quic_lb/v3/quic_lb.proto`
(cached: `temp/research/envoy-quic_lb.proto`); changelog 1.34.0. This is the
*server* (CID-generator) half — exactly the backend-cooperation half u7s would
need — and the draft describes the LB decoding it. Note this proves
cooperation is *possible* only when the backend is Envoy so configured; it is
not a property u7s gets for free from arbitrary pods.

### nginx — NO (terminates; CID routing is host-internal only)

nginx terminates QUIC/HTTP3 (`ngx_http_v3_module`). Its CID handling is
host-local, not an external routable-CID scheme: `quic_bpf on` "enables routing
of QUIC packets using eBPF … [to support] QUIC connection migration" — this
steers packets to the correct *worker process* across SO_REUSEPORT sockets on
one host, not to a backend across nodes. `quic_host_key` is merely "the secret
key used to encrypt stateless reset and address validation tokens," not a
routing encoding. No draft-ietf-quic-load-balancers support. Source:
`nginx.org/en/docs/http/ngx_http_v3_module.html` (cached:
`temp/research/nginx-http3.html`), `quic_bpf`/`quic_host_key` directives.

### HAProxy — NO (terminates; CID secret is for tokens, not routing)

HAProxy terminates QUIC/HTTP3. Its cluster-wide CID-related knob,
`cluster-secret`, is "used to derive stateless reset tokens for all the QUIC
connections … [and] to encrypt Retry tokens" — address-validation and reset
machinery, not routable-CID encoding. QUIC bind/server options
(`quic-cc-algo`, `quic-force-retry`) confirm HAProxy is the QUIC endpoint, not
a routable-CID cooperator for an external LB. No draft support. Source:
HAProxy configuration manual (cached: `temp/research/haproxy-config.txt`),
`cluster-secret` / `quic-force-retry` / `quic-cc-algo`.

### Traefik — NO (terminates HTTP/3 at the entrypoint)

Traefik terminates HTTP/3 at an entrypoint and advertises it via the `alt-svc`
header (`http3.advertisedPort`). Multi-process distribution relies on
`reusePort` (SO_REUSEPORT kernel hashing), with no CID-aware steering and no
QUIC-LB scheme documented. Source: Traefik entrypoints reference (cached:
`temp/research/traefik-entrypoints.md`), `http3` / `http3.advertisedPort` /
`reusePort`.

Only the QUIC-LB draft itself and Envoy's proto reference the draft across all
fetched sources (verified: grep for `quic-load-balancer|quic_lb|routable
connection` matched only `draft-quic-lb.md` and `envoy-quic_lb.proto`).

## Recommendation + migration-affinity trade-off

**Default: 4-tuple pass-through.** It is the only method that works with the
arbitrary, uncooperative backends u7s must support by default, it needs no CID
map or shared crypto, and it is correctness-first (never misroutes; at worst
forces a client reconnect). Given u7s's envelope (<10 nodes, single ingress
hop — the same reason line 108 declined the draft's richer scheme), this is the
right first landing and the doc's own stated fallback.

**Explicit trade-off accepted by pass-through:**
- **Connection migration (deliberate):** client changes network, rotates to a
  new CID and new 4-tuple. Pass-through re-hashes on the new tuple; ~1/N chance
  of the same backend. Affinity lost; connection resets on miss. This is the
  headline QUIC feature u7s gives up.
- **NAT rebinding (idle-then-resume):** new 4-tuple, possibly same CID.
  Pass-through also re-hashes and may miss. (Opaque-DCID keying would fix *this*
  case but not deliberate migration — see below.)
- **What is NOT lost:** in-flight committed data. A miss is a reconnect, not
  corruption, because u7s never terminates the connection.

**Upgrade path, if/when affinity matters:** go straight to method 3 (QUIC-LB
self-encoding CIDs), skipping method 2. Rationale: method 2 (opaque-DCID pin)
already requires backend cooperation on CID length yet only fixes NAT rebind,
not migration — so it buys a stateful CID map for half the benefit. If backends
are going to cooperate at all, cooperating on the full QUIC-LB encoding (method
3) is the same class of ask and fixes both cases. Make it per-Service opt-in,
enabled only for workloads whose backends emit QUIC-LB CIDs (today: an Envoy
front-proxy sidecar/backend). Do NOT bake "LB-minted CID" into the mechanism
doc — strike that phrasing; the LB decodes a backend-minted CID, it never mints
one.

Consequence for the doc: the QUIC bullet in `ebpf-lb-dataplane.md` (lines
99-111) and the "QUIC is exempt: it already keys on a minted DCID" note (line
160) both rest on the unrealizable "LB-minted DCID." Under this recommendation
QUIC is *not* exempt — it uses the same 4-tuple key as UDP by default, and the
QUIC CID map (lines 99-102, 120) does not exist until the opt-in upgrade. That
also changes the backend reverse-flow collision story (line 159): QUIC no
longer has a distinguishing minted DCID, so it inherits UDP's source-port
remap remedy.

## Coupling to mayor-aie31.11 (flow-table admission control)

**This keying decision removes an option from aie31.11's QUIC admission menu,
because both beads share the same false premise — that the LB mints the DCID.**

aie31.11 proposes, as its QUIC-specific admission lever: "this dataplane
already mints the DCID, so minting it with an embedded MAC makes every later
short-header packet self-authenticating and prevents state creation outright."
That mechanism requires the LB to mint and control the CID — which this survey
finds a non-terminating dataplane cannot do. So:

- If u7s adopts **4-tuple pass-through** (this recommendation), the
  "self-authenticating LB-minted CID" lever is **unavailable** to aie31.11. Its
  QUIC admission must fall back to either RFC 9000 §8.1.2 Retry-token address
  validation (which itself needs the LB to inject/verify Retry — a
  termination-adjacent lift) or, more cleanly, aie31.11's own
  protocol-agnostic default: promote a flow to the main table only on observed
  bidirectionality. The latter is aie31.11's stated "recommended starting
  point if only one thing gets built" and does not depend on CID control.
- If u7s later adopts **QUIC-LB CIDs** (method 3), the anti-forgery property
  comes from the *backend's* encrypted server_id encoding, not an *LB*-minted
  MAC. aie31.11 would need to key admission off the QUIC-LB CID's cryptographic
  validity (LB decrypts/validates the server_id), not off a MAC the LB stamped.

**For the operator to reconcile:** you cannot have LB-minted-CID *admission*
(aie31.11) without LB-minted-CID *keying* (this bead), and neither is
achievable by a non-terminating tc-bpf dataplane. Pick one coherent story:
(a) pass-through keying + bidirectionality-promotion admission for QUIC (my
recommendation — simplest, no backend assumptions), or (b) QUIC-LB
backend-cooperating keying + server_id-validation admission (both gated on
backend cooperation, realistically Envoy-only today). Do not mix a
pass-through datapath with an admission design that assumes a minted CID.

## Open questions for the operator

1. Accept degraded QUIC migration/rebind affinity as the default (pass-through),
   or is preserving QUIC migration a hard requirement that justifies the
   backend-cooperation cost of QUIC-LB CIDs now?
2. Is per-Service opt-in QUIC-LB keying (Envoy-backed workloads) in scope for
   Phase 3, or explicitly deferred?
3. Reconcile the "LB-minted DCID" premise with aie31.11 before either lands —
   which of the two coherent stories (a)/(b) above?
4. Should the mechanism doc be corrected now (strike "minted by the LB,"
   re-mark QUIC as non-exempt under pass-through), or after the operator
   decides? This survey does not touch product code or the doc.

## Confidence

High on the mechanics and the survey verdicts (all from primary RFC/draft text
and each proxy's official docs, cached under `temp/research/`). High that
"LB-minted CID" is unrealizable for a non-terminating dataplane. Medium on the
forward-looking claim that Envoy is the *only* cooperator among mainstream
proxies — verified for these four via official docs, but the QUIC-LB draft is
young and other implementations may add it; not exhaustively surveyed beyond
the four in scope.

## Sources

- RFC 9000 (QUIC transport): §5.1 Connection ID (lines 1274-1330), §5.1.1
  Issuing CIDs, §7.2 Negotiating CIDs (lines 1835-1882), §9.5 Privacy
  Implications of Connection Migration (lines 2892-2963), §17.3.1 1-RTT short
  header (lines 5473-5490). Cached: `temp/research/rfc9000.txt`.
- draft-ietf-quic-load-balancers (quicwg/load-balancers, main): abstract +
  Introduction + Overview (lines 53-146). Cached: `temp/research/draft-quic-lb.md`.
- Envoy: `quic_lb` connection ID generator proto + changelog 1.34.0. Cached:
  `temp/research/envoy-quic_lb.proto`.
- nginx: `ngx_http_v3_module` (`quic_bpf`, `quic_host_key`,
  `quic_active_connection_id_limit`). Cached: `temp/research/nginx-http3.html`.
- HAProxy: configuration manual (`cluster-secret`, `quic-force-retry`,
  `quic-cc-algo`). Cached: `temp/research/haproxy-config.txt`.
- Traefik: entrypoints reference (`http3`, `http3.advertisedPort`,
  `reusePort`). Cached: `temp/research/traefik-entrypoints.md`.
