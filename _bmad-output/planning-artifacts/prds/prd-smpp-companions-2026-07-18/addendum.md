---
title: SMPP 3.4 Security Proxy — PRD Addendum (technical-how)
project: smpp-companions
status: final
updated: 2026-09-20
---

# Addendum — Technical How (Companions v1 PRD)

> Overflow for the PRD: mechanism/transport decisions, perf-target derivation, observability mechanics, library-choice rationale, and the depth that belongs in architecture/solution-design rather than the product spec. The PRD carries the *what*; this carries the *how*. Audit/override information never lives here (that's `.memlog.md`).

## A1. Performance-target derivation & benchmark methodology

**Why these numbers.** Targets were set from a 7-agent source sweep (16+ cited sources; full detail in `.perf-anchors.json`), then calibrated for a solo OSS portfolio v1.

- **Throughput ≥10K / stretch ~25K submit_sm/sec.** Anchors: smpp-core full-TCP submit_sm round-trip ~25K/s (Java 21, single thread); emgload native C ~25K MPS; MockServer (Netty app, 6 cores) saturates ~36K req/s. The codec is ~60× faster than the network path (smpp-core ~1.5M encode/s, ~1.8M decode/s per core) — so the codec is never the relay bottleneck; mTLS on both legs, OIDC, and SMSC latency govern. 10K is 1–2 orders above real carrier ceilings (Sinch 10 MPS/bind, Twilio ≤400 MPS/account, 8x8 ~200 MPS/system_id), so carrier provisioning — not Companions — sets real-world throughput. Honest published ceiling without a percentile-table harness: ~25–36K; claiming >50K end-to-end would read as overreach.
- **Concurrency 10K idle socket pairs in <1 GB heap / <1 vCPU.** JEP 444 supports 1M virtual threads; VT-Netty on JDK 25 held 60K simultaneous connections with zero errors (chrisgleissner, reproducible). Platform-thread contrast: 10K ≈ 250 MB committed, 100K cannot be launched. This is the Loom payoff made concrete.
- **Bind latency p99 ~250 ms warm / ≤ 2 s cold limit.** Decomposed chain: ingress TLS 1.3 (~1 RTT + 0.3–1 ms crypto) + mTLS (+1–2 ms CPU, no extra RTT) + OIDC validation (local JWT via cached JWKS ~1–5 ms; remote introspection warm ~50–200 ms; cold/uncached ~150 ms–2 s) + egress TLS. Keycloak 26.4 login p99 = 47 ms @0 RTT, 130 ms @20 ms RTT. Fail-closed timeout ~2–5 s.
- **Resource envelope.** jlink ~57 MB / 101 ms startup, native-image ~18 MB / 3 ms (ebarlas, JDK 21). Reference disclosures: MockServer 6 cores/ZGC/8 GB; loom-webflux i5-14600K/64 GiB/2 GiB heap.

**Benchmark harness (the A in A+B — also the portfolio artifact).**
- **Codec microbench (JMH, single core, no I/O):** encode/decode ops/s + ns latency. Target band 3×10⁵–1.5×10⁶ encode, 5×10⁵–1.8×10⁶ decode per core.
- **End-to-end relay:** real loopback/local-sink TCP, **mTLS on both legs**, OIDC auth cached, **Netty event-loop relay** (virtual threads own only the control plane); publish a **percentile table** (p50/p90/p99/p99.9) at sustained submit_sm/sec. Single instance on the reference hardware.
- **Concurrency/resource demo:** hold 10K idle ESME↔proxy↔SMSC pairs; publish heap (MB), RSS, and idle CPU%. Idle-CPU-at-N-connections is not published anywhere — this is a contribution.
- **Self-measured gaps (no source exists — the harness fills them):** TLS-handshake µs on JVM/Netty/JDK 25; RSS at N connections; mTLS-on-the-wire throughput penalty for a JVM SMPP stack.

## A2. Observability mechanics

- **Baseline logging:** structured JSON-lines to stdout/file. Events: startup/config-resolved, errors, bind accept/reject (with outcome + `system_id` where relevant). Full message/PDU-body logging is available only at **TRACE** level (off by default). Level configurable.
- **`/metrics` endpoint:** Prometheus text exposition. Counters: submit_sm relayed, DLRs relayed, binds accepted, binds rejected (by reason) — **optionally dimensioned per `system_id`**. Gauges: active connections, active virtual threads, JVM heap used/committed. Optional histograms: per-PDU relay latency, bind latency. **Message content is never emitted.** *Bucket choices and scrape-impl → here, not the PRD.*
- **`/metrics` security posture (v1):** **loopback IPv4 only (`127.0.0.1`)** — the loopback binding is the endpoint's sole authentication (the operator's host process model is the trust boundary); **non-loopback binding is forbidden in v1** (architecture AD-19 — supersedes the earlier "opt-in to bind elsewhere" proposal). **Never** bound on the SMPP transit legs; `system_id` labels permitted (cardinality bounded to the routing table), but **message content / PII never** emitted.
- **What is NOT built:** no dashboard, no Prometheus remote-write, no OTel traces/exemplars, no query/drain/reload control surface. Read-only scrape only.

## A3. The from-scratch line — library choices (Decision B)

"Built from scratch" = the **SMPP layer only**. Mature libraries are mandatory for security primitives:
- **TLS:** JDK 25 `SSLEngine`, or netty-tcnative/BoringSSL/OpenSSL (Netty cites ~3× faster than JDK SSLEngine — unmeasured publicly; self-measure if it matters).
- **OIDC/JWT:** a mature JOSE+JWT library (e.g., Nimbus JOSE+JWT) for signature verification; prefer **local JWT verification via cached JWKS** on the steady-state bind path over remote introspection (latency + provider-load). Remote introspection only when the provider issues opaque tokens.
- **Application substrate: Spring Boot 4.1.x** for externalized config (`@ConfigurationProperties`), DI, lifecycle/graceful shutdown, and the Micrometer metric model — **not** part of the from-scratch SMPP layer (Decision B scopes "from scratch" to the SMPP layer only; architecture AD-16). Netty is driven directly (own bootstrap; no WebFlux/Reactor).
- **Never** hand-roll crypto, TLS record handling, or JWT signature verification.

*Specific versions/pinning → dependency policy (SEC-5).*

## A4. Concurrency & memory discipline (the resource story)

- **Virtual threads carry per-connection work**; Netty event loops remain a fixed pool of platform threads. Rely on JEP 491 (JDK 24+/25): `synchronized` no longer pins carriers — but verify pinning is absent via JFR `jdk.VirtualThreadPinned` events (threshold 20 ms). Avoid `-XX:+PreserveFramePointer` ("drastic negative impact" per JEP 444).
- **One shared `PooledByteBufAllocator`** across all channels (avoid per-channel allocators that multiply the ~16 MB/thread PoolChunk footprint). Size direct memory explicitly via `-XX:MaxDirectMemorySize`; expose `ByteBufAllocatorMetric` for visibility.
- **GC:** ZGC for low pause at the target heap.
- **Container image:** target ~50–100 MB jlink modular runtime, <500 ms cold-start. GraalVM native-image (~20 MB / <50 ms) is a labeled **stretch**, not a v1 commitment — AOT constraints must not leak into v1 design decisions.

## A5. Deployment modes (topology detail)

The two-proxy topology: enterprise runs the **forward proxy** (fronts legacy; trusted-network leg + internet leg), carrier runs the **reverse proxy** (fronts SMSC; internet leg + SMSC leg). `system_id` is brokered end-to-end (legacy == carrier); the proxy tier holds no password.

- **Mode A — one-way TLS:** TLS on the internet leg only; legacy↔proxy leg is password-grant over a trusted network. (Optional convergence of the A-leg toward mTLS is a possibility, not v1.)
- **Mode B — plaintext direct:** no TLS on the internet leg; password-grant in cleartext over the public internet. Opt-in + warning (the accepted-risk mode).
- **Mode C — mTLS:** mutual TLS with per-instance baked client certs on the internet leg (strongest).

**The reverse proxy is stateless** (socket-pairing/connection state only; no `message_id` correlation) — load-bearing on assumption A-1 (carrier allows multiple concurrent binds under one `system_id`). If A-1 is false, the design must become stateful.

**Authority provider & certs:** OIDC for password-grant validation (**ROPC** — architecture AD-12); certs consumed from a runtime trust store (source-agnostic). Trust is consumed from **three roots** — the OIDC provider, the operator PKI / trust store, and the SMSC — not a unified root; the brainstorm's "provider == mTLS CA" is relaxed (architecture AD-10). Companions does **not** call the provider for cert-trust decisions and does **not** issue certs.

## A6. Deferred items (carried from sources, not promoted into PRD FRs)

- Per-leg TLS wiring, cipher/protocol negotiation specifics, OCSP stapling mechanics.
- OIDC grant-type/token-flow specifics (authorization-code vs client-credentials vs introspection) — resolved at architecture based on what the operator's provider issues.
- DLR-splice mechanics (how `deliver_sm` reaches the originating bind without message-state) — architecture, contingent on OQ-2 (splice vs inspect).
- Carrier-multi-bind verification method (OQ-1) — architecture/ops.
- Specific config-file format and secret-injection mechanism for the Docker shape — architecture/addendum follow-up.

## A7. Post-final notes — 2026-09-19 (sprint-change-proposal, correctness-first re-prioritization)

*Owner direction 2026-09-19; ratified via `_bmad-output/planning-artifacts/sprint-change-proposal-2026-09-19.md`. No PRD contract text changes — these notes scope and trace; they do not amend requirements.*

- **Sandbox Prometheus is fixture scope, not product surface.** §13's non-goal ("no metrics dashboard / telemetry backend") governs the PRODUCT. The repo-local docker-compose sandbox (a debugging playground — the same category as its bundled Keycloak vs "no bundled authority provider") gains a Prometheus scraper service in Epic 8. Product posture unchanged: read-only, loopback-only `/metrics` exposition (A2, architecture AD-19); no dashboard, no backend, no management API.
- **Docker Hub publishing is FR-DEPLOY-1 execution, not a new requirement.** The distroless image published automatically via GitHub Actions CI (Epic 8) completes "two first-class shapes" (§6.4) and SM-1's "shippable OSS release"; the published image honors the DEP-1 secrets contract unchanged.
- **Re-sequencing, not descoping.** PERF-1..4 (§7.1) and SM-3 stay locked; Epics 8–9 (observability/installability, whole-codebase review) precede Epic 7 by owner priority. A JMeter-plugin load-gen option is evaluated at Epic 7's start (story-level gate; an architecture AD-24 matter if adopted).

## A8. Post-final note — 2026-09-20 (Story 8.1: A2's histograms landed — bucket choices + scrape arithmetic)

*A2's own pointer ("Bucket choices and scrape-impl → here, not the PRD") makes this the recording home for the two latency histograms Story 8.1 T2 landed (owner decision 2026-09-19, Open Question 1 = B; audit gaps G1/G2 in `_bmad-output/implementation-artifacts/observability-audit-2026-09-19.md`). A recording note, not an amendment: A2's "optional histograms" remain optional and no requirement text changes. The edges are implementation-owned (`proxy/.../observability/MeteredRelayObserver.java`, pinned by `MeteredRelayObserverTest`); the operator-facing rows live in `docs/runbooks.md` ("The latency histograms").*

- **Bind-adjudication latency — `relay_binds_adjudication_seconds`, unlabeled.** Edges `50ms · 100ms · 500ms · 1s · 2.5s · 5s · 8s` (+ `+Inf`), anchored to PERF-3 so every anchor falls strictly between adjacent edges: warm p99 ~250 ms ∈ (100 ms, 500 ms], cold ≤ 2 s ∈ (1 s, 2.5 s], the `companion.bind.adjudication-deadline` default 4 s ∈ (2.5 s, 5 s]. Unlabeled because bucket series multiply per label value and every candidate label is a forbidden dimension (the verdict type is log-only; `system_id` would multiply × the routing table).
- **Per-PDU relay transit — `relay_pdus_transit_seconds{direction}`, `direction` ∈ `INGRESS`|`EGRESS`.** Edges `100µs · 500µs · 1ms · 5ms · 10ms · 50ms · 100ms · 500ms · 1s` (+ `+Inf`), spanning sub-ms→s so PERF-4's sub-ms per-PDU budget stays visible below the 1 ms edge (two edges under it). The closed 2-value `Direction` set is the whole label domain; both series pre-registered.
- **Scrape impl (both).** Pre-registered at construction from closed sets — an idle-boot scrape already shows every row at zero and no fire path can create a series (the AD-19 cardinality mechanism, unchanged); recording is throw-isolated (a recorder failure degrades the histogram, never the verdict/relay path) and metrics-only (no log row). Base unit seconds; each fans out as `_bucket{le=…}` rows plus `_sum`/`_count`.
- **The scrape arithmetic (dated 2026-09-20 — the baseline for the next live conformance check).** Each timer renders one `_bucket` row per edge plus `+Inf`, then `_sum`/`_count`: adjudication 10 rows (7 finite edges + `+Inf`), transit 12 rows per direction (9 finite edges + `+Inf`) × 2 directions = 24 — the three timer meters add 34 scrape rows over the pre-histogram surface. Observer meters: **41** on a forward cell's routing table (the `MeteredRelayObserverTest` pin — 2 PDU + 2 accept + 32 close + reject + unknown + 3 timers; 38 pre-T2) and 39 on a reverse cell (empty table, no accept series). Totals vs the audit's frozen live counts at its baseline commit (87 forward / 86 reverse = 38/36 observer meters + 1/2 resource gauges + 48 JVM binder series): **121 scrape rows forward / 120 reverse** (87/86 + 34; with the audit rig's 2-id routing table — an N-id forward cell shows 39+N observer meters / 119+N scrape rows; the reverse 39/120 is exact because its table is empty). [Corrected 2026-09-20 by the first live check below: every Timer also renders a `_max` row → 124 forward / 123 reverse.]
- **Runbook cross-check (a recorded doc slip).** The runbook's fan-out clause stated adjudication 10 rows — consistent — but transit as "22 rows = 2 × (9 buckets + `_sum` + `_count`)": off by two. The pinned grid is 9 finite edges + `+Inf` = 10 bucket rows per direction (`MeteredRelayObserverTest`'s `containsExactly` incl. `+Inf`; `MetricsEndpointTest`'s transit `+Inf`/`_sum`/`_count` rows), so 24 stands as the arithmetic of record; the slip (counting `+Inf` inconsistently with the adjudication clause in the same sentence) was corrected the same day by the Story 8.1 T5 review round.
- **The first live conformance check (dated 2026-09-20 — Story 8.2 T2, scraped by the landed sandbox Prometheus itself).** Rig: the 9-service compose (the `prometheus` service's own first live run) + the host-run README §5.2 reverse.mode-b proxy — empty routing table, exactly this note's exact-arithmetic cell. Real traffic through the rig's journeys: §6.1 (submit_sm + `_resp`, DLR `deliver_sm` + `_resp`), §6.2 (MO `deliver_sm` + `_resp`), §6.3 (`enquire_link` keepalives); the reconciled scrape taken at uptime ~200 s post-journey. **The product-owned arithmetic reconciles:** exact row-for-row for the 36 one-row meters (2 `relay_pdus_total{direction}` + 32 `relay_connections_closed_total` spanning all 16 CloseReasons × 2 directions + reject + unknown — all verified live) and the 2 resource gauges; the 3 timers rendered the fan-out clause's 34 pre-correction rows (adjudication: 8 `_bucket` with the edges verbatim `0.05/0.1/0.5/1.0/2.5/5.0/8.0` + `+Inf`, then `_count`/`_sum`; transit ×2 directions: 10 `_bucket` with the edges verbatim `1.0E-4…1.0` + `+Inf`, then `_count`/`_sum`) plus the 3 `_max` rows of delta (a) — 37 live rows — so the product-owned live total is **75 = the corrected 123 − 48** (the pre-correction count: 72 = this note's 120 − 48). **Two deltas, both explained:** (a) *a correction to the arithmetic of record* — every Timer ALSO renders a `_max` row in the live exposition (Micrometer's Prometheus rendering; the ZGC GC-timer families in the same scrape carry `_max` too), which the fan-out clause above ("one `_bucket` row per edge plus `+Inf`, then `_sum`/`_count`") did not count: +3 rows, corrected totals **124 forward / 123 reverse** (an N-id forward cell: 122+N) — an arithmetic correction only, no surface change; (b) the "48 JVM binder series" addend is boot state, not product surface — 57 rows on this boot (21 memory + 10 threads + 9 buffer + 10 GC + 3 system + 4 process), the ZGC GC families materializing lazily on the first GC notification and fanning per (action, cause, gc) combo (this boot: `end of GC pause`/`Metadata GC Threshold`/`ZGC Major Pauses` and `end of GC cycle`/`Metadata GC Threshold`/`ZGC Major Cycles`, 3 rows each, + the 4 `jvm_gc_memory_*`). Live whole-scrape total: **132 = 123 + 9**; the exactness claim above scopes to the 36 one-row meters + 2 resource gauges — which ARE exact.
- **The same check, Prometheus-side + journey data (2026-09-20).** `count({job="smpp-proxy",instance="127.0.0.1:9090"})` = 137 = the 132 exposition series + the 5 per-target scrape-health series (`up`, `scrape_duration_seconds`, `scrape_samples_scraped`, `scrape_samples_post_metric_relabeling`, `scrape_series_added`); target 9090 `health=up`, 9091 `down — connection refused` (the Q3 single-instance state, live); two consecutive raw scrapes shape-identical after value-stripping; zero duplicate series. Both histogram families carried live data through the TSDB: adjudication `_count` = 1 (the couple's single adjudication; `_sum` 0.183 s — the one observation in (0.1, 0.5], inside the warm-anchor band the grid was anchored to [T1/T2 identity of the 0.183 s — the value is identical in the T1 proof note too — pending settlement per the deferred-work entry, 2026-09-21]), transit `_count` 9/9 at the scrape = 6 keepalive pairs (INGRESS == EGRESS, never out of step) + §6.1's 2/2 + §6.2's 1/1, every observation under the 100 µs edge (`le="1.0E-4"` == `_count`) — the sub-ms budget visible below the 1 ms edge as the grid intends; transit `_count` tracked `relay_pdus_total` exactly on every observation. Unexercised arm: the forward-cell / N-id formula (a forward cell needs the sandbox §5.6 composed-runbook shape, not the rig's default lone-reverse posture) — deferred to whenever a forward rig runs, the same way this note was the formula's first consumer.
