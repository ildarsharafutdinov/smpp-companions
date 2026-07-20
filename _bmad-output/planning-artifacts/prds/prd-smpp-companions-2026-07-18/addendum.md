---
title: SMPP 3.4 Security Proxy — PRD Addendum (technical-how)
project: smpp-companions
status: final
updated: 2026-07-20
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
