---
stepsCompleted:
  - step-01-validate-prerequisites
inputDocuments:
  - _bmad-output/planning-artifacts/prds/prd-smpp-companions-2026-07-18/prd.md
  - _bmad-output/planning-artifacts/prds/prd-smpp-companions-2026-07-18/addendum.md
  - _bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/ARCHITECTURE-SPINE.md
  - _bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/walkthrough.md
extraction:
  frCount: 19
  nfrCount: 29
  archRequirementCount: 57
  adCount: 31
  frNfrCompleteness: complete
  archAdCoverage: complete
  phantomIdsExcluded:
    - FR-DEPLOY-5
    - FR-MAINT-1
    - DEP-2
    - DEP-3
    - DEP-4
    - OPS-3
---

# SMPP 3.4 Security Proxy (Companions v1) - Epic Breakdown

## Overview

This document provides the complete epic and story breakdown for SMPP 3.4 Security Proxy (Companions v1), decomposing the requirements from the PRD, UX Design if it exists, and Architecture requirements into implementable stories.

**Source contract (all `status: final`):** PRD (`prd.md` + `addendum.md`) is the binding product contract; Architecture (`ARCHITECTURE-SPINE.md` + `walkthrough.md`) is the binding build substrate. No UX contract exists — the product is headless by design (explicit PRD non-goal: no UI, no management API).

## Requirements Inventory

### Functional Requirements

*19 FRs across 5 families (PRD §6). Statements faithful to the PRD; locked targets embedded.*

**§6.1 Protocol Transit**

- **FR-TRANSIT-1** — Transit SMPP 3.4 traffic between legacy system and SMSC using a hybrid model: the proxy inspects and handles only the bind family and unbind (to establish/tear down sessions and apply authentication); all other PDUs are spliced transparently as opaque bytes — not inspected, not filtered, forwarded as-is. Payload-transparent: no claim about, and no restriction on, what message types or PDU content either side sends. *(PDU handling matrix — bind_transmitter/receiver/transceiver (+resp) and unbind (+resp) = inspected/handled; submit_sm, deliver_sm/DLR, enquire_link, submit_multi, data_sm, query_sm, replace_sm, cancel_sm, broadcast_sm, outbind, alert_notification, generic_nack = opaque passthrough — is acceptance criteria for this FR.)*
- **FR-TRANSIT-2** — DLRs (`deliver_sm`) flow back to the originating legacy bind via that same transparent passthrough (on the bind's session affinity) — no separate DLR path and no DLR-specific handling. *(Depends on bind session-affinity — §10 A-1.)*
- **FR-TRANSIT-3** — Interoperate transparently with unmodified SMPP 3.4 stacks on both legs, passing an SMPP 3.4 conformance suite on each leg without altering protocol behavior either side relies on.
- **FR-TRANSIT-4** — The bind/unbind handling implements SMPP 3.4; SMPP 5.x is not implemented.

**§6.2 Trust & Security Model**

- **FR-SEC-1** — The proxy tier holds no SMPP passwords and no password vault. The SMSC remains the sole credential authority. Compromise of a proxy yields network position only — never working carrier credentials.
- **FR-SEC-2** — Confine the legacy password-grant weakness to a trusted zone; never expose it unprotected on untrusted networks, except in the explicitly accepted plaintext Mode B.
- **FR-SEC-3** — Preserve end-to-end identity: legacy `system_id` == carrier `system_id`. No pooling, mapping, or surrogate identity.
- **FR-SEC-4** — Consume operator-provided trust at runtime (source-agnostic certs; OIDC-delegated auth). Do not bundle/run an authority provider, act as a CA, or issue certificates.
- **FR-SEC-5** — Fail-closed: DENY a bind when the authority-provider verdict is unavailable or indeterminate (timeout, network error). Deny-on-ambiguous is the default.

**§6.3 Authentication**

- **FR-AUTH-1** — Delegate password-grant validation to an operator-run OIDC authority provider (Keycloak = reference target, not part of this project).
- **FR-AUTH-2** — Support mTLS client-certificate authentication (Mode C); do not mandate it (Modes A and B operate password-grant only).
- **FR-AUTH-3** — Use per-instance baked client certificates (Mode C); never a shared golden-image key.
- **FR-AUTH-4** — mTLS (Mode C) terminates the client-certificate handshake. Chain-validation depth and trust-anchor handling decided at architecture (OQ-4 → AD-13). CRL/OCSP revocation checking is OUT of v1 (rotation is re-deploy, OPS-2).

**§6.4 Deployment & Form**

- **FR-DEPLOY-1** — Ship two first-class, feature-equivalent shapes — a standalone application (runnable JAR) and a Docker image (packaging the same JAR): same config surface, modes, auth paths.
- **FR-DEPLOY-2** — One codebase plays both roles (enterprise/forward + carrier/reverse); role and mode are deployment-time configuration of the application, not forks.
- **FR-DEPLOY-3** — Validate configuration at startup and fail-fast (refuse to start) on ambiguous, insecure, or missing configuration.
- **FR-DEPLOY-4** — Provision certificates at deploy time (bake via CI/pipeline); do not require runtime ACME/SPIFFE enrollment to function.

**§6.5 Operability & Observability**

- **FR-OBS-1** — Emit baseline operational logging (startup, errors, bind accept/reject, with `system_id` where relevant) to stdout/file as structured JSON-lines. Full message/PDU-body logging is available only at TRACE level (off by default).
- **FR-OBS-2** — Expose a read-only HTTP `/metrics` endpoint (Prometheus exposition): throughput counters, bind counters, resource gauges, configurably dimensioned per `system_id` (operator-controllable cardinality). Loopback-only (IPv4) in v1 (AD-19); never on the SMPP transit legs; message content never emitted (`system_id` labels permitted).

### NonFunctional Requirements

*29 NFRs across 9 families (PRD §7, elaborated by addendum A1–A6). Locked numeric/version targets preserved verbatim.*

**§7.1 Performance (locked targets — anchor-derived)**

- **PERF-1** — Sustain **≥ 10,000 `submit_sm`/sec** throughput, stretch target **~25,000/sec**, with mTLS on both legs, OIDC validation cached, and a Netty event-loop relay (virtual threads own only the control plane). Published ceiling without a percentile-table harness ~25–36K. Reference HW: single instance, 4–8 vCPU modern x86/ARM, Linux, JDK 25 GA, ZGC, 2–4 GiB heap. Proof = reproducible load-test harness vs mock SMSC + `/metrics`; end-to-end relay benchmark must publish a percentile table (p50/p90/p99/p99.9) at sustained `submit_sm`/sec.
- **PERF-2** — Hold **10,000 concurrent idle ESME↔proxy↔SMSC socket pairs (~20K sockets)** in **< 1 GB heap and < 1 vCPU idle** (Loom payoff). VT-Netty on JDK 25 held 60K connections with zero errors. Concurrency/resource demo must publish heap (MB), RSS, idle CPU% at 10K idle pairs.
- **PERF-3** — Bind latency **p99 ~250 ms** warm path (co-located IdP, TLS 1.3, pooled egress); **≤ 2 s** cold-path limit; fail-closed DENY beyond a configured **2–5 s** timeout.
- **PERF-4** — Per-PDU added relay latency **sub-ms** (SMSC round-trip dominates). Codec JMH microbench band (single core, no I/O): encode **3×10⁵–1.5×10⁶ ops/s**, decode **5×10⁵–1.8×10⁶ ops/s** per core.

**§7.2 Security**

- **SEC-1** — TLS floor: TLS 1.2 minimum, TLS 1.3 preferred; publish a cipher allowlist policy (operator-tunable default ships in config).
- **SEC-2** — Parser robustness: handles only bind/unbind PDUs (all else opaque splice); safely rejects malformed/oversized/truncated bind PDUs without crashing. Splice path robust against oversized frames + memory exhaustion via backpressure (REL-2). One shared `PooledByteBufAllocator`; size direct memory via `-XX:MaxDirectMemorySize`; expose `ByteBufAllocatorMetric`.
- **SEC-3** — The proxy→authority-provider link is authenticated and encrypted (TLS/mTLS or service-account token).
- **SEC-4** — No rolled crypto: mature libraries mandatory for crypto/TLS/OIDC (TLS via JDK 25 SSLEngine or netty-tcnative/BoringSSL/OpenSSL; JWT via Nimbus JOSE+JWT; substrate Spring Boot 4.1.x; Netty direct, no WebFlux/Reactor). From-scratch scope = SMPP layer only. Never hand-roll crypto, TLS record handling, or JWT signature verification.
- **SEC-5** — Dependency hygiene: maintain a vulnerability/CVE policy for security-critical dependencies (Netty, JDK); version pinning in the dependency policy.

**§7.3 Privacy**

- **PRIV-1** — Do not persist SMS message bodies. `system_id` may be logged and used as a metrics label. Full message/PDU-body logging TRACE-only (off by default). Message content never emitted in metrics.

**§7.4 Reliability**

- **REL-1** — Transit integrity: do not silently drop, duplicate, or corrupt spliced traffic or DLRs.
- **REL-2** — Backpressure: when the egress leg is slow, the ingress leg backpressures rather than OOM.
- **REL-3** — Graceful shutdown: on SIGTERM, stop accepting new binds, drain in-flight traffic up to a timeout, then exit.
- **REL-4** — Statelessness: the proxy holds no `message_id`→`system_id` correlation (socket-pairing state only). Premise A-1 (carrier multi-bind + DLR affinity) is confirmed; smoke-test it early.

**§7.5 Compatibility**

- **COMP-1** — Interoperate cleanly with unmodified SMPP 3.4 stacks on both ends; zero changes to legacy gear or SMSC behavior.
- **COMP-2** — JDK 25 runtime floor (`--enable-preview` for StructuredTaskScope); JVM-only. Rely on JEP 491 (synchronized no longer pins carriers); verify pinning absent via JFR `jdk.VirtualThreadPinned` events (threshold 20 ms); avoid `-XX:+PreserveFramePointer`.
- **COMP-3** — Linux only (x86/ARM). No macOS or Windows build in v1.
- **COMP-4** — IPv4 only (OQ-9; IPv6 out of v1).

**§7.6 Maintainability**

- **MAINT-1** — Single codebase serves both roles; mode/role selection is deployment-time config, not forks.
- **MAINT-2** — Structured for extraction: the SMPP codec + PDU layer is a clean, separable, independently tested module with documented boundaries (Decision A). Modularity is a code-quality goal, not a v1 product surface; v1 ships an application, not a published library.
- **MAINT-3** — Originality: built entirely from scratch for JDK 25; no Cloudhopper/jSMPP derivation.
- **MAINT-4** — Test strategy required: mock/conformance SMSC, TLS/OIDC test vectors, codec fuzzing.
- **MAINT-5** — Keep native-image-compatible as an opt-in future (avoid reflection-heavy patterns); **NO v1 native-image build** (AD-23/OQ-11).

**§7.7 Deployability**

- **DEP-1** — Docker secrets contract: the Docker shape defines how secrets (certs, keys, provider creds) are injected (file paths / env / mounted secrets). *(Other deployability needs — two-shape parity, deploy-time cert provisioning, config fail-fast — are covered by FR-DEPLOY-1..4.)*

**§7.8 Operability & Observability**

- **OPS-1** — Documentation is the surface: headless, no UI/management API → config reference, deployment-mode guide, troubleshooting/runbooks must exist.
- **OPS-2** — Cert rotation: v1 contract is re-deploy to rotate baked certs (Mode C); CRL/OCSP OUT of v1 (OQ-5).
- **OBS-1** — Read-only `/metrics` scrape (Prometheus text exposition; counters/gauges/optional histograms). Loopback IPv4 (127.0.0.1) only; non-loopback forbidden; never on SMPP legs; message content never emitted. NOT built: no dashboard, no remote-write, no OTel traces/exemplars, no control surface.
- **OBS-2** — Proxy not silent: baseline JSON-lines logging (startup/config-resolved, errors, bind accept/reject with `system_id`); PDU-body TRACE-only (off by default); level configurable.
- **OBS-3** — No management API: operators cannot query/drain/reload/rotate at runtime in v1 (the `/metrics` endpoint is explicitly not a management API).

### Additional Requirements

*Derived from the architecture (31 ADs → 57 implementation requirements), the starter scaffold, the accepted-risk register, and deferred items. These constrain and shape every epic/story.*

#### Starter Template (drives Epic 1, Story 1)

**YES — greenfield, from-scratch scaffold** (Decision-B; only mature TLS/OIDC/JWT libs reused; the SMPP layer is authored from scratch).

- **Language/Runtime:** Java, JDK 25 LTS (pin build 25.0.x) — Loom virtual threads, generational ZGC, ScopedValue. Build runs with `--enable-preview` process-wide (required by AD-5: StructuredTaskScope JEP 505 is 5th-preview on JDK 25; ScopedValue JEP 506 is final). Preview confined to control plane (`security/` + `bootstrap/`); data-plane splice stays pure-stable API.
- **Build tool:** Gradle multi-module (`settings.gradle` + `build.gradle`); dependency management via `netty-bom` + Spring Boot 4.1.x.
- **Module structure (AD-7, two-module seam, inward-only: `proxy → codec`):**
  - `codec/` — SMPP 3.4 codec, PDU model, bind-family framing, command_id set. **PURE: zero dependency on relay/TLS/OIDC/config/metrics/app.** Extractable core (MAINT-2 seed). Package `smpp.companion.codec.*`.
  - `proxy/` — the runnable application. Package `smpp.companion.proxy.*` with sub-packages: `relay/` (Netty pipelines, BindInterceptor, RelayHandler, ConnectionRegistry), `security/` (TLS modes A/B/C, trust-store loading, OIDC/JWKS via Nimbus, BindCredentialVerifier port + ROPC adapter), `config/` (@ConfigurationProperties, fail-fast, role×mode matrix, routing table), `observability/` (JSON-lines logging, SpliceObserver, `/metrics` handler, MetricsRegistry), `bootstrap/` (Spring Boot main, SmartLifecycle, graceful shutdown, dedicated metrics event loop).
  - `docs/` — OPS-1 operator surface.
- **Config keys:** `companion.*` (relaxed binding).
- **Key dependencies (web-verified 2026-07):** Netty 4.2.16.Final (`netty-bom`; NIO/Epoll, NOT io_uring; 4.2 IoHandler transport SPI); Spring Boot 4.1.x (Spring Framework 7.0.8+; NO WebFlux, NO Reactor); Micrometer (PrometheusMeterRegistry); Nimbus JOSE+JWT 10.9.1 (≥10.0.2 for CVE-2025-53864); jSMPP `org.jsmpp:jsmpp:3.0.2` (**TEST/INTEROP ONLY**, never the production codec); GraalVM JDK 25 (stretch only, no v1 native build); reference IdP Keycloak 26.x (operator-provided, not part of project).
- **Deploy shapes:** (a) `java -jar` runnable JAR; (b) Docker image = distroless + jlink runtime (~45–66 MB). Single-instance, no HA/failover. Certs provisioned at deploy; Mode C rotation = re-deploy.
- **Explicit scaffold non-goals (AD-16/19/23):** no WebFlux, no Reactor, no Spring web server / Actuator / embedded Tomcat on the SMPP path, no v1 native-image build target.

#### Architecture-Derived Requirements (by category)

**Threading & concurrency**

- **[AD-1]** Netty event loops (platform threads) own the steady-state byte splice; virtual threads own the control plane (bind adjudication, OIDC, shutdown). VTs never carry steady-state bytes; Netty event loops never run on VTs. Per-leg pipeline: ingress `SslHandler → SmppFrameDecoder → SmppCodec → BindInterceptor → RelayHandler`; egress `SslHandler → SmppFrameDecoder → SmppCodec → RelayHandler`.
- **[AD-4]** No blocking work on the event loop: OIDC/JWKS/DNS/file run on VTs. `SslHandler` uses a bounded delegating Executor for handshake-crypto tasks; on saturation it MUST fail the TLS handshake (deny per AD-11) — never `CallerRunsPolicy`, never unbounded queueing.
- **[AD-5]** Control plane on StructuredTaskScope (JEP 505) + ScopedValue (JEP 506): structured concurrency for bind-adjudication fan-out (fork ROPC token call + local JWKS defense-in-depth verify, join, collapse to one Verdict), graceful shutdown, lifecycle. ScopedValue carries per-bind `RequestContext` — never `ThreadLocal`. Scope lifetime bounds the fan (no orphans).
- **[AD-5]** `--enable-preview` process-wide on JDK 25; pin the exact JDK 25 build + STS preview shape; confine STS to control plane.
- **[AD-6]** Three threading models coexist by separation: (1) Netty event loops (data plane), (2) hand-managed VTs (control plane), (3) Spring-managed executors. `spring.threads.virtual.enabled` only for Spring's own internals; no load-bearing path depends on it.
- **[AD-8]** Per-bind state in one concurrent `ConnectionRegistry` bean (keyed by ingress `ChannelId`, holds peer-egress Channel + flip-flag + session metadata) + a Channel attribute for O(1) event-loop access; teardown via `channelInactive`.
- **[AD-8]** JWKS cache = `AtomicReference<JwkSet>` swapped whole on refresh (never in-place mutation); exposes `close()` for graceful-drain ordering (AD-22).
- **[AD-28]** SslHandler delegating-task Executor = ONE hand-managed fixed **platform-thread** pool (not VT — delegated tasks are CPU-bound and may pin carriers; not a Spring `ThreadPoolTaskExecutor`), shared ingress+egress, bounded queue, abort-and-fail-handshake on saturation.
- **[AD-28]** JWKS refresh = hand-rolled VT on a `ScheduledExecutorService` owned by `security/` (not `@Scheduled`); AD-22 drain stops it before the JWKS cache closes.
- **[AD-28]** Bind adjudication = a SINGLE bounded hand-managed VT `ExecutorService` owned by `security/`, shared across all binds, config-sized, fail-closed on saturation, registered with the AD-22 drain (`shutdownNow()` + await); spawning one VT per bind outside this pool is FORBIDDEN.

**Protocol relay**

- **[AD-2]** Build on the canonical Netty HexDumpProxy pattern: shared event loop for both legs, `AUTO_READ=false`, write-completes-gates-read backpressure. Forward framed-PDU ByteBufs (not raw stream bytes) so each PDU forwards exactly once with boundaries preserved. `SmppFrameDecoder` stays active on both legs during splice; `SmppCodec` (object decode) dormant post-couple. NO live pipeline surgery — `pipeline.remove()` on a live channel is forbidden.
- **[AD-3]** Hybrid PDU model: inspect/handle ONLY the bind family + unbind(+resp) pre-couple / standalone leg (SMPP 3.4 only, no 5.x). Once coupled (AD-25), every PDU — including unbind — is opaque framed bytes; session ends on TCP half/close. MT-only is a deployment expectation, not a proxy filter.
- **[AD-7]** `codec` owns PDU length-framing (`SmppFrameDecoder`): read 4-octet `command_length`, accumulate exactly one PDU, emit one framed ByteBuf per PDU. Generic to every PDU on both legs; stays active during splice. Enforces max `command_length` (65536), rejects < 16, guards length-arithmetic overflow/underflow before any allocation (AD-30).
- **[AD-7]** `codec` owns bind-family parsing (`SmppCodec`, bind branch): parse ONLY bind family (transmitter/receiver/transceiver + `_resp`) into typed objects exposing header `command_id`/`command_status`/`sequence_number` + `system_id`, `password`, `system_type`, `interface_version`. Lets `BindInterceptor` route on `system_id`, hand password to `BindAdjudicator` (AD-12), and lets `RelayHandler` detect `command_status == ESME_ROK` (AD-25 flip).
- **[AD-7]** `codec` owns `SmppCommandIds.BIND_FAMILY` — single source of truth for parsed-vs-opaque. Every non-bind PDU is an opaque framed ByteBuf. Parsed attack surface = exactly two decoders (framer + bind parser), BOTH fuzzed (AD-24).
- **[AD-9]** Stateless relay: holds socket-pairing state only; `deliver_sm`/DLRs ride the splice via the coupled pair (the coupling IS the session affinity). Load-bearing on A-1.
- **[AD-14]** Identity forwarded, not mapped: legacy `system_id` == carrier `system_id`; bind forwarded end-to-end with identity preserved.
- **[AD-25]** Bind→splice transition state machine: splice flag flipped by EXACTLY ONE unit — data-plane `RelayHandler` (control-plane `BindAdjudicator` returns a Verdict, never mutates a data-plane flag). Trigger: on the ingress event loop, upon receipt of decoded `bind_*_resp` with `command_status == ESME_ROK` (codec live pre-couple) — never a peeked `command_id`, never "any frame from egress." Non-ROK → do not flip, tear down.
- **[AD-25]** `bind_*_resp` forwarder split: `BindInterceptor` forwards `bind_*_resp` to the legacy client; `RelayHandler` observes decoded `bind_*_resp` READ-ONLY to flip the flag and NEVER forwards it (first spliced PDU = first PDU after `bind_*_resp`). Post-couple unbind is opaque; session ends on TCP half/close (`channelInactive`) on either leg.
- **[AD-27]** Intra-proxy ownership: bind-family command_id set owned by codec (`SmppCommandIds.BIND_FAMILY`); `BindInterceptor` MUST consume it (redefining locally forbidden). `outbind` and `generic_nack` declared opaque-spliced, not bind-family.
- **[AD-30]** Max frame size: `SmppFrameDecoder` pins max `command_length` **65536** (covers `message_payload` TLV max); frames exceeding dropped + channel closed (fail-closed). Rejects declared lengths < 16; guards overflow before allocation (independent of `-XX:MaxDirectMemorySize`).
- **[AD-30]** Per-channel inbound queue depth (framed-PDU buffers) bounded; `AUTO_READ=false` + write-completes-gates-read is the trip-wire with an explicit low-water mark to re-arm read. `MaxDirectMemorySize` = `max_frame × max_inbound_depth × concurrent_pairs × safety_factor`, exposed via `ByteBufAllocatorMetric` — one named formula so codec max and allocator budget cannot drift.

**Build tooling**

- **[AD-7]** Two-module Gradle seam, strictly inward-only: `codec` pure (zero upward deps); `proxy` = relay+security+config+observability+bootstrap. Direction `proxy → codec`.
- **[AD-23]** No native-image build target in v1: ship JVM build only; keep codebase native-image-COMPATIBLE as a documented stretch (avoid reflection-heavy codec/splice patterns); revisit only if a cold-start-sensitive deployment emerges.

**Data setup**

- **[AD-8]** Only mutable runtime state: (a) ephemeral per-bind connection-pair state, (b) monotonic metrics counters/gauges, (c) JWKS cache. Config, routing table, TLS material immutable after startup. `message_id`→`system_id` correlation NEVER exists; no SMS body EVER persisted (PRIV-1).
- **[AD-17]** Required-config matrix (required/optional/forbidden per cell): forward+A = server cert+key (internet leg), routing table, OIDC provider, SMSC endpoint NOT required (forwards to reverse proxy); forward+B = FORBIDDEN; forward+C = server cert+key + trust store, routing table, OIDC provider. reverse+A = client trust store for forward-proxy/SMSC server cert (AD-26, never cacerts), SMSC endpoint; reverse+B = opt-in ack, SMSC endpoint; reverse+C = client cert+key + trust store, SMSC endpoint.
- **[AD-29]** Routing cardinality v1 = **1:1**: a forward instance fronts EXACTLY ONE carrier egress; routing table = `system_id` allow-list mapping to the single egress. Multi-carrier deferred post-v1. Value schema `{host, port, tlsContextId?}`; Mode C client cert per-instance by default, per-target via `tlsContextId` + `tls.contexts` map.

**Security implementation**

- **[AD-10]** Credential-free at rest: no persisted passwords/vault/CA/issuing keys. At runtime holds only: OIDC client credential (file-path-injected, AD-18); cached JWKS public keys; transient per-bind plaintext password (in memory only during adjudication + forward to SMSC, zeroized); proxy's own TLS end-entity private keys (file-path-injected, held by SslContext — not issuing/CA keys).
- **[AD-11]** Fail-closed universal default: OIDC token 401 → DENY; any non-401 not yielding a locally-verifiable JWT → DENY; JWT sig/iss/aud/exp/nbf mismatch → DENY; 200 verdict overridden by failed local JWT verify → DENY (DENY always wins); kid absent from cached JWKS → DENY (background refresh scheduled, NO foreground refresh-and-retry on bind path).
- **[AD-11]** Introspection path (opaque tokens): anything other than HTTP 200 + JSON + `active:true` → DENY. Mode C: no client cert / cert not reaching configured anchor → TLS handshake fails (`REQUIRE` never `WANT`). Ingress routing: `system_id` not in routing table → DENY (no default route). Startup: trust store absent/empty → fail-fast refuse.
- **[AD-12]** Secret hygiene: password + access token in `char[]`/`byte[]` (never `String`), zeroized on adjudication completion, connection teardown, JVM shutdown, and any exception path. Accurate clocks (NTP, A-4) precondition for exp/nbf.
- **[AD-12]** Two-proxy flow (both directions owned): FORWARD performs OIDC verification; reverse authenticates to forward as TLS client. Mode C → forward validates reverse's mTLS client cert. Mode A (one-way TLS) → forward CANNOT authenticate reverse, so forward's internet-port listener MUST be ACL-isolated to reverse-proxy hosts (mirroring A-3) OR Mode C used. Mode A two-proxy without ACL isolation = ACCEPTED RISK (register + loud startup warning, the Mode B pattern).
- **[AD-13]** mTLS = PKIX defaults: `SslContextBuilder.trustManager(trustStore).clientAuth(REQUIRE)`; rely on PKIX defaults for chain depth (maxPathLength 5); NO custom `PKIXBuilderParameters`, NO custom chain code. Minimal single-purpose trust store (operator issuing-CA roots only).
- **[AD-13]** Trust store NEVER falls back to JDK `cacerts` — applies to EVERY peer path (Mode C client certs AND Mode A egress SMSC validation, AD-26). Mode C client certs PER-INSTANCE; never shared golden-image key. Startup validation: refuse if absent/empty/wrong format/wrong password/zero `trustedCertEntry`. Revocation OUT.
- **[AD-15]** Legacy ingress leg: trusted network is the SOLE ingress gate; proxy performs NO local password check, holds NO local password store; reads `system_id` and routes on it. Trusted-network isolation (A-3) is the deployer's responsibility.
- **[AD-17]** TLS floor: TLS 1.2 min, 1.3 preferred (concrete cipher/protocol allowlist ships in config, operator-tunable — SEC-1). Bad ports / unset provider URL / non-https provider URL → refuse.
- **[AD-18]** Secrets file-path-injected: secrets are FILE PATHS in config pointing at mounted files (Docker secrets / bind-mount / k8s secrets); NEVER a secret value in an env var (leaks via `/proc/<pid>/environ`, `docker inspect`). Fail-fast if a secret file is missing/unreadable.
- **[AD-19]** `/metrics` handler hardening: Netty `HttpServerCodec` + `HttpObjectAggregator` (no hand-rolled HTTP parsing); method MUST be GET, path exactly `/metrics`, all else hard-rejected (404/405); bounded max header/body size. Bind LOOPBACK IPv4 ONLY — the sole authentication of the endpoint; non-loopback FORBIDDEN in v1.
- **[AD-20]** Egress TLS endpoint-identification: on egress, explicitly set `SslContextBuilder.endpointIdentificationAlgorithm` — null for IP-addressed SMSC targets (Netty 4.2 defaults to HTTPS and fails raw-IP) OR provision SMSC certs with IP SANs and keep verification on. SMSC-leg TLS is OPERATOR-CHOICE, DEFAULT OFF under the trusted-network assumption (mirrors AD-15).
- **[AD-26]** Egress TLS trust anchoring: reverse proxy TLS client validates peer (forward/SMSC) server cert against operator-supplied trust store — same posture as AD-13 (never cacerts, fail-fast if absent/empty). Disabling hostname verification (AD-20) conditional on (a) IP-SAN certs with verification ON, or (b) operator SMSC trust store as sole gate.
- **[AD-26]** Explicit opt-in (loud startup warning + ack) required for cacerts / public-PKI SMSC trust; permitted in ANY mode (threat identical across modes — the Mode B pattern), NEVER the default.

**Integration**

- **[AD-12]** OIDC via ROPC (Keycloak Direct Access Grants): token-endpoint status (200/401) IS the verdict; verify returned JWT locally via cached JWKS as defense-in-depth (precedence per AD-11); DISCARD the token and relay the ORIGINAL bind to the SMSC (sole credential authority). Re-validate EVERY bind (NO verdict cache; cache JWKS only). Opaque tokens fall back to RFC 7662 introspection — results NEVER cached.
- **[AD-12]** Provider link (SEC-3): token + JWKS endpoints reached OVER HTTPS, never HTTP; proxy authenticates as confidential client via mTLS (RFC 8705) OR client_secret, credential file-path-injected (AD-18). Fail-fast if provider URL not https. If discovery advertises `grant_types_supported`, probe for Direct Access Grants (non-default since Keycloak 26.2) and WARN; grant-type error at runtime → DENY (AD-11).
- **[AD-12]** `BindCredentialVerifier` port contract (single interface owning the seam): `smpp.companion.proxy.security.BindCredentialVerifier` — `CompletableFuture<Verdict> verify(BindCredential cred, ScopedValue<RequestContext> ctx)`; `BindCredential(SystemId, char[] password)` in `security`; `sealed interface Verdict permits Allow, DenyInvalid, DenyIndeterminate` (NO Throwable, NO free-form reason, NO Nimbus type crosses the port — ROPC adapter absorbs Nimbus). Runs on the hand-managed VT pool (AD-6/AD-28); NEVER `@Async`.

**Infrastructure / deployment**

- **[AD-16]** Spring Boot owns externalized config (@ConfigurationProperties + relaxed binding + fail-fast), DI, lifecycle, graceful shutdown, Micrometer. Netty driven DIRECTLY (own `ServerBootstrap`/`Bootstrap` in a `SmartLifecycle` bean); NO WebFlux, NO Reactor, no Spring web server on the SMPP path.
- **[AD-17]** Config fail-fast + role×mode matrix: validate at startup (non-zero exit on bad config). One instance = one role (forward|reverse) + one mode (A|B|C), mutually exclusive. Mode B is reverse-only (forward+B rejected). Mode B posture: NOT refused — loud startup warning + explicit opt-in ack, then starts.
- **[AD-21]** ByteBuf allocator: ONE shared `PooledByteBufAllocator` across all channels; size `-XX:MaxDirectMemorySize` (derivation AD-30); expose `ByteBufAllocatorMetric`. Start pooled (`io.netty.allocator.type=pooled`), load-test against adaptive allocator (PERF-1 + PERF-2 soak) before choosing.
- **[AD-22]** Graceful shutdown (SIGTERM, Spring SmartLifecycle drives): (1) stop SMPP acceptor (no new binds); (2) DENY in-flight adjudications; (3) drain in-flight splices to timeout (enumerate ConnectionRegistry); (4) stop JWKS refresh (`ScheduledExecutorService.shutdown` + await — refresh VT drains HERE); (5) close JWKS cache; (6) VT control-plane drain; (7) exit. Spring's graceful-shutdown timeout bounds the drain window.

**Observability**

- **[AD-19]** Read-only Prometheus `/metrics` via a TINY loopback HTTP handler on a DEDICATED, hand-managed Netty event loop group (started/stopped via SmartLifecycle; NEVER shares the SMPP relay event loop group) calling `PrometheusMeterRegistry.scrape()`. NO Actuator, NO Tomcat, NO WebFlux.
- **[AD-19]** Metrics cardinality: `system_id` labels ONLY for routing-table values (cardinality = routing-table size, bounded at startup); unknown/rejected `system_id` increment an unlabeled counter (`binds.rejected.unknown_system_id`) — NO free-form `system_id` ever a label. Message content never emitted. Track active-VT via a CUSTOM gauge (Micrometer `jvm_threads_*` does NOT count VTs). NO dashboard/backend/management API.
- **[AD-27]** `SpliceObserver` interface owned by `observability/`: methods `onFramedPdu(Direction)`, `onBindAccept(SystemId)`, `onBindReject(SystemId, Verdict)`, `onByteTransfer(Direction, long)` — NO PDU type, NO content. Trigger events PINNED: `onBindAccept` fires EXACTLY at the AD-25 flip (decoded `bind_*_resp` ROK), NOT at the verdict; `onBindReject` called ONLY for `Verdict` values from `BindCredentialVerifier` (routing-miss/kid-miss/config denies go to AD-19's unlabeled counter).
- **[AD-27]** `SpliceObserver` impl MUST apply AD-19 cardinality rule. `RelayHandler` holds an injected reference and calls it; codec NEVER emits metrics. ONE counter source; Micrometer impl is the only thing behind the seam.

**Monitoring / logging**

- **[AD-19]** Baseline ops logging = structured JSON-lines (UTC ISO-8601): startup/errors/bind accept-reject; full PDU/body ONLY at TRACE, off by default. Bind rejections carry an SMPP `bind_resp` status code (exact OIDC-outcome → status-code mapping owned by a single story; wire-visible only, low blast radius); NEVER a stack trace on the wire.

**Testing / conformance**

- **[AD-9]** Smoke-test assumption A-1 (carrier allows multiple concurrent binds per `system_id` + DLR affinity) EARLY against a real/conformance SMSC. If A-1 is false the design must become stateful.
- **[AD-24]** Author a from-scratch SMPP 3.4 conformance/regression suite in the test module (NO OSS suite exists). Structurally fuzz BOTH the bind-family parser AND the framing decoder (framing runs on every PDU for the connection lifetime — the MORE-EXPOSED surface, SEC-2).
- **[AD-24]** Primary mock SMSC = in-JVM mock built on codec (A-1 fixture + PERF sink; emulates N binds/`system_id` + `deliver_sm` session affinity). jSMPP 3.0.2 = independent interop counterpart (alternate ESME client + server-side mock), NEVER the production codec. A-1 carrier-side check = a separate NON-CI ops step against the real target carrier. Scope the "first-of-kind" claim to "no published SMPP proxy/stateless-relay benchmark."

**Other (operator surface)**

- **[AD-31]** Documentation is a v1 DELIVERABLE governed by the architecture (OPS-1): config reference, per-mode (A/B/C) deployment guide, troubleshooting/runbooks ship with the release under `docs/`. SEC-1 cipher-allowlist policy, Mode B warning text, and the A-1 real-carrier operational test plan dock here.

#### Architectural Decisions Summary (AD-1..AD-31)

| AD | Title | One-liner |
|----|-------|-----------|
| AD-1 | Event-loop relay paradigm | Netty event loops own the steady-state byte splice; VTs own the control plane; VTs never carry steady-state bytes. |
| AD-2 | Relay coupling + framed-ByteBuf splice | HexDumpProxy pattern (shared loop, AUTO_READ=false, write-gates-read); forward framed-PDU ByteBufs; framer stays active, codec dormant post-couple; no live pipeline surgery. |
| AD-3 | Hybrid PDU model | Inspect/handle ONLY bind family + unbind pre-couple (SMPP 3.4 only); once coupled every PDU incl. unbind is opaque bytes; MT-only is deploy expectation, not filter. |
| AD-4 | No blocking work on the event loop | Blocking calls on VTs; SslHandler bounded delegating Executor fails handshake on saturation — never CallerRunsPolicy, never unbounded. |
| AD-5 | Control plane on STS + ScopedValue | STS (JEP 505 preview) + ScopedValue (JEP 506 final) for adjudication fan-out, shutdown, lifecycle; RequestContext via ScopedValue never ThreadLocal; --enable-preview process-wide. |
| AD-6 | Three threading models kept coherent | Netty loops (data plane) + hand-managed VTs (control plane) + Spring executors; spring.threads.virtual.enabled only for Spring internals. |
| AD-7 | Two-module Gradle seam, inward-only | codec pure (zero upward deps); proxy = relay+security+config+observability+bootstrap; direction proxy → codec. |
| AD-8 | State-ownership (shape + home) | Mutable state: per-bind ConnectionRegistry (ingress ChannelId + Channel attr), monotonic metrics, AtomicReference<JwkSet> JWKS swapped whole; no message_id↔system_id; no SMS body persisted. |
| AD-9 | Stateless relay on assumption A-1 | Socket-pairing state only; DLRs ride the splice via the coupled pair (= session affinity); smoke-test A-1 early. |
| AD-10 | Credential-free proxy tier (at rest) | No persisted passwords/vault/CA/issuing keys; runtime holds OIDC cred, JWKS public keys, transient password (zeroized), own TLS end-entity keys; three trust roots. |
| AD-11 | Fail-closed universal default | Every auth-adjacent decision denies on indeterminate; DENY wins on verdict/defense-in-depth disagreement; kid-miss → DENY (no foreground refresh). |
| AD-12 | OIDC via ROPC, disposable JWT verdict, BindCredentialVerifier port | Token 200/401 = verdict; local JWKS defense-in-depth; discard token, relay original bind; re-validate every bind; port with CompletableFuture<Verdict>; Mode A two-proxy needs ACL isolation or Mode C. |
| AD-13 | mTLS = PKIX defaults; trust store never cacerts (OQ-4) | trustManager(store).clientAuth(REQUIRE), PKIX maxPathLen 5; never cacerts for ANY peer path; per-instance Mode C certs; revocation OUT. |
| AD-14 | Identity forwarded, not mapped | legacy system_id == carrier system_id; no pooling/mapping/surrogate. |
| AD-15 | Legacy ingress leg: no local password check | Trusted network is sole ingress gate; no local check/store; route on system_id; isolation (A-3) is deployer's job. |
| AD-16 | Spring Boot platform, Netty driven directly | Spring owns config/DI/lifecycle/shutdown/Micrometer; Netty via ServerBootstrap/Bootstrap in SmartLifecycle; NO WebFlux/Reactor/web server on SMPP path. |
| AD-17 | Config fail-fast + role×mode matrix + Mode B posture | Non-zero exit on bad config; one role + one mode; Mode B reverse-only with warning + ack; required-config matrix; TLS 1.2 min/1.3 preferred. |
| AD-18 | Secrets file-path-injected | Secrets = file paths to mounted files; never a value in an env var; fail-fast if missing/unreadable. |
| AD-19 | /metrics on own Netty (Micrometer); observability posture | Loopback HTTP handler on dedicated Netty loop; no Actuator/Tomcat/WebFlux; loopback IPv4 only; system_id labels only for routing-table values; JSON-lines logging; custom VT gauge. |
| AD-20 | Egress TLS endpoint-identification + SMSC-leg default | Set endpointIdentificationAlgorithm (null for raw-IP SMSC); SMSC-leg TLS operator-choice, default off under trusted-net. |
| AD-21 | ByteBuf allocator posture | One shared PooledByteBufAllocator; size MaxDirectMemorySize (AD-30); expose ByteBufAllocatorMetric; start pooled, load-test before choosing. |
| AD-22 | Graceful shutdown coordination | SIGTERM → stop acceptor → DENY in-flight → drain splices → stop JWKS refresh → close JWKS cache → VT drain → exit. |
| AD-23 | No native-image build target in v1 (OQ-11) | JVM build only; keep native-image-compatible as stretch; revisit only if cold-start-sensitive deployment emerges. |
| AD-24 | Test & conformance toolchain | From-scratch SMPP 3.4 conformance suite; fuzz bind parser AND framing decoder; in-JVM mock SMSC; jSMPP 3.0.2 interop only; A-1 carrier check = non-CI ops step. |
| AD-25 | Bind→splice transition state machine | Splice flag flipped by exactly RelayHandler on decoded bind_*_resp ROK; BindInterceptor forwards bind_resp; RelayHandler read-only; post-couple unbind opaque; session ends on TCP half/close. |
| AD-26 | Egress TLS trust anchoring | Validate peer against operator trust store (never cacerts, fail-fast); hostname-off conditional on IP-SAN certs or operator trust store as sole gate; cacerts/public-PKI = explicit opt-in any mode, never default. |
| AD-27 | Intra-proxy ownership seams | codec owns SmppCommandIds.BIND_FAMILY (consumed, not redefined); outbind/generic_nack opaque; SpliceObserver in observability/ with pinned triggers; codec never emits metrics; one counter source. |
| AD-28 | Bounded delegating executors | SslHandler Executor = one fixed platform-thread pool, abort-on-saturation; JWKS refresh = hand-rolled VT on ScheduledExecutorService; adjudication = single bounded VT pool, fail-closed, no VT-per-bind outside it. |
| AD-29 | Routing cardinality (v1 = 1:1) + value schema | One carrier egress per forward instance; system_id allow-list → single egress; {host, port, tlsContextId?}; multi-carrier deferred. |
| AD-30 | Max frame + per-channel inbound budget + direct-memory | Pin max command_length 65536 (exceed → drop+close), reject <16, overflow guard pre-allocation; bounded inbound queue + low-water re-arm; MaxDirectMemorySize = max_frame × depth × pairs × safety. |
| AD-31 | Documentation is the operator surface (OPS-1) | Docs = v1 deliverable: config reference, per-mode guide, runbooks under docs/; cipher policy, Mode B warning, A-1 test plan dock here. |

#### Accepted Risks (constrain story scope)

- **ROPC hard-dependency** — v1 hard-depends on ROPC (Direct Access Grants), a deprecated grant (RFC 9700 "MUST NOT"; removed in OAuth 2.1). The `BindCredentialVerifier` port LOCALIZES a future rework to one adapter but does NOT eliminate the dependency (no standard replacement grant). Keycloak 26.7 still ships it; if removed, v1 must be reworked. **Single most fragile external dependency in the trust model.**
- **Preview-API dependency (StructuredTaskScope)** — STS (JEP 505) preview-only on JDK 25 (still preview JDK 26 via JEP 525; not final until ~JDK 27); ScopedValue final. `--enable-preview` runs process-wide, placing Netty/Nimbus/codec under preview semantics. Mitigations: pin JDK 25 build; confine STS to control plane.
- **Password-only ingress on the legacy leg** — by design; mitigated by trusted-zone confinement (AD-15).
- **`system_id` spoofing on the trusted network** — any trusted-net host can claim any permitted `system_id`; sole control = network isolation (A-3).
- **Authority-provider / PKI-CA compromise** — OIDC provider can mint verdicts; can mint client certs only if operator runs the same entity as its Mode C PKI CA. Provider/CA HA + security = operator responsibility (A-2).
- **Mode B plaintext password over the public internet** — opt-in + loud warning, starts (AD-17).
- **Mode A two-proxy without ACL isolation** — forward proxy cannot authenticate reverse in one-way TLS; any peer reaching forward's internet port is relayed plaintext passwords; mitigate = ACL-isolate or use Mode C.
- **Payload transparency = no content-level protection** — no inspection/filtering/type-enforcement (AD-3).
- **Long-lived baked Mode C client certs** — rotation = re-deploy; per-instance keys bound the blast radius (OPS-2).
- **Authority-provider outage blocks new binds** — ongoing splices survive on cached JWKS/trust (A-2).
- **No local brute-force / rate-limit protection** — planned future companion; acknowledged gap.
- **No metrics dashboard / telemetry backend / management API** — read-only `/metrics` + baseline logging only.
- **Single-instance, no HA/failover** — statelessness is a future-HA enabler, not a v1 commitment.

#### Deferred (decisions pushed down — each can wait without letting two units diverge)

- Exact cipher/TLS allowlist contents (ships in config, AD-17/SEC-1).
- JWKS cache TTL / refresh-ahead / rate-limit values, ROPC timeouts (tune to PERF-3; kid-miss policy IS fixed — AD-11).
- `bind_resp` status-code → OIDC-outcome mapping (single story; wire-visible only).
- Routing-table YAML shape + multi-carrier routing (v1 = 1:1, AD-29).
- Prometheus histogram buckets / scrape-handler exacts (AD-19 fixes posture + cardinality).
- `application.yml` exact keys (AD-17 fixes the matrix).
- DLR-splice byte mechanics (determined by AD-2/AD-9/AD-25).
- A-1 real-carrier operational test plan (non-CI ops step, AD-24; docks under docs, AD-31).
- Full STRIDE/DFD threat model (spine carries load-bearing trust invariants + register; exhaustive enumeration belongs in walkthrough).
- Perf-harness exacts (JMH codec bench, end-to-end relay percentile table, idle-CPU-at-N demo).
- Native-image build (out of v1, AD-23).
- Scaffolding for future Companions siblings (out of v1; only forward-looking invariant = inward-only codec seam, AD-7).

### UX Design Requirements

**N/A — Companions v1 is a headless, operator-configured product with no UI and no management API** (explicit PRD non-goal: §13 "no UI"; OBS-3 "no management API"). No UX design contract exists or is required. The operator surface is documentation (OPS-1 / AD-31).

### FR Coverage Map

{{requirements_coverage_map}}

## Epic List

{{epics_list}}

<!-- Repeat for each epic in epics_list (N = 1, 2, 3...) -->

## Epic {{N}}: {{epic_title_N}}

{{epic_goal_N}}

<!-- Repeat for each story (M = 1, 2, 3...) within epic N -->

### Story {{N}}.{{M}}: {{story_title_N_M}}

As a {{user_type}},
I want {{capability}},
So that {{value_benefit}}.

**Acceptance Criteria:**

<!-- for each AC on this story -->

**Given** {{precondition}}
**When** {{action}}
**Then** {{expected_outcome}}
**And** {{additional_criteria}}

<!-- End story repeat -->
