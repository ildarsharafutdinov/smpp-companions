---
title: SMPP 3.4 Security Proxy (Companions v1)
project: smpp-companions
status: final
created: 2026-07-18
updated: 2026-07-20
inputs:
  - _bmad-output/brainstorming/brainstorm-smpp-security-proxy-2026-07-18/brainstorm-intent.md
  - _bmad-output/planning-artifacts/briefs/brief-smpp-companions-2026-07-18/brief.md
  - _bmad-output/planning-artifacts/briefs/brief-smpp-companions-2026-07-18/addendum.md
---

# SMPP 3.4 Security Proxy — Companions v1

> A headless, operator-configured, open-source SMPP 3.4 security-transit proxy. The first module of a planned family of non-invasive augmentation layers for legacy SMPP. Built from scratch on JDK 25 + Netty (event-loop relay) + Spring Boot; virtual threads own the control plane.
>
> `→ addendum` flags technical detail deferred to `addendum.md`. Decision audit: `.memlog.md` (full trail) and §12 (resolved/open questions).

## 1. Problem

Legacy SMPP 3.4 systems must exchange traffic with carrier SMSCs over untrusted networks, but they **cannot be modified** and carry a hard authentication weakness: they perform **password-grant binds only**, cannot present client certificates, and cannot do mTLS. That weakness cannot be safely exposed to the internet.

The obvious fix — a security proxy in front of the legacy system — typically **backfires**: the proxy ends up *holding* the credentials it was meant to protect (a password vault), so any proxy compromise yields a stash of working carrier passwords with a huge blast radius.

The itch this product scratches: **confine the legacy auth weakness to a trusted zone, broker a single credential end-to-end, keep the proxy tier credential-free, and cover the full range of real legacy reach** — without bundling the trust infrastructure (IdP, PKI) itself.

The deeper itch is the **pattern**: a non-invasive augmentation layer that bolts modern capabilities onto untouchable legacy. Security-transit is the first instance; it will not be the last.

## 2. Vision & Positioning

**Companions v1** is a headless, operator-configured, open-source SMPP 3.4 security-transit proxy. One converged codebase plays **both sides of the wire**: the *enterprise/forward* role (fronting a legacy system connecting to a carrier) and the *carrier/reverse* role (fronting an SMSC accepting binds). It:

- confines the legacy password-grant weakness to a trusted zone;
- forwards a **single credential end-to-end** (legacy `system_id` == carrier `system_id`);
- delegates grant validation to an operator-run authority provider over **OIDC**;
- ships **credential-free** — so the SMSC remains the sole credential authority and proxy compromise yields *network position*, not a stash of working passwords;
- covers real-world legacy reach through three mutually exclusive deployment modes (A one-way TLS, B plaintext direct, C mTLS);
- **consumes** external trust (source-agnostic certs at runtime; auth via the operator's authority provider) rather than **providing** it;
- is **payload-transparent** — it inspects/handles only bind/unbind and splices every other PDU through unmodified (see §6.1);
- ships as a standalone **application (runnable JAR)** and a **Docker image** (which packages that JAR), both first-class.

**Positioning.** Cloudhopper and jSMPP are the inspirations — the established JVM SMPP libraries that proved the shape and the demand — but Companions is built **entirely from scratch for JDK 25** (not a fork, no reuse of their code): current JDK, Loom-era concurrency, and a *security-proxy* shape they were not. It is not a general SMPP library; it is the **secure-transit companion** for systems that already speak SMPP.

**Family boundary (guardrail).** *Companions* is a planned family. v1 delivers **one working security companion** with clean internals; it does **not** deliver a modular SMPP *platform*. Internal modularity is a code-quality goal (§7.6, MAINT-2), not a v1 product surface. See §5 and §13.

**Craft is the headline.** This is a portfolio piece: the point is to demonstrate modern-JVM engineering (Loom concurrency, Netty networking, from-scratch protocol implementation) applied to a genuine security-architecture problem — done well enough to be proud of and to actually use.

## 3. Stakeholders

- **Author / solo developer (primary)** — wants a coherent, demonstrably correct OSS portfolio piece; original from-scratch work they are proud to show and actually use. *Sets the success bar.*
- **Operator / deployer** — runs headless middleware as an application (runnable JAR) or Docker image; provisions certs and runs their own authority provider (Keycloak reference). Needs credential-free operation and clear mode selection.
- **Enterprise / ESME legacy owner** — must reach carrier SMSCs securely despite an unmodifiable, mTLS-incapable SMPP 3.4 stack.
- **Carrier / SMSC operator** — wants to harden ingress without forcing clients off SMPP 3.4; the SMSC remains the credential authority and its session-affinity semantics must be respected.
- **Security architect (trust-model reviewer)** — validates the trust crown jewel lives in the operator-run authority provider, not the proxy; that accepted risks are explicit and bounded. *(Unusual for a hobby project but load-bearing for a security-branded one.)*
- **Future Companions-family contributors** — inherit a clean, modular SMPP core and a credential-free, dual-role architecture to extend.

## 4. Goals & Success Criteria

**Goals.**
- **Originality** — built entirely from scratch for JDK 25; no Cloudhopper/jSMPP derivation.
- **Well-built** — demonstrably correct, with a measurable performance & resource story (§7.1) proven by a reproducible harness.
- **Genuine security value** — the credential-free trust model holds under review; accepted risks are owned, not buried.
- **Author-proud + actually-used** — scratches the original itch; something the author deploys.
- **Establishes the pattern** — a clean foundation the next companion can build on.

**Success criteria.**
- **SM-1** — A shippable OSS release (application (runnable JAR) + Docker) that the author is proud of and uses.
- **SM-2** — The trust model survives a security-architect review (credential-free invariant holds; fail-closed default verified; accepted risks documented).
- **SM-3** — The performance & resource targets in §7.1 are met and **published** via a reproducible harness — a first-of-kind benchmark for an SMPP proxy (no published relay benchmark exists today).
- **CM-1 (counter-metric)** — Scope does not creep toward adoption-chasing or platform-building. v1 ships *one* companion; modularity stays internal.

**Adoption is a bonus, not the bar.**

**License.** Apache-2.0 (permissive, JVM-OSS standard, adoption-friendly).

## 5. Scope

**In (v1).**
- SMPP **3.4**. The proxy inspects/handles only bind/unbind and splices all other PDUs transparently (§6.1); it is payload-transparent and enforces no message-type or content restriction.
- Three deployment modes **A / B / C** (one-way TLS / plaintext direct / mTLS) — all three shipped and documented; Mode B posture in §8.
- Password-grant forwarding end-to-end + mTLS (Mode C).
- OIDC-delegated password-grant validation (BYO authority provider; Keycloak = reference).
- Runtime-provided, source-agnostic certificates; per-instance baked keys (Mode C).
- Two first-class deployment shapes: **application (runnable JAR) + Docker image**.
- One codebase, both roles (enterprise/forward + carrier/reverse).
- Credential-free proxy tier; single-credential brokering (identity preserved end-to-end).
- Baseline operational logging + a read-only `/metrics` endpoint (§7.8).

**Out / non-goals (v1).** See §13 for the full list and reconciliations. Headlines: no UI; no SMPP 5.x; no message inspection/routing logic; no management/control API; no bundled authority provider or cert issuance; no metrics *dashboard*/telemetry backend; Linux only; IPv4 only.

## 6. Functional Requirements

*Capabilities, not implementation. Mechanisms → `addendum.md`.*

### 6.1 Protocol Transit
- **FR-TRANSIT-1** — Transit SMPP 3.4 traffic between legacy system and SMSC using a **hybrid model**: the proxy **inspects and handles only the bind family and unbind** (to establish/tear down sessions and apply authentication); **all other PDUs are spliced transparently as opaque bytes** — not inspected, not filtered, forwarded as-is. The proxy is **payload-transparent**: it makes no claim about — and enforces no restriction on — what message types or PDU content either side sends.
- **FR-TRANSIT-2** — DLRs (`deliver_sm`) flow back to the originating legacy bind via that same transparent passthrough (on the bind's session affinity) — no separate DLR path and no DLR-specific handling. *(Depends on bind session-affinity — §10 A-1.)*
- **FR-TRANSIT-3** — Interoperate transparently with unmodified SMPP 3.4 stacks on both legs, passing an SMPP 3.4 conformance suite on each leg without altering protocol behavior either side relies on.
- **FR-TRANSIT-4** — The bind/unbind handling implements **SMPP 3.4**; SMPP 5.x is not implemented.

**PDU handling matrix:**

| PDU | v1 handling |
|---|---|
| bind_transmitter / receiver / transceiver (+resp) | **Inspected / handled** — session establishment + auth |
| unbind (+resp) | **Inspected / handled** — session teardown |
| All other PDUs (`submit_sm`, `deliver_sm`/DLR, `enquire_link`, `submit_multi`, `data_sm`, `query_sm`, `replace_sm`, `cancel_sm`, `broadcast_sm`, `outbind`, `alert_notification`, `generic_nack`, …) | **Transparent passthrough** — spliced as opaque bytes, not inspected |

*The proxy neither generates nor filters non-bind PDUs; it forwards them. MT-only is a deployment expectation, not a proxy-enforced filter.*

### 6.2 Trust & Security Model
- **FR-SEC-1** — The proxy tier holds **no SMPP passwords and no password vault**. The SMSC remains the sole credential authority. Compromise of a proxy yields network position only — never working carrier credentials.
- **FR-SEC-2** — Confine the legacy password-grant weakness to a trusted zone; never expose it unprotected on untrusted networks, except in the explicitly accepted plaintext Mode B.
- **FR-SEC-3** — Preserve end-to-end identity: legacy `system_id` == carrier `system_id`. No pooling, mapping, or surrogate identity.
- **FR-SEC-4** — **Consume** operator-provided trust at runtime (source-agnostic certs; OIDC-delegated auth). Do not bundle/run an authority provider, act as a CA, or issue certificates.
- **FR-SEC-5** — **Fail-closed:** DENY a bind when the authority-provider verdict is unavailable or indeterminate (timeout, network error). Deny-on-ambiguous is the default.

### 6.3 Authentication
- **FR-AUTH-1** — Delegate password-grant validation to an operator-run **OIDC** authority provider (Keycloak = reference target, not part of this project).
- **FR-AUTH-2** — **Support** mTLS client-certificate authentication (Mode C); do **not** mandate it (Modes A and B operate password-grant only).
- **FR-AUTH-3** — Use **per-instance** baked client certificates (Mode C); never a shared golden-image key.
- **FR-AUTH-4** — mTLS (Mode C) terminates the client-certificate handshake. **Chain-validation depth and trust-anchor handling are decided at the architecture/solution phase (OQ-4).** CRL/OCSP revocation checking is OUT of v1 regardless (rotation is re-deploy, OPS-2).

### 6.4 Deployment & Form
- **FR-DEPLOY-1** — Ship two first-class, **feature-equivalent** shapes — a standalone **application (runnable JAR)** and a **Docker image** (packaging the same JAR): same config surface, modes, auth paths.
- **FR-DEPLOY-2** — One codebase plays both roles (enterprise/forward + carrier/reverse); role and mode are deployment-time configuration of the application, not forks.
- **FR-DEPLOY-3** — Validate configuration at startup and **fail-fast** (refuse to start) on ambiguous, insecure, or missing configuration.
- **FR-DEPLOY-4** — Provision certificates at deploy time (bake via CI/pipeline); do not require runtime ACME/SPIFFE enrollment to function.

### 6.5 Operability & Observability
- **FR-OBS-1** — Emit baseline operational logging (startup, errors, bind accept/reject, with `system_id` where relevant) to stdout/file as structured JSON-lines. Full message/PDU-body logging is available only at **TRACE** level (off by default).
- **FR-OBS-2** — Expose a read-only HTTP **`/metrics`** endpoint (Prometheus exposition): throughput counters, bind counters, and resource gauges, **configurably dimensioned per `system_id`** (operator-controllable cardinality). **Loopback-only (IPv4) in v1** (the loopback binding is the endpoint's sole authentication — non-loopback is forbidden, architecture AD-19); never on the SMPP transit legs; **message content is never emitted** (`system_id` labels are permitted).

## 7. Non-Functional Requirements

*The WHAT/guarantee lives here; mechanisms → `addendum.md`.*

### 7.1 Performance *(locked targets — anchor-derived)*
Reference hardware: single instance, 4–8 vCPU modern x86/ARM, Linux, JDK 25 GA, ZGC, 2–4 GiB heap.
- **PERF-1 (throughput)** — Sustain **≥ 10,000 submit_sm/sec**, stretch **~25,000/sec**, with mTLS on both legs, OIDC validation cached, **Netty event-loop relay** (virtual threads own only the control plane — bind adjudication, OIDC, shutdown). *(Honest published ceiling without a percentile-table harness: ~25–36K.)*
- **PERF-2 (concurrency)** — Hold **10,000 concurrent idle ESME↔proxy↔SMSC socket pairs** (~20K sockets) in **< 1 GB heap** and **< 1 vCPU** idle.
- **PERF-3 (bind latency)** — **p99 ~250 ms** on the warm path (co-located IdP, TLS 1.3, pooled egress); **≤ 2 s** cold-path limit; **fail-closed DENY** beyond a configured **2–5 s** timeout.
- **PERF-4 (relay latency)** — Per-PDU added latency is **sub-ms** (the SMSC round-trip dominates; the codec is ~60× faster than the network path).
- **Proof:** targets are demonstrated via a reproducible load-test harness against a mock SMSC + the `/metrics` surface (observability posture, §7.8). No published SMPP-proxy benchmark exists; these are self-measured.

### 7.2 Security
- **SEC-1 (TLS floor)** — Minimum **TLS 1.2**, **TLS 1.3 preferred**; publish a cipher allowlist policy. *(Specific list → addendum.)*
- **SEC-2 (parser robustness)** — The parser handles only bind/unbind PDUs (all other traffic is opaque splice); it safely rejects malformed, oversized, or truncated bind PDUs without crashing. The byte-splice path is robust against oversized frames and memory exhaustion (backpressure, REL-2).
- **SEC-3 (provider link)** — The proxy→authority-provider link is authenticated and encrypted (TLS/mTLS or service-account token).
- **SEC-4 (no rolled crypto)** — Mature libraries are mandatory for crypto/TLS/OIDC primitives (Decision B). The from-scratch principle covers the SMPP layer only.
- **SEC-5 (dependency hygiene)** — Maintain a vulnerability/CVE policy for security-critical dependencies (Netty, JDK).

### 7.3 Privacy
- **PRIV-1** — Do **not** persist SMS message bodies. `system_id` **may** be logged and used as a metrics label; per-`system_id` metrics are available. **Full message/PDU-body logging is available only at TRACE level** (off by default). Message content is never emitted in metrics.

### 7.4 Reliability
- **REL-1 (transit integrity)** — Do not silently drop, duplicate, or corrupt spliced traffic or DLRs.
- **REL-2 (backpressure)** — When the egress leg is slow, the ingress leg backpressures rather than OOM.
- **REL-3 (graceful shutdown)** — On SIGTERM: stop accepting new binds, drain in-flight traffic up to a timeout, then exit.
- **REL-4 (statelessness)** — The proxy holds no `message_id`-to-`system_id` correlation (socket-pairing state only). *Premise A-1 (carrier multi-bind + DLR affinity) is confirmed.*

### 7.5 Compatibility
- **COMP-1** — Interoperate cleanly with unmodified SMPP 3.4 stacks on both ends; zero changes to legacy gear or SMSC behavior.
- **COMP-2** — **JDK 25** runtime floor (Loom-era; `--enable-preview` for `StructuredTaskScope`); JVM-only.
- **COMP-3** — **Linux only** (x86/ARM). No macOS or Windows build in v1.
- **COMP-4** — **IPv4 only.**

### 7.6 Maintainability
- **MAINT-1 (single codebase)** — One codebase serves both roles; mode/role selection is deployment-time config, not forks.
- **MAINT-2 (structured for extraction)** — The SMPP codec + PDU layer is a clean, separable, independently tested module with documented boundaries — **structured for future extraction** (Decision A). *Modularity is a code-quality goal, not a v1 product surface; v1 ships an application, not a published library artifact.*
- **MAINT-3 (originality)** — Built from scratch for JDK 25; no Cloudhopper/jSMPP derivation (SMPP layer only — see SEC-4).
- **MAINT-4 (test strategy)** — An integration-test strategy is required: mock/conformance SMSC, TLS/OIDC test vectors, codec fuzzing. *(A solo-authored security boundary must be testable.)*
- **MAINT-5 (native-image compatibility)** — Keep the codebase compatible with GraalVM native-image as an **opt-in future** path (avoid reflection-heavy patterns); this compatibility-stretch posture is fixed. **Architecture decision (AD-23 / OQ-11): NO v1 native-image build** (always-on single-instance → startup/footprint gains are noise; ZGC unavailable in native-image); revisit only if a cold-start-sensitive deployment emerges.

### 7.7 Deployability
- **DEP-1 (Docker secrets contract)** — The Docker shape defines how secrets (certs, keys, provider creds) are injected (file paths / env / mounted secrets). *(Mechanism → addendum.)*

Two-shape parity, deploy-time cert provisioning, and config fail-fast are deployability needs already covered by FR-DEPLOY-1..4 (§6.4).

### 7.8 Operability & Observability
- **OPS-1 (documentation is the surface)** — Because the product is headless with no UI/management API, **documentation is the operator surface**: config reference, deployment-mode guide, troubleshooting/runbooks must exist.
- **OPS-2 (cert rotation)** — v1 operational contract: **re-deploy to rotate** baked certs (Mode C). CRL/OCSP revocation is OUT of v1.
- **OBS-1 (read-only metrics)** — A `/metrics` scrape endpoint is provided (FR-OBS-2). There is **no dashboard, no telemetry backend, no UI**.
- **OBS-2 (proxy not silent)** — Baseline operational logging (FR-OBS-1) ensures "no observability" never reads as "the proxy is silent."
- **OBS-3 (no management API)** — Operators cannot query/drain/reload/rotate at runtime in v1; deliberate limitation.

## 8. Deployment Model

**Two orthogonal axes** (previously conflated — disambiguated here):

- **Form-factor axis:** standalone **application (runnable JAR)** vs **Docker image** (which packages the JAR).
- **Topology/security axis:** three mutually exclusive modes.
  - **Mode A — one-way TLS:** the proxy terminates/originates TLS on the internet leg; the legacy leg is password-grant over a trusted network.
  - **Mode B — plaintext direct:** no TLS on the internet leg; password-grant carried in cleartext over the public internet. **Accepted-risk mode.**
  - **Mode C — mTLS:** mutual TLS with client certificates on the internet leg (strongest).

**Mode B posture:** Mode B is **shipped and documented** (some operators have legitimate plaintext-internal use cases), but it is **not the default**, emits a **loud startup warning**, and requires an **explicit opt-in acknowledgment**. Not refused at startup, but never silent.

**Both roles.** The same application plays enterprise/forward and carrier/reverse; role + mode are deployment-time config of one runnable JAR (the Docker image packages the same JAR). The forward role selects the egress target by `system_id` (a routing table); whether a single v1 instance fronts multiple carriers is an architecture/scope detail.

**Single-side adoption:** supported — one party adopting Companions (enterprise-only or carrier-only) is a valid v1 deployment, not only the two-proxy topology.

**Trusted-network precondition.** On the legacy↔proxy leg, the trusted network is the sole ingress gate (the proxy does not authenticate that leg); network isolation is the deployer's responsibility — stated explicitly, not buried.

## 9. Trust & Security Model (narrative)

The trust model **is** the product — it earns a narrative, not just scattered NFRs. In one thread: the proxy tier is **credential-free** (FR-SEC-1) — the legacy password is *brokered end-to-end and validated by delegation, never held* — so the SMSC remains the sole credential authority and proxy compromise yields only network position. The legacy password-grant weakness is **confined to a trusted zone** (FR-SEC-2); trust is **delegated, not assumed** — the proxy never adjudicates it and fails closed on any indeterminate verdict (FR-SEC-5); and all trust is **consumed, not manufactured** (FR-SEC-4: certs from a runtime trust store; no CA, no issuance, no bundled IdP). The capabilities live in §6.2; the deliberate, owned tradeoffs in §11.

*Full adversarial threat modeling is deferred to architecture/addendum; this section states the product-level trust posture.*

## 10. Assumptions, Constraints & Dependencies

- **A-1 (confirmed by author):** the target carrier allows **multiple concurrent binds under one `system_id`** and routes `deliver_sm`/DLRs back on the bind with session affinity. This is the premise of the stateless-splice architecture. *(Confirmed; the architect should still smoke-test it early against a real/conformance SMSC — it remains the single most load-bearing assumption.)*
- **A-2:** The authority provider is a **hard dependency** for new binds — a provider outage means no new binds succeed (ongoing mTLS survives on cached trust). Operator's HA responsibility.
- **A-3:** Trusted-network isolation on the legacy leg is the deployer's responsibility.
- **A-4:** Accurate clocks (NTP) are an operational precondition.
- **Constraints:** JDK 25; JVM-only; **Linux**; **IPv4**; SMPP 3.4; payload-transparent; single-instance v1.

## 11. Accepted Risks & Limitations

*A security product owns its accepted risks explicitly — these are deliberate, reviewable decisions, not buried caveats.*

- **Password-only ingress on the legacy leg** — by design (the legacy system cannot do better); mitigated by trusted-zone confinement.
- **`system_id` spoofing on the trusted network** — any host on the trusted net can claim any `system_id` (and, if multi-carrier routing is enabled, be steered toward any carrier's egress) before any check; trusted-network isolation (A-3) is the sole control.
- **Authority-provider compromise = full impersonation** — if the operator's OIDC provider is compromised, an attacker can mint verdicts that pass any bind; it can mint client **certs only if the operator runs the same entity as its Mode C PKI CA** (trust is consumed from **three roots** — OIDC provider, operator PKI, SMSC — not one; architecture AD-10). The provider is a trust root, not the proxy (A-2). Owned, not hidden.
- **ROPC hard-dependency** — password-grant validation uses **ROPC (Direct Access Grants)**, the only standard grant that validates a raw password with no browser — and a **deprecated** one (RFC 9700 "MUST NOT"; OAuth 2.1 removes it). v1 **hard-depends** on it: the `BindCredentialVerifier` port (architecture AD-12) localizes a future rework to one adapter but **does not eliminate the dependency** (no standard replacement grant exists). The first-party/headless/in-memory framing places this outside the deprecation's primary rationale (3rd-party end-user apps); Keycloak 26.7 still ships it. The single most fragile external dependency in the trust model.
- **Mode B plaintext password over the public internet** — accepted-risk mode, opt-in + warning (§8).
- **The proxy is payload-transparent** — it does not inspect, filter, or enforce message type (MT/MO) or PDU content. Whatever the endpoints send post-bind is relayed; operators own what transits the proxy.
- **Long-lived baked client certs (Mode C)** — rotation is re-deploy (OPS-2); per-instance keys (FR-AUTH-3) bound the blast radius.
- **Authority-provider outage blocks new binds** — accepted (A-2); ongoing traffic survives on cached trust.
- **No local brute-force / rate-limit protection** — rate-limiting is a planned future companion; v1 ships no local throttle. Acknowledged gap.
- **No metrics dashboard / telemetry backend / management API** — a read-only `/metrics` scrape and baseline logging are provided; everything beyond is out of v1.
- **Single-instance (no HA/failover)** — statelessness is a *future-HA enabler*, not a v1 commitment.

## 12. Open Questions & Decisions Needed

**Decided at the architecture/solution phase (architecture status: final — AD-1..31):**
- **OQ-4** — mTLS (Mode C) chain-validation depth and trust-anchor handling → **decided: PKIX defaults (no custom chain-validation code); the trust store never falls back to JDK `cacerts`** (architecture AD-13). Revocation remains OUT (OQ-5).
- **OQ-11** — Native-image build target in v1 → **decided: NO v1 native build** (compatibility-stretch only; ZGC unavailable in native-image) (architecture AD-23).

**Resolved during PRD authoring** *(kept for audit):*
- ~~OQ-1~~ — Carrier multi-bind + DLR affinity → **confirmed (author)**: yes. The stateless-splice premise (A-1) holds.
- ~~OQ-2~~ — Byte-splice vs PDU-aware → **decided: hybrid** (inspect bind/unbind only; splice all else transparently). §6.1.
- ~~OQ-3~~ — Application↔topology mapping → **dissolved**: one JAR configured for role+mode; Docker packages the same JAR.
- ~~OQ-5~~ — Cert revocation → **decided**: re-deploy-to-rotate (CRL/OCSP OUT). OPS-2.
- ~~OQ-6~~ — Graceful-shutdown drain → **decided**: stop new binds, drain in-flight to timeout. REL-3.
- ~~OQ-7~~ — Mode B posture → **decided**: ship + opt-in + loud startup warning. §8.
- ~~OQ-8~~ — PDU matrix → **decided**: handled = bind/unbind; all else transparent passthrough. §6.1.
- ~~OQ-9~~ — IPv6 → **decided: IPv4 only** (COMP-4); Linux only (COMP-3).
- ~~OQ-10~~ — OSS license → **decided: Apache-2.0**. §4.

## 13. Out of Scope / Non-Goals (v1)

- No UI; no SMPP 5.x; **no message inspection/routing/filtering logic** (post-bind PDUs spliced transparently — the proxy is payload-transparent); no management/control API (read-only `/metrics` is **not** a management API).
- No metrics dashboard / telemetry backend / OTel traces / exemplars.
- No bundled authority provider; no cert issuance / CA role; no runtime ACME/SPIFFE enrollment.
- No macOS or Windows build (**Linux only**); no IPv6 (**IPv4 only**).
- No HA / multi-instance / failover (single-instance v1).
- No CRL/OCSP revocation infra (re-deploy-to-rotate).
- No GraalVM native-image build target as a v1 commitment (compatibility-stretch only — MAINT-5/OQ-11).
- No rate-limiting / anomaly detection; no PDU-level audit/inspection; no protocol translation. *(All planned future companions.)*

**Reconciliations (source contradictions, resolved here):**
- *Audit/logging:* baseline operational logging (startup/errors/bind accept-reject, incl. `system_id`) = **IN**; full message-body logging = **TRACE-only**; PDU-level audit/inspection = **OUT** (future companion). "No observability" means no dashboard/telemetry, not "the proxy is silent."
- *Rate-limiting:* **OUT** for v1 (planned sibling); the no-local-throttle gap is an accepted risk (§11).
- *Family siblings (future SMPP library, JMeter plugin, logging/audit, rate-limiting, protocol-translation, metrics):* all **non-v1**; v1 internals stay "structured for extraction" but ship nothing as a platform (Decision A).

## 14. Glossary (lightweight)

- **SMPP 3.4** — Short Message Peer-to-Peer protocol, v3.4 (the legacy carrier-SMS wire protocol).
- **ESME** — External Short Messaging Entity (a system that binds to an SMSC; the "enterprise" side).
- **SMSC** — Short Message Service Center (the carrier side).
- **MT / MO** — Mobile-Terminated (outbound to handset) / Mobile-Originated (inbound from handset).
- **DLR** — Delivery Report.
- **`system_id`** — the SMPP bind identifier (the "credential" identity preserved end-to-end).
- **mTLS** — mutual TLS (both sides present certificates).
- **OIDC** — OpenID Connect (the standard the authority provider speaks; Keycloak is the reference).
- **IdP** — Identity Provider (the authority provider; Keycloak is the reference target).
- **PKI** — Public Key Infrastructure (the operator's cert/trust environment — Companions consumes it, does not provide it).
- **BYO** — Bring Your Own (the operator runs their own authority provider / PKI).
- **OTel** — OpenTelemetry (traces/exemplars — out of v1 scope).
- **AOT** — Ahead-of-Time compilation (GraalVM native-image; v1 compatibility-stretch, not a build target — OQ-11).
- **Application (runnable JAR)** — the standalone runnable Java application form-factor (`java -jar …`); the Docker image packages this same JAR.
