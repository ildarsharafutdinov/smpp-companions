# Test Design for Architecture: Companions v1 — SMPP 3.4 Security-Transit Proxy

**Purpose:** Architectural risk assessment, NFR testability requirements, testability concerns, and risk-mitigation plans. This is the QA → Engineering contract: what the architecture must provide or decide before test development begins. It is *not* the test-execution recipe (that is the companion `test-design-qa.md`).

**Date:** 2026-07-22
**Author:** Murat (Master Test Architect)
**Status:** ✅ Accepted — Architecture Review Passed 2026-07-23 (Q1–Q7 resolved → AD-32/33/34 + AD-27/3/25/19/30/24 amendments; see `ARCHITECTURE-SPINE.md`)
**Project:** smpp-companions — SMPP 3.4 security-transit proxy (solo OSS, Apache-2.0)
**PRD Reference:** `_bmad-output/planning-artifacts/prds/prd-smpp-companions-2026-07-18/prd.md`
**ADR / Architecture Reference:** `_bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/ARCHITECTURE-SPINE.md` (AD-1..AD-34) + `_bmad-output/planning-artifacts/epics.md`

---

## Executive Summary

**Scope:** A headless, single-instance SMPP 3.4 security-transit proxy. Two-leg relay (legacy ESME ↔ proxy ↔ SMSC); the proxy inspects/handles only the bind family (FR-TRANSIT-1) and splices all other PDUs as opaque bytes. Authentication is delegated to an operator OIDC provider via ROPC (FR-AUTH-1); the proxy is fail-closed (FR-SEC-5) and credential-free-at-rest (FR-SEC-1). v1 ships two feature-equivalent shapes — runnable JAR + Docker (FR-DEPLOY-1). There is **no UI, no management API, no dashboard** (OBS-3); documentation is the operator surface (OPS-1).

**Business Context** (from PRD §1, §3):

- **Revenue/Impact:** Solo OSS portfolio piece; success is a shippable, defensible security artifact, not revenue.
- **Problem:** Carriers/enterprises lack a transparent SMPP 3.4 transit proxy that delegates authentication to a modern OIDC authority without becoming a credential vault.
- **GA Launch:** v1 (JAR + Docker), 2026.

**Success Metrics** (PRD §1):

- **SM-1** — A shippable OSS release (runnable JAR + Docker) the author is proud of and uses.
- **SM-2** — The trust model survives a security-architect review (credential-free invariant holds; fail-closed default verified; accepted risks documented).
- **SM-3** — The performance & resource targets (§7.1) are met **and published** via a reproducible harness — a first-of-kind benchmark for an SMPP proxy/stateless relay.

**Architecture** (key decisions from the spine):

- **AD-1 / AD-2:** Netty event-loop relay; framed-`ByteBuf` splice; virtual threads own only the control plane.
- **AD-7:** Two-module Gradle seam — `codec` (PURE, zero upward deps) + `proxy` (MAINT-2 extractability enforced by the build boundary).
- **AD-11:** Fail-closed universal default — every auth-adjacent decision DENYs on indeterminate.
- **AD-12:** OIDC via ROPC, disposable JWT verdict, `BindCredentialVerifier` port + `sealed Verdict` (the adjudication seam).
- **AD-13 / AD-26:** mTLS = PKIX defaults; trust store **never** JDK `cacerts` for ANY peer path (ingress Mode C + egress).
- **AD-5:** Control plane on `StructuredTaskScope` + `ScopedValue` (JEP 505, `--enable-preview`).

**Expected Scale** (PRD §7.1, locked):

- PERF-1 ≥ 10,000 `submit_sm`/s (stretch ~25K), mTLS both legs, OIDC cached.
- PERF-2 10,000 idle socket pairs (~20K sockets) in < 1 GB heap / < 1 vCPU idle.
- PERF-3 bind p99 ~ 250 ms warm / ≤ 2 s cold / fail-closed DENY beyond 2–5 s.

**Risk Summary:**

- **Total risks:** 35 (reconciled register, post red-team; see note below).
- **High-priority (score ≥ 6):** 18 risks (5 P0 gate-blockers at score 9 + 13 P1 at score 6) requiring immediate mitigation.
- **Test effort:** 251 scenarios, ~290–710 hrs (~7–18 weeks FTE), written test-first across E1–E6 — not a separate QA phase.

> **Register count note:** The reconciled register in the progress file is re-stated here verbatim by row. By actual row count it totals 35 (18 high ≥6, 15 medium score 4, 2 low score 1–2). The progress tally's "16 P2" appears to over-count by one (15 score-4 rows exist); this document uses the verifiable row count.

---

## Quick Guide

### 🚨 BLOCKERS — Team Must Decide (Cannot Proceed Without)

**A. Seven pre-implementation open questions — ✅ RESOLVED 2026-07-23 (Architecture Review Passed).** Each is captured as a spine AD (or amendment); see `ARCHITECTURE-SPINE.md` AD-32/33/34 + the AD-27/3/25/19/30/24 amendments:

1. **Q1 — Pre-couple non-bind PDU policy (RELAY-002, P0) — ✅ RESOLVED → AD-32.** Fail-closed, zero config knobs: ONLY bind-family handled cooperatively pre-couple; **everything else (incl. `unbind`, `enquire_link`, `submit_sm`, unknown `command_id`) → close, no response** (above-spec fail-closed, uniform); egress `generic_nack`/non-ROK `bind_resp` from the SMSC → **forwarded verbatim** (SMSC is the credential authority; AD-33's collapse is scoped to the proxy's own pre-SMSC denials). RELAY-002 rewritten (RELAY-002a/b removed; RELAY-002c asserts verbatim forwarding).
2. **Q2 — jcstress adoption (RELAY-007/024, P0) — ✅ RESOLVED → AD-24 note.** jcstress adopted, scoped to cross-thread state (`ConnectionRegistry` teardown, `AtomicReference<JwkSet>` swap, `CompletableFuture`×`ScopedValue` handoff), nightly, paired with a delay-injection event-loop-jitter soak. P0 R5 coverage claim holds.
3. **Q3 — Cipher allowlist pin (SEC-089) — ✅ RESOLVED → AD-34.** Default pinned: protocols `[TLSv1.3, TLSv1.2]`; TLS-1.2 = ECDHE-ECDSA/RSA-AES{128,256}-GCM (no CBC/static-RSA/legacy) + optional ChaCha20; `companion.tls.*` tunable; empty provider-intersect→fail-fast. SEC-089 now implementable.
4. **Q4 — Two-proxy E2E (E2E-001) — ✅ RESOLVED → AD-24 note.** Adopted, weekly/manual tier (forward+reverse real Spring Boot processes over in-JVM mock SMSC+IdP, Mode C via deploy-time contract; also validates DEP-1).
5. **Q5 — AD-30 shared-constant assertion (RELAY-026) — ✅ RESOLVED → AD-30 amendment.** ArchUnit/Gradle static assertion (codec-max≡formula≡config one constant) + startup `ByteBufAllocatorMetric` self-check (live `MaxDirectMemorySize` ≥ budget, fail-fast).
6. **Q6 — CI-gate positive controls (SEC-099/CODEC-041/OBS-043) — ✅ RESOLVED.** Per-gate known-bad fixture + assert-it-fires (CVE/JDK-pin/inward-only/forbidden-dep/docs-config). Recorded in the CI/test-design tier.
7. **Q7 — bind_resp status → OIDC-outcome mapping (R23) — ✅ RESOLVED → AD-33.** Binary wire collapse: ALLOW→`ESME_ROK`; all denials→one generic bind-failure code (exact code still owning-story); rich outcome logs/counters only. SEC-078..080 unblocked.

**B. Five P0 gate-blocker risks (score 9) — must be mitigated, not merely tested:**

1. **R1** Fail-closed branch miss → accept-on-indeterminate (~15 DENY branches across ROPC token-endpoint + RFC 7662 introspection + JWT defense-in-depth).
2. **R2** ROPC/IdP interop failure → total bind outage (availability).
3. **R5** Concurrency race → REL-1 transit-integrity violation (pre-couple window, registry teardown, half-close/unbind/RST ordering, partial-A-1 affinity).
4. **R7** Trust-anchoring defect (cacerts default on ingress Mode C + egress AD-26; REQUIRE-vs-WANT; cert edge-cases).
5. **R8** Credential-free-at-rest / zeroization violated (escape via String/log/metric/JFR/heap-dump).

**Status:** ✅ Q1–Q7 RESOLVED (2026-07-23) — captured as AD-32/33/34 + amendments in the spine. The P0 mitigation plans (below) remain to be built into production code (not patched by tests). Epic 2 must falsify AD-32 against the real/conformance SMSC (uniform bare-close; carrier bind-timeout AND `enquire_link` keepalive interval > PERF-3 bind latency; carrier does not pipeline pre-`bind_resp`).

---

### ⚠️ HIGH PRIORITY — Team Should Validate (We Provide Recommendation, You Approve)

The 13 P1 risks (score 6) — recommendations in the Risk Assessment table; approve or adjust during implementation:

- **R3** parser/framing DoS + per-channel exception containment · **R6** PERF overclaim/methodology bar · **R11** graceful-shutdown in-flight drop / partial-verdict race · **R12** two-shape parity drift · **R14** codec diverges from SMPP 3.4 (weak oracle) · **R16** CVE/dependency drift, no automated gate · **R17** startup fail-fast refuse-branch coverage · **R18** Mode A two-proxy ACL-isolation control · **R25** load-gen coordinated omission / open-vs-closed model · **R26** JMH harness pitfalls · **R27** direct-memory budget exhaustion · **R28** event-loop blocking (convention-enforced, not mechanical) · **R33** conformance suite is sole oracle → golden-vector 3rd oracle needed.

**What we need from the team:** Review the per-risk recommendations and approve (or suggest changes) as each owning epic begins.

---

### 📋 INFO ONLY — Solutions Provided (Review, No Decisions Needed)

1. **Test strategy:** Unit + structural fuzz + integration + conformance + perf/E2E, risk-prioritized P0→P3. Rationale: the `codec` seam gives textbook isolation; the security/integrity crown jewels need exhaustive parameterized matrices.
2. **Tooling:** JUnit 5 (Jupiter) + AssertJ (unit/integration); JQF + jqwik (structural fuzz); JMH (codec microbenchmarks); a from-scratch open-model load harness (no OSS SMPP load tool exists); in-JVM mock SMSC (on `codec`) + jSMPP 3.0.2 (interop-only oracle); Spring Boot test slices + `@ConfigurationProperties` fail-fast matrix; JDK `SSLEngine`/Netty `SslContext` TLS vectors; BlockHound (event-loop blocking); ArchUnit (structure). *(Full recipe in `test-design-qa.md`.)*
3. **Tiered CI/CD:** PR (unit + bounded fuzz + fast integration + CI gates) / Nightly (perf, race-soak, real-Keycloak, jcstress) / Weekly + non-CI (arch matrix, two-proxy E2E, A-1 real-carrier ops).
4. **Coverage:** 251 scenarios prioritized P0–P3; 64 P0 (security/integrity-critical), P0+P1 = 177 form the mandatory coverage core.
5. **Quality gates:** P0 100%, P1 ≥ 95%, fuzz clean on both decoders, PERF evidenced with full disclosure, CVE scan clean, two-shape parity green. *(Full criteria in `test-design-qa.md`.)*

**What we need from the team:** Just review and acknowledge.

---

## For Architects and Devs — Open Topics

### Risk Assessment

**Total risks identified:** 35 (18 high-priority score ≥ 6, 15 medium score 3–5, 2 low score 1–2).

Priority mapping (`risk_threshold: p1`): score 9 → P0 (gate-blocker) · 6–8 → P1 (must cover) · 4–5 → P2 (monitor) · 1–3 → P3 (document). The 18 P0+P1 risks are the mandatory coverage core.

#### High-Priority Risks (Score ≥ 6) — Immediate Attention

| Risk ID    | Category | Description                                                                                                                       | P | I | Score   | Mitigation (production-code / seam)                                                                                                        | Owner     | Timeline |
| ---------- | -------- | --------------------------------------------------------------------------------------------------------------------------------- | - | - | ------- | ------------------------------------------------------------------------------------------------------------------------------------------ | --------- | -------- |
| **R1**     | SEC      | Fail-closed branch miss → accept-on-indeterminate (~15 DENY branches: ROPC token-endpoint non-401 + RFC 7662 introspection + JWT defense-in-depth: alg=none, alg-confusion, kid-miss, exp/nbf skew). DECOMPOSED per-branch. | 3 | 3 | **9**   | Closed `sealed Verdict` enumeration via `BindCredentialVerifier` port; parameterize every AD-11 branch; injectable `Clock` for time-based branches. | Author    | Epic 3   |
| **R2**     | SEC      | ROPC/IdP interop failure → total bind outage (availability).                                                                      | 3 | 3 | **9**   | Story 3.1 ROPC viability probe; all 4 AD-12 paths; fallback decision tree; nightly real-Keycloak integration.                               | Author    | Epic 3   |
| **R5**     | DATA     | Concurrency race → REL-1 transit-integrity violation (pre-couple window, registry teardown race, half-close/unbind/RST ordering, partial-A-1 affinity). DECOMPOSED per-seam. | 3 | 3 | **9**   | Keep AD-25 single-flipper mechanical; jcstress invariants for flag + registry; race-oriented soak (delay-injection/jitter).                | Author    | Epic 2/3 |
| **R7**     | SEC      | Trust-anchoring defect: cacerts is the JDK **default** for a missing peer trust store (ingress Mode C + egress AD-26); REQUIRE-vs-WANT; cert edge-cases (EKU/expired/self-signed/unknown-ext). | 3 | 3 | **9**   | Enforce "never cacerts" via startup fail-fast (mechanical, not convention); pin `clientAuth(REQUIRE)`; TLS vectors incl. already-expired cert. | Author    | Epic 3   |
| **R8**     | SEC      | Credential-free-at-rest / zeroization violated (password + token discard; escape via String/log/metric/JFR/heap-dump).            | 3 | 3 | **9**   | `char[]`/`byte[]` never `String`; zeroize on every path incl. exception; deterministic zeroization assertion; JFR/dump hygiene doc.         | Author    | Epic 3   |
| **R3**     | SEC      | Parser/framing DoS or crash on malformed input (most-exposed surface) + per-channel exception containment (relay-wide DoS if it escapes the event loop). | 2 | 3 | 6       | Fuzz both decoders (JQF/jqwik); AD-30 length guards before allocation; exception containment to `exceptionCaught`.                         | Author    | Epic 1/2 |
| **R6**     | PERF     | PERF targets overclaimed / methodology bar (self-measured, first-of-kind, 4 regimes).                                             | 2 | 3 | 6       | Honest harness methodology + no-crypto baseline; publish saturation knee + failure modes (R25/R26 support).                               | Author    | Epic 6   |
| **R11**    | REL      | Graceful shutdown drops in-flight / partial-verdict race (AD-22 7-step ordering under concurrency).                               | 2 | 3 | 6       | Implement AD-22 ordering exactly; SIGTERM ordering test; lift release-shape checks into Epic 5.                                            | Author    | Epic 4/5 |
| **R12**    | OPS      | Two-shape parity drift (jlink crypto-module omission, `--enable-preview` threading, ZGC + MaxDirectMemorySize both shapes).       | 2 | 3 | 6       | Parity smoke both shapes (JAR + Docker) in Epic 5; Docker-secrets E2E Docker-only.                                                         | Author    | Epic 5   |
| **R14**    | COMP     | Codec diverges from SMPP 3.4 (weak oracle: in-JVM mock shares the production codec, jSMPP partial).                               | 2 | 3 | 6       | Add spec-derived golden-vector corpus as a 3rd oracle independent of both (R33); jSMPP interop on both legs.                              | Author    | Epic 1/2 |
| **R16**    | SEC      | CVE / dependency drift — Netty/JDK/Nimbus, **no automated gate**.                                                                 | 2 | 3 | 6       | OWASP dependency-check/Dependabot in CI with a positive control (Q6); pin Nimbus ≥ 10.0.2 (CVE-2025-53864); pin JDK 25 build.              | Author    | Epic 1/CI|
| **R17**    | SEC      | Startup fail-fast refuse-branch coverage (AD-17/13/12/18 matrix: trust-store absent/empty/wrong-format/wrong-password/zero-entries, non-https provider, missing secret file, forward+B rejected, Mode-B-no-ack, bad ports). | 2 | 3 | 6       | Exhaustive `@ConfigurationProperties` role×mode fail-fast unit matrix.                                                                     | Author    | Epic 1   |
| **R18**    | SEC      | Mode A two-proxy ACL-isolation control unverified (forward proxy cannot authenticate reverse proxy in one-way TLS).               | 2 | 3 | 6       | CI-testable portion = loud startup warning + opt-in ack + runbook + config/startup scan (the ACL itself is a deploy-time invariant).      | Author    | Epic 3/5 |
| **R25**    | PERF     | Load-gen coordinated omission / open-vs-closed model (from-scratch, no reference) invalidates PERF-1 percentiles.                 | 2 | 3 | 6       | Open-model load harness; load-gen on separate cores; no coordinated omission (harness is itself an Epic 6 deliverable).                   | Author    | Epic 6   |
| **R26**    | PERF     | JMH codec-bench harness pitfalls (DCE, warmup/fork, Blackhole, GC interference).                                                  | 2 | 3 | 6       | Canonical JMH discipline (Blackhole, fork ≥ 2, warmup); publish the benchmark source.                                                      | Author    | Epic 1/6 |
| **R27**    | PERF     | Direct-memory budget exhaustion under load/error/burst (AD-30 cliff + correlated slow-consumer burst + write-failure/error-path ByteBuf leak). | 2 | 3 | 6       | Shared `PooledByteBufAllocator` + `ByteBufAllocatorMetric` assertion; PARANOID leak detection on error paths; AD-30 shared-constant (Q5). | Author    | Epic 2/6 |
| **R28**    | PERF     | Event-loop blocking by a stray blocking call — convention-enforced (AD-4), not mechanical (JFR catches VT pinning only).          | 2 | 3 | 6       | BlockHound (or an event-loop-latency watchdog) on event-loop threads with a positive control.                                              | Author    | Epic 2/6 |
| **R33**    | TECH     | Conformance suite is the sole correctness oracle and shares the author's mental model.                                            | 2 | 3 | 6       | Author a spec-derived golden-vector corpus (authoritative SMPP 3.4 byte sequences + expected outcomes) as a 3rd, independent oracle.       | Author    | Epic 1/2 |

#### Medium-Priority Risks (Score 3–5) — Monitor

| Risk ID | Category | Description                                                                                           | P | I | Score | Mitigation                                                                  | Owner  |
| ------- | -------- | ----------------------------------------------------------------------------------------------------- | - | - | ----- | --------------------------------------------------------------------------- | ------ |
| R9      | TECH     | STS preview-API drift (+ STS-fork retaining BindCredential beyond scope; build-pin enforcement gap). | 2 | 2 | 4     | Pin exact JDK 25 build; confine STS to control plane; JFR pin check.        | Author |
| R10     | SEC      | /metrics: cardinality DoS + PRIV-1 body leak + handler hardening + loopback-only binding.            | 2 | 2 | 4     | Cardinality bounded to routing table; content-suppression tests; AD-19 handler. | Author |
| R20     | SEC      | JWKS kid-miss refresh storm / thundering-herd (no single-flight dedup) → IdP amplification / self-DoS.| 2 | 2 | 4     | Single-flight kid-miss refresh dedup.                                       | Author |
| R21     | SEC      | Adjudication VT pool + SslHandler delegated-task pool exhaustion → bind-plane/handshake DoS.         | 2 | 2 | 4     | Bounded pools with fail-closed/fail-handshake on saturation (AD-28).        | Author |
| R22     | SEC      | Secret file-path-injection AD-18 (reject env-var VALUE; fail-fast on missing/unreadable).            | 2 | 2 | 4     | Startup scan rejects secret values in env vars; fail-fast on unreadable file. | Author |
| R23     | SEC      | bind_resp status-code → OIDC-outcome mapping oracle (system_id enumeration / IdP availability).      | 2 | 2 | 4     | Pin the exact mapping (Q7); avoid side channels.                            | Author |
| R29     | PERF     | Bind-rate ceiling hidden by mock IdP (no verdict cache + Keycloak ~15 logins/s/vCPU).               | 2 | 2 | 4     | Nightly real-Keycloak bind-rate probe.                                      | Author |
| R30     | PERF     | GC/backpressure perf cliffs (ZGC pause under load, backpressure-knee thrash).                       | 2 | 2 | 4     | ZGC generational config; backpressure-knee reported in PERF harness.        | Author |
| R31     | TECH     | CompletableFuture × ScopedValue context-propagation gap on verify() return path.                    | 2 | 2 | 4     | Explicit context-propagation test on the return path.                       | Author |
| R32     | OPS      | Egress-establishment failure post-ALLOW — underspecified error path (legacy hangs / pair leak).     | 2 | 2 | 4     | Specify + test the post-ALLOW egress-failure path (teardown, no pair leak). | Author |
| R34     | OPS      | Docker SIGTERM/PID-1 propagation (packaged shutdown never reaches the JVM).                         | 2 | 2 | 4     | Docker entrypoint forwards SIGTERM as PID-1; test in Docker shape.          | Author |
| R35     | OPS      | DEP-1 Docker-secrets / distroless non-root read + env-var-secret rejection.                         | 2 | 2 | 4     | Distroless non-root + file-secret contract E2E in Docker only.              | Author |
| R36     | TECH     | COMP-3/4 build + runtime gates (Epoll-vs-NIO dev/prod diff, IPv4-only, x86/ARM CI matrix).          | 2 | 2 | 4     | x86+ARM packaged smoke; IPv4-only assertion at bind + outbound.             | Author |
| R37     | OPS      | OPS-1 docs drift from `companion.*` config surface.                                                 | 2 | 2 | 4     | Docs-config consistency scan in CI (OBS-029).                               | Author |
| R38     | OPS      | A-1 non-CI ops plan has no pass/fail or DLR-affinity criteria (cannot actually falsify A-1).        | 2 | 2 | 4     | Define explicit pass/fail + DLR-affinity criteria in the A-1 checklist.     | Author |

#### Low-Priority Risks (Score 1–2) — Document

| Risk ID | Category | Description                                                           | P | I | Score | Action    |
| ------- | -------- | --------------------------------------------------------------------- | - | - | ----- | --------- |
| R15     | MAINT    | Native-image-compat claim unfalsifiable in v1 (no native build; AD-23). | 1 | 1 | 1     | Document (stretch only) |
| R24     | SEC      | TLS 1.3 0-RTT/early-data replay not asserted disabled.               | 1 | 2 | 2     | Assert disabled (TLS vector) |

#### Risk Category Legend

- **TECH**: Technical/Architecture (flaws, integration, preview-API, scalability)
- **SEC**: Security (auth, trust anchoring, credential handling, data exposure)
- **PERF**: Performance (SLA violations, harness methodology, resource limits)
- **DATA**: Data Integrity (transit-integrity: drop/duplicate/corrupt)
- **REL**: Reliability (shutdown, backpressure, statelessness)
- **OPS**: Operations (deployment, packaging parity, config, operator surface)
- **COMP**: Compatibility (interop, JDK/Linux/IPv4)
- **MAINT**: Maintainability (extractability, testability, stretch claims)

---

### NFR Testability Requirements

**Purpose:** What the architecture must provide so NFR validation can be automated later. Planning guidance only — final PASS/CONCERNS/FAIL belongs in `nfr-assess` after implementation evidence exists.

| NFR Category (ids) | Threshold / Requirement (locked) | Current Design Support | Gap / Decision Needed | Planned Evidence |
| --- | --- | --- | --- | --- |
| **Security** — SEC-1..5, PRIV-1, FR-SEC-1..5, FR-AUTH-1..4 | TLS 1.2 min/1.3 pref + cipher allowlist (SEC-1); parser/splice robustness (SEC-2); provider link HTTPS+mTLS (SEC-3); mature libs only (SEC-4); CVE hygiene (SEC-5); no body persistence, TRACE-only body logging (PRIV-1) | Supported: AD-11 fail-closed, AD-13/AD-26 trust anchoring, AD-12 ROPC port, AD-19 metrics posture. | **Q3** cipher allowlist not yet pinned in config (SEC-089 blocked). Injectable-Clock seam covers JWT exp/nbf + ROPC/introspection timeouts but **NOT TLS cert-path validation** (AD-13 bans `PKIXBuilderParameters.setDate`) — testability boundary, not a gap. | JDK `SSLEngine`/Netty `SslContext` TLS vectors; fail-closed negative-path matrix; CVE scan + positive control; content-never-in-logs/metrics negative assertions. |
| **Performance** — PERF-1..4 | PERF-1 ≥10K `submit_sm`/s (stretch ~25K); PERF-2 10K idle pairs <1 GB heap/<1 vCPU; PERF-3 bind p99 ~250 ms warm/≤2 s cold/DENY 2–5 s; PERF-4 sub-ms per-PDU + codec JMH targets. | Partial: AD-1 event-loop relay, AD-21/AD-30 allocator posture. **Methodology IS the bar** (R6) — self-measured, first-of-kind. | Harness itself is an Epic 6 deliverable (R25 open-model, R26 JMH pitfalls). No reference benchmark exists. | Open-model relay percentile harness + no-crypto baseline; idle-pair resource demo; bind-latency harness; JMH codec microbench. |
| **Reliability** — REL-1..4, FR-TRANSIT-1..4 | Transit integrity — no silent drop/dup/corrupt (REL-1); backpressure not OOM (REL-2); graceful-shutdown drain (REL-3); statelessness — no `message_id`→`system_id` map (REL-4). | Supported: AD-2 splice coupling, AD-8 state ownership, AD-22 shutdown ordering, AD-9 statelessness on A-1. | Concurrency defects are statistical (R5) — need race-fuzz, not just load. **Q2** jcstress adoption pending. | Relay conformance both legs; race-soak (delay-injection); SIGTERM ordering test; REL-4 structural arch-scan (no `message_id` map). |
| **Maintainability** — MAINT-1..5 | Single codebase both roles (MAINT-1); codec structured for extraction (MAINT-2); from-scratch, no jSMPP derivation (MAINT-3); integration-test strategy (MAINT-4); native-image stretch only (MAINT-5). | Supported: AD-7 Gradle seam enforces MAINT-2 more strongly than any test rule; AD-24 toolchain. | MAINT-5 has **no test by design** (AD-23: no v1 native build). | ArchUnit inward-only codec dep test; dep allowlist; documented stretch (no scenario). |
| **Deployability** — FR-DEPLOY-1..4, DEP-1 | Two feature-equivalent shapes JAR + Docker (FR-DEPLOY-1); one codebase both roles (FR-DEPLOY-2); startup fail-fast (FR-DEPLOY-3); deploy-time cert provisioning (FR-DEPLOY-4); Docker-secrets contract (DEP-1). | Supported: AD-17 config matrix, AD-18 file-path secrets, AD-16 Spring lifecycle. | Parity drift risk (R12); Docker-secrets contract only exercisable in Docker shape (R35). | Parity smoke both shapes; Docker-secrets E2E (Docker-only); `@ConfigurationProperties` fail-fast matrix. |
| **Operability / Observability** — OPS-1..2, OBS-1..3, FR-OBS-1..2 | Docs are the operator surface (OPS-1); re-deploy to rotate certs (OPS-2); read-only loopback `/metrics` (OBS-1); baseline JSON logging (OBS-2); no management API (OBS-3). | Supported: AD-19 metrics handler, AD-31 docs-as-surface. | Minimal observability limits post-failure diagnosis (concern #6); docs drift risk (R37). | `/metrics` cardinality+content+loopback assertions; log-contract test; no-mgmt-API assertion; docs-config consistency scan. |
| **Compatibility** — COMP-1..4 | Interop with unmodified SMPP 3.4 both legs (COMP-1); JDK 25 floor (COMP-2); Linux only x86/ARM (COMP-3); IPv4 only (COMP-4). | Supported: AD-24 conformance + jSMPP interop. | Epoll-vs-NIO dev/prod diff; weak oracle landscape (R14/R33). | Conformance both legs + jSMPP interop; JFR JDK-pin check; x86/ARM packaged smoke; IPv4-only assertion. |

**Unknown thresholds:** **None.** Every in-scope NFR is locked or consciously deferred to config (exact cipher list, JWKS TTL/refresh/ROPC timeouts, histogram buckets, `application.yml` keys). Deferred-to-config items are not gaps. **No compliance category** (not regulated).

**Assessment boundary:** This step *plans* NFR validation (thresholds + evidence + tools). Final PASS/CONCERNS/FAIL is deferred to `nfr-assess` after implementation evidence exists.

---

### Testability Concerns and Architectural Gaps

**🚨 ACTIONABLE CONCERNS — Architecture Team Must Address**

#### 1. Blockers to Fast Feedback (What We Need From Architecture)

| Concern | Impact on Testing | What Architecture Must Provide | Owner | Timeline |
| --- | --- | --- | --- | --- |
| **A-1 unfalsifiable in CI** (controllability) | The load-bearing premise — carrier allows multiple concurrent binds per `system_id` + DLR affinity — can only be checked against a real/conformance SMSC. The in-JVM mock *emulates* A-1 (assumes the property it should validate); if A-1 is false the stateless design is invalid and CI cannot catch it. | Model affinity in the in-JVM mock + jSMPP server-side mock; ship a documented non-CI A-1 checklist (AD-31) **with explicit pass/fail + DLR-affinity criteria** (R38); smoke early in Epic 2. | Author/Architect | Epic 2 + non-CI ops |
| **No injectable clock for time-based paths** (controllability) | `exp`/`nbf` adjudication, JWKS refresh-ahead, ROPC/bind timeouts (PERF-3 fail-closed 2–5 s), kid-miss background refresh are all time-sensitive; sleeping in tests is non-deterministic. | `BindCredentialVerifier` + JWKS cache + adjudication timers MUST accept an injected `Clock`/scheduler seam. **Boundary:** this does NOT cover TLS cert-path validation (AD-13 bans `PKIXBuilderParameters.setDate`). | Author/Architect | Epic 3 |
| **Fail-closed completeness is an exhaustive enumeration, not a happy path** (observability-of-correctness) | AD-11 carries ~15 indeterminate branches + DENY-wins-on-disagreement + RFC 7662 enumeration + Mode C handshake-fail. A single missed branch = accept-on-indeterminate = credential bypass (R1). | Keep `sealed Verdict` a closed enumeration; decompose AD-11 into per-branch parameterized paths — a single catch-all is un-trackable. | Author/Architect | Epic 3 |
| **Concurrency correctness is probabilistic, not deterministic** (reliability) | AD-25 single-flipper, AD-2/AD-30 `AUTO_READ` backpressure, `ConnectionRegistry` teardown, `AtomicReference<JwkSet>` swap, STS fan-out join — races surface as REL-1 drop/dup/corrupt, which are statistical. | Make the flag + registry **jcstress-instrumentable**; adopt jcstress as a build target (**Q2**); add a race-oriented soak (delay-injection/event-loop-jitter) distinct from the throughput soak. | Author/Architect | Epic 2 (Q2 decision) |
| **Performance targets are self-measured with no reference** (methodology = the bar) | PERF-1/2/3/4 are first-of-kind; SM-3 lives or dies on harness methodology. | Treat the harness as a deliverable (Epic 6) with explicit methodology gates: HW/JDK/reboot/sysctl disclosure, p50/p90/p99/p99.9 tables, open-model load, load-gen on separate cores, saturation knee + failure modes, no-crypto baseline. | Author | Epic 6 |
| **Minimal observability limits post-failure diagnosis** (observability) | No management API, no dashboard, loopback-only `/metrics`, TRACE-only body logging (off by default). A prod-only failure has thin tooling. PRIV-1 must be asserted by **absence** (hard to test). | Assert the observability surface is sufficient (right counters exist, cardinality bounded) and make PRIV-1 absence-assertions explicit (content never in logs/metrics at default level). | Author | Epic 4 |
| **Two packaging shapes must stay feature-equivalent** (deployability/parity) | JAR + distroless Docker (jlink) doubles some integration surface; the Docker-secrets contract (DEP-1) is only exercisable in the Docker shape. | Parity smoke in both shapes; Docker-secrets E2E in Docker only; **lift release-shape checks into Epic 5 acceptance** (SIGTERM/PID-1, secrets contract, loopback binding). | Author | Epic 5 |

#### 2. Architectural Improvements Needed (What Should Be Changed)

1. **Oracle independence (deepest gap — R14/R33).** The in-JVM mock SMSC is built ON the production codec (AD-24) → shares its parsing bugs → cannot catch codec defects; jSMPP 3.0.2 is the only independent oracle and is partial.
   - **Required change:** author a spec-derived golden-vector corpus (authoritative SMPP 3.4 byte sequences + expected decode/forward outcomes) as a 3rd oracle independent of both.
   - **Impact if not fixed:** a codec defect shared by mock + production is invisible; REL-1/COMP-1 coverage is falsely reassuring.
   - **Owner:** Author · **Timeline:** Epic 1/2.

2. **AD-4 (no blocking on the event loop) is convention-enforced, not mechanically asserted (R28).** JFR `jdk.VirtualThreadPinned` catches VT pinning only — it does nothing for a platform-thread Netty event loop stalled by a stray blocking call.
   - **Required change:** BlockHound (or an event-loop-latency watchdog) on the event-loop threads, with a positive control.
   - **Impact if not fixed:** a blocking call on the relay event loop silently destroys PERF-1 sub-ms latency with no test signal.
   - **Owner:** Author · **Timeline:** Epic 2/6.

3. **AD-30 codec-max ↔ `MaxDirectMemorySize` drift is silent at runtime (Q5/RELAY-026).** A conservative drift in the shared constant passes a soak but wastes/breaks the memory budget.
   - **Required change:** ArchUnit/Gradle static assertion that codec-max (65536) and the `MaxDirectMemorySize` formula input reference ONE named constant.
   - **Impact if not fixed:** the memory budget and the codec cap drift apart without failing any runtime test.
   - **Owner:** Author/Architect · **Timeline:** Epic 1 exit.

4. **CI gates can pass while doing nothing (R16/Q6).** A CVE scan / JDK-pin / dep-allowlist that is misconfigured silently passes.
   - **Required change:** inject a known-bad control for each gate (known-vulnerable Netty coordinate / off-pin JDK / forbidden `spring-boot-starter-web` dep) and assert the gate *fires*.
   - **Impact if not fixed:** a regression that disables a gate is invisible until a real CVE/JDK slip reaches production.
   - **Owner:** Author · **Timeline:** Epic 1/CI.

---

### Testability Assessment Summary

**📊 CURRENT STATE — FYI**

#### What Works Well

- **Codec seam = textbook isolation.** `codec` is PURE (zero upward deps) → unit + fuzz with no proxy/TLS/OIDC deps. The Gradle boundary (AD-7) enforces MAINT-2 more strongly than any test rule.
- **`BindCredentialVerifier` port** (`CompletableFuture<Verdict>`) + `sealed Verdict` + `BindCredential` record → adjudication is unit-testable with a fake verifier, decoupled from Nimbus/ROPC/IdP.
- **`SpliceObserver` interface** + pinned triggers → metrics/observability testable via a capturing observer without a live relay; the codec never emits metrics (AD-27).
- **Fail-closed is a closed enumeration** → cleanly parameterizable.
- **Two independent SMSC stand-ins** (in-JVM mock on `codec` + jSMPP 3.0.2) → cross-validation of conformance (with the golden-vector 3rd oracle closing R14/R33).
- **`@ConfigurationProperties` + fail-fast role×mode matrix** → config validation is a finite, exhaustively unit-testable table (R17).
- **Named `MaxDirectMemorySize` formula + shared `PooledByteBufAllocator` + `ByteBufAllocatorMetric`** → memory budget is computable/assertable (with the Q5 static assertion).

#### Accepted Trade-offs (No Action Required)

- **Injectable Clock does not cover TLS cert-path validation.** AD-13 bans `PKIXBuilderParameters.setDate`; the expired-cert vector instead uses a genuinely already-expired short-lived cert (1970–1971) against the real clock. Recorded as a testability boundary, not a defect.
- **R15 native-image claim is unfalsifiable in v1.** AD-23 ships no native build by design; the stretch is documented only (no scenario).
- **Heap/JFR inspection for zeroization is non-deterministic.** SEC-048/049 are best-effort fragility guards + a hygiene doc; the deterministic zeroization evidence is the same-reference `char[]` all-`\0` assertion (SEC-046).

This is technical debt that should be revisited if a cold-start-sensitive deployment shape emerges (native image) or if PKIX date-injection becomes a hard requirement.

---

### Risk Mitigation Plans (P0 Gate-Blockers, Score 9)

**Purpose:** Detailed mitigation strategies for the 5 P0 risks. These MUST be addressed (in production code / seams, not patched by tests) before release. P1 (score-6) mitigations are summarized in the Risk Assessment table above and detailed as scenarios in `test-design-qa.md`.

#### R1: Fail-closed branch miss → accept-on-indeterminate (Score: 9) — CRITICAL

**Mitigation Strategy:**

1. Make fail-closed a closed enumeration: every auth-adjacent branch returns one of `Allow | DenyInvalid | DenyIndeterminate` via the `BindCredentialVerifier` port + `sealed Verdict` (AD-12) — no void return, no exception-based escape hatch that could default to accept.
2. Decompose AD-11's ~15 DENY branches into individually-parameterized code paths: ROPC token-endpoint non-401 matrix; RFC 7662 introspection matrix (5xx/timeout/network/3xx/4xx/non-JSON/missing-`active`/`active:false`); JWT defense-in-depth (alg=none, alg-confusion, kid-miss, exp/nbf skew, 200-vs-local-verify disagreement); Mode C handshake-fail; ingress routing-miss. No catch-all branch.
3. Provide an injectable `Clock`/scheduler seam so exp/nbf and PERF-3 timeout branches are exercised deterministically.

**Owner:** Author · **Timeline:** Epic 3 · **Status:** Planned
**Verification:** parameterized negative-path matrix passes 100%; a mutation that flips any single DENY branch to accept is caught by the matrix (no branch reaches accept-on-indeterminate).

#### R2: ROPC/IdP interop failure → total bind outage (Score: 9) — CRITICAL

**Mitigation Strategy:**

1. Execute the Story 3.1 ROPC viability probe at Epic 3 entry against a real Keycloak 26.x: confirm Direct Access Grants, JWT-vs-opaque response shape, and mTLS-vs-`client_secret` provider auth.
2. Implement and cover all 4 AD-12 ROPC paths: JWT verdict + local JWKS defense-in-depth; opaque → RFC 7662 introspection; mTLS confidential client (RFC 8705); `client_secret` confidential client.
3. Author a fallback-decision-tree (what to do if ROPC is removed/disabled by the IdP) and dock it as an accepted-risk register entry.
4. Add a nightly real-Keycloak integration (not the mock IdP) so Keycloak version drift surfaces continuously.

**Owner:** Author · **Timeline:** Epic 3 · **Status:** Planned
**Verification:** all 4 paths green against real Keycloak; fallback tree documented; bind outage under IdP error → DENY (fail-closed), never a hang.

#### R5: Concurrency race → REL-1 transit-integrity violation (Score: 9) — CRITICAL

**Mitigation Strategy:**

1. Keep the AD-25 single-flipper invariant mechanical: exactly one unit (`RelayHandler`) mutates the splice flag on receipt of `bind_*_resp` with `ESME_ROK`; the control plane only returns a `Verdict` — it never mutates a data-plane flag.
2. Make the concurrency seams jcstress-instrumentable — the flipper flag, `ConnectionRegistry` `channelInactive` teardown, `AtomicReference<JwkSet>` swap — and adopt jcstress as a build target (Q2).
3. Add a race-oriented soak (delay-injection / event-loop-jitter / randomized `channelInvalid`) distinct from the Epic 6 throughput soak.
4. Decompose coverage per seam: pre-couple non-bind window, registry teardown race, half-close/unbind/RST ordering, partial-A-1 affinity.

**Owner:** Author · **Timeline:** Epic 2/3 · **Status:** Planned (contingent on Q2)
**Verification:** jcstress invariants hold; race-soak shows zero REL-1 drop/duplicate/corrupt over the soak window; PARANOID leak detection clean.

#### R7: Trust-anchoring defect — cacerts default / REQUIRE-vs-WANT / cert edge-cases (Score: 9) — CRITICAL

**Mitigation Strategy:**

1. Enforce "trust store never `cacerts` for ANY peer path" (AD-13 ingress Mode C + AD-26 egress) **mechanically** via startup fail-fast: refuse if the trust store is absent, empty, wrong-format, wrong-password, or contains zero `trustedCertEntry` entries. The secure state must not hold only via a remembered override line (the JDK default IS `cacerts`).
2. Pin mTLS `clientAuth(REQUIRE)` never `WANT` (AD-11/AD-13).
3. Ship JDK `SSLEngine`/Netty `SslContext` TLS vectors for modes A/B/C covering cert edge-cases (wrong-EKU, expired, self-signed, unknown-extension) and the explicit cacerts-fallback negative case.
4. For the expired-cert vector, craft a genuinely already-expired short-lived cert (validity 1970–1971) and assert PKIX rejection against the real clock — because the injectable-Clock seam does not cover TLS cert-path validation (AD-13).

**Owner:** Author · **Timeline:** Epic 3 · **Status:** Planned
**Verification:** TLS vector suite green; startup refuses on every trust-store defect; no code path reaches `cacerts` for peer validation.

#### R8: Credential-free-at-rest / zeroization violated (Score: 9) — CRITICAL

**Mitigation Strategy:**

1. Hold password + access token in `char[]`/`byte[]`, never `String`; zeroize on adjudication completion, connection teardown, JVM shutdown, and every exception path (AD-12/AD-10).
2. Add the deterministic zeroization assertion (same-reference `char[]` all-`\0` immediately after the zeroize call) — this is the load-bearing evidence (SEC-046).
3. Assert PRIV-1 by absence: message content never appears in logs or metrics at the default level; scan the `Verdict`/`CompletableFuture`/`ScopedValue` capture channels and the OIDC `client_secret` (non-mTLS confidential path) for escape.
4. Dock JFR/heap-dump hygiene as a documented ops control (JFR OldObjectSample, heap/core dump); the non-deterministic heap/JFR inspection (SEC-048/049) is a best-effort fragility guard, not primary evidence.

**Owner:** Author · **Timeline:** Epic 3 · **Status:** Planned
**Verification:** deterministic zeroization assertion passes on all paths incl. exception; content-never-in-logs/metrics negative assertions pass; no `String`-typed credential in the security package.

---

### Assumptions and Dependencies

#### Assumptions (architectural)

1. **A-1 (load-bearing):** the carrier allows multiple concurrent binds per `system_id` **and** preserves `deliver_sm` (DLR) session affinity. This is the premise of the stateless design (AD-9, REL-4). It is **not falsifiable in CI** — only via the non-CI real-carrier ops step (R4/R38).
2. **A-2:** OIDC provider + PKI/CA HA and security are the operator's responsibility; a provider/CA compromise can mint verdicts (accepted-risk register).
3. **A-3:** trusted-network isolation on the legacy↔proxy leg is the deployer's responsibility; `system_id` spoofing on the trusted network is an accepted risk (sole control = network isolation).
4. **A-4:** accurate clocks (NTP) are a precondition for JWT `exp`/`nbf` adjudication.
5. **Keycloak 26.x** is the reference IdP (not part of this project); ROPC (Direct Access Grants) is the single most fragile external dependency — non-default since Keycloak 26.2.
6. **JDK 25 build is pinned;** `StructuredTaskScope`/`ScopedValue` (JEP 505) run under `--enable-preview`, confined to the control plane.
7. **No compliance category** is in scope (the product is not regulated).

#### Dependencies

1. **JDK 25 pinned build + `--enable-preview`** — required throughout; a CI JDK-pin gate with positive control (Q6/DEPLOY-014).
2. **Keycloak 26.x reachable** for nightly real-IdP integration (R2/R29 evidence).
3. **Nimbus JOSE+JWT ≥ 10.0.2** (CVE-2025-53864); **Netty 4.2.x**; **jSMPP 3.0.2** (test/interop only, never the production codec).
4. ~~Q1–Q7 resolved~~ **✅ DONE 2026-07-23** (AD-32/33/34 + amendments) — carried into the owning epics' stories.

#### Risks to the Plan

- ~~**Risk:** Q2 (jcstress) is not adopted.~~ ✅ RESOLVED (AD-24 note) — jcstress adopted (cross-thread state, nightly) + delay-injection soak; P0 R5 coverage holds.
- ~~**Risk:** Q3 (cipher allowlist) is not pinned before Epic 1 exit.~~ ✅ RESOLVED (AD-34) — default pinned; SEC-089 implementable.
- ~~**Risk:** Q1 (pre-couple policy) is not pinned.~~ ✅ RESOLVED (AD-32) — RELAY-002 rewritten to a protocol-violation-close test + RELAY-002a/b/c siblings.
- **Risk:** A-1 non-CI ops step is not executed before release.
  - **Impact:** R4/R38 cannot be falsified; the stateless design rests on an unverified carrier assumption.
  - **Contingency:** explicit risk acknowledgment + deferred A-1 execution with a named ops owner.

---

**End of Architecture Document**

**Next Steps for Architecture Team:**

1. ~~Review the Quick Guide and prioritize Q1–Q7~~ ✅ Q1–Q7 RESOLVED (AD-32/33/34). Review the 5 P0 mitigation plans and build them into code.
2. Assign owners and timelines (all "Author" here — solo project; confirm epic placement).
3. Validate the architectural assumptions (A-1..A-4) and dependencies.
4. Provide feedback on the testability gaps (oracle independence, event-loop blocking assertion, AD-30 shared constant, CI-gate positive controls).

**Next Steps for QA:**

1. ✅ Q1–Q7 RESOLVED — scenarios are unblocked; proceed to ATDD scaffolds for the P0/P1 set.
2. Refer to the companion `test-design-qa.md` for the full 251-scenario recipe and execution tiers.
3. Begin test-infrastructure setup: in-JVM mock SMSC, golden-vector corpus, TLS vector certs, injected-`Clock` fakes.
