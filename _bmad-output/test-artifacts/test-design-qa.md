---
workflowStatus: 'complete'
totalSteps: 5
stepsCompleted: ['step-01-detect-mode', 'step-02-load-context', 'step-03-risk-and-testability', 'step-04-coverage-plan', 'step-05-generate-output']
lastStep: 'step-05-generate-output'
lastSaved: '2026-07-22'
project: 'smpp-companions (SMPP 3.4 Security Proxy)'
mode: 'System-Level'
---

# Test Design for QA: Companions v1 — SMPP 3.4 Security-Transit Proxy

**Purpose:** Test execution recipe for the QA implementer. Defines what to test, how to test it (which JVM tool/level per scenario), and what QA needs from the architecture/Dev work before testing can start. This is the HOW companion to the architecture doc's WHAT/WHY.

**Date:** 2026-07-22
**Author:** Murat (Master Test Architect)
**Status:** Draft
**Project:** smpp-companions v1 (headless JVM backend, Apache-2.0, single-instance, SMPP 3.4 only)

**Toolchain (JVM — NOT Playwright/k6):** JUnit 5 (Jupiter) + AssertJ (unit/integration) · JQF + jqwik (structural fuzz) · JMH (perf microbenchmarks) · from-scratch open-model load harness (relay percentiles — no OSS SMPP load tool exists) · in-JVM mock SMSC built on the codec + jSMPP 3.0.2 (interop-only independent oracle) · Spring Boot test slices + `@ConfigurationProperties` fail-fast matrix · JDK SSLEngine / Netty SslContext TLS vectors · BlockHound (event-loop blocking) · ArchUnit (dependency/structure) · OWASP dependency-check / Dependabot + Gradle toolchain / JDK-pin (CI gates).

**Related:**
- Architecture doc (`test-design-architecture.md`) — testability concerns, architectural blockers, risk mitigation plans.
- Scenario catalog (`test-design/test-coverage-scenarios.md`) — the authoritative 251-scenario catalog (full technique/tooling/notes per scenario). This doc's P0/P1 tables summarize; the catalog is the source of truth for per-scenario detail.
- Progress / synthesis (`test-design-progress.md`) — reconciled register, NFR evidence map, coverage matrix.

---

## Executive Summary

**Scope:** System-level test design for the Companions v1 SMPP 3.4 security-transit proxy — a headless JVM backend (JDK 25 `--enable-preview`, Netty 4.2 event-loop relay, Spring Boot 4.1, Nimbus JOSE+JWT 10.9.1, generational ZGC, Linux/IPv4). Two Gradle modules: `codec` (PURE, zero upward deps) + `proxy`. The relay splices an opaque SMPP 3.4 byte stream between a legacy ESME and an SMSC, adjudicating each bind against an OIDC provider (Keycloak 26.x reference) before coupling the pair. The crown jewels under test are: (1) fail-closed bind adjudication, (2) credential-free-at-rest / zeroization, (3) stateless splice integrity (REL-1: no drop/dup/corrupt), and (4) trust anchoring (cacerts-default-is-insecure).

**Risk Summary:**

- Total Risks: **35** — **5 P0** (score 9, gate-blockers: R1 fail-closed miss, R2 ROPC outage, R5 concurrency→REL-1, R7 trust anchoring, R8 credential-free/zeroization) · **13 P1** (score 6, must-cover) · **15 P2** (score 4, monitor) · **2 P3** (score 1–2, document).
- Coverage core (risk_threshold = p1): every one of the 18 P0/P1 risks has ≥1 explicit passing scenario (see catalog §9.3).
- Critical categories: **SEC** (the fail-closed / trust-anchoring / credential-free crown jewels — 52 of 64 P0 scenarios) and **DATA/REL** (the five decomposed R5 concurrency seams — 12 of 64 P0 scenarios).

**Coverage Summary (251 scenarios — see catalog §1):**

| Priority | Count | Focus |
|----------|-------|-------|
| P0 | 64 | Fail-closed DENY matrices (ROPC + introspection + JWT), trust anchoring, credential-free/zeroization, the 5 R5 concurrency seams |
| P1 | 113 | Codec conformance + golden-vector oracle, backpressure/BlockHound, startup fail-fast, TLS vectors, perf methodology, two-shape parity, A-1 jSMPP conformance |
| P2 | 72 | JWKS refresh, pool saturation, secret hygiene, observability contract, docs drift, arch/IPv4 matrix |
| P3 | 2 | TLS 1.3 0-RTT disabled (R24) |
| **Total** | **251** | **~7–18 weeks FTE, distributed across Epics E1–E6 (solo author, test-first)** |

---

## Not in Scope

**Components or systems explicitly excluded from this test plan (PRD §13 out-of-scope, accepted):**

| Item | Reasoning | Mitigation |
| --- | --- | --- |
| **UI / web front-end** | Headless backend; no HTTP user-facing surface. The only HTTP endpoint is loopback `/metrics` (covered by OBS). | N/A — no UI exists. |
| **SMPP 5.x / non-3.4 protocol** | PRD scopes SMPP 3.4 only. Bind family is parsed; all else is opaque splice. | CODEC-026/027/028 regression-lock the parsed surface to exactly the 6-id bind family; non-bind PDUs are opaque. |
| **High Availability / clustering / replication** | v1 is single-instance; stateless-by-design to make future HA possible (REL-4/AD-8). | RELAY-025 structural scan asserts no `message_id`→`system_id` map exists (the statelessness invariant that future HA depends on). |
| **Native image / GraalVM (MAINT-5)** | AD-23: no v1 native build; stretch claim only. No `native-image` is produced. | R15 documented only (P3); MAINT-5 has no scenario by design. |
| **CRL / OCSP certificate revocation checking** | Out of PRD v1 scope; trust anchoring relies on the operator trust store + PKIX defaults (AD-13). | SEC-039 asserts PKIX default rejection of unknown-critical-extension certs; no revocation path is built, so none is tested. |
| **Rate limiting / traffic shaping** | Not a PRD v1 feature; backpressure is AUTO_READ-based (REL-2/AD-2), not a rate limiter. | RELAY-013/014/015 cover the AUTO_READ backpressure state machine and the AD-30 direct-memory budget. |
| **Compliance / regulatory category** | Not a regulated product; no compliance NFR. | NFR plan omits compliance (see Step-3 §3 of progress file). |

**Note:** Items above have been reviewed and accepted as out-of-scope. The A-1 real-carrier falsification is in-scope but **non-CI** (see Execution Strategy).

---

## Dependencies & Test Blockers

**CRITICAL:** QA cannot fully proceed without these items. Seven are pre-implementation questions the architecture must resolve (they gate specific scenarios); four are QA-infrastructure deliverables that must be built.

### Backend/Architecture Dependencies (Pre-Implementation — the 7 open questions)

**Source:** catalog §9.2; progress file Step 4. Each blocks the owning epic's exit.

1. **Q1 — Pre-couple non-bind PDU policy** — Architecture/Dev — Epic E2
   - What QA needs: AD-25/AD-3 must pin **buffer-and-forward-in-order** vs **drop** for a non-bind PDU arriving between bind and bind_resp.
   - Why it blocks: RELAY-002 (P0) currently passes for *both* policies, so it validates only determinism, not a specific REL-1 property. The whole P0 R5 pre-couple seam hinges on this.

2. **Q2 — jcstress adoption** — Architecture/Dev — Epic E2/E6
   - What QA needs: adopt jcstress as a build target (recommended), or explicitly downgrade the P0 R5 concurrency-coverage claim and strengthen the JUnit-based race-soak.
   - Why it blocks: RELAY-007 (registry invariant) and RELAY-024 (race-soak) are P0 R5 coverage. Single-shot conformance cannot surface statistical concurrency defects.

3. **Q3 — Cipher allowlist pin** — Architecture/Config — Epic E1/E3
   - What QA needs: the concrete default TLS cipher allowlist pinned in shipped config (AD-17/SEC-1).
   - Why it blocks: SEC-089 (P1, cipher enforcement) and OBS-032 (docs) are placeholders — you cannot assert a specific non-allowlisted cipher is rejected while the allowlist is undefined.

4. **Q4 — Two-proxy E2E** — Architecture/Dev — Epic E5/E6
   - What QA needs: a decision to stand up two real proxy instances (forward + reverse).
   - Why it blocks: E2E-001 (P1) is the only scenario that exercises the forward↔reverse Mode C seam; every other scenario uses a single proxy instance.

5. **Q5 — AD-30 shared-constant assertion** — Architecture/Dev — Epic E2
   - What QA needs: add the ArchUnit/Gradle static assertion that the codec max (65536) and the `MaxDirectMemorySize` formula input reference ONE named constant.
   - Why it blocks: RELAY-026 (P1) is the compile-time drift guard a runtime soak cannot provide.

6. **Q6 — CI-gate positive controls** — Architecture/Dev — CI
   - What QA needs: injected-known-bad controls for the CVE gate (SEC-099), codec allowlist gate (CODEC-041), and forbidden-runtime-dependency gate (OBS-043).
   - Why it blocks: without a positive control, a misconfigured gate silently passes every test while being disabled.

7. **Q7 — bind_resp status → OIDC-outcome mapping** — Architecture/Dev — Epic E3
   - What QA needs: the exact `bind_resp` status-code → Verdict mapping, owned by a single deferred story.
   - Why it blocks: SEC-078/079/080 (P2, no enumeration oracle on the wire) depend on the mapping oracle.

### Testability Seams QA Needs Architecture to Provide (Pre-Implementation)

1. **Injectable `Clock` / scheduler seam** — Architecture/Dev — Epic E3
   - What QA needs: `BindCredentialVerifier` + JWKS cache + adjudication timers + shutdown drain windows MUST accept an injected `Clock`/scheduler.
   - Why it blocks: deterministic time-based tests (JWT exp/nbf skew — SEC-023/024; ROPC/introspection timeouts — SEC-009/018/SEC-092; PERF-3 DENY 2–5s — PERF-032; shutdown drain — OBS-020). **Boundary:** this seam does NOT cover TLS cert-path validation (SEC-037 uses a genuinely already-expired cert instead).

2. **Golden-vector corpus (the 3rd oracle)** — QA/Dev — Epic E1
   - What QA needs: a checked-in, spec-derived SMPP 3.4 byte-sequence corpus (CODEC-030) authored independently of the production codec AND jSMPP.
   - Why it blocks: the in-JVM mock SMSC is built ON the production codec (AD-24) and shares its parsing bugs; jSMPP 3.0.2 is only a partial oracle. The corpus (CODEC-030/031/033) is the independent 3rd oracle that closes R33.

3. **Race-fuzz / delay-injection harness** — QA/Dev — Epic E6
   - What QA needs: a Netty testing `EventExecutor` with delay injection + randomized `channelInvalid`/RST/connect-failure injection (RELAY-024) — distinct from the throughput-oriented Epic-6 soak.
   - Why it blocks: single-shot conformance and the throughput run do not surface registry teardown races, half-close ordering, or write-failure propagation (the R5 statistical defects).

4. **BlockHound on event-loop threads** — QA/Dev — Epic E2
   - What QA needs: BlockHound (or an event-loop-latency watchdog) registered on the `NioEventLoopGroup` threads, with a test-specific allow-list for legitimate JDK internals (e.g. SslHandler delegated tasks).
   - Why it blocks: AD-4 (no blocking on the event loop) is convention-enforced; JFR `jdk.VirtualThreadPinned` catches VT pinning only, not a platform-thread event loop stalled by a stray blocking call. RELAY-018/019 are the mechanical backstop.

### QA Infrastructure Setup (Built Test-First Across Epics)

1. **In-JVM mock SMSC** (on `codec`) — Epic E1/E2
   - The primary CI SMSC stand-in. Programs affinity (emulates A-1), injects delay/stall (backpressure), captures forwarded PDUs. Built on the production codec (so it shares codec bugs → why the golden corpus + jSMPP are mandatory independent oracles).

2. **jSMPP 3.0.2 interop harness** (interop-only, NEVER the production codec) — Epic E1/E2
   - The 2nd independent oracle: a server-side mock (OBS-038) and a client-side ESME (drives numbered submit_sm streams). Validates the proxy's affinity behavior against a stack that shares neither the production codec's bugs nor its A-1 assumption.

3. **Spring Boot test slices + `@ConfigurationProperties` fail-fast fixtures** — Epic E1
   - The finite role×mode × required/optional/forbidden matrix (SEC-050..061, SEC-096/097). Pure config-validation unit tests — instant and exhaustive.

4. **Open-model load harness** (Epic 6 deliverable) — Epic E6
   - From-scratch (no OSS SMPP load tool exists). Open-model, load-gen pinned to separate cores, coordinated-omission check (PERF-010). The harness is itself a deliverable with methodology gates (PERF-070/071).

5. **Test environments** — Epic E1
   - Local: JDK 25 (`--enable-preview`) + Gradle toolchain pin; codec module isolated (zero proxy deps).
   - CI: x86 + ARM runners; JDK-pin gate; CVE scan; ArchUnit/dep scans; all on the pinned JDK 25 build.
   - Nightly: real Keycloak 26.x (Testcontainers); perf suite; race-soak; jcstress.
   - Non-CI ops: the A-1 real-carrier target (the only genuine A-1 falsification).

**Example unit-test pattern (JUnit 5 / Jupiter — the P0 fail-closed matrix):**

```java
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.assertThat;

@Tag("p0")
@Tag("unit")
@Tag("sec")
class RocpcDenyMatrixTest {

    private final FakeOidcHttp idp = new FakeOidcHttp();
    private final BindCredentialVerifier verifier =
        new RocpcAdapter(idp, fakeJwks(), Clock.fixed(Instant.EPOCH, ZoneOffset.UTC));

    @DisplayName("SEC-001: ROPC 401 -> DenyInvalid (definitive credential rejection)")
    @Test
    void ropc_401_is_denyInvalid() {
        idp.stubTokenEndpoint(401);
        Verdict v = verifier.verify(bindCredential("esme", "pw".toCharArray())).join();
        assertThat(v).isEqualTo(Verdict.DenyInvalid());
    }

    @DisplayName("SEC-007: ROPC 4xx != 401 -> DenyIndeterminate")
    @ParameterizedTest(name = "status {0} -> DenyIndeterminate")
    @ValueSource(ints = {400, 403, 429})
    void ropc_other4xx_is_indeterminate(int status) {
        idp.stubTokenEndpoint(status);
        Verdict v = verifier.verify(bindCredential("esme", "pw".toCharArray())).join();
        assertThat(v).isEqualTo(Verdict.DenyIndeterminate());
    }
}
```

---

## Risk Assessment

**Note:** Full risk details and mitigation plans live in the architecture doc. This section summarizes the risks that drive QA test selection. Scoring: P (likelihood of a defect, 1–3) × I (severity if it escapes, 1–3). Priority mapping: score 9 → P0 · 6–8 → P1 · 4–5 → P2 · 1–3 → P3.

### P0 Risks (Score 9 — gate-blockers; the crown jewels)

| Risk ID | Category | Description | Score | QA Test Coverage |
| --- | --- | --- | --- | --- |
| **R1** | SEC | Fail-closed branch miss → accept-on-indeterminate (~15 DENY branches across ROPC token-endpoint + RFC 7662 introspection + JWT defense-in-depth) | **9** | Exhaustive per-branch parameterized matrix: SEC-001..027, SEC-093/094 (ROPC + introspection + JWT), decomposed per-branch so no single catch-all hides a miss |
| **R2** | SEC | ROPC/IdP interop failure → total bind outage (availability); the most fragile dependency | **9** | Real Keycloak 26.x interop on all 4 AD-12 paths + viability probe + fallback decision tree: SEC-028..032 (nightly) |
| **R5** | DATA | Concurrency race → REL-1 transit-integrity violation (5 seams: pre-couple window, registry teardown race, half-close/unbind/RST ordering, partial-A-1 affinity) | **9** | 5 decomposed per-seam scenarios + race-soak: RELAY-001..011, RELAY-024 (+ jcstress RELAY-007) |
| **R7** | SEC | Trust-anchoring defect (cacerts default on ingress Mode C + egress AD-26; REQUIRE-vs-WANT; cert edge-cases) | **9** | TLS vectors both legs: SEC-033..041 + FR-AUTH-3 scan SEC-098 |
| **R8** | SEC | Credential-free-at-rest / zeroization violated (password + token escape via String/log/metric/JFR/heap-dump) | **9** | Type + sink-escape + deterministic zeroization: SEC-042..049, SEC-095 (client_secret) |

### P1 Risks (Score 6 — the must-cover core)

| Risk ID | Category | Description | Score | QA Test Coverage |
| --- | --- | --- | --- | --- |
| **R3** | SEC | Parser/framing DoS or crash + per-channel exception containment (relay-wide DoS) | 6 | CODEC-005..011/025/033 + CODEC-013..015 (fuzz + containment) |
| **R6** | PERF | PERF targets overclaimed (self-measured, first-of-kind; methodology IS the bar) | 6 | PERF-010..017 + PERF-070/071 (methodology gates: open-model, knee, disclosure) |
| **R11** | REL | Graceful shutdown drops in-flight / partial-verdict race (AD-22 ordering under concurrency) | 6 | OBS-015..021 + RELAY-022/023 (7-step ordering + drain + race) |
| **R12** | OPS | Two-shape parity drift (jlink crypto-module omission, `--enable-preview` threading, ZGC budget both shapes) | 6 | DEPLOY-001..005 + E2E-001 (parity smoke + composed two-proxy) |
| **R14** | COMP | Codec diverges from SMPP 3.4 (weak oracle: mock shares codec, jSMPP partial) | 6 | CODEC-016..033 + CODEC-039..041 (golden decode + jSMPP agreement + arch scan) |
| **R16** | SEC | CVE / dependency drift — Netty/JDK/Nimbus, no automated gate | 6 | SEC-091 + SEC-099 (CVE gate + positive control) |
| **R17** | SEC | Startup fail-fast refuse-branch coverage (role×mode matrix) | 6 | SEC-050..061 + SEC-096/097 (exhaustive `@ConfigurationProperties` matrix) |
| **R18** | SEC | Mode A two-proxy ACL-isolation control unverified | 6 | SEC-063..066 + OBS-034 (warning + ack + doc + config scan) |
| **R25** | PERF | Load-gen coordinated omission / open-vs-closed model invalidates PERF-1 percentiles | 6 | PERF-010 (open-model + injected-pause check) |
| **R26** | PERF | JMH codec-bench harness pitfalls (DCE, warmup/fork, Blackhole, GC) | 6 | PERF-001..006 (Blackhole, fork≥2, `-prof gc`) |
| **R27** | PERF | Direct-memory budget exhaustion under load/error/burst (AD-30 formula at cliff) | 6 | RELAY-013/015/017/026 + PERF-040 (PARANOID + ByteBufAllocatorMetric + shared-constant) |
| **R28** | PERF | Event-loop blocking by stray blocking call (convention-enforced, not mechanical) | 6 | RELAY-018/019 (BlockHound control + clean hot path) + PERF-060 |
| **R33** | TECH | Conformance suite is sole correctness oracle → need golden-vector 3rd oracle | 6 | CODEC-030/031/033 (corpus + jSMPP agreement + negative vectors) |

**P2/P3 risks** (15 P2 score-4 + 2 P3): R9 (STS preview drift), R10 (`/metrics` cardinality/PRIV-1), R20 (kid-miss storm), R21 (pool saturation), R22 (secret file-path), R23 (bind_resp mapping oracle), R29 (bind-rate ceiling), R30 (GC cliffs), R31 (CF×ScopedValue), R32 (egress-establishment failure), R34 (Docker SIGTERM/PID-1), R35 (Docker-secrets), R36 (arch/IPv4 matrix), R37 (docs drift), R38 (A-1 non-CI falsifiability); R15 (native-image, P3), R24 (TLS 0-RTT, P3). Each has targeted coverage in the P2/P3 catalog sections; see architecture doc for full register.

---

## NFR Test Coverage Plan

**Purpose:** Map every in-scope NFR to planned validation. This section defines what evidence QA should create or collect; it does **not** assign final PASS/CONCERNS/FAIL status — that is deferred to `nfr-assess` after implementation evidence exists. **No UNKNOWN thresholds** — every NFR is locked or consciously deferred to config.

| NFR Category | Requirement / Threshold (locked) | Planned Validation | Tool / Level | Evidence Artifact | Priority |
| --- | --- | --- | --- | --- | --- |
| **Performance** | PERF-1 ≥10K submit_sm/s (stretch ~25K), mTLS both legs, OIDC cached; p50/p90/p99/p99.9 table | Open-model sustained run + no-crypto baseline + knee/failure-modes | Open-model harness (perf) | PERF-011/013/016 percentile + knee report | P1 |
| **Performance** | PERF-2 10K idle socket pairs (<1 GB heap / <1 vCPU idle) | Idle-pair resource demo + linearity ramp | Idle-pair harness (perf) | PERF-020 heap/RSS/CPU disclosure | P1 |
| **Performance** | PERF-3 bind p99 ~250 ms warm / ≤2 s cold / DENY 2–5 s | Bind-latency harness warm + cold + timeout→DENY | Harness + injected Clock (perf/unit) | PERF-030/031/032 + SEC-092 | P1 |
| **Performance** | PERF-4 sub-ms per-PDU; codec encode 3×10⁵–1.5×10⁶ / decode 5×10⁵–1.8×10⁶ ops/s/core | JMH codec microbench + per-PDU relay latency | JMH (perf/unit) | PERF-001/002/004/017 bench report | P1 |
| **Security** | SEC-1 TLS 1.2 min / 1.3 pref + cipher allowlist | TLS-floor + allowlist + endpoint-id runtime vectors | JDK SSLEngine (integration) | SEC-087/088/089 vectors | P1 |
| **Security** | SEC-2 parser/splice robustness | Structural fuzz BOTH decoders + oversized-frame/backpressure | JQF/jqwik (fuzz + integration) | CODEC-011/025, RELAY-013..017 fuzz logs | P1 |
| **Security** | SEC-3..5 provider https / no rolled crypto / CVE hygiene | https fail-fast + no-PKIXBuilderParameters scan + CVE gate | Config slice + arch scan + CI (integration) | SEC-053, SEC-090, SEC-091/099 | P1 |
| **Security** | PRIV-1 no SMS body persistence; TRACE-only body logging | Content-never-in-logs/metrics at default + zeroization | Negative-by-absence (integration) | OBS-010/023/025, SEC-045..049 | P1 |
| **Reliability** | REL-1 transit integrity (no drop/dup/corrupt) | Relay conformance + race-soak over numbered PDU streams | Conformance + race-soak (integration/fuzz) | RELAY-001..011/024, CODEC-034..038 | P0 |
| **Reliability** | REL-2 backpressure (not OOM) | Correlated slow-consumer soak + AUTO_READ state machine | Soak + ByteBufAllocatorMetric (perf/unit) | RELAY-013/014/015, PERF-040 | P1 |
| **Reliability** | REL-3 graceful shutdown (AD-22 7-step) | SIGTERM ordering + drain + partial-verdict race | Spring lifecycle + injected Clock (integration) | OBS-015..021, RELAY-022/023, DEPLOY-006 | P1 |
| **Reliability** | REL-4 statelessness (no message_id→system_id map) | Behavioral (DLR per coupled pair) + structural arch-scan | Conformance + ArchUnit (integration) | RELAY-011/025 | P1 |
| **Compatibility** | COMP-1..4 SMPP 3.4 interop / JDK 25 / Linux / IPv4 | Conformance both legs + jSMPP interop + JDK-pin + Epoll/IPv4 gates | Conformance + CI matrix (integration) | CODEC-031, OBS-038, DEPLOY-010..014 | P1 |
| **Maintainability** | MAINT-2 codec extractable; MAINT-4 test strategy; MAINT-5 native stretch | Codec isolation arch test + dep allowlist + documented stretch | ArchUnit + Gradle (integration) | CODEC-039/040/041 | P1 |
| **Deployability** | FR-DEPLOY-1/2/4 + DEP-1 two-shape parity + Docker secrets | Parity smoke both shapes + Docker-secrets E2E | E2E (docker/packaged) | DEPLOY-001..009 | P1 |
| **Operability/Observability** | OBS-1/2/3 + OPS-1/2 `/metrics` + log contract + no-mgmt-API + cert rotation=deploy | `/metrics` cardinality/content/loopback + log JSON + immutability scan | Integration + CI docs scan | OBS-001..043 | P1/P2 |

**Missing thresholds or evidence sources:** None. The deferred-to-config items (exact cipher allowlist — Q3; JWKS TTL/refresh bounds; histogram buckets; `application.yml` keys) are consciously config-driven, not gaps. Q3 is the only one that blocks a test (SEC-089/OBS-032); it is tracked as open blocker Q3 above.

---

## Entry Criteria

**QA testing cannot begin until ALL of the following are met:**

- [ ] All requirements and assumptions agreed upon by QA, Dev, PM (PRD + ADR + architecture spine signed off).
- [ ] Test environments provisioned: JDK 25 pinned build (`--enable-preview`) on x86 + ARM CI runners; Gradle toolchain/JDK-pin gate green; real Keycloak 26.x Testcontainers image available for nightly.
- [ ] The four testability seams provided: injectable `Clock`/scheduler, golden-vector corpus resource, race-fuzz/delay-injection executor, BlockHound registration on event-loop threads.
- [ ] The in-JVM mock SMSC + jSMPP 3.0.2 interop harness + open-model load harness scaffolds present (built test-first in E1/E2/E6).
- [ ] Pre-implementation blockers resolved for the owning epic: Q1 (pre-couple policy) before E2 exit; Q2 (jcstress) before E2/E6; Q3 (cipher allowlist) before E3; Q4 (two-proxy) before E5/E6; Q5 (shared-constant) before E2; Q6 (positive controls) before CI gate stories; Q7 (bind_resp mapping) before its story.
- [ ] Feature code deployed to the test environment at the pinned JDK 25 build.
- [ ] A-1 non-CI ops plan documented (OBS-035..037) with explicit PASS/FAIL + DLR-affinity criteria, even if not yet executed.

## Exit Criteria

**The testing phase is complete when ALL of the following are met:**

- [ ] **P0 pass rate = 100%** (all 64 P0 scenarios green; no P0-risk scenario failure at release).
- [ ] **P1 pass rate ≥ 95%** (failures triaged and accepted with risk acknowledgment).
- [ ] No open P0/P1-risk-scenario failures; no open high-severity bugs.
- [ ] **Every P0/P1 risk has ≥1 passing scenario** (the 18-risk coverage core — catalog §9.3).
- [ ] JQF/jqwik fuzz clean on BOTH decoders (framer + bind parser); race-soak + jcstress (if adopted) clean over the soak window — zero REL-1 violations, zero PARANOID leaks.
- [ ] PERF-1/2/3/4 evidenced by the reproducible harness with **full disclosure** (PERF-070); no peak number published without its saturation knee + failure modes (PERF-071).
- [ ] CVE scan clean (Netty/JDK/Nimbus); Nimbus ≥ 10.0.2 (CVE-2025-53864); JDK 25 build pinned; codec dependency allowlist + forbidden-runtime-dependency gates green (with positive controls).
- [ ] Two-shape parity smoke green (runnable-JAR + distroless Docker); A-1 non-CI plan executed or explicitly deferred with risk acknowledgment.
- [ ] Coverage ≥ 80% (codec + security packages near-100% given MAINT-2 extractability).
- [ ] Test coverage agreed as sufficient by the author (solo) against the 18-risk coverage core.

---

## Test Coverage Plan

**IMPORTANT:** P0/P1/P2/P3 = **priority and risk level** (what to focus on if time-constrained), NOT execution timing. See "Execution Strategy" for when tests run (PR / Nightly / Weekly / non-CI).

### P0 (Critical)

**Criteria:** Blocks core functionality + score-9 risk + no workaround + affects the crown jewels (fail-closed, credential-free, REL-1 integrity, trust anchoring).

| Test ID | Requirement | Test Level | Risk Link | Notes |
| --- | --- | --- | --- | --- |
| **RELAY-001** | AD-25 single-flipper: splice flag flips ONLY on decoded bind_*_resp with ESME_ROK (no flip on non-ROK / peeked command_id / egress frame / Allow-without-bind_resp) | unit | R5 | Parametrized state-machine matrix; the one load-bearing runtime mechanism in isolation |
| **RELAY-002** | Pre-couple eager submit_sm held out-of-splice; if forwarded, lands strictly after couple in order `[BLOCKED-ON-Q1]` | conformance | R5 | Validates determinism until Q1 pins buffer-vs-drop policy |
| **RELAY-003** | Pre-couple non-bind PDU on the egress leg (deliver_sm pre-bind_resp) is NOT leaked to legacy | conformance | R5 | Egress leg mirror of RELAY-002; asymmetric pipelines |
| **RELAY-004** | Client retry-bind (2nd bind) while first adjudication in-flight is deterministically rejected — no 2nd pair, no registry corruption | integration | R5 | R5a; fake verifier with latched verdict |
| **RELAY-005** | Near-simultaneous channelInvalid on both legs tears down idempotently: 1 removal, safe double-zeroize, attribute cleared | integration | R5, R8 | R5b teardown race; covers relay slice of R8 |
| **RELAY-006** | Egress-connect failure AFTER registry entry created removes entry + tears down ingress — no orphaned pair | integration | R5, R32 | R5b orphan; leaked entry corrupts PERF-2 + AD-22 enumeration |
| **RELAY-007** | ConnectionRegistry concurrent lifecycle invariant (no lost/orphan/double entry) under all interleavings `[BLOCKED-ON-Q2]` | unit | R5 | jcstress; if Q2 declined, downgrade to JUnit stress |
| **RELAY-008** | Post-couple TCP half-close propagates teardown to both legs + registry; in-flight PDUs drained/dropped (no dup/corrupt) | conformance | R5 | R5c core; REL-1 headline; sequence-number integrity |
| **RELAY-009** | In-flight unbind_resp/submit_sm_resp racing peer channelInvalid completes/cancels cleanly — no partial length-prefix on the wire | conformance | R5 | R5c write/close micro-race |
| **RELAY-010** | Peer TCP RST mid-splice tears down both legs + registry AND is OBSERVED (metric/SpliceObserver) — not silent drop | conformance | R5 | R5c RST; silent drop is the worst REL-1 failure |
| **RELAY-011** | Concurrent coupled pairs under same system_id: zero DLR cross-bleed (deliver_sm lands on originating ingress only) | conformance | R5 | R5d — CI-testable core of A-1; mock EMULATES A-1 |
| **RELAY-024** | Dedicated race-soak: bind→couple→splice→teardown under delay-injection + jitter + randomized channelInvalid, REL-1 invariants over millions of iterations `[BLOCKED-ON-Q2]` | fuzz | R5 | The race-detector; distinct from throughput soak |
| **SEC-001** | ROPC token endpoint returns HTTP 401 → DenyInvalid | unit | R1 | Branch-1 of exhaustive AD-11 matrix |
| **SEC-002** | ROPC 200 with non-JWT JSON body → DenyIndeterminate | unit | R1 | |
| **SEC-003** | ROPC 200 with HTML body → DenyIndeterminate | unit | R1 | Misconfigured proxy login page |
| **SEC-004** | ROPC 200 with empty body → DenyIndeterminate | unit | R1 | |
| **SEC-005** | ROPC 200 with malformed/unparseable JWT → DenyIndeterminate (no exception escapes) | unit | R1 | |
| **SEC-006** | ROPC 3xx redirect → DenyIndeterminate (no redirect follow) | unit | R1 | |
| **SEC-007** | ROPC 4xx ≠ 401 → DenyIndeterminate | unit | R1 | Only 401 → DenyInvalid |
| **SEC-008** | ROPC 5xx → DenyIndeterminate | unit | R1 | |
| **SEC-009** | ROPC call exceeds configured deadline → DenyIndeterminate; no late-allow | unit | R1 | Injectable clock; covers JWT/ROPC timeouts |
| **SEC-010** | ROPC network error (refused/reset/EOF) → DenyIndeterminate; exception absorbed | unit | R1 | No Nimbus/IO type crosses the port |
| **SEC-011** | JWT kid absent from cached JWKS → DenyIndeterminate; background refresh only, zero foreground retry | unit | R1, R20 | AD-11 immediate-deny |
| **SEC-012** | Verdict/local-JWT disagreement (200 valid-looking JWT, local JWKS verify fails) → DenyInvalid | unit | R1 | DENY wins on defense-in-depth disagreement |
| **SEC-013** | Introspection returns active:false → DenyInvalid | unit | R1 | RFC 7662 path enumeration |
| **SEC-014** | Introspection returns non-JSON → DenyIndeterminate | unit | R1 | |
| **SEC-015** | Introspection 200 JSON omits active field → DenyIndeterminate | unit | R1 | |
| **SEC-016** | Introspection active wrong JSON type → DenyIndeterminate (only boolean true accepts) | unit | R1 | |
| **SEC-017** | Introspection 5xx → DenyIndeterminate | unit | R1 | |
| **SEC-018** | Introspection timeout → DenyIndeterminate | unit | R1 | Injectable clock |
| **SEC-019** | Introspection verdict never cached — 2nd identical opaque-token bind re-queries IdP | unit | R1 | AD-12 no-verdict-cache |
| **SEC-093** | Introspection HTTP-failure matrix (network-error / 3xx / 4xx≠default → DenyIndeterminate) `[critic-fix]` | unit | R1 | Closes asymmetric R1 hole (ROPC was exhaustive, introspection wasn't) |
| **SEC-094** | JWT/ROPC no-verdict-cache: same BindCredential re-hits token endpoint `[critic-fix]` | unit | R1, R8 | Mirrors SEC-019 for JWT path; AD-12 load-bearing |
| **SEC-020** | Reject JWT alg=none → DenyInvalid | unit | R1 | Spec-derived vectors, not Nimbus-generated |
| **SEC-021** | Reject JWT alg-confusion (RS↔HS key confusion) → DenyInvalid | unit | R1 | Public key never reinterpreted as HMAC secret |
| **SEC-022** | Reject JWT kid path/key-injection (traversal/attacker key) → DenyIndeterminate; no file lookup | unit | R1 | |
| **SEC-023** | Reject JWT past exp, no false-accept across skew window (injectable clock) | unit | R1 | |
| **SEC-024** | Reject JWT with nbf in the future (injectable clock) | unit | R1 | |
| **SEC-025** | Reject JWT iss mismatch → DenyInvalid | unit | R1 | |
| **SEC-026** | Reject JWT aud mismatch → DenyInvalid | unit | R1 | |
| **SEC-027** | Reject JWT tampered signature → DenyInvalid | unit | R1 | |
| **SEC-028** | ROPC JWT happy path vs real Keycloak 26.x → Allow, discard token, relay ORIGINAL bind | integration | R2 | AD-12 path 1; nightly tier; Story 3.1 gate |
| **SEC-029** | Opaque-token RFC 7662 introspection happy path vs real Keycloak → Allow | integration | R2 | AD-12 path 2 |
| **SEC-030** | Provider auth via mTLS RFC 8705 (not client_secret) reaches token endpoint | integration | R2 | AD-12 path 3 |
| **SEC-031** | ≥1 DENY branch e2e vs real Keycloak (wrong pw→401→DENY; stopped IdP→timeout→DENY) | integration | R2, R1 | AD-12 path 4 |
| **SEC-032** | ROPC viability probe + fallback decision-tree artifact (Story 3.1) | integration | R2 | Gate-blocker; lands before any other Epic 3 story |
| **SEC-033** | Ingress Mode C never falls back to JDK cacerts — client cert chaining to cacerts root rejected | integration | R7 | Default-state-is-insecure |
| **SEC-034** | Egress AD-26 never falls back to cacerts — peer cert chaining to public root rejected | integration | R7 | |
| **SEC-035** | Mode C uses clientAuth(REQUIRE) — no client cert fails handshake (not WANT soft-accept) | integration | R7 | |
| **SEC-036** | Reject Mode C client cert with wrong EKU (serverAuth-only) | integration | R7 | |
| **SEC-037** | Reject genuinely already-expired peer cert (real clock; 1970–1971 validity) `[critic-fix REWRITTEN]` | integration | R7 | Injectable clock infeasible for TLS cert-path (AD-13) |
| **SEC-038** | Reject self-signed cert not reaching configured anchor | integration | R7 | |
| **SEC-039** | Reject cert with unknown critical extension (PKIX default) | integration | R7 | |
| **SEC-040** | Egress raw-IP SMSC: endpointIdentificationAlgorithm=null allows IP-SAN cert (AD-20) | integration | R7 | Netty HTTPS default overridden |
| **SEC-041** | Egress cacerts/public-PKI SMSC trust is opt-in (any mode) with loud warning + ack, never default | integration | R7, R18 | |
| **SEC-042** | Credential primitives are char[]/byte[] and never String (password char[], token byte[]) | unit | R8 | ArchUnit + reflection scan |
| **SEC-043** | Verdict sealed interface carries no credential/token field | unit | R8 | Credential cannot escape via Verdict |
| **SEC-044** | BindCredentialVerifier port signature carries no token | unit | R8, R31 | Token never crosses port boundary |
| **SEC-045** | Credential never escapes via log/metric/Verdict/CompletableFuture (parametrized over sinks) | unit | R8 | |
| **SEC-046** | Password char[] zeroized on completion/teardown/exception — THE deterministic zeroization evidence | unit | R8 | Same-reference all-'\0' immediately after zeroize |
| **SEC-047** | Token byte[] discarded + zeroized after verify; ORIGINAL bind forwarded to SMSC | integration | R8, R2 | |
| **SEC-048** | Best-effort heap-inspection fragility guard (NOT zeroization evidence — that is SEC-046) `[critic-fix REFRAMED]` | integration | R8 | Inherent false-negative risk |
| **SEC-049** | Best-effort JFR/heap-dump hygiene guard + hygiene doc `[critic-fix REFRAMED]` | integration | R8 | Sampled profiler; not validation |
| **SEC-095** | OIDC client_secret hygiene: char[]/byte[] (not String), never escapes, when non-mTLS confidential path configured `[critic-fix]` | unit | R8 | Long-lived in-memory secret; extends SEC-042/045 |

**Total P0:** 64 tests (RELAY 12 · SEC 52).

---

### P1 (High)

**Criteria:** Important features + score-6 risk + common workflows + the conformance/methodology/parity backbone.

| Test ID | Requirement | Test Level | Risk Link | Notes |
| --- | --- | --- | --- | --- |
| **CODEC-001** | Framer emits one framed ByteBuf for one complete well-formed PDU (single read) | unit | R3, R14 | Baseline; one-frame-per-PDU invariant |
| **CODEC-002** | Framer reassembles one PDU when bytes split across many reads, incl. split inside 4-octet command_length header | unit | R3, R14 | Header-split = trickiest accumulation |
| **CODEC-003** | Framer emits N distinct in-order frames when multiple PDUs coalesced in one read | unit | R3 | ByteToMessageDecoder loop contract |
| **CODEC-004** | Framer discards partial PDU left at channelInactive — no truncated frame | unit | R3 | REL-1 corrupt prevention |
| **CODEC-005** | Framer rejects declared command_length < 16 + closes channel | unit | R3 | AD-30 lower bound |
| **CODEC-006** | Framer rejects declared command_length > 65536 (mid-range oversize) | unit | R3 | AD-30 upper reject; counting allocator |
| **CODEC-007** | Framer accepts command_length == 16 (header-only, zero-body) | unit | R3, R14 | Lower valid boundary |
| **CODEC-008** | Framer accepts 65536 (exact max), rejects 65537 (off-by-one) | unit | R3 | Classic length-field boundary |
| **CODEC-009** | Framer waits (no partial frame, no busy-spin) when declared length exceeds buffered | unit | R3 | Determinism / no spin |
| **CODEC-010** | Framer rejects overflow-class lengths (near 2³¹ / 0xFFFFFFFF) BEFORE allocation — no OOM, no wrap | unit | R3 | THE critical AD-30 length-field vuln |
| **CODEC-011** | JQF structural fuzz of SmppFrameDecoder over arbitrary byte streams: no uncaught exception, bounded memory | fuzz | R3 | AD-24 mandated (more-exposed surface) |
| **CODEC-012** | jqwik property: any chunking of a valid PDU reassembles to identical single frame | fuzz | R3 | Generalizes CODEC-002 |
| **CODEC-013** | Decoder exception on malformed frame is contained — does not kill the event loop | unit | R3 | R3 relay-wide-DoS dimension |
| **CODEC-014** | Per-channel isolation: malformed frame on channel A does not corrupt healthy frame on channel B (shared event loop) | integration | R3 | Cross-channel containment proof |
| **CODEC-015** | Framer ByteBuf retain/release correct on normal + error path — no direct-memory leak (PARANOID) | unit | R3 | R3/R27 error-path leak |
| **CODEC-016** | Bind parser decodes golden bind_transceiver to exact fields (system_id/password/system_type/iface_version/header) | unit | R14, R33 | Golden bytes from independent corpus |
| **CODEC-017** | Bind parser decodes golden bind_transmitter + bind_receiver (all 3 request types) | unit | R14, R33 | command_id differentiation |
| **CODEC-018** | Bind parser detects command_status==ROK on golden bind_*_resp (AD-25 splice-flip trigger) | unit | R14, R33 | Codec-level signal for AD-25 |
| **CODEC-019** | Bind parser decodes non-ROK bind_*_resp without raising ROK trigger | unit | R14 | Negative branch of AD-25 trigger |
| **CODEC-020** | Bind parser handles C-octet-string edges: empty, max-length, all-fields-empty | unit | R14 | Spec boundary conformance |
| **CODEC-021** | Bind parser rejects unterminated C-octet-string without over-read/loop | unit | R3 | Classic unbounded-scan vuln |
| **CODEC-022** | Bind parser rejects truncated bind body without AIOOBE/negative-size | unit | R3 | All body-length arithmetic bounds-checked |
| **CODEC-023** | Bind parser decodes header correctly even when body is junk | unit | R3 | Header robustness independent of body |
| **CODEC-025** | JQF structural fuzz of bind-family parser over framed buffers: no uncaught exception, no read past frame | fuzz | R3 | AD-24 mandated |
| **CODEC-026** | SmppCommandIds.BIND_FAMILY is exactly the 6-id set | unit | R14 | AD-27 single-source-of-truth |
| **CODEC-027** | outbind + generic_nack NOT in BIND_FAMILY (opaque-spliced) | unit | R14 | Guards against widening parsed surface |
| **CODEC-028** | Non-bind command_ids (submit_sm/deliver_sm/enquire_link/unbind) not parsed by bind parser — opaque | unit | R14, R3 | Parsed surface = exactly two decoders |
| **CODEC-029** | command_id response bit (bit 31) distinguishes bind req from bind_resp; both recognized | unit | R14 | |
| **CODEC-030** | Spec-derived golden-vector corpus authored independently, loaded from resource (not codec-synthesized) | unit | R33, R14 | THE fix for R33 (3rd oracle) |
| **CODEC-031** | Independent-oracle agreement: codec decode == jSMPP decode of same golden bytes (bind family) | conformance | R14, R33 | Two independent stacks agreeing |
| **CODEC-032** | Encode→bytes round-trip: typed bind encodes byte-identical to golden vector | unit | R14 | Encoder conformance |
| **CODEC-033** | Golden NEGATIVE vectors: spec-derived malformed PDUs produce expected reject deterministically | unit | R3, R33 | Deterministic oracle for R3 |
| **CODEC-034** | Real TCP socket: PDU split at every byte boundary reassembles into one correct frame | conformance | R3, R14 | MUST use real socket, not ByteBuf slices |
| **CODEC-035** | Real TCP socket: multiple PDUs + partial fragments interleaved reassemble in order | conformance | R3 | Multi-PDU coalesce over real TCP |
| **CODEC-036** | Real TCP socket: writer closes mid-PDU — no truncated frame, clean close | conformance | R3 | Partial-at-close over real socket |
| **CODEC-037** | Byte-exact forwarding: after parsing bind, original framed ByteBuf byte-identical + un-mutated | unit | R14, R3 | AD-12 ORIGINAL bind relayed (security property) |
| **CODEC-038** | Byte-exact forwarding: opaque PDUs forwarded byte-identical, no decode/re-serialize | fuzz | R3, R14 | REL-1 byte integrity for opaque majority |
| **CODEC-039** | Inward-only dependency gate: codec classes depend on ZERO proxy.* packages | integration | R14 | ArchUnit CI rule; AD-7 MAINT-2 |
| **CODEC-040** | Codec dependency allowlist: only netty-buffer/netty-codec + JDK stdlib (no Spring/Nimbus/micrometer) | integration | R14 | MAINT-2 + AD-27 codec never emits metrics |
| **CODEC-041** | CI-gate positive control: codec allowlist gate FIRES on injected forbidden dep `[critic-fix]` | integration | R14, R16 | Proves gate can't silently bypass |
| **RELAY-012** | Egress reconnect/flap does NOT re-route stale DLRs to new pair; old entry torn down | integration | R5 | R5d partial-A-1-affinity under flap |
| **RELAY-013** | Direct-memory ceiling holds under combined PERF-1+PERF-2 load: ByteBufAllocatorMetric ≤ AD-30 bound | perf | R27 | Budget-at-cliff |
| **RELAY-014** | AUTO_READ backpressure state machine: high-water disarms read, low-water re-arms (parametrized) | unit | R27 | AD-2/AD-30 state machine |
| **RELAY-015** | Correlated slow-consumer burst: egress stalls, ingress floods — AUTO_READ trips, memory bounded, no OOM | perf | R27 | REL-2 headline; absorbed PERF-041 |
| **RELAY-017** | Error-path ByteBuf release integrity: zero leaks across error+churn matrix under PARANOID | integration | R27 | Absorbed RELAY-016 + PERF-042 |
| **RELAY-018** | BlockHound positive control: injected blocking call on event-loop thread IS detected | integration | R28 | Proves allow-list not over-broad; MODEL for CI controls |
| **RELAY-019** | BlockHound clean on relay hot path: bind→couple→splice→unbind churn yields ZERO blocking detections | integration | R28 | The real AD-4 assertion |
| **RELAY-022** | Graceful shutdown drains in-flight splices within timeout: no drop of completed, no partial frame, registry→0 | integration | R11 | R11 relay/concurrency slice |
| **RELAY-023** | ALLOW verdict racing SIGTERM does NOT couple: adjudication cancelled fail-closed, flag never flips | integration | R11 | R11 partial-verdict race |
| **RELAY-025** | REL-4 structural arch-scan: no message_id→system_id map exists in relay/ `[critic-fix]` | integration | R5, R38 | Closes REL-4 NFR-evidence gap |
| **RELAY-026** | AD-30 shared-constant assertion: codec-max + MaxDirectMemorySize formula reference ONE named constant `[critic-fix]` | integration | R27 | Compile-time drift prevention |
| **SEC-050** | Startup refuses invalid trust store (absent/empty/wrong-format/wrong-password/zero-entries) | unit | R17, R7 | `@ConfigurationProperties` fail-fast |
| **SEC-051** | Startup refuses forward-role + Mode B (forbidden cell) | unit | R17 | Mode B is reverse-only |
| **SEC-052** | Mode B reverse: starts only with opt-in ack; without ack refuses, with ack warns + starts | unit | R17 | AD-17 Mode B posture |
| **SEC-053** | Startup refuses non-https OIDC provider URL | unit | R17 | AD-12 SEC-3 link must be https |
| **SEC-054** | Startup refuses missing/unset OIDC provider URL | unit | R17 | |
| **SEC-055** | Startup refuses bad/missing SMPP bind or SMSC ports | unit | R17 | |
| **SEC-056** | Startup refuses forward (A/C) missing server cert+key | unit | R17 | Required-config cell |
| **SEC-057** | Startup refuses reverse Mode C missing client cert+key | unit | R17 | Required-config cell |
| **SEC-058** | Startup refuses forward with empty/missing routing table | unit | R17 | AD-29 1:1, no default route |
| **SEC-059** | Startup refuses reverse missing SMSC endpoint | unit | R17 | |
| **SEC-060** | Startup refuses missing/unreadable secret file (parametrized over secret types) | unit | R17, R22 | AD-18 |
| **SEC-061** | Startup refuses TLS floor below TLS 1.2 (SSLv3/TLS1.0/1.1) | unit | R17 | SEC-1 |
| **SEC-063** | Mode A forward emits loud ACL-isolation startup warning | integration | R18 | Deployer-dependent; CI-testable portion |
| **SEC-064** | Mode A forward ack gate: warn-and-start only with explicit opt-in ack | integration | R18 | |
| **SEC-065** | Runbook documenting Mode A two-proxy ACL isolation exists under docs/ | integration | R18 | OPS-1 |
| **SEC-066** | CI config/startup scan detects forward+Mode-A and asserts warning + ack present | integration | R18 | |
| **SEC-087** | TLS 1.2 minimum enforced at runtime — TLS 1.1 ClientHello fails handshake | integration | R17 | Runtime TLS-floor vector |
| **SEC-088** | TLS 1.3 preferred and succeeds at runtime on both legs | integration | R17 | Runtime TLS-floor vector |
| **SEC-089** | Cipher allowlist enforced — non-allowlisted cipher fails handshake `[BLOCKED-ON-Q3]` | integration | R17 | Placeholder until allowlist pinned |
| **SEC-090** | No hand-rolled crypto/TLS/JWT — JDK SSLEngine + Nimbus only; no custom PKIXBuilderParameters | unit | R7 | AD-13/SEC-4 |
| **SEC-091** | CI CVE/dependency-check gate fails on known CVE in Netty/JDK/Nimbus; Nimbus ≥ 10.0.2 | integration | R16 | OWASP dependency-check + Dependabot |
| **SEC-092** | PERF-3 DENY timeout boundary — adjudication crossing 2–5s deadline fails-closed, no late-allow | unit | R1, R2 | Injectable clock |
| **SEC-096** | role×mode cell: reverse+A missing client trust store → refuse `[critic-fix]` | unit | R17, R7 | Pins role×mode cell like SEC-051 |
| **SEC-097** | role×mode cell: forward+A STARTS without SMSC endpoint (positive) `[critic-fix]` | unit | R17 | Complement of SEC-059 |
| **SEC-098** | FR-AUTH-3 no-shared-golden-key: no baked client cert/key in image/repo `[critic-fix]` | integration | R7 | Per-instance Mode C certs |
| **SEC-099** | CI-gate positive control: CVE gate FIRES on injected known-vulnerable coordinate `[critic-fix]` | integration | R16 | Proves suppression file can't disable gate |
| **OBS-004** | Metrics server binds loopback IPv4 only (127.0.0.1); not localhost/::1/0.0.0.0 | integration | R10, R17 | Binding is sole /metrics auth (AD-19) |
| **OBS-006** | HTTP request-smuggling vectors neutralized by HttpServerCodec+HttpObjectAggregator | integration | R10 | No hand-rolled parsing |
| **OBS-009** | Unknown system_id increments unlabeled counter, never creates free-form label | integration | R10, R23 | Most important cardinality/enumeration property |
| **OBS-010** | PDU/message body never appears in /metrics scrape text (PRIV-1) | integration | R10, R8 | Negative-by-absence |
| **OBS-015** | E2E SIGTERM: process exits within Spring shutdown timeout (packaging/process-exit aspect) `[critic-fix SCOPE-REDUCED]` | e2e | R11, R5 | Keeps only process-exit aspect (drain owned by RELAY-022) |
| **OBS-016** | AD-22 7-step shutdown macro-ordering holds (acceptor stop before in-flight DENY before drain before exit) | integration | R11 | Pairwise-timestamp assertion |
| **OBS-017** | New bind attempted after acceptor stops is rejected/DENYed | integration | R11, R1 | Fail-closed during shutdown |
| **OBS-018** | JWKS refresh ScheduledExecutorService shut down BEFORE JWKS cache closed (no refresh-after-close orphan) | integration | R11, R20 | Most-missed sub-ordering |
| **OBS-019** | In-flight adjudication at SIGTERM DENYed fail-closed; token discarded (no partial-Allow race) | integration | R11, R1, R8 | |
| **OBS-020** | Splice whose peer never half-closes force-closed at Spring timeout (not hung) | integration | R11, R3 | Injectable clock bounds drain window |
| **OBS-023** | Bind-accept log line JSON with UTC ts + system_id; password absent even at TRACE | integration | R10, R8 | PRIV-1 negative-by-absence |
| **OBS-025** | PDU body absent from logs at default (INFO); present only when level raised to TRACE | integration | R10, R8 | Load-bearing content-suppression |
| **OBS-034** | Docs contain deployer-dependent controls runbook (Mode A ACL-isolation + egress cacerts-prevention) | unit | R37, R18, R7 | Backs two P0/P1 risks |
| **OBS-038** | Conformance vs jSMPP server-side mock: ≥2 concurrent binds same system_id both ROK + DLR on originating bind | conformance | R38, R33, R5 | Strongest CI approximation of A-1 |
| **DEPLOY-001** | jlink runtime image bundles crypto + management JDK modules (jdk.crypto.ec/cryptoki, java.management) | integration | R12 | jdeps-driven module resolution |
| **DEPLOY-002** | Epoll native transport present for target arch + libc matches base (x86_64 + aarch_64 classifiers) | integration | R12, R36 | Static arch/libc gate |
| **DEPLOY-003** | --enable-preview present + functional at runtime in BOTH Docker entrypoint AND JAR launcher | e2e | R12, R9 | STS preview-API parity |
| **DEPLOY-004** | -XX:+UseZGC + -XX:MaxDirectMemorySize set at runtime in BOTH shapes | e2e | R12 | GC + direct-memory budget parity |
| **DEPLOY-005** | Two-shape behavioral parity: identical config/modes/auth paths yield identical outcomes in JAR + Docker | e2e | R12 | HEADLINE R12 parity; fake verifier makes deterministic |
| **PERF-001** | JMH submit_sm encode hits 3×10⁵–1.5×10⁶ ops/s/core band (Blackholed) | perf | R26 | Lower PERF-4 band; codec-only |
| **PERF-002** | JMH submit_sm decode hits 5×10⁵–1.8×10⁶ ops/s/core band (Blackholed) | perf | R26 | Higher band |
| **PERF-004** | JMH -prof gc confirms per-op allocation controlled (no GC interference) | perf | R26 | Underpins PERF-001/002 credibility |
| **PERF-010** | Open-model load harness on separate pinned cores passes coordinated-omission check (injected 50ms pause shows in p99.9) | perf | R25, R6 | Core R25; injected-pause check IS the proof |
| **PERF-011** | Sustained ≥10K submit_sm/s at mTLS both legs; publishes p50/p90/p99/p99.9 table | perf | R6, R25 | Headline PERF-1; percentile table is deliverable |
| **PERF-013** | No-crypto baseline (TLS off both legs) attributes relay-vs-crypto cost | perf | R6 | Methodology bar |
| **PERF-015** | OIDC-cached resolved: JWKS warm + verdict NOT cached (AD-12); bind-rate reported separately | perf | R6, R29 | cached = JWKS, NOT verdict |
| **PERF-016** | Saturation knee found + failure modes reported (drop/OOM/backpressure/TLS-exec saturation) | perf | R6, R30 | No peak credible without knee |
| **PERF-017** | Per-PDU added relay latency p99 <1ms vs zero-latency mock SMSC | perf | R6 | PERF-4 relay component |
| **PERF-020** | 10K idle socket pairs <1GB heap / <1 vCPU idle with full env disclosure | perf | R6 | Highest overclaim risk; no number without disclosure |
| **PERF-030** | Warm bind p99 ~250ms with co-located mock IdP + warm JWKS (injectable clock) | perf | R29, R6 | PERF-3 warm |
| **PERF-031** | Cold-path bind p99 ≤2s on first bind after cold JWKS fetch (injectable clock) | perf | R6 | PERF-3 cold |
| **PERF-032** | Fail-closed DENY returns DenyIndeterminate within 2–5s (injectable clock past deadline) | perf | R6 | PERF-3 DENY timing |
| **PERF-040** | ByteBufAllocatorMetric usedDirectMemory() ≤ MaxDirectMemorySize at PERF-1 cliff (AD-30 formula) | perf | R27 | Validates one named formula |
| **PERF-070** | Disclosure gate: every perf number tagged payload + cipher + single-instance + HW/JDK/reboot/sysctl | perf | R6 | The methodology bar |
| **PERF-071** | Reporting gate: no peak number published without saturation knee + failure modes | perf | R6, R30 | Overclaim guard |
| **E2E-001** | Two-real-proxy-instance (forward↔reverse) composed-flow end-to-end `[critic-fix]` | e2e | R12 | Only test of the forward↔reverse Mode C seam |

**Total P1:** 113 tests (CODEC 40 · RELAY 11 · SEC 26 · OBS 14 · DEPLOY 5 · PERF 16 · E2E 1).

---

### P2 (Medium)

**Criteria:** Secondary features + score-4 risk + edge cases + regression prevention + docs/observability contract.

Summarized by area (full per-scenario detail in the catalog `test-coverage-scenarios.md`):

| Area | Count | Representative scenarios | Risks covered |
| --- | --- | --- | --- |
| **CODEC** | 1 | CODEC-024 (parser exposes password as char[], never String — codec seam for zeroization) | R8 |
| **RELAY** | 2 | RELAY-020 (egress connect-refused post-ALLOW no-hang), RELAY-021 (egress TLS handshake-fail teardown) | R32 |
| **SEC** | 18 | SEC-067..070 (JWKS kid-miss single-flight + bounded refresh), SEC-071..074 (VT/delegated-task pool saturation fail-closed), SEC-075..077 (secret file-path/no-env-var-value), SEC-078..080 (bind_resp no enumeration oracle `[BLOCKED-ON-Q7]`), SEC-083..086 (CF×ScopedValue propagation + STS confinement + JDK-pin + STS-control-plane-only) | R20, R21, R22, R23, R9, R31, R16 |
| **OBS** | 29 | OBS-001..003/005/007/008 (`/metrics` contract + handler hardening + cardinality-DoS soak), OBS-011..014 (active-VT gauge + metrics-loop isolation + no-Actuator/Tomcat/WebFlux + pinned-trigger), OBS-021 (VT pool drain), OBS-022/024/026..028 (log JSON contract + no-stacktrace), OBS-029..033 (docs drift + per-mode matrix + Mode B + cipher `[BLOCKED-ON-Q3]` + ROPC deprecation), OBS-035..037 (A-1 non-CI plan falsifiability), OBS-039..043 (no-mgmt-API + idempotent scrape + immutability + direct-memory gauge + CI-gate positive control) | R10, R37, R38, R16 |
| **DEPLOY** | 9 | DEPLOY-006 (docker stop SIGTERM→PID-1 reaches JVM), DEPLOY-007..009 (non-root + Docker secrets + env-var-value rejection + missing-secret fail-fast), DEPLOY-010..014 (Epoll runtime + IPv4 metrics + IPv4 egress + x86/ARM matrix + JDK-pin toolchain) | R34, R35, R36, R9 |
| **PERF** | 13 | PERF-003/005/006 (framer hot-path + fork-variance + unit allocation guard), PERF-012 (stretch 25K), PERF-014 (payload-corner sweep), PERF-021 (idle linearity ramp), PERF-033..034 (real-Keycloak bind-rate + mock-labeled regression-only), PERF-050..052 (ZGC pause + cycle freq + oscillating-load race), PERF-060..061 (BlockHound under load + shutdown under PERF-1) | R6, R26, R27, R28, R29, R30, R11 |

**Total P2:** 72 tests. **Pointer:** see catalog §2 (CODEC-024), §3 (RELAY-020/021), §4.9–4.14 + §4.15 (SEC P2 set), §5 (OBS), §6 (DEPLOY-006..014), §7 (PERF).

### P3 (Low)

**Criteria:** Nice-to-have + stretch + defense-in-depth.

| Test ID | Requirement | Test Level | Notes |
| --- | --- | --- | --- |
| **SEC-081** | Ingress TLS 1.3 0-RTT/early-data rejected (replay not possible) | integration | R24 |
| **SEC-082** | Egress TLS 1.3 client does not request/send 0-RTT to SMSC/forward peer | integration | R24 |

**Total P3:** 2 tests. (R15 native-image is documented only — no scenario by design per AD-23.)

---

## Execution Strategy

**Philosophy:** Run everything in PRs unless it has significant infrastructure overhead or is non-deterministic/long-running. The JVM unit+fuzz+fast-integration suite (JUnit 5 parallelized) targets <15 min in PR. Defer to Nightly only for perf, race-soak, real-IdP, and jcstress; Weekly/non-CI for arch-matrix, two-proxy E2E, and the A-1 real-carrier step.

**Organized by TOOL TYPE / TIER:**

### Every PR (<15 min): Unit + bounded Fuzz + fast Integration + CI gates

**All fast functional tests** (from any priority level that runs without expensive infra):

- All **UNIT** tests: codec framer/parser matrices, SEC port-matrix (fake verifier), `@ConfigurationProperties` fail-fast matrix, ArchUnit/dep scans, config/docs scans.
- Bounded **FUZZ**: JQF/jqwik on both decoders (time-boxed; full-corpus expansion runs nightly).
- Fast **INTEGRATION** not needing the in-JVM mock SMSC on a live socket pair or JDK SSLEngine vectors (e.g. CODEC-014 per-channel isolation if cheap, the SEC-042..046 zeroization unit seam).
- **CI build gates** — each with a **positive control** (so a misconfigured gate can't silently pass):
  - CVE/dependency-check (SEC-091 + control SEC-099): Netty/JDK/Nimbus, Nimbus ≥ 10.0.2.
  - JDK-pin / Gradle toolchain (DEPLOY-014 + SEC-085): exact pinned JDK 25 build.
  - Codec dependency allowlist (CODEC-040 + control CODEC-041): netty-buffer/netty-codec + JDK only.
  - Forbidden-runtime-dependency gate (OBS-013 + control OBS-043): no spring-boot-starter-web/tomcat/webflux/actuator/reactor on proxy runtime classpath.
  - Docs↔config consistency (OBS-029): `companion.*` keys bidirectionally consistent.
- Parallelized across N Gradle test shards; `-enable-preview` on the pinned JDK 25.

**Why run in PRs:** Fast feedback, no expensive infrastructure; catches regressions in the crown jewels (fail-closed, zeroization, codec) on every change.

### PR-integration job or Nightly: Integration needing live sockets / TLS vectors

- **RELAY conformance** (RELAY-001..011, RELAY-024) needing the in-JVM mock SMSC on real socket pairs + capturing SpliceObserver + fake BindCredentialVerifier with latched verdicts.
- **SEC TLS vectors** (SEC-033..041) needing JDK SSLEngine / Netty SslContext loopback pairs with crafted X.509.
- **OBS** `/metrics` + log-contract integration (OBS-001..010, OBS-023..025) needing a bound metrics loop.
- **DEPLOY** static image scans (DEPLOY-001/002) and runtime JVM-arg introspection (DEPLOY-003/004).

**Why defer:** Real socket pairs + TLS handshakes exceed the PR time budget on a single shard; run on a dedicated integration job (PR-triggered, longer) or fold into nightly if they exceed budget.

### Nightly (expensive, ~30–60+ min): Perf + race-soak + real-Keycloak + jcstress

- **PERF suite**: JMH codec bench (PERF-001/002/004), open-model relay percentile harness (PERF-010/011/013/015/016/017), idle-pair demo (PERF-020), bind-latency (PERF-030/031/032), direct-memory-at-cliff (PERF-040), disclosure/reporting gates (PERF-070/071).
- **Race-soak** RELAY-024 (delay-injection + jitter + randomized channelInvalid, millions of iterations) + error/churn matrix RELAY-017 (PARANOID) + correlated-burst RELAY-015.
- **jcstress** RELAY-007 (registry invariant) — if Q2 adopted.
- **Real-Keycloak integration** (SEC-028..032, PERF-033) via Testcontainers Keycloak 26.x — the genuine ROPC/IdP interop gate.
- **ZGC characterization** (PERF-050/051/052) under JFR.

**Why defer to nightly:** Expensive infrastructure (real Keycloak, long-running soaks), 10–40+ min per test, non-deterministic under load.

### Weekly + non-CI (hours): Arch matrix + two-proxy E2E + endurance + A-1 real-carrier

- **x86 + ARM packaged smoke** (DEPLOY-013) on native runners (prefer native arm64 over QEMU).
- **Two-proxy forward↔reverse E2E** (E2E-001) — the only composed two-instance test (Q4).
- **Endurance soak** (extended RELAY-024 / PERF-052).
- **OBS-038** jSMPP server-side conformance (independent oracle; weekly or nightly).

**Non-CI ops step (manual, the only genuine A-1 gate):**
- **The A-1 real-carrier falsification** (OBS-035..038 plan executed against the real target carrier or an independent conformance SMSC — NEVER the in-JVM codec-based mock, which emulates/assumes A-1). Defined PASS (≥2 concurrent binds, same system_id, both ROK on real carrier) + FAIL (2nd bind rejected OR DLR observed on wrong bind) + DLR-affinity assertion (submit on bind A → deliver_sm on bind A's socket, not bind B). Executed by ops, not CI; the in-JVM mock cannot falsify A-1.

**Manual tests (excluded from automation):**
- A-1 real-carrier step (above).
- ROPC viability/fallback decision-tree review (artifact exists — SEC-032 asserts presence).
- Docs/operability review for the deployer-dependent controls runbook.

---

## QA Effort Estimate

**QA test development effort only** (solo author writing tests test-first across the epics — not a separate QA phase). Excludes architecture, production code, DevOps, and IdP/carrier provisioning.

| Priority | Count | Effort Range | Notes |
| --- | --- | --- | --- |
| P0 | 64 | ~150–300 hrs | Parametrized security/concurrency/TLS matrices; shared setup (fake verifier, mock SMSC, golden corpus) amortizes across the 52-SEC + 12-RELAY set |
| P1 | 113 | ~100–300 hrs | Integration + conformance + the from-scratch open-model load harness (itself an Epic-6 deliverable) |
| P2 | 72 | ~40–110 hrs | Edge cases, docs scans, observability contract, arch/IPv4 matrix |
| P3 | 2 | ~2–6 hrs | TLS 1.3 0-RTT vectors |
| **Total** | **251** | **~290–720 hrs (~7–18 weeks FTE)** | **1 solo author, full-time, distributed across E1–E6** |

**Assumptions:**

- Includes test design, implementation, debugging, CI integration.
- Excludes ongoing maintenance (~10% effort post-release).
- Assumes the four testability seams (injectable Clock, golden corpus, race-fuzz executor, BlockHound) and the three harness scaffolds (in-JVM mock SMSC, jSMPP interop, open-model load harness) are built test-first alongside the epics, not as a separate upfront phase.
- Ranges are deliberately wide: the P0 parametrized matrices share heavy setup (amortizes low) but each per-branch DENY/JWT/TLS vector is individually authored (amortizes high); the open-model harness methodology work (PERF-010/070/071) is open-ended.

**Distribution across epics (test-first, not a trailing QA phase):**

| Epic | Theme | Primary test investment |
| --- | --- | --- |
| **E1** | Foundation / codec / config | CODEC-001..041 (40 P1), SEC-050..061/096/097 fail-fast matrix, golden corpus (CODEC-030) |
| **E2** | Relay + A-1 smoke | RELAY-001..011/024 (12 P0 R5 seams), RELAY-013..019, A-1 jSMPP (OBS-038) |
| **E3** | TLS + ROPC | SEC-001..049/093/094/095 (52 P0 crown jewels), SEC-087..092, real-Keycloak (SEC-028..032) |
| **E4** | Metrics / logs | OBS-001..043 (43 scenarios), REL-3 shutdown (OBS-015..021) |
| **E5** | JAR + Docker | DEPLOY-001..009 (parity + Docker secrets + SIGTERM), E2E-001 (two-proxy) |
| **E6** | Perf + docs | PERF-001..071 (perf suite + methodology gates), OBS-029..037 docs scans, ROPC-deprecation docs |

**Dependencies from other teams:**

- See "Dependencies & Test Blockers" — the 7 open questions and 4 testability seams are the gating inputs.

---

## Implementation Planning Handoff

The test design produces implementation tasks that must be scheduled (solo author; assign to the epic's Dev owner):

| Work Item | Owner | Target Epic | Dependencies / Notes |
| --- | --- | --- | --- |
| Provide injectable `Clock`/scheduler seam in BindCredentialVerifier + JWKS cache + adjudication timers + shutdown drain | Dev/Arch | E3 | Gates SEC-009/018/023/024/092, PERF-030..032, OBS-020 |
| Author spec-derived golden-vector corpus (CODEC-030) as checked-in resource | Dev/QA | E1 | The R33 3rd oracle; gates CODEC-016..033 |
| Build race-fuzz/delay-injection EventExecutor harness | QA/Dev | E6 | Gates RELAY-024; distinct from throughput soak |
| Register BlockHound on event-loop threads + test allow-list | QA/Dev | E2 | Gates RELAY-018/019; MODEL for CI positive controls |
| Resolve Q1 (pre-couple policy) | Arch | E2 | Gates RELAY-002 P0 property |
| Resolve Q2 (jcstress adoption) | Arch | E2/E6 | Gates RELAY-007/024 P0 depth |
| Resolve Q3 (cipher allowlist pin) | Arch/Config | E1/E3 | Gates SEC-089/OBS-032 |
| Resolve Q4 (two-proxy E2E standup) | Arch/Dev | E5/E6 | Gates E2E-001 |
| Resolve Q5 (AD-30 shared-constant ArchUnit assertion) | Arch/Dev | E2 | Gates RELAY-026 |
| Resolve Q6 (CI-gate positive controls) | Dev/CI | CI | Gates SEC-099/CODEC-041/OBS-043 |
| Resolve Q7 (bind_resp status→OIDC mapping) | Dev | E3 | Gates SEC-078..080 |
| Build open-model load harness (separate-core, coordinated-omission check) | QA/Dev | E6 | Itself a deliverable; gates PERF-010..017/070/071 |
| Execute A-1 non-CI real-carrier plan | Ops | post-E2 | The only genuine A-1 falsification |

---

## Tooling & Access

Non-standard tools/access required for this JVM backend:

| Tool or Service | Purpose | Access Required | Status |
| --- | --- | --- | --- |
| JDK 25 (pinned build, `--enable-preview`) | STS JEP 505 preview-API; build + test runtime | Pinned JDK 25 distro + exact build (toolchain) | Ready (toolchain spec) |
| Gradle (toolchain + JDK-pin) | Multi-module build; codec isolation; dep allowlist gates | Gradle 2-module (codec + proxy) | Ready |
| JUnit 5 (Jupiter) + AssertJ | Unit + integration + `@ParameterizedTest` matrices | Test deps | Ready |
| JQF + jqwik | Structural fuzz of both decoders | Test deps | Ready |
| JMH | Codec microbenchmarks (PERF-4) | Test/jmh source set | Ready |
| BlockHound | Event-loop blocking detection (AD-4 backstop) | Test dep + agent | Ready |
| ArchUnit | Codec inward-only + REL-4 + no-rolled-crypto structural scans | Test dep | Ready |
| jSMPP 3.0.2 | Independent interop oracle (test-only; NEVER production codec) | Test dep | Ready |
| in-JVM mock SMSC (on codec) | Primary CI SMSC stand-in + affinity/delay/capture | QA-built (E1/E2) | Pending (build test-first) |
| Open-model load harness | Relay percentiles (no OSS SMPP load tool exists) | QA-built (E6) | Pending (build test-first) |
| JDK SSLEngine / Netty SslContext | TLS vectors (modes A/B/C, cacerts, REQUIRE-vs-WANT, cert edges) | Test fixtures + crafted X.509 (BouncyCastle/keytool) | Ready |
| Spring Boot test slices | `@ConfigurationProperties` fail-fast matrix; SmartLifecycle | Test deps | Ready |
| Testcontainers Keycloak 26.x | Real ROPC/IdP interop (SEC-028..032, PERF-033) | Docker + Keycloak 26.x image | Pending (nightly infra) |
| OWASP dependency-check + Dependabot | CVE gate (Netty/JDK/Nimbus) | CI integration | Ready |
| x86 (amd64) + ARM (arm64) CI runners | Arch matrix (Epoll classifier, DEPLOY-013) | Native runners (prefer native over QEMU) | Pending (CI provisioning) |
| Real target carrier / conformance SMSC | A-1 non-CI falsification (OBS-035..038) | Ops access to carrier test bed | Pending (ops, non-CI) |

**Access requests needed:**

- [ ] x86 + ARM native CI runners (or cross-build with native smoke).
- [ ] Keycloak 26.x Testcontainers image in the nightly CI environment.
- [ ] Access to the target carrier test bed (or an independent conformance SMSC) for the A-1 non-CI step.
- [ ] Pinned JDK 25 build artifact available to all CI runners (toolchain).

---

## Interworking & Regression

**Components impacted by this feature (and the regression scope):**

| Service/Component | Impact | Regression Scope | Validation Steps |
| --- | --- | --- | --- |
| **codec module** | The parsed-vs-opaque boundary; the more-exposed framer surface | CODEC-001..041 must stay green; ArchUnit inward-only (CODEC-039) + dep allowlist (CODEC-040/041) | Every PR runs the codec unit+fuzz suite; any change to `SmppCommandIds.BIND_FAMILY` fails CODEC-026/027 |
| **relay (event loop)** | The AD-25 single-flipper + the 5 R5 concurrency seams + backpressure | RELAY-001..026; race-soak RELAY-024 nightly | RELAY-001 (flip decision) in PR; conformance + race-soak nightly |
| **security (adjudication)** | The fail-closed crown jewels + zeroization | SEC-001..099; the ~15-branch DENY matrix | SEC port-matrix unit in PR; real-Keycloak nightly |
| **two-proxy seam (forward↔reverse)** | The composed Mode C leg only exercised by E2E-001 | E2E-001 weekly/non-CI | No per-leg test catches forward↔reverse integration bugs |
| **packaged shapes (JAR + Docker)** | jlink modules, Epoll, `--enable-preview`, ZGC, secrets contract | DEPLOY-001..014 | Static scans PR; packaged parity E2E weekly; two-shape parity (DEPLOY-005) is the headline |

**Regression strategy:**

- The P0 suite (64 scenarios) is the release gate: any P0 failure blocks release.
- The codec ArchUnit + dependency-allowlist gates mechanically enforce MAINT-2 (codec extractability) and AD-27 (parsed surface) on every PR — a drift here fails the build before review.
- Two-shape parity (DEPLOY-005) runs weekly; any parity delta is a P1 regression (R12).
- Cross-team coordination: the A-1 non-CI step requires ops + carrier access — it is not automatable and must be re-run after any relay/affinity change.

---

## Appendix A: Code Examples & Tagging

**JUnit 5 / Jupiter tagging for selective execution** (replaces Playwright `@P0`/`@API` grep — this is a JVM backend):

```java
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.assertThat;

// P0 critical — fail-closed DENY matrix
@Tag("p0")
@Tag("unit")
@Tag("sec")
class IntrospectionDenyMatrixTest {

    @DisplayName("SEC-013: introspection active:false -> DenyInvalid")
    @Test
    void active_false_is_denyInvalid() {
        var idp = new FakeIntrospectionHttp();           // in-JVM fake, no real IdP
        idp.stub(200, "{\"active\":false}");
        var verifier = new IntrospectionAdapter(idp, Clock.fixed(Instant.EPOCH, ZoneOffset.UTC));

        Verdict v = verifier.verify(opaqueToken()).join();

        assertThat(v).isEqualTo(Verdict.DenyInvalid());
    }

    @DisplayName("SEC-016: introspection active wrong type -> DenyIndeterminate")
    @ParameterizedTest(name = "\"{0}\" -> DenyIndeterminate")
    @ValueSource(strings = {"true\"","1\"","yes\""})
    void active_wrong_type_is_indeterminate(String badActive) {
        var idp = new FakeIntrospectionHttp();
        idp.stub(200, "{\"active\":" + badActive + "}");
        var verifier = new IntrospectionAdapter(idp, Clock.fixed(Instant.EPOCH, ZoneOffset.UTC));

        assertThat(verifier.verify(opaqueToken()).join()).isEqualTo(Verdict.DenyIndeterminate());
    }
}
```

**Run specific tags via Gradle/JUnit 5:**

```bash
# Run only P0 tests (JUnit 5 @Tag filter)
./gradlew test -Dinclude.tags=p0

# Run P0 + P1
./gradlew test -Dinclude.tags='p0 | p1'

# Run only the security area
./gradlew test -Dinclude.tags=sec

# Run only unit tests in PR
./gradlew test -Dinclude.tags=unit

# Nightly: run the full suite including perf + fuzz
./gradlew test jmh test --tests '*' -Dinclude.tags='perf | fuzz | integration'
```

**Fuzz example (JQF on the framing decoder — CODEC-011):**

```java
import com.code_intelligence.jaz.api.FuzzTest;
import static org.assertj.core.api.Assertions.assertThat;

class SmppFrameDecoderFuzzTest {

    // JQF structural fuzz: arbitrary byte stream through the framer
    @FuzzTest(maxDuration = "60s")
    void framer_never_throws_and_bounds_memory(byte[] bytes) {
        var ch = new EmbeddedChannel(new SmppFrameDecoder(MAX_FRAME));
        try {
            ch.writeInbound(Unpooled.wrappedBuffer(bytes));
        } catch (Throwable ignored) {
            // invariant: no Throwable escapes decode to the event loop
        }
        // bounded memory: recording allocator shows no alloc > cap
        assertThat(recordingAllocator.maxAlloc()).isLessThanOrEqualTo(MAX_FRAME);
    }
}
```

**BlockHound positive control (RELAY-018 — the MODEL for CI-gate positive controls):**

```java
@Tag("p1")
@Tag("integration")
@Tag("relay")
@Test
@DisplayName("RELAY-018: BlockHound FIRES on an injected blocking call on the event loop")
void blockhound_detects_injected_blocking(BlockHoundTestExtension bh) {
    bh.allowBlockingCallsIn("jdk.internal");           // legitimate JDK internals
    bh.injectBlockingCallIntoRelayHandler(Duration.ofMillis(50)); // the probe

    assertThatThrownBy(() -> driveBindCoupleSplice())
        .isInstanceOf(BlockingOperationError.class);   // gate FIRES, not silently passes
}
```

---

## Appendix B: Knowledge Base References

- **Risk Governance**: `knowledge/risk-governance.md` — risk scoring methodology (P × I, 1–3 each).
- **Probability-Impact**: `knowledge/probability-impact.md` — P/I scale calibration.
- **Test Levels Framework**: `knowledge/test-levels-framework.md` — unit vs fuzz vs integration vs conformance vs perf vs e2e selection; lowest-sufficient level.
- **Test Priorities Matrix**: maps score → P0/P1/P2/P3 (9 → P0, 6–8 → P1, 4–5 → P2, 1–3 → P3).
- **NFR Criteria**: `knowledge/nfr-criteria.md` — in-scope NFR categories + threshold sources (no UNKNOWN thresholds).
- **Test Quality**: `knowledge/test-quality.md` — definition of done (deterministic, no Thread.sleep, PARANOID where allocation matters).
- **ADR Quality / Readiness Checklist**: `knowledge/adr-quality-readiness-checklist.md` — AD-1..AD-31 invariants the tests validate.

**Cross-document consistency:**

- Both architecture + QA docs reference the same 35 risks by ID (R1..R38, excluding R4/R13/R19) and the same 7 open blockers (Q1..Q7).
- Both use consistent priority levels (P0/P1/P2/P3) and the same scenario IDs (RELAY-/SEC-/CODEC-/OBS-/DEPLOY-/PERF-/E2E-).
- Scenario detail lives once in the catalog (`test-coverage-scenarios.md`); this doc summarizes P0/P1 and points to it for P2/P3 + per-scenario technique/tooling.

---

**Generated by:** BMad TEA Agent (Murat, Master Test Architect)
**Workflow:** `bmad-testarch-test-design` (system-level, Step 5)
**Version:** 4.0 (BMad v6) — adapted to JVM toolchain (JUnit 5 / JQF / JMH / in-JVM mock SMSC / Spring Boot slices / BlockHound / ArchUnit / CI gates)
