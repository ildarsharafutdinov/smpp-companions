---
workflowStatus: 'completed'
totalSteps: 5
stepsCompleted: ['step-01-detect-mode', 'step-02-load-context', 'step-03-risk-and-testability', 'step-04-coverage-plan', 'step-05-generate-output']
lastStep: 'step-05-generate-output'
nextStep: ''
lastSaved: '2026-07-22'
inputDocuments:
  - _bmad-output/planning-artifacts/prds/prd-smpp-companions-2026-07-18/prd.md
  - _bmad-output/planning-artifacts/prds/prd-smpp-companions-2026-07-18/.perf-anchors.json
  - _bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/ARCHITECTURE-SPINE.md
  - _bmad-output/planning-artifacts/epics.md
  - knowledge/risk-governance.md
  - knowledge/probability-impact.md
  - knowledge/nfr-criteria.md
  - knowledge/test-levels-framework.md
  - knowledge/test-quality.md
  - knowledge/adr-quality-readiness-checklist.md
---

# Test Design — Workflow Progress

**Project:** smpp-companions (SMPP 3.4 Security Proxy)
**Architect:** Murat (Master Test Architect)
**Mode:** System-Level
**Risk threshold:** p1

## Step 1: Detect Mode & Prerequisites — COMPLETE

### Mode Detection

Both detection methods converge on **System-Level Mode**:

- **User-intent priority (A):** Project has *both* PRD/ADR/architecture *and* epics.
  Per rule "Both PRD/ADR + Epic/Stories → Prefer System-Level Mode first."
- **File-based detection (B):** No `implementation_artifacts/sprint-status.yaml` exists
  → System-Level Mode.

### Prerequisite Check (System-Level)

| Required input | Status | Source |
|---|---|---|
| PRD (functional + non-functional) | ✅ | `planning-artifacts/prds/prd-smpp-companions-2026-07-18/prd.md` |
| ADR / architecture decision records | ✅ | AD-1..AD-31 in `planning-artifacts/epics.md` |
| Architecture / tech-spec document | ✅ | `planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/ARCHITECTURE-SPINE.md` |

No halt conditions. Proceeding to context load.

## Step 2: Load Context & Knowledge Base — COMPLETE

### Configuration (tea/config.yaml)
- tea_use_playwright_utils: true · tea_use_pactjs_utils: false · tea_pact_mcp: none · tea_browser_automation: auto
- test_stack_type: auto → **detected_stack = backend (JVM)** — Gradle multi-module, no source yet (declared stack from architecture)

### Stack & dependencies
- JDK 25 LTS (`--enable-preview` process-wide for StructuredTaskScope JEP 505) · generational ZGC
- Netty 4.2.16.Final (event loops / data plane) · Spring Boot 4.1.x (config/DI/lifecycle/Micrometer) · Nimbus JOSE+JWT 10.9.1
- jSMPP 3.0.2 (**test/interop only**) · Micrometer PrometheusMeterRegistry
- Gradle 2-module seam: `codec` (PURE, zero upward deps) + `proxy`

### Integration points
- Legacy SMPP 3.4 ESME ↔ proxy ↔ SMSC (two legs); bind family inspected, all else opaque splice
- OIDC provider (Keycloak 26.x ref): ROPC token endpoint + JWKS + RFC 7662 introspection fallback
- TLS modes A (one-way) / B (plaintext, reverse-only) / C (mTLS); `/metrics` loopback Prometheus scrape

### Conditional fragment decisions
- **Playwright CLI/MCP/browser exploration:** SKIP — headless backend, no UI.
- **Playwright utils:** flagged enabled, but the declared stack is **JVM/Java**, not JS/TS — the real test tooling is JUnit 5 + JQF/jqwik (fuzz) + JMH (perf) + in-JVM mock SMSC + jSMPP interop (fixed by AD-24). Playwright utils are N/A here.
- **Pact.js utils:** SKIP — disabled; not microservices. SMPP 3.4 wire "contract" is validated via the from-scratch conformance suite + jSMPP interop, not consumer-driven HTTP pacts.

### Locked NFR thresholds (no missing thresholds — all locked or consciously deferred to config)
- PERF-1 ≥10,000 submit_sm/sec (stretch ~25K), mTLS both legs, OIDC cached; publish p50/p90/p99/p99.9 table
- PERF-2 10K idle socket pairs (~20K sockets) <1 GB heap / <1 vCPU idle
- PERF-3 bind p99 ~250 ms warm / ≤2 s cold / fail-closed DENY 2–5 s
- PERF-4 sub-ms per-PDU relay; codec JMH encode 3×10⁵–1.5×10⁶, decode 5×10⁵–1.8×10⁶ ops/s/core
- SEC-1 TLS 1.2 min/1.3 pref + cipher allowlist · SEC-2 parser/splice robustness · SEC-3..5 provider link / no rolled crypto / CVE hygiene
- PRIV-1 no SMS body persistence; TRACE-only body logging · REL-1..4 integrity/backpressure/graceful-shutdown/statelessness
- Deferred-to-config (not gaps): exact cipher list, JWKS TTL/refresh/ROPC timeouts, histogram buckets, `application.yml` keys

### Testability posture (from AD-24 + two-module seam)
- **Excellent isolation:** `codec` is PURE → unit + fuzz testable with zero proxy deps.
- **Conformance required:** from-scratch SMPP 3.4 conformance suite (no OSS suite exists) on both legs.
- **Fuzzing required (SEC-2):** BOTH the bind-family parser AND the framing decoder (framing is the more-exposed surface — runs on every PDU for connection lifetime).
- **Mocks/fixtures fixed:** in-JVM mock SMSC (on `codec`); jSMPP 3.0.2 independent interop counterpart; A-1 carrier check = non-CI ops step.
- **6 epics, linear DAG:** E1 foundation/codec/config → E2 relay + A-1 smoke → E3 TLS+ROPC → E4 metrics/logs → E5 JAR+Docker → E6 perf+docs.

### Knowledge fragments loaded (System-Level required + scoring scale)
adr-quality-readiness-checklist · nfr-criteria · test-levels-framework · risk-governance · test-quality · probability-impact

> Threat-model grounding: `walkthrough.md` (§2 trust model, §10 register) + `reviews/verify-security.md` (SM-2 re-verification: **pass-with-findings**, prior S1–S15 CLOSED, new N1–N4 all folded into the revised AD-10/11/12 + register). Architecture is post-adversarial-review; the spine's security claims are already verified — test design inherits them as invariants to validate, not to rediscover.

## Step 3: Testability & Risk Assessment — COMPLETE

### 1. Testability Review (System-Level)

**🚨 Testability Concerns (actionable first)**

1. **A-1 is unfalsifiable in CI (controllability).** The load-bearing assumption — carrier allows multiple concurrent binds per `system_id` + DLR affinity — can only be smoke-tested against a real/conformance SMSC as a **non-CI ops step** (AD-24). The in-JVM mock SMSC *emulates* A-1, i.e. assumes the property it should validate. If A-1 is false the entire stateless design is invalid and CI cannot catch it. → Model affinity in the in-JVM mock + jSMPP server-side mock; ship a documented non-CI A-1 checklist (docks under docs, AD-31); smoke early in Epic 2.

2. **Time-dependent OIDC/JWT paths need an injectable clock (controllability).** `exp`/`nbf` adjudication, JWKS refresh-ahead, ROPC/bind timeouts (PERF-3 fail-closed 2–5 s), kid-miss background refresh — all time-sensitive. Sleeping in tests is non-deterministic. → `BindCredentialVerifier` + JWKS cache + adjudication timers MUST accept an injected `Clock`/scheduler seam for deterministic negative-path and timeout tests.

3. **Fail-closed completeness is an exhaustive enumeration, not a happy path (observability-of-correctness).** AD-11 carries ~12 indeterminate branches + the "DENY-wins-on-disagreement" precedence + the RFC 7662 introspection enumeration + Mode C handshake-fail. A single missed branch = accept-on-indeterminate = the worst defect class. → Parameterized negative-path matrix (highest-value test investment).

4. **Concurrency correctness is probabilistic, not deterministic (reliability).** The AD-25 single-flipper flag, AD-2/AD-30 `AUTO_READ` backpressure, `ConnectionRegistry` `channelInactive` teardown, `AtomicReference<JwkSet>` swap, STS fan-out join — races surface as REL-1 drop/duplicate/corrupt, which are statistical. → `jcstress`-style invariants for the flag/registry; relay conformance under load; soak for backpressure/memory.

5. **Performance targets are self-measured with no reference (methodology = the bar).** PERF-1/2/3/4 are first-of-kind; SM-3 (the craft headline) lives or dies on harness methodology (per `.perf-anchors` calibration): HW/JDK/reboot/sysctl disclosure, percentile tables p50/p90/p99/p99.9, open-model load, load-gen on separate cores, saturation knee + failure modes reported, no-crypto baseline to attribute relay cost vs. crypto cost. → The harness is itself a deliverable (Epic 6) with explicit methodology gates.

6. **Minimal observability limits post-failure diagnosis (observability).** No management API, no dashboard, loopback-only `/metrics`, TRACE-only body logging (off by default). A prod-only failure has thin tooling. → Assert the observability surface is *sufficient* (right counters exist, cardinality bounded) and assert PRIV-1 by **absence** (message content never in logs/metrics at default level — hard to test, must be explicit).

7. **Two packaging shapes must stay feature-equivalent (deployability/parity).** JAR + distroless Docker (jlink) doubles some integration surface; the Docker-secrets contract (DEP-1) is only exercisable in the Docker shape. → Parity smoke in both shapes; Docker-secrets E2E in Docker only.

**✅ Testability Assessment Summary (already strong)**
- **Codec seam = textbook isolation.** `codec` is PURE (zero upward deps) → unit + fuzz with no proxy/TLS/OIDC deps. The Gradle boundary enforces MAINT-2 more strongly than any test rule.
- **`BindCredentialVerifier` port** (`CompletableFuture<Verdict>`) + `sealed Verdict` + `BindCredential` record → adjudication unit-testable with a fake verifier, decoupled from Nimbus/ROPC/IdP.
- **`SpliceObserver` interface** + pinned triggers → metrics/observability testable via a capturing observer without a live relay.
- **Fail-closed is a closed enumeration** → cleanly parameterizable.
- **Two independent SMSC stand-ins** (in-JVM mock on `codec` + jSMPP 3.0.2) → cross-validation of conformance.
- **`@ConfigurationProperties` + fail-fast role×mode matrix** → config validation is a finite, exhaustively unit-testable table.
- **Named `MaxDirectMemorySize` formula + shared `PooledByteBufAllocator` + `ByteBufAllocatorMetric`** → memory budget is computable/assertable.

**Architecturally Significant Requirements (ASRs)**
| ASR | Status | Note |
|---|---|---|
| A-1 (carrier multi-bind + DLR affinity) | **ACTIONABLE** | Load-bearing; non-CI ops test + conformance-mock affinity modeling |
| AD-25 bind→splice single-flipper | **ACTIONABLE** | Correctness + concurrency invariants (the one load-bearing runtime mechanism) |
| AD-11 fail-closed enumeration | **ACTIONABLE** | Exhaustive negative-path matrix |
| AD-5 STS preview-API (JEP 505) | **FYI** | Pin exact JDK 25 build; confine to control plane; CI on pinned build + JFR pin check |
| ROPC hard-dependency (AD-12) | **FYI** | Can't test "deprecation trajectory"; test ROPC works on Keycloak 26.x now + viability probe + fallback decision tree |

### 2. Risk Assessment (P×I, 1–3 each; score = P×I)

Priority mapping (aligns with `risk_threshold: p1`): **score 9 → P0 (gate-blocker) · 6–8 → P1 (must cover) · 4–5 → P2 (monitor) · 1–3 → P3 (document)**. P = likelihood of a defect in this area (driven by complexity/novelty/fragility); I = severity if it escapes to production.

| ID | Risk | Cat | P | I | Score | Pri | Action |
|----|------|-----|---|---|-------|-----|--------|
| **R2** | ROPC adapter defect / IdP interop failure (JWT vs opaque, mTLS provider auth, Keycloak version drift) — the most fragile dependency | SEC | 3 | 3 | **9** | **P0** | BLOCK — viability probe (Story 3.1) + all 4 AD-12 paths + fallback decision tree |
| **R1** | A fail-closed branch is missed → accept-on-indeterminate (AD-11 ~12 branches + introspection + precedence) | SEC | 2 | 3 | 6 | P1 | MITIGATE — exhaustive parameterized negative-path matrix |
| **R3** | Framing/codec parser crash or DoS on malformed input (framing runs on every PDU — most-exposed surface) | SEC | 2 | 3 | 6 | P1 | MITIGATE — structural fuzz of BOTH parsers + AD-30 length guards |
| **R4** | A-1 false → stateless design invalid (DLRs misroute) | DATA | 2 | 3 | 6 | P1 | MITIGATE — conformance-mock affinity + non-CI real-carrier checklist + early Epic 2 smoke |
| **R5** | Concurrency race → REL-1 transit-integrity violation (drop/dup/corrupt) | DATA | 2 | 3 | 6 | P1 | MITIGATE — `jcstress` flag/registry + relay conformance + soak |
| **R7** | mTLS Mode C / trust-store defect (cacerts fallback, REQUIRE vs WANT, PKIX, per-instance certs) | SEC | 2 | 3 | 6 | P1 | MITIGATE — TLS vectors modes A/B/C + trust-store validation enumeration |
| **R8** | Credential-free-at-rest / zeroization invariant violated (password/token escapes via `String`, log, or heap) | SEC | 2 | 3 | 6 | P1 | MITIGATE — no-password-in-logs/heap/string-pool + zeroization on all paths incl. exception |
| R6 | PERF targets unmet or overclaimed (self-measured, first-of-kind) | PERF | 2 | 2 | 4 | P2 | MONITOR — honest harness methodology + no-crypto baseline |
| R9 | STS preview-API behavior drift across JDK 25 builds | TECH | 2 | 2 | 4 | P2 | MONITOR — pin JDK build; confine to control plane |
| R10 | Metrics cardinality DoS or PRIV-1 body leak via `/metrics` | SEC | 2 | 2 | 4 | P2 | MONITOR — cardinality bounded to routing table + content-suppression tests |
| R11 | Graceful shutdown drops in-flight or races a partial verdict (AD-22 ordering) | REL | 2 | 2 | 4 | P2 | MONITOR — SIGTERM ordering test |
| R12 | Two-shape parity drift (JAR vs Docker) | OPS | 2 | 2 | 4 | P2 | MONITOR — parity smoke both shapes; Docker-secrets E2E Docker-only |
| R13 | TLS floor / cipher-allowlist misconfig or egress endpoint-identification break (raw-IP SMSC, AD-20) | SEC | 2 | 2 | 4 | P2 | MONITOR — TLS-floor + endpoint-id vectors |
| R14 | Production codec diverges from SMPP 3.4 (jSMPP interop not exercised) | COMP | 2 | 2 | 4 | P2 | MONITOR — jSMPP interop on both legs |
| R16 | CVE / dependency drift (Netty, JDK, Nimbus) | SEC | 2 | 2 | 4 | P2 | MONITOR — CVE scan in CI; pin Nimbus ≥10.0.2 (CVE-2025-53864) |
| R15 | Native-image-compat claim unfalsifiable in v1 (no build) | MAINT | 1 | 1 | 1 | P3 | DOCUMENT — stretch only |

**Tally:** 1 BLOCK (P0: R2) · 6 MITIGATE (P1: R1, R3, R4, R5, R7, R8) · 8 MONITOR (P2) · 1 DOCUMENT (P3). All P0+P1 must have explicit coverage in the plan (risk_threshold = p1).

### 3. NFR Planning Assessment

**Categories in scope:** Security (SEC-1..5, PRIV-1) · Performance (PERF-1..4) · Reliability (REL-1..4) · Maintainability (MAINT-1..5) · Deployability (DEP-1, FR-DEPLOY-1..4) · Operability/Observability (OPS-1..2, OBS-1..3) · Compatibility (COMP-1..4). **No compliance category** (not regulated). **No UNKNOWN thresholds** — every NFR is locked or consciously deferred to config.

| NFR | Threshold (locked) | Planned evidence | Tool/level |
|-----|--------------------|------------------|------------|
| PERF-1 | ≥10K submit_sm/s (stretch ~25K), mTLS both legs, OIDC cached; p50/90/99/99.9 table | End-to-end relay percentile harness + no-crypto baseline | JMH-style harness / in-JVM mock SMSC · perf |
| PERF-2 | 10K idle socket pairs (<1 GB heap / <1 vCPU) | Idle-pair resource demo (heap/RSS/CPU) | resource demo · perf |
| PERF-3 | bind p99 ~250 ms warm / ≤2 s cold / DENY 2–5 s | Bind-latency harness warm + cold + timeout→DENY | harness + injected clock · perf |
| PERF-4 | sub-ms per-PDU; codec encode 3×10⁵–1.5×10⁶ / decode 5×10⁵–1.8×10⁶ ops/s/core | JMH codec microbench | JMH · unit/perf |
| SEC-1 | TLS 1.2 min/1.3 pref + cipher allowlist | TLS-floor + allowlist + endpoint-id vectors | TLS vectors · integration |
| SEC-2 | parser/splice robustness | Fuzz BOTH parsers + oversized-frame/backpressure | JQF/jqwik · fuzz + integration |
| SEC-3..5 | provider link / no rolled crypto / CVE hygiene | provider-https fail-fast + CVE scan CI | integration + CI scan |
| PRIV-1 | no body persistence; TRACE-only body logging | content-never-in-logs/metrics at default + zeroization | negative assertions · integration |
| REL-1..4 | integrity / backpressure / graceful-shutdown / statelessness | relay conformance + backpressure soak + SIGTERM ordering + no `message_id` map | conformance + soak · integration |
| COMP-1..4 | interop / JDK 25 / Linux / IPv4 | conformance both legs + jSMPP interop + JFR pin check + build/runtime gate | conformance + interop · integration |
| MAINT-2/4/5 | codec extractable / test strategy / native-image stretch | codec isolation (no upward deps) + coverage gate + documented stretch | arch test + CI |
| DEP-1 / FR-DEPLOY | Docker secrets / two-shape parity | parity smoke both shapes + Docker-secrets E2E | E2E · docker |
| OPS-1..2 / OBS-1..3 | docs surface / cert rotation / read-only loopback metrics | /metrics cardinality+content+loopback + log contract + no-mgmt-API | integration |

**Boundary respected:** this step *plans* NFR validation (thresholds + evidence + tools). Final PASS/CONCERNS/FAIL assessment is deferred to `nfr-assess` after implementation evidence exists.

### 4. Risk Findings Summary

The trust crown jewel (fail-closed + credential-free-at-rest) and the stateless-splice premise (A-1) concentrate the risk. **R2 (ROPC) is the lone gate-blocker** — consistent with the architecture calling it the single most fragile dependency — and its mitigation is already structured in the epic plan (Story 3.1 viability probe + 4 AD-12 paths + fallback decision tree); test coverage must mirror that split. The six P1 risks (R1/R3/R4/R5/R7/R8) are the non-negotiable coverage core; the eight P2 risks are monitored with targeted tests; R15 is documented only. Testability is strong where the architecture invested in seams (codec purity, the verifier port, SpliceObserver, the config matrix) and weak where physics/external-dependencies intrude (A-1 in CI, preview-API JDK pinning, self-measured perf).

### Step 3 — Red-team reconciliation (4-lens adversarial workflow; REVISED REGISTER)

Provenance: a 4-lens adversarial workflow (security / performance / reliability / conformance-ops) critiqued the Step-3 register against the loaded PRD+spine+epics+security-review. Below is the reconciled register. Rescoring decisions are Murat's, justified.

**Rescoring accepted (9 raises, 0 lowers):**
- **R1 6→9 P0** (fail-closed): ~15 distinct DENY branches across TWO auth paths (ROPC token-endpoint + RFC 7662 introspection) × happy-path implementation bias × STS-preview concurrency; a miss = accept-on-indeterminate = credential bypass. Accept — but **decompose into per-branch sub-scenarios** (a single catch-all is un-trackable).
- **R5 6→9 P0** (concurrency→REL-1): not one worry but ≥5 distinct fragile seams (pre-couple window, registry teardown race, half-close/unbind/RST ordering, partial-A-1 affinity); statistical defects the shared-stack mock cannot surface; REL-1 is the headline guarantee and silent corruption is the worst failure class. Accept — **decompose into per-seam sub-scenarios**.
- **R7 6→9 P0** (trust anchoring): the JDK/Netty **default** for a missing peer trust store IS `cacerts` — the secure state holds only via explicit override, so one forgotten line silently reverts to trust-root collapse (MitM SMSC harvests plaintext passwords). "Default-state-is-insecure" ⇒ P=3. Merges egress AD-26 + cert edge-cases (wrong-EKU, expired, REQUIRE-vs-WANT, self-signed).
- **R8 6→9 P0** (credential-free/zeroization): the product's HEADLINE invariant + Java zeroization fragility (GC/escape-analysis/`String` interning) + many escape channels (logs, metrics, `Verdict`/`CompletableFuture` capture, `ScopedValue` outliving scope, JFR OldObjectSample, heap/core dump). Merges token-discard + JFR/dump.
- **R6 4→6 P1**, **R11 4→6 P1**, **R12 4→6 P1**, **R14 4→6 P1**, **R16 4→6 P1** — all accepted (methodology-is-the-bar for a portfolio headline; shutdown dropping in-flight SMS = REL-1; jlink crypto-module omission + `--enable-preview` threading; weak oracle landscape; high CVE cadence with NO automated gate).

**R2 stays 9 P0** (availability dimension) deliberately distinct from R1 (credential dimension) to avoid double-counting — R2 = total bind outage; R1 = silent mis-adjudication.

**Structural blind spots the red-team exposed (shape the coverage plan):**
1. **Oracle independence (deepest gap).** The in-JVM mock SMSC is built ON the production codec (AD-24) → shares its parsing bugs → cannot catch codec defects; jSMPP 3.0.2 is the only independent oracle and is partial. ⇒ Add a **spec-derived golden-vector corpus** (authoritative SMPP 3.4 byte sequences + expected decode/forward outcomes) as a 3rd oracle independent of both. (Drives R14, R33, conformance coverage.)
2. **Concurrency defects need a race-fuzz harness, not just load.** Single-shot conformance and the throughput run won't surface registry teardown races, half-close ordering, or write-failure propagation. ⇒ A **delay-injection / event-loop-jitter / randomized-channelInvalid soak** (Epic 6 soak is throughput-oriented, not race-oriented).
3. **AD-4 (no blocking on the event loop) is convention-enforced, not mechanically asserted.** JFR `jdk.VirtualThreadPinned` catches VT pinning only — it does nothing for a platform-thread Netty event loop stalled by a stray blocking call. ⇒ **BlockHound (or an event-loop-latency watchdog) on the event-loop threads.**
4. **Deployer-dependent controls** (Mode A ACL-isolation, egress cacerts-prevention) have a narrow CI-testable portion: the loud startup warning + opt-in ack + runbook doc + a config/startup scan. The ACL/cacerts prevention itself is a deploy-time invariant, not an integration test.
5. **Injectable `Clock` seam** is mandatory for deterministic time-based tests (exp/nbf skew, ROPC/PERF-3 timeouts, kid-miss refresh).
6. **Lift release-shape checks** (two-shape parity, Docker SIGTERM/PID-1, secrets contract, loopback binding) **into Epic 5 acceptance** — catch when cheapest, not at the Epic 6 gate.

#### REVISED RISK REGISTER (post red-team)

| ID | Risk | Cat | P×I | Pri | Owning epic(s) |
|----|------|-----|-----|-----|----------------|
| **R1** | Fail-closed branch miss → accept-on-indeterminate (~15 DENY branches: ROPC token-endpoint + RFC7662 introspection + JWT-defense-in-depth crypto: alg=none, alg-confusion, kid, exp/nbf skew) — **DECOMPOSED** | SEC | 9 | **P0** | E3 |
| **R2** | ROPC/IdP interop failure → total bind outage (availability) | SEC | 9 | **P0** | E3 |
| **R5** | Concurrency race → REL-1 transit-integrity violation (pre-couple window, registry teardown race, half-close/unbind/RST ordering, partial-A-1 affinity) — **DECOMPOSED** | DATA | 9 | **P0** | E2,E3 |
| **R7** | Trust-anchoring defect (cacerts default on ingress Mode C + egress AD-26, REQUIRE-vs-WANT, cert edge-cases: EKU/expired/self-signed/unknown-ext) | SEC | 9 | **P0** | E3 |
| **R8** | Credential-free-at-rest / zeroization violated (password + token discard; escape via String/log/metric/JFR/heap-dump) | SEC | 9 | **P0** | E3 |
| R3 | Parser/framing DoS or crash on malformed input (most-exposed surface) + per-channel exception containment (relay-wide DoS if it escapes the event loop) | SEC | 6 | P1 | E1,E2 |
| R6 | PERF targets overclaimed / methodology bar (self-measured, first-of-kind, 4 regimes) | PERF | 6 | P1 | E6 |
| R11 | Graceful shutdown drops in-flight / partial-verdict race (AD-22 7-step ordering under concurrency) | REL | 6 | P1 | E4,E5 |
| R12 | Two-shape parity drift (jlink crypto-module omission, `--enable-preview` threading, ZGC+MaxDirectMemorySize both shapes) | OPS | 6 | P1 | E5 |
| R14 | Codec diverges from SMPP 3.4 (weak oracle: mock shares codec, jSMPP partial) | COMP | 6 | P1 | E1,E2 |
| R16 | CVE / dependency drift — Netty/JDK/Nimbus, NO automated gate | SEC | 6 | P1 | E1,CI |
| R17 | Startup fail-fast refuse-branch coverage (AD-17/13/12/18 matrix: trust-store absent/empty/wrong-format/wrong-password/zero-entries, non-https provider, missing secret file, forward+B rejected, Mode-B-no-ack, bad ports) | SEC | 6 | P1 | E1 |
| R18 | Mode A two-proxy ACL-isolation control unverified (N1; CI-testable = warning+ack+doc+config scan) | SEC | 6 | P1 | E3,E5 |
| R25 | Load-gen coordinated omission / open-vs-closed model (from-scratch, no reference) invalidates PERF-1 percentiles | PERF | 6 | P1 | E6 |
| R26 | JMH codec-bench harness pitfalls (DCE, warmup/fork, Blackhole, GC interference) | PERF | 6 | P1 | E1,E6 |
| R27 | Direct-memory budget exhaustion under load/error/burst (AD-30 formula-at-cliff + correlated slow-consumer burst + write-failure buffer leak + error-path ByteBuf leak) | PERF | 6 | P1 | E2,E6 |
| R28 | Event-loop blocking by stray blocking call — convention-enforced, not mechanical (JFR catches VT pinning only) | PERF | 6 | P1 | E2,E6 |
| R33 | Conformance suite is sole correctness oracle, shares author's mental model → need golden-vector 3rd oracle | TECH | 6 | P1 | E1,E2 |
| R9 | STS preview-API drift (+ STS-fork retaining BindCredential beyond scope; build-pin enforcement gap) | TECH | 4 | P2 | E3 |
| R10 | /metrics: cardinality DoS + PRIV-1 body leak + handler hardening (method/path/smuggling) + loopback-only binding | SEC | 4 | P2 | E4 |
| R20 | JWKS kid-miss refresh storm / thundering-herd (no single-flight dedup) → IdP amplification / self-DoS | SEC | 4 | P2 | E3 |
| R21 | Adjudication VT pool + SslHandler delegated-task pool exhaustion → bind-plane/handshake DoS | SEC | 4 | P2 | E3,E6 |
| R22 | Secret file-path-injection AD-18 (reject env-var VALUE; fail-fast on missing/unreadable) | SEC | 4 | P2 | E1,E5 |
| R23 | bind_resp status-code → OIDC-outcome mapping oracle (system_id enumeration / IdP availability) | SEC | 4 | P2 | E3 |
| R29 | Bind-rate ceiling hidden by mock IdP (no verdict cache + Keycloak ~15 logins/s/vCPU) | PERF | 4 | P2 | E3,E6 |
| R30 | GC/backpressure perf cliffs (ZGC pause under load, backpressure-knee thrash) | PERF | 4 | P2 | E6 |
| R31 | CompletableFuture×ScopedValue context-propagation gap on verify() return path | TECH | 4 | P2 | E3 |
| R32 | Egress-establishment failure post-ALLOW — underspecified error path (legacy hangs / pair leak) | OPS | 4 | P2 | E2,E3 |
| R34 | Docker SIGTERM/PID-1 propagation (packaged shutdown never reaches JVM) | OPS | 4 | P2 | E5 |
| R35 | DEP-1 Docker-secrets / distroless non-root read + env-var-secret rejection | OPS | 4 | P2 | E5 |
| R36 | COMP-3/4 build+runtime gates (Epoll-vs-NIO dev/prod diff, IPv4-only at bind+outbound, x86/ARM CI matrix) | TECH | 4 | P2 | E1,E5,E6 |
| R37 | OPS-1 docs drift from `companion.*` config surface | OPS | 4 | P2 | E6 |
| R38 | A-1 non-CI ops plan has no pass/fail or DLR-affinity criteria (cannot actually falsify A-1) | OPS | 4 | P2 | E2,docs |
| R15 | Native-image-compat claim unfalsifiable in v1 | MAINT | 1 | P3 | — |
| R24 | TLS 1.3 0-RTT/early-data replay not asserted disabled | SEC | 2 | P3 | E3 |

**Tally (revised):** 5 P0 (R1,R2,R5,R7,R8) · 13 P1 (R3,R6,R11,R12,R14,R16,R17,R18,R25,R26,R27,R28,R33) · 15 P2 · 2 P3 = 35 risks. Coverage core (risk_threshold=p1) = the 5 P0 + 13 P1 = **18 risks with mandatory explicit coverage**.

## Step 4: Coverage Plan & Execution Strategy — COMPLETE

Provenance: a 6-area-designer + 1-critic workflow (CODEC/RELAY/SEC/OBS/DEPLOY/PERF) produced **242 atomic test scenarios**; the critic cross-checked the set against all 18 P0/P1 risks + the NFR set. Below is the reconciled synthesis (full per-scenario catalog is written into the QA doc in Step 5). Area totals: CODEC 40 · RELAY 24 · SEC 91 · OBS 42 · DEPLOY 14 · PERF 31 = **242 (+~10 critic fixes ≈ 252)**.

### Critic reconciliation (applied)
**Added scenarios (closing P0/P1 + NFR-evidence holes):**
- `SEC-093` — introspection HTTP-error matrix (network-error / 3xx / 4xx≠default → DenyIndeterminate) via the port; closes the asymmetric R1 hole (ROPC path was exhaustive, introspection wasn't).
- `SEC-094` — JWT/ROPC **no-verdict-cache** focused unit test (same `BindCredential` twice → token endpoint hit twice), mirroring SEC-019 for the JWT path (AD-12 load-bearing invariant).
- `SEC-095` — extend SEC-042 (type) + SEC-045 (sink-escape) to the **OIDC client_secret** when the non-mTLS confidential-client path is configured (long-lived in-memory secret).
- `SEC-096` / `SEC-097` — R17 role×mode cells: reverse+A trust-store-missing → refuse; positive forward+A-starts-without-SMSC.
- `RELAY-025` — REL-4 **structural arch-scan**: no `message_id`→`system_id` map exists in `relay/` (the statelessness invariant; a redundant perf cache would break it without failing RELAY-011).
- `SEC-098` — FR-AUTH-3 **no-shared-golden-key** config/build scan (per-instance Mode C certs).
- `RELAY-026` — AD-30 **shared-constant static assertion** (ArchUnit/Gradle): codec-max (65536) and `MaxDirectMemorySize` formula input reference ONE named constant (compile-time drift prevention — a runtime soak can't catch conservative drift).
- `E2E-001` — **two-real-proxy-instance** (forward↔reverse) composed-flow end-to-end (forward OIDC adjudication → forward↔reverse Mode C leg → reverse→SMSC); catches seam bugs no per-leg test can.
- `SEC-099` / `CODEC-041` / `OBS-043` — **CI-gate positive controls** (model on RELAY-018's BlockHound control): inject a known-vulnerable Netty coordinate / off-pin JDK / forbidden spring-boot-starter-web dep and assert each gate *fires*, not merely exists.

**Weak/non-implementable scenarios fixed:**
- `SEC-037` (expired cert) — injectable-clock-past-notAfter is **infeasible** (SSLEngine uses the system clock; `PKIXBuilderParameters.setDate` is banned by AD-13). **Fix:** craft a genuinely already-expired short-lived cert (1970–1971 validity) and assert PKIX rejection against the real clock. (The injectable-Clock seam covers JWT exp/nbf and ROPC/introspection timeouts, **not** TLS cert-path validation — recorded as a testability boundary.)
- `SEC-048` / `SEC-049` (heap/JFR inspection) — non-deterministic after GC / sampled profiler; **reframed** as best-effort fragility guards + a JFR/dump hygiene doc; the deterministic zeroization evidence is SEC-046 (same-reference `char[]` all-`\0` immediately after the zeroize call).
- `SEC-089` (cipher allowlist) — placeholder until the concrete default allowlist is pinned in config (AD-17/SEC-1); marked implementable-after-config.
- `RELAY-002` (pre-couple non-bind PDU) — the test passes for *both* buffer-and-forward and drop, so it validates only determinism, not a REL-1 property. **Blocked on pinning the pre-couple policy** (open question Q1).

**Dedup decisions (4):** keep RELAY-010 + RELAY-017, fold RELAY-016's autoRead-disarmed assertion into RELAY-017's error matrix (write-failure cell was triplicated); merge PERF-041 into RELAY-015 (same-level slow-egress burst); merge PERF-042 into RELAY-017 (subset at higher level); keep OBS-015 only for the e2e packaging/process-exit aspect, drop its re-assertion of splice zero-drop (owned by RELAY-022). Net ≈ −4 → ~248, +~10 additions ≈ **~254 scenarios**.

### Coverage matrix (by area × level; priority breakdown finalized in the QA doc tables)

| Area | Unit | Fuzz | Integration | Conformance | Perf/E2E | Total | P0 concentration |
|------|------|------|-------------|-------------|----------|-------|-------------------|
| CODEC | 26 | 4 | 5 | 5 | — | 40 | — (MAINT-2 purity) |
| RELAY | 4 | 2 (race-soak) | 10 | 7 | 1 | 24 | 12 (R5 seams) |
| SEC | 33 | — | 58 | — | 1 | 91 (+critic) | ~49 (R1/R2/R7/R8) |
| OBS | 2 | — | 39 | 1 | — | 42 | — |
| DEPLOY | — | — | 5 | — | 9 | 14 | — |
| PERF | 1 | — | — | — | 30 | 31 | — |

**P0 scenarios ≈ 61** (RELAY-001..011,024 + SEC-001..049) — all security/integrity-critical, decomposed from the 5 P0 risks. P0 + P1 ≈ 150 form the mandatory coverage core.

### NFR coverage & evidence map (planned validation; final PASS/CONCERNS/FAIL deferred to `nfr-assess`)

| NFR | Evidence scenarios | Tool / level |
|-----|--------------------|--------------|
| PERF-1 ≥10K submit_sm/s | PERF-010/011/013/015/016 | open-model harness + no-crypto baseline · perf |
| PERF-2 10K idle pairs | PERF-020/021 | idle-pair resource demo · perf |
| PERF-3 bind latency | PERF-030/031/032, SEC-092 | bind-latency harness + injectable clock · perf/unit |
| PERF-4 codec/relay | PERF-001..006/017 | JMH + zero-latency mock · perf/unit |
| SEC-1 TLS floor + allowlist | SEC-087/088/089 | JDK SSLEngine vectors · integration |
| SEC-2 parser/splice robustness | CODEC-005..011/025, RELAY-013..017 | JQF/jqwik fuzz + PARANOID · fuzz/integration |
| SEC-3..5 provider link / no-rolled-crypto / CVE | SEC-090/091, SEC-053 | arch scan + CVE gate (positive control) |
| PRIV-1 no body persistence | OBS-010/023/025, SEC-045..049 | negative-by-absence + zeroization |
| REL-1 integrity | RELAY-001..011/024, CODEC-034..038 | conformance + race-soak |
| REL-2 backpressure | RELAY-013..017, PERF-041 | soak + ByteBufAllocatorMetric |
| REL-3 graceful shutdown | OBS-015..021, RELAY-022/023, DEPLOY-006 | Spring lifecycle + SIGTERM |
| REL-4 statelessness | RELAY-011/025 | behavioral + arch-scan (no message_id map) |
| COMP-1..4 interop/JDK/Linux/IPv4 | CODEC-031, OBS-038, DEPLOY-010..014 | jSMPP conformance + CI matrix |
| FR-DEPLOY-1/2/4 + DEP-1 | DEPLOY-001..009 | parity smoke + Docker-secrets E2E |
| OBS-1/2/3 + OPS-1/2 | OBS-001..042 | /metrics + log-contract + no-mgmt-API + docs scan |
| MAINT-2/4/5 | CODEC-039/040, R15 | ArchUnit inward-only + dep allowlist (MAINT-5 = documented stretch, no test by design) |

**No UNKNOWN thresholds.** NFR-evidence gaps closed by critic (REL-4 scan, FR-AUTH-3 scan). MAINT-5 has no scenario by design (AD-23: no v1 native build).

### Execution strategy (adapted to the JVM toolchain)
- **Every PR (<15 min):** all UNIT + bounded FUZZ (JQF/jqwik) + fast INTEGRATION (codec, SEC port-matrix via fake verifier, config fail-fast unit matrix, ArchUnit/dep scans) + the CI build gates (CVE scan SEC-091, JDK pin DEPLOY-014, codec allowlist CODEC-040, docs-config consistency OBS-029) — each with a positive control.
- **PR integration job or nightly:** INTEGRATION needing an in-JVM mock SMSC / EmbeddedChannel pairs / JDK SSLEngine TLS vectors (RELAY conformance, OBS /metrics, SEC TLS vectors) if they exceed the PR budget.
- **Nightly (expensive):** PERF suite (JMH codec bench, open-model relay percentile harness, idle-pair demo, bind-latency) + race-soak RELAY-024 + error/churn matrix RELAY-017 + correlated-burst RELAY-015 + jcstress RELAY-007 (if adopted) + real-Keycloak integration (SEC-028..032, PERF-033).
- **Weekly / manual:** x86+ARM packaged smoke (DEPLOY-013), two-proxy forward↔reverse E2E (E2E-001), endurance soak.
- **Non-CI ops step:** the A-1 real-carrier falsification (OBS-035..038) — defined pass/fail + DLR-affinity criteria; the only genuine A-1 gate.

### Resource estimates (ranges; solo author writing tests test-first across the epics, not a separate QA phase)
| Priority | ~Count | Effort range | Note |
|----------|--------|--------------|------|
| P0 | ~63 | ~150–300 hrs | parametrized security/concurrency/TLS matrices; shared setup amortizes |
| P1 | ~90 | ~90–270 hrs | integration + conformance |
| P2 | ~85 | ~45–130 hrs | edge cases, docs scans |
| P3 | ~4 | ~4–8 hrs | TLS 0-RTT, native-image note |
| **Total** | **~254** | **~290–710 hrs (~7–18 weeks FTE)** | distributed across E1–E6 implementation |

### Quality gates
- P0 pass rate = **100%**; P1 pass rate **≥ 95%**; no open P0/P1-risk scenario failures at release.
- Every P0/P1 risk has **≥1 passing scenario** (the 18-risk coverage core).
- JQF/jqwik fuzz clean on **both** decoders; race-soak + jcstress clean (zero REL-1 violations, zero PARANOID leaks) over the soak window.
- PERF-1/2/3/4 evidenced by the reproducible harness with **full disclosure**; no peak number published without its saturation knee + failure modes (PERF-070/071).
- CVE scan clean (Netty/JDK/Nimbus); Nimbus ≥ 10.0.2; JDK 25 build pinned.
- Two-shape parity smoke green (JAR + Docker); A-1 non-CI plan executed or explicitly deferred with risk acknowledgment.
- Coverage ≥ 80% (codec + security packages near-100% given MAINT-2 extractability).
- All open blockers (below) resolved before the owning epic's exit.

### Open questions / pre-implementation blockers (architecture must resolve) — ✅ RESOLVED 2026-07-23 (Q1→AD-32, Q2→AD-24 note, Q3→AD-34, Q4→AD-24 note, Q5→AD-30 amend, Q6 CI tier, Q7→AD-33). List below kept as the historical record of what was open at design time.
1. **Q1 — Pre-couple non-bind PDU policy (RELAY-002, P0):** AD-25/AD-3 must pin **buffer-and-forward-in-order** vs **drop**. Blocks a P0 REL-1 scenario from validating a specific property.
2. **Q2 — jcstress adoption (RELAY-007/024, P0):** adopt jcstress as a build target (recommended) or downgrade the P0 R5 concurrency-coverage claim. The deepest P0 risk's coverage hinges on this.
3. **Q3 — Cipher allowlist pin (SEC-089):** pin the concrete default cipher allowlist in config before the enforcement test is implementable.
4. **Q4 — Two-proxy E2E (E2E-001):** decide to stand up two real proxy instances (recommended — catches forward↔reverse seam bugs).
5. **Q5 — AD-30 shared-constant assertion (RELAY-026):** add the ArchUnit/Gradle static assertion (compile-time drift prevention).
6. **Q6 — CI-gate positive controls (SEC-099/CODEC-041/OBS-043):** add injected-known-bad controls so a misconfigured gate can't silently pass.
7. **Q7 — bind_resp status→OIDC-outcome mapping (R23):** the exact mapping is owned by a single story (deferred); SEC-078..080 depend on it.

## Step 5: Generate Outputs & Validate — COMPLETE

**Deliverables generated (system-level):**
- `test-design/test-coverage-scenarios.md` — durable scenario catalog, **251 scenarios** (CODEC 41 · RELAY 25 · SEC 98 · OBS 43 · DEPLOY 14 · PERF 29 · E2E 1) = **64 P0 / 113 P1 / 72 P2 / 2 P3**; all critic fixes applied (12 additions, 4 reframes, 3 dedup merges).
- `test-design-architecture.md` (372 lines) — engineering contract: 35-risk register, NFR testability requirements, 7 testability concerns, 4 architectural improvements, 5 P0 mitigation plans, Q1–Q7 blockers. Status: Architecture Review Pending.
- `test-design-qa.md` (802 lines) — execution recipe: NFR coverage plan, entry/exit, P0/P1 full coverage tables, execution tiers, estimates, tooling — fully re-platformed from Playwright/k6 to the JVM toolchain (zero residue).
- `test-design/smpp-companions-handoff.md` — risk→epic mapping, per-epic quality gates, P0/P1→story-AC guidance, Q1–Q7 resolution table.

**Validation:** `pass-with-findings`. Validator confirmed: correct JVM adaptation (JUnit 5/JQF/jqwik/JMH/in-JVM mock SMSC/BlockHound/ArchUnit/Spring slices/CI gates); risk scores exact; no Playwright/k6 residue; CLI/browser-session cleanup N/A (headless JVM); all artifacts under `_bmad-output/test-artifacts/`. Findings applied this step:
- **Count correction:** the reconciled register has **35 risks / 15 P2** (not 36/16 — an off-by-one I'd carried since Step 3). Fixed in QA doc (exec summary, P2/P3 line, Appendix B), architecture doc (already correct), and this progress file.
- **Scenario-count sync:** architecture doc's stale Step-4 estimates (~254/~61/~150) → authoritative **251 / 64 / 177**.
- **Handoff doc:** generated (was the one structural gap).
- Accepted trade-offs (documented, not defects): arch doc 372 lines vs ~150–200 target (inherent — 35-row register + 5 P0 mitigation plans); QA doc P2/P3 risks as a prose paragraph vs a full table (all 17 mapped in the catalog); both docs over the "keep concise" target because inline P0(64)+P1(113) tables are the value. Authoritative detail lives in the catalog; the two formal docs cross-reference it.

**Final tallies:** 35 risks (5 P0 · 13 P1 · 15 P2 · 2 P3) → 251 scenarios (64 P0 · 113 P1 · 72 P2 · 2 P3). Coverage core = 18 P0/P1 risks, all with ≥1 owning scenario. 7 open blockers (Q1–Q7) assigned to owning epics/decisions.

**on_complete hook:** resolved empty → skipped.
