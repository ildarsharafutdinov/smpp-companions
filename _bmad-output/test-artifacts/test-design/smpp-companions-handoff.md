---
title: 'TEA Test Design → BMAD Handoff'
version: '1.0'
workflowType: 'testarch-test-design-handoff'
sourceWorkflow: 'testarch-test-design'
generatedBy: 'TEA Master Test Architect (Murat)'
generatedAt: '2026-07-22'
projectName: 'smpp-companions'
mode: 'system-level'
---

# TEA → BMAD Integration Handoff — SMPP Companions v1

> System-level test design is complete. Epics already exist (`epics.md`, Epic 1–6), so this handoff maps the test risk register + P0/P1 scenarios onto those epics as **exit-criteria / story acceptance guidance** and feeds forward to `bmad-testarch-atdd` (red-phase acceptance tests per story) and `bmad-testarch-automate`. Authoritative scenario detail: `test-design/test-coverage-scenarios.md` (251 scenarios). Risk/testability detail: `test-design-architecture.md` + `test-design-qa.md`.

## TEA Artifacts Inventory

| Artifact | Path | BMAD Integration Point |
| --- | --- | --- |
| Risk register + reconciliation (35 risks, post red-team) | `_bmad-output/test-artifacts/test-design-progress.md` (Step 3) | Epic risk classification, story priority |
| Coverage synthesis (matrix, NFR map, strategy, gates, 7 blockers) | same file (Step 4) | Story test requirements, epic exit gates |
| Scenario catalog (251 scenarios, full detail) | `_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md` | Story acceptance criteria, ATDD scaffolds |
| Architecture test-design (engineering contract) | `_bmad-output/test-artifacts/test-design-architecture.md` | Testability blockers (Q1–Q7) for architecture/dev |
| QA test-design (execution recipe) | `_bmad-output/test-artifacts/test-design-qa.md` | Test infrastructure, execution tiers, estimates |

## Epic-Level Integration Guidance

### Risk References — P0/P1 risks as epic quality gates

The 5 P0 (score 9) and 13 P1 (score 6) risks are the **coverage core** (`risk_threshold = p1`); each must have ≥1 passing scenario before its owning epic exits.

| Epic | P0 risks owned | P1 risks owned | Headline gate |
| --- | --- | --- | --- |
| **E1** Foundation + codec + config | — | R3, R14, R16, R17, R26, R33 | Conformance-proven + fuzz-hardened codec; config fail-fast matrix exhaustive; codec module PURE (ArchUnit); CI gates with positive controls |
| **E2** Relay + A-1 smoke | **R5** | R27, R28, R32, R38 | A-1 affinity smoke (in-JVM + jSMPP oracle); AD-25 single-flipper + race-soak REL-1 integrity; ~~blockers Q1 & Q2~~ ✅ resolved (AD-32/AD-24) — RELAY-002 + carve-outs land here |
| **E3** TLS + OIDC/ROPC | **R1, R2, R7, R8** | R9, R18, R20, R21, R23, R29, R31, R24 | ROPC viability probe (Story 3.1) + 4 AD-12 paths + fallback tree; exhaustive fail-closed matrix; trust anchoring + credential-free invariants |
| **E4** Metrics + logs | — | R10, R11 | /metrics loopback + cardinality + no-content; AD-22 graceful-shutdown end-to-end |
| **E5** JAR + Docker | — | R12, R22, R34, R35, R36 | Two-shape parity (jlink crypto modules, `--enable-preview`, ZGC); Docker SIGTERM→JVM; secrets contract |
| **E6** Perf + docs | — | R6, R25, R26, R29, R30, R37 | Reproducible perf harness (open-model, no-crypto baseline, percentile tables); full disclosure gates; docs-as-surface |

### Quality Gates (per epic, test-driven)

- **P0 = 100% pass** for every epic that owns a P0 risk (E2: R5; E3: R1/R2/R7/R8).
- **P1 ≥ 95% pass** for every owning epic; failures triaged + accepted.
- JQF/jqwik fuzz clean on **both** decoders before E1/E2 exit.
- Race-soak (+ jcstress per the AD-24 note) zero REL-1 violations / zero PARANOID leaks before E2/E3 exit.
- Real-Keycloak ROPC + introspection + mTLS-provider + ≥1 DENY paths green before E3 exit (Story 3.1 gate).
- Two-shape parity + Docker SIGTERM-drain green before E5 exit (lift from E6).
- PERF-1/2/3/4 evidenced with full disclosure (no peak without knee + failure modes) before E6 exit.
- A-1 non-CI real-carrier ops plan executed (or explicitly deferred w/ risk acknowledgment) — gates the stateless design.

## Story-Level Integration Guidance

### P0/P1 Test Scenarios → Story Acceptance Criteria

The **64 P0** and **113 P1** scenarios (full list in `test-coverage-scenarios.md`) become story-level acceptance criteria. Highest-leverage injections per epic:

- **E1/S1 (codec):** the AD-30 length-field guards (CODEC-005/006/008/010 incl. overflow-class pre-allocation), BIND_FAMILY source-of-truth (CODEC-026/027), and the **spec-derived golden-vector corpus** (CODEC-030) are ACs — they are the 3rd oracle that makes conformance falsifiable.
- **E2 opener / Story 2.1 (relay + A-1):** AD-25 single-flipper matrix (RELAY-001) + the pre-couple-window behavior (RELAY-002 + carve-outs 002a/b/c per AD-32) + the A-1 affinity smoke against the jSMPP oracle (OBS-038) are ACs. The **race-soak RELAY-024** and registry jcstress RELAY-007 (AD-24 note) are E2 exit gates.
- **E3/Story 3.1 (ROPC risk gate):** the viability probe + fallback decision tree (SEC-032) **must land first**; then the exhaustive fail-closed matrix (SEC-001..027 incl. introspection SEC-093 + JWT crypto SEC-020..027), trust anchoring (SEC-033..041), and credential-free/zeroization (SEC-042..049 incl. client_secret SEC-095).
- **E4 (operability):** /metrics cardinality+content+loopback (OBS-004/009/010) and AD-22 7-step shutdown (OBS-015..021) are ACs.
- **E5 (deploy):** two-shape parity (DEPLOY-005), `--enable-preview`/ZGC/MaxDirectMemory in both shapes (DEPLOY-003/004), Docker SIGTERM→JVM (DEPLOY-006), secrets contract (DEPLOY-007..009).
- **E6 (perf+docs):** the open-model coordinated-omission check (PERF-010), no-crypto baseline (PERF-013), saturation-knee+failure-modes (PERF-016/071), and disclosure gate (PERF-070).

### Blockers — ✅ RESOLVED 2026-07-23 (Architecture Review Passed; AD-32/33/34 + amendments)

| ID | Blocker | Resolution |
| --- | --- | --- |
| Q1 | Pre-couple non-bind PDU policy | ✅ **AD-32** — uniform close, no response (above-spec fail-closed); ONLY bind-family handled pre-couple; egress `generic_nack`/non-ROK `bind_resp` → forwarded verbatim (SMSC authoritative); zero knobs. RELAY-002 rewritten; 002a/b removed (carve-outs dropped), 002c remains. |
| Q2 | jcstress adoption | ✅ **AD-24 note** — jcstress (cross-thread state, nightly) + delay-injection soak. P0 R5 holds. |
| Q3 | Cipher allowlist pin | ✅ **AD-34** — ECDHE-AES-GCM default, `companion.tls.*`, fail-fast. SEC-089 unblocked. |
| Q4 | Two-proxy E2E | ✅ **AD-24 note** — E2E-001 weekly tier (validates DEP-1 too). |
| Q5 | AD-30 shared-constant assertion | ✅ **AD-30 amend** — ArchUnit one-constant + startup `ByteBufAllocatorMetric` self-check. |
| Q6 | CI-gate positive controls | ✅ per-gate known-bad fixture + assert-it-fires (CI tier). |
| Q7 | bind_resp → OIDC-outcome mapping | ✅ **AD-33** — binary wire collapse; exact code per owning story. SEC-078..080 unblocked. |

**Epic-2 falsification items (AD-32):** jSMPP `bind()` handles the close+error gracefully; carrier bind-timeout > PERF-3 cold/DENY; carrier does not pipeline `submit_sm` pre-`bind_resp`.

### Data-TestId Requirements

**N/A.** Companions v1 is headless with no UI and no management API (PRD §13, OBS-3). The operator surface is documentation (OPS-1) + the read-only loopback `/metrics` scrape. Testability seams are programmatic, not DOM: the `BindCredentialVerifier` port (fake verifier), the `SpliceObserver` interface (capturing observer), the `@ConfigurationProperties` fail-fast matrix, the `ByteBufAllocatorMetric`, an injectable `Clock`, and the golden-vector corpus resource.

## Risk-to-Story Mapping (P0 + P1; full register in architecture doc)

| Risk ID | Cat | P×I | Primary epic(s) | Test level(s) | Lead scenario(s) |
| --- | --- | --- | --- | --- | --- |
| R1 | SEC | 9 | E3 | unit (port matrix) | SEC-001..027, SEC-093/094 |
| R2 | SEC | 9 | E3 | integration (real Keycloak) | SEC-028..032 |
| R5 | DATA | 9 | E2, E3 | unit + conformance + race-soak | RELAY-001..011, RELAY-024 |
| R7 | SEC | 9 | E3 | integration (TLS vectors) | SEC-033..041 |
| R8 | SEC | 9 | E3 | unit + integration (heap inspection) | SEC-042..049, SEC-095 |
| R3 | SEC | 6 | E1, E2 | fuzz + unit + conformance | CODEC-011/025, CODEC-034 |
| R6 | PERF | 6 | E6 | perf (harness) | PERF-010/011/013/016 |
| R11 | REL | 6 | E4, E5 | integration + e2e | OBS-015..021, DEPLOY-006 |
| R12 | OPS | 6 | E5 | e2e (parity) | DEPLOY-001..005 |
| R14 | COMP | 6 | E1, E2 | conformance (jSMPP + golden) | CODEC-030/031, OBS-038 |
| R16 | SEC | 6 | E1, CI | CI gate (+ control) | SEC-091, SEC-099 |
| R17 | SEC | 6 | E1 | unit (config matrix) | SEC-050..061, SEC-096/097 |
| R18 | SEC | 6 | E3, E5 | integration (warning+scan) | SEC-063..066 |
| R25 | PERF | 6 | E6 | perf (load-gen methodology) | PERF-010 |
| R26 | PERF | 6 | E1, E6 | perf (JMH) | PERF-001/002/004 |
| R27 | PERF | 6 | E2, E6 | perf + integration | RELAY-013/015/017, PERF-040 |
| R28 | PERF | 6 | E2, E6 | integration (BlockHound) | RELAY-018/019 |
| R33 | TECH | 6 | E1, E2 | conformance (3rd oracle) | CODEC-030, OBS-038 |

## Recommended BMAD → TEA Workflow Sequence

1. **TEA Test Design** (`TD`) — ✅ complete; produces this handoff.
2. ~~Resolve Q1–Q7~~ **✅ DONE 2026-07-23** (AD-32/33/34 + amendments) — P0 scenarios unblocked.
3. **BMAD Create Story** (`CS`) — for each epic, carry the P0/P1 scenarios above into story acceptance criteria (stories are still templated in `epics.md`).
4. **TEA ATDD** (`AT`) — generate red-phase acceptance-test scaffolds from the P0/P1 scenarios (esp. the fail-closed matrix, the A-1 affinity smoke, the trust-anchoring vectors).
5. **BMAD Dev Story** (`DS`) → **Code Review** (`CR`) — implement test-first.
6. **TEA Automate** (`TA`) — expand to the full 251-scenario suite.
7. **TEA Trace** (`TR`) — coverage traceability + gate decision.
8. **TEA NFR Audit** (`NR`) — once PERF/SEC/REL evidence exists, the final PASS/CONCERNS/FAIL (test-design only *planned* the evidence).

## Phase Transition Quality Gates

| From → To | Gate criteria |
| --- | --- |
| Test Design → Q-resolution | ✅ PASSED 2026-07-23 — all 5 P0 risks have a mitigation strategy + owning scenario; Q1–Q7 RESOLVED (AD-32/33/34) |
| Q-resolution → Create Story | Stories carry the P0/P1 scenarios from this handoff as acceptance criteria |
| Create Story → ATDD | Failing acceptance tests exist for all P0/P1 scenarios (or the scenario is explicitly deferred) |
| ATDD → Implementation | Red-phase scaffolds green-only-on-correct for the fail-closed + trust + zeroization + integrity invariants |
| Implementation → Test Automation | All acceptance tests pass; fuzz/race-soak clean |
| Test Automation → Release | Trace matrix ≥ 80% coverage of P0/P1; NFR audit PASS on PERF/SEC/REL; A-1 real-carrier step executed |
