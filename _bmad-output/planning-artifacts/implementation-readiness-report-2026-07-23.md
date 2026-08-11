---
stepsCompleted:
  - step-01-document-discovery
  - step-02-prd-analysis
  - step-03-epic-coverage-validation
  - step-04-ux-alignment
  - step-05-epic-quality-review
  - step-06-final-assessment
finalStatus: READY
issuesTotal: 7
issuesCritical: 0
issuesMajor: 0
issuesMinor: 7
project: smpp-companions
date: 2026-07-23
documentsIncluded:
  prd:
    - _bmad-output/planning-artifacts/prds/prd-smpp-companions-2026-07-18/prd.md
    - _bmad-output/planning-artifacts/prds/prd-smpp-companions-2026-07-18/addendum.md
  architecture:
    - _bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/ARCHITECTURE-SPINE.md
    - _bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/walkthrough.md
  epics:
    - _bmad-output/planning-artifacts/epics.md
  ux: N/A  # headless product (PRD non-goal: no UI; OBS-3: no management API)
---

# Implementation Readiness Assessment Report

**Date:** 2026-07-23
**Project:** smpp-companions

## Step 1: Document Discovery

### Document Inventory

**PRD** (folder form — single canonical PRD, not sharded):
- `prds/prd-smpp-companions-2026-07-18/prd.md` — 29,255 B, 2026-07-20 *(binding contract)*
- `prds/prd-smpp-companions-2026-07-18/addendum.md` — 8,907 B, 2026-07-20 *(part of binding contract)*
- Supporting: reconcile-* / review-* process docs; `.perf-anchors.json`, `.source-map.json`, `.memlog.md`

**Architecture** (folder form — single spine):
- `architecture/architecture-smpp-companions-2026-07-19/ARCHITECTURE-SPINE.md` — 63,882 B, 2026-07-23 *(binding build substrate)*
- `architecture/architecture-smpp-companions-2026-07-19/walkthrough.md` — 14,559 B, 2026-07-20 *(binding substrate)*
- `reviews/` — 12 adversarial/security/rubric/webverify/lint/reconcile/update artifacts (2026-07-19 → 2026-07-23); `.memlog.md`

**Epics** (whole document):
- `epics.md` — 57,284 B, 2026-07-23 *(Epic 1–6; stories templated)*

**UX:** N/A — headless product (PRD non-goal: no UI; OBS-3: no management API). Documented non-applicability, not a gap.

### Duplicate / Missing Resolution

- **Duplicates:** None. (`architecture/.../reviews/review-reconcile-prd.md` matched the `*prd*.md` pattern but is an architecture-side review artifact, not a competing PRD.)
- **Missing:** UX — expected absent (headless). No action required.

### Assessment Inputs Selected

- PRD: `prd.md` + `addendum.md`
- Architecture: `ARCHITECTURE-SPINE.md` + `walkthrough.md`
- Epics: `epics.md`
- UX: N/A

## Step 2: PRD Analysis

*Source: `prd.md` (status: final) + `addendum.md` (status: final). Full text extracted; no summarization.*

### Functional Requirements (19)

**§6.1 Protocol Transit**
- **FR-TRANSIT-1** — Transit SMPP 3.4 traffic using a hybrid model: inspect/handle **only the bind family and unbind** (establish/tear down sessions, apply auth); **all other PDUs spliced transparently as opaque bytes** (not inspected, not filtered, forwarded as-is). Payload-transparent: no claim about, no restriction on, message types or PDU content either side sends. *(PDU matrix: bind_transmitter/receiver/transceiver +resp and unbind +resp = inspected/handled; submit_sm, deliver_sm/DLR, enquire_link, submit_multi, data_sm, query_sm, replace_sm, cancel_sm, broadcast_sm, outbind, alert_notification, generic_nack = opaque passthrough.)*
- **FR-TRANSIT-2** — DLRs (`deliver_sm`) flow back to the originating legacy bind via the same transparent passthrough (on the bind's session affinity) — no separate DLR path, no DLR-specific handling. *(Depends on bind session-affinity — §10 A-1.)*
- **FR-TRANSIT-3** — Interoperate transparently with unmodified SMPP 3.4 stacks on both legs, passing an SMPP 3.4 conformance suite on each leg without altering protocol behavior either side relies on.
- **FR-TRANSIT-4** — The bind/unbind handling implements **SMPP 3.4**; SMPP 5.x is not implemented.

**§6.2 Trust & Security Model**
- **FR-SEC-1** — The proxy tier holds **no SMPP passwords and no password vault**. The SMSC remains the sole credential authority. Compromise of a proxy yields network position only — never working carrier credentials.
- **FR-SEC-2** — Confine the legacy password-grant weakness to a trusted zone; never expose it unprotected on untrusted networks, except in the explicitly accepted plaintext Mode B.
- **FR-SEC-3** — Preserve end-to-end identity: legacy `system_id` == carrier `system_id`. No pooling, mapping, or surrogate identity.
- **FR-SEC-4** — **Consume** operator-provided trust at runtime (source-agnostic certs; OIDC-delegated auth). Do not bundle/run an authority provider, act as a CA, or issue certificates.
- **FR-SEC-5** — **Fail-closed:** DENY a bind when the authority-provider verdict is unavailable or indeterminate (timeout, network error). Deny-on-ambiguous is the default.

**§6.3 Authentication**
- **FR-AUTH-1** — Delegate password-grant validation to an operator-run **OIDC** authority provider (Keycloak = reference target, not part of this project).
- **FR-AUTH-2** — **Support** mTLS client-certificate authentication (Mode C); do **not** mandate it (Modes A and B operate password-grant only).
- **FR-AUTH-3** — Use **per-instance** baked client certificates (Mode C); never a shared golden-image key.
- **FR-AUTH-4** — mTLS (Mode C) terminates the client-certificate handshake. Chain-validation depth and trust-anchor handling decided at architecture (OQ-4). CRL/OCSP revocation checking is OUT of v1 (rotation is re-deploy, OPS-2).

**§6.4 Deployment & Form**
- **FR-DEPLOY-1** — Ship two first-class, **feature-equivalent** shapes — a standalone **application (runnable JAR)** and a **Docker image** (packaging the same JAR): same config surface, modes, auth paths.
- **FR-DEPLOY-2** — One codebase plays both roles (enterprise/forward + carrier/reverse); role and mode are deployment-time configuration of the application, not forks.
- **FR-DEPLOY-3** — Validate configuration at startup and **fail-fast** (refuse to start) on ambiguous, insecure, or missing configuration.
- **FR-DEPLOY-4** — Provision certificates at deploy time (bake via CI/pipeline); do not require runtime ACME/SPIFFE enrollment to function.

**§6.5 Operability & Observability**
- **FR-OBS-1** — Emit baseline operational logging (startup, errors, bind accept/reject, with `system_id` where relevant) to stdout/file as structured JSON-lines. Full message/PDU-body logging available only at **TRACE** level (off by default).
- **FR-OBS-2** — Expose a read-only HTTP **`/metrics`** endpoint (Prometheus exposition): throughput counters, bind counters, resource gauges, **configurably dimensioned per `system_id`** (operator-controllable cardinality). **Loopback-only (IPv4) in v1** (loopback binding is the endpoint's sole authentication — non-loopback forbidden, AD-19); never on the SMPP transit legs; **message content never emitted** (`system_id` labels permitted).

**Total FRs: 19**

### Non-Functional Requirements (29)

**§7.1 Performance (locked, anchor-derived; ref HW: single instance, 4–8 vCPU x86/ARM, Linux, JDK 25 GA, ZGC, 2–4 GiB heap)**
- **PERF-1 (throughput)** — Sustain **≥ 10,000 submit_sm/sec**, stretch **~25,000/sec**, mTLS both legs, OIDC validation cached, Netty event-loop relay (VTs own only the control plane). *(Honest published ceiling without a percentile-table harness: ~25–36K.)*
- **PERF-2 (concurrency)** — Hold **10,000 concurrent idle ESME↔proxy↔SMSC socket pairs** (~20K sockets) in **< 1 GB heap** and **< 1 vCPU** idle.
- **PERF-3 (bind latency)** — **p99 ~250 ms** warm (co-located IdP, TLS 1.3, pooled egress); **≤ 2 s** cold-path limit; **fail-closed DENY** beyond configured **2–5 s** timeout.
- **PERF-4 (relay latency)** — Per-PDU added latency **sub-ms** (SMSC round-trip dominates; codec ~60× faster than the network path).

**§7.2 Security**
- **SEC-1 (TLS floor)** — Minimum **TLS 1.2**, **TLS 1.3 preferred**; publish a cipher allowlist policy.
- **SEC-2 (parser robustness)** — Parser handles only bind/unbind PDUs (all else opaque splice); safely rejects malformed/oversized/truncated bind PDUs without crashing. Byte-splice path robust against oversized frames + memory exhaustion (backpressure, REL-2).
- **SEC-3 (provider link)** — Proxy→authority-provider link authenticated and encrypted (TLS/mTLS or service-account token).
- **SEC-4 (no rolled crypto)** — Mature libraries mandatory for crypto/TLS/OIDC primitives (Decision B); from-scratch principle covers the SMPP layer only.
- **SEC-5 (dependency hygiene)** — Maintain a vulnerability/CVE policy for security-critical dependencies (Netty, JDK).

**§7.3 Privacy**
- **PRIV-1** — Do **not** persist SMS message bodies. `system_id` **may** be logged and used as a metrics label; per-`system_id` metrics available. Full message/PDU-body logging **TRACE-only** (off by default). Message content never emitted in metrics.

**§7.4 Reliability**
- **REL-1 (transit integrity)** — Do not silently drop, duplicate, or corrupt spliced traffic or DLRs.
- **REL-2 (backpressure)** — When the egress leg is slow, the ingress leg backpressures rather than OOM.
- **REL-3 (graceful shutdown)** — On SIGTERM: stop accepting new binds, drain in-flight traffic up to a timeout, then exit.
- **REL-4 (statelessness)** — Proxy holds no `message_id`-to-`system_id` correlation (socket-pairing state only). Premise A-1 (carrier multi-bind + DLR affinity) confirmed.

**§7.5 Compatibility**
- **COMP-1** — Interoperate cleanly with unmodified SMPP 3.4 stacks on both ends; zero changes to legacy gear or SMSC behavior.
- **COMP-2** — **JDK 25** runtime floor (`--enable-preview` for `StructuredTaskScope`); JVM-only.
- **COMP-3** — **Linux only** (x86/ARM). No macOS or Windows build in v1.
- **COMP-4** — **IPv4 only.**

**§7.6 Maintainability**
- **MAINT-1 (single codebase)** — One codebase serves both roles; mode/role selection is deployment-time config, not forks.
- **MAINT-2 (structured for extraction)** — SMPP codec + PDU layer is a clean, separable, independently tested module with documented boundaries — structured for future extraction (Decision A). Modularity is a code-quality goal, not a v1 product surface.
- **MAINT-3 (originality)** — Built from scratch for JDK 25; no Cloudhopper/jSMPP derivation (SMPP layer only).
- **MAINT-4 (test strategy)** — Integration-test strategy required: mock/conformance SMSC, TLS/OIDC test vectors, codec fuzzing.
- **MAINT-5 (native-image compatibility)** — Keep compatible with GraalVM native-image as opt-in future; **NO v1 native-image build** (AD-23 / OQ-11); revisit only if a cold-start-sensitive deployment emerges.

**§7.7 Deployability**
- **DEP-1 (Docker secrets contract)** — Docker shape defines how secrets (certs, keys, provider creds) are injected (file paths / env / mounted secrets). *(Two-shape parity, deploy-time cert provisioning, config fail-fast covered by FR-DEPLOY-1..4.)*

**§7.8 Operability & Observability**
- **OPS-1 (documentation is the surface)** — Headless, no UI/management API → config reference, deployment-mode guide, troubleshooting/runbooks must exist.
- **OPS-2 (cert rotation)** — v1 contract: **re-deploy to rotate** baked certs (Mode C). CRL/OCSP revocation OUT of v1.
- **OBS-1 (read-only metrics)** — `/metrics` scrape endpoint provided; **no dashboard, no telemetry backend, no UI**.
- **OBS-2 (proxy not silent)** — Baseline operational logging ensures "no observability" never reads as "the proxy is silent."
- **OBS-3 (no management API)** — Operators cannot query/drain/reload/rotate at runtime in v1; deliberate limitation.

**Total NFRs: 29**

### Additional Requirements (Constraints, Assumptions, Success Criteria)

**Assumptions (§10):**
- **A-1 (confirmed, load-bearing)** — Target carrier allows multiple concurrent binds under one `system_id` and routes `deliver_sm`/DLRs back on the bind with session affinity. Premise of the stateless-splice architecture. *(Architect should still smoke-test early.)*
- **A-2** — Authority provider is a hard dependency for new binds; provider outage = no new binds (ongoing mTLS survives on cached trust). Operator HA responsibility.
- **A-3** — Trusted-network isolation on the legacy leg is the deployer's responsibility.
- **A-4** — Accurate clocks (NTP) are an operational precondition.

**Constraints:** JDK 25; JVM-only; Linux; IPv4; SMPP 3.4; payload-transparent; single-instance v1.

**Success criteria (§4):**
- **SM-1** — Shippable OSS release (JAR + Docker) the author is proud of and uses.
- **SM-2** — Trust model survives a security-architect review (credential-free invariant holds; fail-closed verified; accepted risks documented).
- **SM-3** — Performance & resource targets (§7.1) met and **published** via a reproducible harness (first-of-kind SMPP-proxy benchmark).
- **CM-1 (counter-metric)** — Scope does not creep toward adoption-chasing/platform-building; v1 ships one companion, modularity stays internal.

**Other:** License Apache-2.0. Mode B posture = shipped + documented, not default, loud startup warning + explicit opt-in ack, not refused at startup (§8).

### PRD Completeness Assessment

**Strong / ready:**
- Every FR and NFR carries a locked, verifiable target. Performance targets (PERF-1..4) are quantified with reference hardware and a defined proof method (reproducible harness + percentile table); privacy/reliability invariants are stated as testable negations.
- Traceable ID scheme (FR-{family}-{n}, NFR-{family}-{n}) — clean input for coverage validation.
- Assumptions (A-1..A-4), constraints, accepted risks (§11), and open questions (§12) are explicit and owned — not buried. A-1 is flagged load-bearing with a smoke-test directive.
- The addendum cleanly separates *how* (mechanism) from the PRD's *what*, and the PRD cross-references architecture ADs where decisions were deferred (AD-19, AD-23, AD-13, AD-12) — bidirectional traceability already partly wired.

**Watch-items (not blockers; flagged for downstream validation):**
- Several NFRs are intentionally *deferred-to-config* (exact cipher allowlist SEC-1, JWKS TTL/refresh, ROPC timeouts, histogram buckets, `application.yml` keys) — these are conscious deferrals, NOT missing thresholds, but Step 3+ must confirm each has an owning epic/story.
- **PERF-1/2/3/4 are first-of-kind / self-measured** — the *methodology* is the bar (SM-3); readiness depends on the harness being a planned deliverable (must verify Epic 6 owns it).
- **ROPC hard-dependency (FR-AUTH-1)** is the single most fragile external dependency (RFC 9700 deprecation); readiness hinges on the viability-probe + fallback-decision-tree being scoped (must verify Epic 3 owns it).
- **A-1 is unfalsifiable in CI** — readiness depends on a non-CI ops plan being scoped (must verify Epic 2 owns the smoke + a docs-docked ops checklist).

**Verdict:** PRD is complete, internally consistent, and traceable — a high-quality input. No extraction gaps (19 FR + 29 NFR confirmed against `epics.md`). Proceeding to epic-coverage validation to confirm every requirement below has a home.

## Step 3: Epic Coverage Validation

*Scope: confirm every PRD Functional Requirement has a traceable epic home. (FR coverage only — NFR/AD traceability is later; story quality is later.)*

### Coverage Matrix

| FR | PRD Requirement (gist) | Epic Coverage | Status |
|---|---|---|---|
| FR-TRANSIT-1 | Hybrid transit; bind family handled, all else opaque splice | Epic 2 — relay | ✓ Covered |
| FR-TRANSIT-2 | DLRs ride coupled pair (session affinity) | Epic 2 | ✓ Covered |
| FR-TRANSIT-3 | Interop + conformance both legs | Epic 2 | ✓ Covered |
| FR-TRANSIT-4 | SMPP 3.4 only; 5.x rejected | Epic 1 — codec | ✓ Covered |
| FR-SEC-1 | No passwords/vault; SMSC sole authority | Epic 3 | ✓ Covered |
| FR-SEC-2 | Confine password-grant to trusted zone; Mode B exception | Epic 3 | ✓ Covered |
| FR-SEC-3 | Identity forwarded, not mapped | Epic 3 | ✓ Covered |
| FR-SEC-4 | Consume operator trust; no bundled CA/IdP/issuance | Epic 3 | ✓ Covered |
| FR-SEC-5 | Fail-closed DENY on indeterminate | Epic 3 | ✓ Covered |
| FR-AUTH-1 | ROPC delegation to operator OIDC (Keycloak) | Epic 3 | ✓ Covered |
| FR-AUTH-2 | Support mTLS Mode C; don't mandate | Epic 3 | ✓ Covered |
| FR-AUTH-3 | Per-instance baked certs; no golden-image key | Epic 3 | ✓ Covered |
| FR-AUTH-4 | mTLS terminates handshake; PKIX; CRL/OCSP out | Epic 3 | ✓ Covered |
| FR-DEPLOY-1 | Two feature-equivalent shapes (JAR + Docker) | Epic 5 | ✓ Covered |
| FR-DEPLOY-2 | One codebase, both roles; role+mode = config | Epic 1 | ✓ Covered |
| FR-DEPLOY-3 | Startup config fail-fast | Epic 1 | ✓ Covered |
| FR-DEPLOY-4 | Deploy-time cert provisioning; no runtime ACME/SPIFFE | Epic 5 | ✓ Covered |
| FR-OBS-1 | Baseline JSON-lines logging; TRACE-only body | Epic 4 | ✓ Covered |
| FR-OBS-2 | Read-only loopback `/metrics`; cardinality bounded | Epic 4 | ✓ Covered |

### Missing Requirements

**None.** All 19 PRD FRs have a single, plausible epic home. No critical or high-priority gaps.

**Phantom check (FRs claimed in epics but absent from PRD):** Clean. The epics extraction explicitly excluded `FR-DEPLOY-5` and `FR-MAINT-1` as phantoms — correct, since `MAINT-1` is an NFR (not an FR) and `FR-DEPLOY-5` does not exist in PRD §6. No phantom FRs leaked into the epic plan.

### Coverage Statistics

- Total PRD FRs: **19**
- FRs covered in epics: **19**
- Coverage percentage: **100%**
- Phantoms: **0**

### Observation (not a gap)

Every FR has an **epic-level** home, but the individual **stories are still templated** (`{{N}}.{{M}}` placeholders in `epics.md`). Story-level acceptance criteria are intentionally deferred to the Phase 4 `Create Story` step — and the TEA handoff (`smpp-companions-handoff.md`) already maps the 64 P0 / 113 P1 test scenarios onto the owning epics as story-AC guidance. So the deferred detail is *pre-wired*, not missing. Epic→FR coverage is complete; the build path is clear.

## Step 4: UX Alignment

### UX Document Status

**Not Found** — and **not applicable** (verified, not assumed).

### Implication Assessment (three tests)

- **PRD mentions UI?** Yes, only to *exclude* it: §5 "no UI", §13 "No UI; … no management/control API"; product defined as "**headless**, operator-configured".
- **Web/mobile implied?** No. Sole HTTP surface = read-only **loopback `/metrics`** scrape (Prometheus text), explicitly "not a management API" (OBS-3, AD-19). Not interactive.
- **User-facing app?** No — headless middleware. Operator configures via files (`companion.*`) and reads docs + scrapes metrics.

**Conclusion:** UX absence is a deliberate, documented non-goal — **no warning warranted.**

### Operator-Experience Surface (the de-facto "UX") — accounted for

| Operator-facing surface | Owning NFR/AD | Epic | Status |
|---|---|---|---|
| Documentation = operator surface (config ref, per-mode guide, runbooks) | OPS-1 / AD-31 | Epic 6 | ✓ scoped |
| Config ergonomics + fail-fast clarity (`companion.*`) | AD-17 | Epic 1 | ✓ scoped |
| Read-only `/metrics` scrape format | AD-19 / OBS-1 | Epic 4 | ✓ scoped |
| Mode B loud startup warning + opt-in ack | §8 / AD-17 | Epic 1 + Epic 3 | ✓ scoped |

### Alignment Issues

None. There is no UX contract to align; the architecture's non-interactive surfaces (`/metrics`, JSON-lines logging, config fail-fast) are consistent with the headless PRD.

### Warnings

None.

## Step 5: Epic Quality Review

*Method: 4 independent dimension reviewers (user-value; independence/dependencies; story-structure/special-checks; compliance/traceability) over `epics.md` + PRD + architecture + TEA handoff, then adversarial verification of every finding against the headless-infra context to filter app-centric false positives. 20 raw findings → 15 dismissed → **0 critical / 0 major / 6 minor confirmed**. Two verify calls were lost to a transient 429 rate-limit; those two findings were recovered from the journal and adjudicated manually (one was severity-none/positive; one confirmed as a 7th minor below).*

### Headline

**The epic plan is structurally sound.** The linear DAG (E1→E2→E3→E4→E5→E6) is acyclic with no forward code dependencies; the seed→consume pattern (E2 seeds `BindCredentialVerifier`/`SpliceObserver` contracts, E3/E4 swap impls via DI behind unchanged interfaces) is correct in principle; all 6 epics pass the headless-aware user-value test (each delivers a genuine, demonstrable operator/system outcome and is independently valuable). **No epic is rendered undeliverable.** Every confirmed finding is a **documentation-reconciliation nit**, and six of seven share a single root cause: **`epics.md` was not reconciled after the 2026-07-23 AD-32/33/34 additions + test-design Q-resolution.**

### Best-Practices Compliance Checklist (per epic)

| Criterion | E1 | E2 | E3 | E4 | E5 | E6 |
|---|---|---|---|---|---|---|
| Delivers user/operator value | ✓ | ✓ | ✓ | ✓ | ✓ | ✓* |
| Functions independently (on stated deps) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Stories appropriately sized | — templated, pre-wired via handoff (see obs.) | | | | | |
| No forward dependencies | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| DB/entity timing | N/A — stateless, no DB (REL-4/AD-8/AD-9) | | | | | |
| Clear acceptance criteria | epic-level yes; story ACs deferred to Phase 4 (CS) | | | | | |
| Traceability to FRs/NFRs maintained | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (NFR-only) |
| Starter-template Story 1.1 (greenfield) | ✓ declared (drives E1/S1) | — | — | — | — | — |
| CI placed early | ✓ (E1: CVE/JDK-pin/codec gates) | — | — | — | — | — |

\* E6's operator value is real (perf evidence + docs surface); one cosmetic nit — see minor #7.

### 🟠 Major Violations

**None.** Three findings were initially claimed as major (E2→E4 SpliceObserver coupling; E2 `BindCredentialVerifier` seed contract; AD-32/33/34 ownership). All three were reduced to **minor** on adversarial verification — in each case the alleged structural break (compile failure / hidden coupling / broken traceability invariant) did not hold once the binding architecture was read, leaving a documentation-precision issue only.

### 🟡 Minor Findings (7) — grouped by root cause

**Cluster A — Contract-drift across the E2↔E3/E4 seams (highest-value minors):**

1. **AD-12 `VerdictRequest`/`cancelHttp()` omitted from the epics** (CONFIRMED, minor). The binding architecture mandates a cancellation handle for the IdP-amplification mitigation (AD-32 case-3 teardown must abort the in-flight ROPC): spine:139 Cancellation clause — *"`verify` returns a `VerdictRequest` exposing `CompletableFuture<Verdict> future()` + `void cancelHttp()` … the IdP-amplification mitigation … is otherwise unreachable through the seam"*; spine:213 — *`cancelHttp()` makes the aborted-verdict land near-instantly* (race-free Verdict-callback re-check). But `epics.md` cites only the stale `CompletableFuture<Verdict> verify()` shape at line 212 (inline AD-12 copy) and line 257 (AD-12 summary table); the E2 opener (364) and E3 risk-gate (375) ratify only the old signature.
   - *Nuance:* the drift is **coordinated** — the spine's own *primary* signature (139, first sentence) is *also* `CompletableFuture<Verdict> verify(...)`, with `VerdictRequest` layered into the Cancellation clause. So the fix touches both docs.
   - *Why it matters most:* it is the only confirmed finding touching a **security control**; a story author following the E2 opener literally would freeze an incomplete port and lose the IdP-amplification mitigation. **Fix before Phase 4 story authoring.**
   - **Fix:** update epics.md:212/257/364/375 to the `VerdictRequest{future(), cancelHttp()}` shape; state E2's always-allow stub returns a `VerdictRequest` with an immediately-completed future + noop `cancelHttp()`, and the E2 opener ratifies `VerdictRequest`/`cancelHttp()` against real Keycloak; confirm E3's ROPC adapter binds `cancelHttp()` to the HTTP-client abort. Also fix the spine's stale primary signature (139 first sentence).

2. **AD-27 `SpliceObserver` paraphrase lists 4 methods vs the binding 5** (PARTIALLY_VALID, minor) — **SUPERSEDED 2026-08-11**: AD-27 is now a 4-method shape (`onFramedPdu`/`onBindAccept`/`onBindReject`/`onConnectionClosed`; `onByteTransfer(Direction, long)` REMOVED — PDU count comes from `onFramedPdu` fires alone). The "4 vs 5" framing below is doubly stale (`onConnectionClosed` was added to epics after this report; `onByteTransfer` is now removed) and the Fix below is moot; see the architecture `.memlog.md` AD-27 amendment for the authoritative change. `epics.md`:225 lists `onFramedPdu`/`onBindAccept`/`onBindReject`/`onByteTransfer` only — missing `onConnectionClosed` (+ `CloseReason`), which the binding spine:223 defines and locates at the `channelInactive` teardown site. `epics.md`:385 says E4 adds "one method per AD-32" — inconsistent with E2 seeding the full AD-27 shape (363: "shape fixed by AD-27"). (The claimed compile-time break was **refuted**: E2's seed, by delegating shape to AD-27, already carries `onConnectionClosed`, so E2's relay can author the teardown callsite.)
   - **Fix:** add `onConnectionClosed` + `CloseReason` to the epics.md:225 paraphrase; reword :385 from "one method added" to "impl swapped behind the unchanged AD-27 interface"; reconcile the spine's own "corrected to one method added" note with its 5-method listing.

**Cluster B — Traceability staleness (the unreconciled-2026-07-23 root cause):**

3. **Newest ADs AD-32/33/34 (+ cross-cutting AD-6) absent from every "Key ADs" list** (PARTIALLY_VALID, minor). AD-32 (pre-couple non-bind policy / Q1), AD-33 (bind-denial wire collapse / Q7), AD-34 (TLS cipher default / Q3) appear only in the AD summary table / Accepted-Risks prose — never in an epic's Key-ADs list. The work **is** traceable (FR/NFR coverage + package ownership + handoff AC mapping, e.g. RELAY-002→E2, SEC-078..080/SEC-089→E3), and AD-6 sets precedent for cross-cutting ADs being intentionally unlisted — so this is polish, not a broken invariant.
   - **Fix (optional polish):** add AD-32 to Epic 2 Key ADs; add AD-33, AD-34 to Epic 3 Key ADs; add a one-line convention note that pervasive/governance ADs (AD-6) are intentionally excluded from per-epic Key lists.

4. **Stale, self-contradictory AD count** (CONFIRMED, minor). Frontmatter `adCount: 31` (line 14) and prose "31 ADs → 57 implementation requirements" (line 133) contradict the "AD-1..AD-34" header (line 242) and the 34-row summary table.
   - **Fix:** set `adCount` → 34; "31 ADs" → "34 ADs"; re-derive `archRequirementCount` (57) against the current spine (AD-32/33/34 each add binding sub-rules).

**Cluster C — Sequencing/clarity across the epic seams:**

5. **Story 3.1's ROPC-viability verdict doesn't declare a gate on E2's opener** (PARTIALLY_VALID, minor). Story 3.1 (probe) can run during E1; both 3.1 and E2's opener make a real ROPC call. If 3.1 finds ROPC removed/announced-for-removal, E2's opener should consume the fallback decision rather than independently rediscover it. Chronologically satisfiable (3.1 finishes before E2 starts) but left implicit. (E2's opener self-validates ROPC, so worst case is duplicated effort, not an undetected failure.)
   - **Fix:** one-line note that the E3→E2 dependency applies to E3's *implementation* stories (3.1 is the documented exception), and that 3.1's viability verdict feeds E2's opener.

6. **R5 P0-gate straddles the E2/E3 seam, but the handoff lists R5 under E2 only** (CONFIRMED-manual, minor; *recovered from a rate-limited verify call*). The handoff "P0 risks owned" table (line 35-36) lists R5 under E2 only, but the risk-to-story table (line 89) maps R5 to **E2 + E3**. The E2 exit gate could be misread as fully retiring R5 when E3 also carries R5 P0 scenarios (AD-32 Verdict-callback race conditions).
   - **Fix:** reconcile the two handoff tables — list R5 under both E2 and E3 in "P0 risks owned", or scope E2's R5 exit gate to the A-1/relay-integrity scenarios and call out which R5 P0 scenarios carry to E3.

7. **Epic 6 goal closes with non-operator/portfolio language + couples docs to perf** (PARTIALLY_VALID→cleared, minor; low confidence). The goal tail ("the portfolio 'craft is the headline' claim is proven…") is internal framing, not operator-facing; and docs delivery is coupled to PERF-1 validation, which the epic itself notes can bounce work back to E1/E2. Verifier judged this largely a false positive ("craft is the headline" is the PRD's own §2 positioning + SM-3 success criterion; the perf-bounce exception is honest scoping, not a defect). **Optional:** drop the portfolio clause from the operator-facing goal; consider docs as a track that doesn't block on PERF-1.

### Considered & Cleared (false positives — recorded to show what was checked)

- *"Linear DAG" but E4 has two predecessors (E2+E3)* — descriptor imprecision only; transitive order is linear, dual dep is correct/necessary (SpliceObserver from E2, Verdict from E3). Optional reword.
- *Epic 1 bundles 3 outcomes on the critical path* — legitimately epic-level for a headless proxy; a story-sequencing note (scaffold+CI first, then codec), not a structural defect.
- *Story 1.1 scaffold vs TEA handoff E1/S1=(codec)* — the "Starter Template drives E1/S1" text sits in Additional Requirements (constrains/shapes), not a story definition; no contest.
- *CI authorship not explicitly owned in E1* — CI IS named as an E1 deliverable (SEC-5 CVE scan, COMP-2 JDK pin, codec/dep gates).
- *Epic exit-gate R-IDs live only in the handoff* — correct for the phased workflow (handoff is the designated AC/gate artifact at epic-breakdown altitude); not a violation.
- *DB/entity creation timing* — N/A (stateless; REL-4/AD-8/AD-9). No anti-pattern applicable.
- *Epic 5 user-value* — positive (severity none); strong "ship both shapes" outcome, independently valuable. No defect.

### Epic-Quality Verdict

**PASS.** The plan meets create-epics-and-stories best practices for a headless product: every epic delivers operator value, the dependency DAG is sound with no forward references, FR/NFR/AD traceability is complete at epic altitude, and story-AC pre-wiring is delegated to the TEA handoff by design. All seven findings are **minor documentation-reconciliation items** (six share one root cause) — none block Phase 4. **Recommended single remediation pass over `epics.md`** (items 1-4 are the substantive cluster; 1 is the only security-relevant one and should land before story authoring). No structural rework required.

## Summary and Recommendations

### Overall Readiness Status

**✅ READY** — proceed to Phase 4 (Sprint Planning → Create Story).

The planning spine is complete and internally consistent across all four inputs:
- **PRD**: complete — 19 FR + 29 NFR, every target locked or consciously deferred-to-config; assumptions/risks owned.
- **Architecture**: final, post-adversarial-review, post-security-verify; 34 ADs; all 7 test-design blockers (Q1–Q7) resolved 2026-07-23.
- **Epics**: 6-epic linear DAG; **FR coverage 100% (19/19), 0 phantoms**; NFR/AD ownership complete at epic altitude.
- **UX**: N/A (headless — documented non-goal, not a gap); operator surfaces (docs/config/`/metrics`/Mode-B warning) all scoped.

No critical or major issues. The 7 findings are **all minor**, all documentation-reconciliation, none structural.

### Issues Requiring Immediate Action

**None that block implementation.** One item is worth fixing *before* story authoring because it touches a security control:

- **[M1] AD-12 `VerdictRequest`/`cancelHttp()` contract drift** (Step 5, minor #1) — the epics (and the spine's own primary signature) cite the stale `CompletableFuture<Verdict> verify()` shape, omitting the mandated cancellation handle that makes the IdP-amplification mitigation reachable. A story author following the E2 opener literally would freeze an incomplete port. Fix in `epics.md` (212/257/364/375) **and** the spine's primary signature (139) before Epic 2 story authoring.

### Recommended Next Steps

1. **Lightweight reconciliation pass over `epics.md`** (~30 min, fixes 6 of 7 findings — one root cause: the doc wasn't refreshed after the 2026-07-23 AD-32/33/34 additions):
   - M1 — update the AD-12 port to `VerdictRequest{future(), cancelHttp()}` (+ spine primary signature). *(security-relevant — do first)*
   - M2 — reconcile the AD-27 `SpliceObserver` method list (4→5) and the "one method added" phrasing.
   - M3 — add AD-32→E2, AD-33/34→E3 to the Key-ADs lists (optional polish).
   - M4 — `adCount` 31→34, "31 ADs"→"34 ADs", re-derive `archRequirementCount`.
2. **Optional clarity additions** (M5: Story-3.1-viability-verdict gates E2 opener; M6: reconcile the handoff's R5 ownership across E2/E3; M7: drop the portfolio clause from Epic 6's operator-facing goal).
3. **Proceed to Phase 4:** `[SP]` **Sprint Planning** (`bmad-sprint-planning`) → `[CS]` **Create Story** (`bmad-create-story`), starting with **Epic 1, Story 1** (Gradle two-module substrate + pure SMPP 3.4 codec + fail-fast config), carrying the P0/P1 scenarios from `smpp-companions-handoff.md` into story acceptance criteria.

### Final Note

This assessment identified **7 issues** (0 critical, 0 major, 7 minor) across **3 categories** (contract-drift, traceability staleness, sequencing clarity), validated by an adversarial multi-agent review that dismissed 15 of 20 raw findings as app-centric false positives against this headless product. The plan is **ready for implementation**; address M1 before Epic 2 story authoring and optionally sweep the remaining minors in one pass. Findings may be applied to improve the artifacts, or you may proceed as-is.

---
**Assessed by:** Implementation Readiness skill (PM requirements-traceability persona) + adversarial multi-agent epic-quality review
**Date:** 2026-07-23
**Report:** `_bmad-output/planning-artifacts/implementation-readiness-report-2026-07-23.md`
