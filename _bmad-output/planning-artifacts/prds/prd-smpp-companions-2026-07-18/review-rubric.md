# PRD Quality Review — SMPP 3.4 Security Proxy (Companions v1)

*Rubric: `.claude/skills/bmad-prd/assets/prd-validation-checklist.md`. Stakes calibration: hobby / solo OSS portfolio piece — rigor light, substance bar still applies. Shape: chain-top (feeds architecture → stories), so downstream usability is weighted higher than for a standalone PRD.*

## Overall verdict

This is a strong PRD for the stated stakes — sharper than most hobby/portfolio PRDs need to be. The trust-model thesis is genuinely load-bearing (credential-free invariant, payload-transparency, dual-role one-codebase), the NFRs are concrete and anchor-derived rather than boilerplate, and accepted risks are owned explicitly (Mode B, A-1, no rate-limiting). What's at risk is mostly mechanical: there is no Assumptions Index despite four inline `[ASSUMPTION]` tags, success criteria lack stable IDs for downstream traceability, and one Open Question (OQ-11) contradicts its own NFR (MAINT-5) — a real internal inconsistency rather than a stylistic nit. None of it blocks hand-off to architecture; all of it is cheap to fix.

---

## Decision-readiness — strong

Decisions are stated as decisions, not buried as considerations. The Mode B treatment is exemplary — "Accepted-risk mode," "loud startup warning," "explicit opt-in acknowledgment," "Not refused at startup, but never silent" (§8) — that is how a hard call is owned rather than smoothed. The Open Questions list (§12) keeps a clean audit trail: ten OQs marked resolved with their resolution and where it landed in the PRD (OQ-1→A-1, OQ-2→§6.1, OQ-5→OPS-2, etc.), and two genuinely still-open (OQ-4 chain-depth, OQ-11 native-image) that are correctly deferred to architecture rather than fake-resolved. Trade-offs are named with what was given up: Modes A/B/C trade security posture for legacy reach; payload-transparency trades inspection capability for the credential-free invariant; statelessness (REL-4) trades future-HA-readiness for v1 simplicity.

A-1 is flagged honestly as "confirmed by author" *and* "the single most load-bearing assumption" that "the architect should still smoke-test… early against a real/conformance SMSC" (§10) — exactly the right dual posture for a premise the whole stateless-splice architecture rests on.

### Findings
- **medium** No `[NOTE FOR PM]` callouts anywhere in the PRD (grep confirms zero). The rubric specifically asks for these at deferred decisions and unresolved tensions. Several real tensions would qualify: A-1's load-bearing status, Mode B's accepted-risk posture, the payload-transparency trade-off. *Fix:* not strictly required — the OQ list and §11 cover the same ground — but if the project's authoring convention expects `[NOTE FOR PM]`, add 2–3 at the genuine tension points (A-1, Mode B, OQ-4).
- **low** OQ-11 contradicts MAINT-5 (see Strategic coherence / Internal consistency below). This is the one place decision-readiness slips: an Open Question that is in fact already answered elsewhere in the document.

---

## Substance over theater — strong

Very little furniture. The Vision (§2) is product-specific — it could not be swapped into another SMPP library's PRD without rewriting, because every clause ("credential-free," "dual-role," "payload-transparent," "consumes not provides trust") does work elsewhere in the spec. The NFRs (§7) are anchor-derived with explicit numbers (PERF-1 ≥10K/≥25K, PERF-2 10K sockets <1 GB/<1 vCPU, PERF-3 p99 ≤~250 ms warm / ≤~2 s cold / DENY ~2–5 s) — this is the opposite of NFR theater ("system must be scalable"). The addendum's A1 even shows the work: which sources produced which numbers and where the published ceiling would be overreach ("claiming >50K end-to-end would read as overreach").

Differentiation is earned, not template-furniture: Cloudhopper/jSMPP are named as inspirations but explicitly *not* forked (MAINT-3), and the "secure-transit companion" positioning is a real gap in the JVM SMPP ecosystem.

### Findings
- **low** Six stakeholders (§3) is heavy for a solo/portfolio piece. "Future Companions-family contributors" drives no FR in v1 (it is forward-looking framing for MAINT-2), and "Security architect (trust-model reviewer)" drives §9 but §9 could stand without a named persona. The self-aware parenthetical on the latter ("*Unusual for a hobby project but load-bearing for a security-branded one.*") mostly earns its keep. *Fix:* optional — keep all six if you want the portfolio-showcase breadth, but recognize two are framing, not decision-drivers.

---

## Strategic coherence — strong (with one internal inconsistency)

The thesis is explicit and recurs throughout: *non-invasive augmentation layer for legacy SMPP; security-transit is the first instance of a planned pattern; credential-free proxy tier; OIDC-delegated auth.* Features serve this thesis rather than reading as a backlog: payload-transparency is *required* by the credential-free invariant (inspecting payloads would create a content-trust surface the proxy disclaims); dual-role one-codebase is *required* by credential-free end-to-end brokering (both legs must agree on identity); Modes A/B/C are *required* by "cover the full range of real legacy reach." The counter-metric is present and on-thesis ("scope does not creep toward adoption-chasing or platform-building").

Success criteria are partly measurable (perf targets "met and published via a reproducible harness") and partly qualitative ("trust model survives a security-architect review"). For hobby stakes that mix is adequate; the qualitative ones would be a problem at investor-grade stakes but are honest here.

### Findings
- **medium** Internal inconsistency between MAINT-5 and OQ-11. MAINT-5 (§7.6, line 173) states decisively: native-image is "an **opt-in future** path… **Not a v1 commitment** (stretch only)." §13 (line 267) repeats: "No GraalVM native-image as a v1 commitment (stretch)." Yet OQ-11 (§12, line 246) still lists it as **Open**: "Native-image: v1 commitment vs stretch (MAINT-5)." Either MAINT-5 is the resolution (in which case OQ-11 should move to the "Resolved during PRD authoring" block with the others) or the question is genuinely open (in which case MAINT-5 is overstating a settled decision). *Fix:* move OQ-11 to Resolved with "→ decided: stretch only, see MAINT-5." This is a real defect because downstream readers cannot tell whether native-image compatibility is a v1 constraint or not.

---

## Done-ness clarity — adequate

Most FRs carry testable consequences inline. FR-SEC-5 ("Fail-closed: DENY a bind when the authority-provider verdict is unavailable or indeterminate") is the gold standard for this PRD — unambiguous, falsifiable, single test path. FR-SEC-1 (no passwords, no vault), FR-SEC-3 (legacy `system_id` == carrier `system_id`, no pooling/mapping/surrogate), FR-DEPLOY-3 (fail-fast on ambiguous config), FR-AUTH-3 (per-instance baked certs, never shared golden-image) are all verifiable by inspection or test. The PDU handling matrix in §6.1 is excellent — a single table that an engineer can implement against directly.

No separate Acceptance Criteria section, but for this shape (capability spec, no UX) the FRs mostly carry their own consequences — acceptable per the rubric ("Sometimes the FR's consequences carry this").

### Findings
- **medium** Soft language in two FRs weakens done-ness. **FR-OBS-2** (line 132): "**optionally** dimensioned per `system_id`" — "optionally" inside an FR leaves v1 scope ambiguous (is the per-`system_id` dimension shipped, or is it a config flag, or is it deferred?). **FR-TRANSIT-3** (line 98): "alter no protocol behavior either side **expects**" — "expects" is not directly testable; the test becomes "what a reference SMPP 3.4 stack tolerates," which is fine operationally but should be stated that way. *Fix:* FR-OBS-2 — decide (ship per-`system_id` labels in v1, or mark `[NON-GOAL for MVP]`); FR-TRANSIT-3 — replace "expects" with a conformance-test reference (e.g., "passes an SMPP 3.4 conformance suite on both legs").
- **low** PERF-3's "~250 ms / ~2 s / ~2–5 s" use tilde-approximations throughout. For "locked targets — anchor-derived" (§7.1 header), the tildes undermine "locked." *Fix:* either drop the tildes (commit to the numbers) or rename the header to "anchor-derived targets" without "locked."

---

## Scope honesty — strong

This is the PRD's strongest dimension. §5 (In/Out), §11 (Accepted Risks & Limitations), §13 (Out of Scope with explicit reconciliations of source contradictions), and §10 (Assumptions, Constraints & Dependencies) form a complete scope surface. Reconciliations in §13 are particularly good — they name the contradiction source explicitly ("source contradictions, resolved here") and resolve audit/logging and rate-limiting scope conflicts in plain language. A-1's dual framing (confirmed + still-smoke-test-early) is the model for how to handle a load-bearing premise. Mode B is owned rather than buried.

### Findings
- **medium** No Assumptions Index. The legend (line 17) promises "`[ASSUMPTION]` marks a product call the facilitator inferred; the author should confirm or redirect each," and four inline tags exist (§5 line 80 "all three shipped and documented"; §8 line 205 "Single-side adoption"; §13 line 266 "No CRL/OCSP revocation infra"; plus the legend itself). But there is no consolidated index at the end and no roundtrip-verification that every inline tag is indexed. For a chain-top PRD this matters — architecture will need to confirm-or-redirect each, and a registry is the artifact that gets checked off. *Fix:* add an "Assumptions Index" subsection (near §10 or as §15) listing each inline `[ASSUMPTION]` with its location, status (confirmed/open/redirected), and owner action.

---

## Downstream usability — adequate

This is a chain-top PRD (explicitly feeds architecture → stories), so the rubric weights it higher. FR IDs are stable, semantically prefixed, and unique (FR-TRANSIT-*, FR-SEC-*, FR-AUTH-*, FR-DEPLOY-*, FR-OBS-*); NFR IDs likewise (PERF-*, SEC-*, PRIV-*, REL-*, COMP-*, MAINT-*, DEP-*, OPS-*, OBS-*). Cross-references mostly resolve (§6.1 ← §13; §10 A-1 ← REL-4 / FR-TRANSIT-2; §7.1 ← §4; §8 ← §11). The `→ addendum` mechanism is well-executed: the PRD carries the *what*, addendum.md carries the *how*, and the split is clean (library choices, perf-anchor derivation, observability mechanics, topology detail all live in addendum). Glossary (§14) is lightweight but covers the SMPP-specific nouns.

No UJs (User Journeys) — and that is the *correct* shape choice for a headless operator middleware (per Shape fit below), so this is not a defect.

### Findings
- **medium** Success criteria (§4) lack stable IDs. Grep confirms zero `SM-*` identifiers anywhere. The four success bullets (shippable OSS release; trust model survives review; perf targets met and published; counter-metric on scope) are exactly the things epics/stories will need to trace to, but they have no handles. *Fix:* tag them SM-1..SM-4 (and the counter-metric CM-1), so architecture and story creation can reference "implements SM-3" rather than paraphrasing.
- **low** Minor glossary drift. "Authority provider" is the canonical term (used ~12 times) but is not a glossary entry; the §14 OIDC entry mentions it in passing. "IdP" appears in §1 (line 25) and PERF-3 (line 142) without glossary coverage and without explicit aliasing to "authority provider." "Codec" is used in PERF-4 ("the codec is ~60× faster than the network path") unglossaried. *Fix:* add glossary entries for **authority provider** (= "the operator-run OIDC identity provider; Keycloak is the reference"), **IdP** (alias to authority provider), and **codec** (= "the SMPP PDU encode/decode layer built from scratch per MAINT-2").

---

## Shape fit — adequate (correctly light on UJs, slightly over-formalized on NFRs)

The shape is mostly right. Per the rubric: "Internal tool, single-operator role → capability spec shape; UJs may be overhead." Companions is a headless operator-configured middleware with no UX surface, and the PRD correctly omits UJs — adding them would be the over-formalization failure mode. SMs are operational (perf, concurrency, trust-review) rather than user-facing, also correct.

The mild over-formalization is in §7: ten NFR sub-categories (Performance, Security, Privacy, Reliability, Compatibility, Maintainability, Deployability, Operability, Observability) for a v1 hobby piece is more granularity than the stakes require. It is *defensible* — "Craft is the headline" (§2) makes the rigor itself part of the portfolio artifact — but a leaner NFR section (e.g., folding Privacy into Security, Deployability into Operability) would lose nothing decision-relevant and read as more proportionate.

### Findings
- **low** Ten NFR sub-categories is on the heavy side for a solo v1. Several are thin (PRIV-1 is a single bullet; DEP-3 explicitly duplicates FR-DEPLOY-3; OBS-* largely restate FR-OBS-*). *Fix:* optional — keep if the formal structure is itself portfolio-showcase material; otherwise consolidate Privacy→Security, Deployability→Operability, and dedupe the OBS/FR-OBS redundancy.

---

## Mechanical notes

- **Assumptions Index roundtrip — BROKEN.** Four inline `[ASSUMPTION]` tags (lines 80, 205, 266, plus the legend at 17), zero consolidated index. See Scope honesty finding above.
- **`[NOTE FOR PM]` callouts — ABSENT.** Zero occurrences. Not strictly required given the OQ list and §11, but the rubric expects them at real tensions.
- **OQ numbering — contiguous but cosmetically gapped.** OQ-1, 2, 3, 5, 6, 7, 8, 9, 10 are in the "Resolved" block; OQ-4 and OQ-11 are in the "Open" block. Numbers 1–11 all exist, but the split display makes it look like OQ-4 and OQ-11 jumped. No actual gap; consider reordering or a one-line note.
- **OQ-11 ↔ MAINT-5 inconsistency.** See Decision-readiness and Strategic coherence findings — this is the most consequential mechanical issue because it creates a genuine ambiguity about a v1 constraint.
- **Glossary drift — minor.** "authority provider" / "IdP" / "OIDC provider" used semi-interchangeably; "codec" unglossaried. See Downstream usability finding.
- **Success-criteria IDs — absent.** See Downstream usability finding.
- **PERF-3 "locked targets" vs tilde-approximations.** See Done-ness clarity finding.
- **Cross-references — resolve cleanly.** Spot-checked §6.1, §10 A-1, §7.1, §8, §11, §13 — all targets exist.
- **Required sections for stakes — present.** Problem, Vision, Stakeholders, Goals/Success, Scope, FRs, NFRs, Deployment Model, Trust narrative, Assumptions, Risks, Open Questions, Non-Goals, Glossary. No "Acceptance Criteria" section, but FRs carry testable consequences inline — acceptable for this shape.
