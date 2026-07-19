# Structural Review — Companions v1 PRD + Addendum

**Reviewer role:** STRUCTURAL editor (propose cuts, reorganization, simplification — comprehension preserved).
**Scope:** `prd.md` + `addendum.md`.
**Stakes calibration:** Hobby/portfolio. Lean, not investor-grade. Findings prioritize HIGH-VALUE, LOW-RISK moves. Confident PM voice preserved throughout; nothing here changes meaning.

---

## Overall assessment

The PRD is confident, well-ordered at the section level, and the PRD↔addendum split (what vs how) is sound — addendum A1–A6 cleanly absorb the mechanism/derivation overflow. The §6.1 PDU matrix and §7.1 performance targets are genuinely well-placed and earn their space.

The dominant structural problem is **repetition across altitudes**: the same capability, risk, or non-goal is stated at three or more altitudes (vision → scope → FR/NFR → narrative → accepted-risk → out-of-scope), and the reader cannot always tell which instance is canonical. Specifically:

- the v1 capability list appears three times (§2 vision bullets, §5 Scope-In, §6 FRs);
- non-goals are spread across §5, §11, and §13 (plus §13 Reconciliations as a fourth pass on two topics);
- §7.7 Deployability near-verbatim restates §6.4; §9 Trust narrative restates §6.2; §7.8/§7.9 overlap each other and §6.5;
- Modes A/B/C are defined twice (§8 and addendum A5) and "payload-transparent" is stated five times;
- "Decision A" and "Decision B" are referenced four times but never defined as a list.

None of this is wrong — it is the natural cost of an audit-rich authoring trail — but a one-pass de-dup that names a canonical home for each repeated concept would tighten the doc materially without losing anything load-bearing.

A note on `autofix_safe`: almost every redundancy below carries a slight framing difference at a different altitude, so choosing the canonical home is a PM judgment, not a mechanical edit. I have marked `autofix_safe: false` throughout and explain in the summary why no findings qualify for pure-mechanical autofix.

---

## Top findings (ranked HIGH-VALUE/LOW-RISK first)

### 1. [HIGH] Capability list stated three times; canonical home unclear
**Where:** §2 (vision bullets), §5 (Scope In), §6 (FRs), with §8 (deployment).
**Issue:** The seven-bullet capability list in §2 ("confines weakness", "forwards single credential", "delegates to OIDC", "ships credential-free", "modes A/B/C", "consumes trust", "payload-transparent", "JAR + Docker") is restated almost item-for-item in §5 In and again as FRs in §6. A reader scanning "what does v1 do" hits three near-identical lists.
**Recommendation:** Make §6 (FRs) the canonical capability home. Cut §2's bullet list to *positioning-only* (what is novel vs Cloudhopper/jSMPP, the "secure-transit companion" framing) and reduce §5 In to a one-line-per-item index that links to §6/§8. Net: three passes → one full + two indexes.
**Autofix safe:** No.

### 2. [HIGH] §7.7 Deployability is a near-verbatim echo of §6.4
**Where:** §6.4 (FR-DEPLOY-1..4) and §7.7 (DEP-1..4).
**Issue:** DEP-1/2/3 restate FR-DEPLOY-1/2/3 almost word-for-word; DEP-3 even self-identifies as "(ties to FR-DEPLOY-3)". DEP-4 (Docker secrets mechanism → addendum) is the only one carrying independent content. This is the cleanest duplication in the doc.
**Recommendation:** Drop §7.7's mirroring bullets. Either (a) collapse §7.7 to a single line — "Deployability NFRs are satisfied by FR-DEPLOY-1..4; DEP-4 (Docker secrets injection → addendum) is the deployability-specific addition" — or (b) move DEP-4 up into §6.4 and remove §7.7 entirely.
**Autofix safe:** No (which home owns it is a PM call, even though the duplication is clear).

### 3. [HIGH] Non-goal content spread across three (arguably four) sections
**Where:** §5 Out/non-goals headlines, §11 Accepted Risks & Limitations, §13 Out of Scope, §13 Reconciliations.
**Issue:** §5 already says "See §13 for the full list" and serves as a pointer — that layer is fine. The real overlap is §11 ↔ §13: "no metrics dashboard", "no rate-limiting", and "single-instance / no HA" each appear in both, framed as accepted-risk in one and hard-non-goal in the other. §13 Reconciliations then adds a *third* pass on audit/logging and rate-limiting.
**Recommendation:** Draw the line explicitly — §11 = accepted risks (things v1 *could* do but deliberately doesn't, with mitigation/ownership); §13 = hard non-goals (out of contemplation). Items appearing in both (metrics dashboard, rate-limiting, HA, payload-transparency) pick one home. Fold the §13 Reconciliations content into whichever section owns the topic; the reconciliation *rationale* is useful, the third pass is not.
**Autofix safe:** No.

### 4. [MEDIUM] §9 Trust narrative restates §6.2 FR-SEC bullets
**Where:** §6.2 (FR-SEC-1..5) and §9 (Trust & Security Model narrative).
**Issue:** §9's five bullets (Credential-free invariant, Weakness confinement, Delegated trust, External trust consumption, Owned risks) map 1:1 onto FR-SEC-1..5. The framing — "the trust model *is* the product; it earns its own narrative" — is genuinely valuable and not in §6.2; the bullet-by-bullet restatement is.
**Recommendation:** Keep §9's opening framing sentence and the "Owned risks → §11" pointer. Replace the four restatement bullets with a short paragraph that names the trust model in narrative voice and cross-refs §6.2 for the formal invariants. Saves ~10 lines without losing the narrative payoff.
**Autofix safe:** No.

### 5. [MEDIUM] §7.8 Operability and §7.9 Observability overlap each other and §6.5
**Where:** §7.8 (OPS-1..3), §7.9 (OBS-1..3), §6.5 (FR-OBS-1..2).
**Issue:** Both NFR subsections cover the operator-facing surface; OBS-1/OBS-2 explicitly point back to FR-OBS-1/2 (so they are pointers, not new requirements); OBS-3 (no management API) restates §13; OPS-3 (NTP) duplicates assumption A-4. The OPS/OBS split is not pulling its weight.
**Recommendation:** Merge into one "§7.8 Operability & Observability" subsection. Collapse OBS-1/OBS-2 to a single line referencing §6.5 (since they already self-identify as pointers). Keep the unique OPS content (docs-as-surface, cert-rotation contract, NTP precondition) and OBS-3's deliberate-limit note.
**Autofix safe:** No.

### 6. [MEDIUM] Modes A/B/C defined twice; payload-transparent stated five times
**Where:** Modes — §8 (canonical) and addendum A5 (near-verbatim copy, lines 54–56). Payload-transparent — §2 line 39, §5 line 79, §6.1 line 96, §11 line 235, §13 line 261.
**Issue:** A5's per-mode bullets ("Mode A — one-way TLS: … trusted network", etc.) are essentially a copy-paste of §8 lines 197–199. The surrounding A5 content (proxy2 statelessness, two-proxy topology wiring, authority-provider & certs mechanics) is genuinely addendum-level and should stay.
**Recommendation:** In A5, keep the topology-detail paragraph and replace the three per-mode lines with "Modes A/B/C are defined in PRD §8; this section covers their topology consequences." For payload-transparent, let §6.1 (with the PDU matrix) be the canonical definition; cross-ref from §2/§5/§11/§13 rather than restate.
**Autofix safe:** No (A5 has surrounding detail; the edit is a judgment call, not mechanical).

### 7. [MEDIUM] "Decision A" and "Decision B" referenced but never defined
**Where:** §7.6 MAINT-2 ("Decision A"), §7.2 SEC-4 ("Decision B"), §13 Reconciliations ("Decision A"), addendum A3 ("Decision B").
**Issue:** These labels are used inline as though the reader knows them, but no Decisions table exists in either document. The reader must infer A = structured-for-extraction/modularity, B = mature-library primitives over hand-rolled crypto.
**Recommendation:** Either add a short "Decisions" subsection (a two-row table is enough) that names Decision A and Decision B in one place — §12 alongside OQ-4/OQ-11 is a natural home — or drop the labels and inline the meaning at each reference site.
**Autofix safe:** No.

### 8. [MEDIUM] Resolved-OQ audit trail inflates §12
**Where:** §12 Open Questions & Decisions Needed — the "Resolved during PRD authoring" block (9 of 11 entries).
**Issue:** Only OQ-4 and OQ-11 are actually open; the other nine (OQ-1/2/3/5/6/7/8/9/10) are resolved audit. The addendum's own header states "Audit/override information never lives [in the addendum] (that's `.memlog.md`)" — by that convention the resolved-OQ block is audit content sitting in the PRD body. It does serve a "decisions were made deliberately" signal, so it should not simply vanish.
**Recommendation (options):** (a) Compress to a one-line-per-decision table (drop per-entry rationales, keep the resolution + cross-ref); or (b) move the full resolved block to `.memlog.md` (the audit home the addendum already names), leaving §12 as the open-questions queue plus a one-line pointer to the audit log. Either preserves the audit signal while cutting §12's footprint substantially.
**Autofix safe:** No (the "deliberately resolved" signal is part of the PM voice; do not strip blindly).

### 9. [LOW] §4 Goals partially mirrored in §7.6
**Where:** §4 (Originality, Establishes the pattern) and §7.6 (MAINT-3 Originality, MAINT-2 structured-for-extraction).
**Issue:** Goals and NFRs are different altitudes, so some echo is expected — but "Originality — built from scratch, no Cloudhopper/jSMPP derivation" is stated almost verbatim in both places.
**Recommendation:** Keep the goal-level statement in §4. In MAINT-3 reduce to "Originality (per §4 goal) — SMPP layer built from scratch; library primitives per SEC-4."
**Autofix safe:** No.

### 10. [LOW] §10 A-3 and A-4 duplicate §8 and §7.8
**Where:** §10 A-3 (trusted-network deployer responsibility) and A-4 (NTP) ↔ §8 (Trusted-network precondition paragraph) ↔ §7.8 OPS-3 (time-sync).
**Issue:** A-3 and the §8 "Trusted-network precondition" paragraph say the same thing; A-4 and OPS-3 both say "NTP required."
**Recommendation:** Keep A-3/A-4 in §10 (the assumption list is the right home). Convert the §8 trusted-network paragraph and OPS-3 to cross-refs ("see A-3" / "see A-4"), or simply trim them to one clause each.
**Autofix safe:** No.

### 11. [LOW] §13 Reconciliations sit at a different altitude than the surrounding bullets
**Where:** §13 Out-of-Scope bullets vs the §13 "Reconciliations" sub-block.
**Issue:** The Reconciliations read like audit-trail resolution notes ("source contradictions, resolved here") interleaved with hard non-goals. Two of the three reconciliation entries (audit/logging, rate-limiting) overlap §11.
**Recommendation:** Either fold the unique reconciliation rationale into the owning section's bullet ("X is OUT because…") or relocate the reconciliations alongside the resolved-OQ audit (see Finding 8). The third reconciliation (family siblings) belongs naturally in §13 and can stay.
**Autofix safe:** No.

### 12. [LOW] §11 Accepted Risks cross-refs are healthy — use as the model
**Where:** §11 entries link to §8, OPS-2, A-2, FR-AUTH-3.
**Observation (not a defect):** §11 is the best-structured section in the doc — each risk lives in exactly one canonical home and §11 points to it. This is the pattern the rest of the doc should adopt when fixing Findings 1, 3, 4, 6.
**Recommendation:** Use §11's cross-ref discipline as the template for the de-dup pass.
**Autofix safe:** No.

---

## Smaller notes (not promoted to findings)

- **§3 Stakeholders** lists "Future Companions-family contributors" — slight tension with §13 "v1 ships nothing as a platform," but acceptable as vision framing. No change.
- **§12 OQ numbering** is non-contiguous (1, 2, 3, [4 open], 5, 6, 7, 8, 9, 10, [11 open]). If Finding 8 is applied, only OQ-4 and OQ-11 remain and the gap becomes invisible to the reader.
- **§6.1 PDU matrix** is excellent and earns its space — it is the natural canonical anchor for payload-transparent behavior (see Finding 6).
- **§7.1 PERF-4** parenthetical "(the codec is ~60× faster than the network path)" duplicates addendum A1's framing. Minor; keep in §7.1 since it justifies the sub-ms claim inline.
- **§4 License (Apache-2.0)** and **OQ-10 resolved (Apache-2.0)** — OQ-10 already cross-refs §4, so this is a pointer, not a true duplicate. No action.
- **Addendum** is consistently structured (A1–A6); the only structural issue is A5 re-listing the modes (Finding 6).

---

## Sequenced fix plan (lowest risk first)

Each step is independently shippable; the doc improves monotonically.

1. **Finding 8** — compress or relocate the resolved-OQ block (pure audit footprint reduction).
2. **Finding 6** — make §8 canonical for Modes; trim A5 and §5 mode mentions to cross-refs.
3. **Finding 2** — collapse §7.7 into §6.4 (or convert to a one-line cross-ref block).
4. **Finding 5** — merge §7.8 + §7.9 into one Operability & Observability subsection.
5. **Finding 4** — trim §9 narrative to framing + pointer to §6.2.
6. **Finding 7** — add a Decisions home (two-row table) or drop the A/B labels.
7. **Findings 1 + 3** — consolidate the capability list (§2/§5/§6) and the non-goal homes (§11/§13 + Reconciliations). These are the largest edits and benefit from a single coordinated PM pass.

Findings 9–12 are LOW and can be folded into the passes above opportunistically.
