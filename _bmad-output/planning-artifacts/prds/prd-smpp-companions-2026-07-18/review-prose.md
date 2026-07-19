# Prose Review — Companions v1 PRD + Addendum

**Reviewer:** clinical copy-editor (PROSE)
**Scope:** `prd.md` (286 lines) + `addendum.md` (68 lines)
**Stance:** mechanical fixes only — no meaning changes, no voice stripping, no padding. `autofix_safe: true` marks changes that cannot alter meaning (typos, grammar, consistency, redundancy).

The prose is strong: tight, intentional, and consistent in voice. Findings below are mostly mechanics. Grouped by severity, then by category.

---

## Summary

The document is well-written and reads as deliberate. The main recurring issue is **terminology drift on the form-factor phrase** ("application (JAR)" vs "application (runnable JAR)" vs "Application (JAR)" vs "application JAR") — 8 occurrences, 4 variants. After that, the remaining items are scattered: two missing articles, the mathematically awkward `≤ ~` combination, a handful of clipped/dangling phrasings in the addendum, and -ly-adverb hyphenation. Nothing here changes meaning; most fixes are mechanical.

---

## HIGH — consistency / grammar (autofix-safe)

### H1. Form-factor phrase inconsistency (8 occurrences, 4 variants)
The same artifact is named four ways. Pick one canonical form and apply everywhere.

| Line | Current | Variant |
|---|---|---|
| prd.md:40 | `application (runnable JAR)` | runnable |
| prd.md:51 | `an application (JAR)` | bare |
| prd.md:67 | `application JAR` (no parens) | bare, no parens |
| prd.md:84 | `application (runnable JAR)` | runnable |
| prd.md:125 | `application (runnable JAR)` | runnable |
| prd.md:176 | `Application (JAR)` | bare, capitalized |
| prd.md:195 | `application (runnable JAR)` | runnable |
| prd.md:285 | `Application (JAR)` (glossary headword) | bare, capitalized |

**Recommendation:** standardize on **`application (runnable JAR)`** in running text (the most descriptive form, already the majority) and keep **`Application (JAR)`** as the glossary headword at prd.md:285 (glossary convention: short canonical term). Fix the three outliers: prd.md:51, prd.md:67, prd.md:176. `autofix_safe: true`

### H2. Missing article — "with huge blast radius" (prd.md:23)
> "...yields a stash of working carrier passwords with huge blast radius."

`with huge blast radius` → `with a huge blast radius`. `autofix_safe: true`

### H3. Missing article — "the SMSC remains credential authority" (prd.md:53)
> "...the SMSC remains credential authority and its session-affinity semantics must be respected."

`remains credential authority` → `remains the credential authority`. (Lines 36, 112, 213 correctly say "the sole credential authority" / "the credential authority" — line 53 is the outlier.) `autofix_safe: true`

---

## MEDIUM — clarity / awkward phrasing

### M1. `p99 ≤ ~250 ms` — combining `≤` with `~` is mathematically incoherent
"Less-than-or-equal-to approximately 250" is logically fuzzy. Appears at:
- prd.md:142 — `p99 ≤ ~250 ms` ... `≤ ~2 s`
- addendum.md:18 — `p99 ≤~250 ms warm / ≤~2 s cold`

**Recommendation:** pick one operator. Either commit to a target ceiling (`p99 ≤ 250 ms`) or describe it as an approximation (`p99 ≈ 250 ms`, or `p99 target ~250 ms`). The surrounding text already hedges ("Honest published ceiling…"), so `~250 ms` (drop the `≤`) reads cleanest. `autofix_safe: true` once the operator choice is confirmed.

### M2. "a *security-proxy* shape they weren't" — clipped/dangling (prd.md:42)
> "...current JDK, Loom-era concurrency, and a *security-proxy* shape they weren't."

"They weren't [a security-proxy shape]" is grammatically elliptical and the "weren't" contraction clashes with the otherwise formal register. **Recommendation:** `...and a *security-proxy* shape they were not.` (minimal) or recast: `...and a *security-proxy* shape — which they were not.`

### M3. "Idle-CPU-at-N-connections is unpublished anywhere" (addendum.md:24)
> "Idle-CPU-at-N-connections is unpublished anywhere — this is a contribution."

`is unpublished anywhere` is unidiomatic (the negative polarity of "anywhere" conflicts with the affirmative "is unpublished"). **Recommendation:** `Idle-CPU-at-N-connections is not published anywhere` or simply `...is unpublished`. `autofix_safe: true`

### M4. Compound subject with `+` and plural verb (addendum.md:16)
> "...so the codec is never the relay bottleneck; mTLS-on-both-legs + OIDC + SMSC latency govern."

Three `+`-joined noun phrases with a bare plural verb reads as a list-as-equation rather than a sentence. **Recommendation:** `mTLS-on-both-legs, OIDC, and SMSC latency govern` (commas + and) — keeps the plural verb grammatical and the sentence readable.

### M5. "Per-PDU relay added latency sub-ms" — word order (prd.md:143)
> "PERF-4 (relay latency) — Per-PDU relay added latency **sub-ms** (the SMSC round-trip dominates...)."

The noun stack "Per-PDU relay added latency" is hard to parse. **Recommendation:** `Added per-PDU relay latency is **sub-ms**` or `Per-PDU added latency is **sub-ms**`. `autofix_safe: true` (reorder only).

### M6. "no bundled authority provider / no cert issuance" — doubled negative (prd.md:89)
> "Headlines: no UI; no SMPP 5.x; no message inspection/routing logic; no management/control API; no bundled authority provider / no cert issuance; no metrics *dashboard*/telemetry backend; Linux only; IPv4 only."

The `/ no cert issuance` repeats "no" and breaks the parallel list rhythm. **Recommendation:** `no bundled authority provider or cert issuance`. `autofix_safe: true`

### M7. "bind + unbind" vs "bind family and unbind" vs "bind/unbind" (prd.md)
The bind-handling scope is described three ways across the doc:
- prd.md:39, 79 — `bind + unbind`
- prd.md:96 — `the bind family and unbind`
- prd.md:99, 148, 250 — `bind/unbind`
- prd.md:255 — `bind family + unbind`

All are intelligible, but a canonical phrase helps a spec reader. **Recommendation:** standardize on `bind/unbind` for the short form (matches the PDU table semantics at prd.md:106–107) and reserve `bind family` for the one place (prd.md:96 / FR-TRANSIT-1) where the "family" emphasis is doing work. `autofix_safe: true`

### M8. Addendum coinages / informal diction
- addendum.md:17 — `100K unlaunchable` → `100K cannot be launched` (cleaner; "unlaunchable" reads as a coined adjective). `autofix_safe: true`
- addendum.md:54 — `is a *could*, not v1` → `is a possibility, not v1` (or `is a maybe`). The quoted "*could*" as a noun is informal even for the addendum's terser register.
- addendum.md:37 — `Netty tcnative` → `netty-tcnative` (the artifact's actual name; lowercase, hyphenated). `autofix_safe: true`
- addendum.md:68 — `addendum-followup` → `addendum follow-up` (hyphenation of compound noun). `autofix_safe: true`

### M9. Abbreviations introduced without expansion
The PRD's glossary (§14) is explicitly "lightweight," but several in-text abbreviations are never expanded on first use and are not in the glossary:
- **IdP** — first appears prd.md:25 ("without bundling the trust infrastructure (IdP, PKI) itself"). Identity Provider.
- **PKI** — same line. Public Key Infrastructure.
- **BYO** — prd.md:82 ("BYO authority provider"). Bring-your-own.
- **OTel** — prd.md:262, addendum.md:32. OpenTelemetry.
- **VT-Netty** — addendum.md:17 ("VT-Netty on JDK 25 held 60K..."). Virtual-threads + Netty — not obvious.
- **AOT** — addendum.md:48 ("AOT constraints"). Ahead-of-time.
- **JEP** — addendum.md:17, 45 ("JEP 444", "JEP 491"). JDK Enhancement Proposal.
- **JWKS** — addendum.md:18, 38. JSON Web Key Set.
- **JOSE** — addendum.md:38. JSON Object Signing and Encryption.

**Recommendation:** either expand on first use in running text (preferred for the PRD-facing ones: IdP, PKI, BYO, OTel) or add a short "Abbreviations" subsection to the glossary. The addendum-internal ones (VT-Netty, AOT, JEP, JWKS, JOSE) are acceptable as-is for a technical-how appendix but VT-Netty in particular deserves a one-word gloss since it is load-bearing for the concurrency claim. Not autofix-safe (requires author judgment on which to expand vs assume).

---

## LOW — style / micro

### L1. `-ly`-adverb hyphenation (6 occurrences)
Most modern style guides (Chicago, AP, APA) drop the hyphen after an `-ly` adverb in a compound modifier. The doc is mixed:
- prd.md:37, 196 — `mutually-exclusive` → `mutually exclusive`
- prd.md:50 — `demonstrably-correct` → `demonstrably correct` (note prd.md:61 already uses the unhyphenated `demonstrably correct` — internal inconsistency)
- prd.md:113 — `explicitly-accepted` → `explicitly accepted`
- prd.md:170 — `independently-tested` → `independently tested`

`autofix_safe: true` (style-rule mechanical). Apply if the project follows a standard style guide; skip if "hyphenate all compound modifiers" is a deliberate house choice.

### L2. Split infinitive — "to actually use" (prd.md:46)
> "...done well enough to be proud of and to actually use."

Cosmetic. `to use it in practice` or `actually to use` avoids the split if desired. Not autofix-safe (voice choice).

### L3. Passive voice in spec language (acceptable, flag for awareness)
Specs naturally use passive; these are not errors. Surfaced only in case the author wants active alternatives:
- prd.md:53 — `its session-affinity semantics must be respected` → `operators must respect its session-affinity semantics`
- prd.md:122 — `Chain-validation depth and trust-anchor handling are decided at the architecture/solution phase` → `The architecture/solution phase decides chain-validation depth and trust-anchor handling`
- prd.md:144 — `targets are demonstrated via a reproducible load-test harness` → `a reproducible load-test harness demonstrates the targets`

Not autofix-safe (voice choice; passive is defensible in spec writing).

### L4. "transparent passthrough" / "opaque splice" / "transparently as opaque bytes" (prd.md:96, 107, 148, 250, 255)
Not wrong — "transparent to the endpoints, opaque to the proxy" is the intended dual framing — but the phrasing rotates across five variants for the same concept. If tightening: pick `spliced as opaque bytes` as the canonical verb phrase and let "transparent" qualify the proxy's behavior, not the splice. Not autofix-safe (judgment).

---

## FR-ID and NFR-ID formatting — clean

- **FR-IDs** all follow `FR-{CATEGORY}-{N}` consistently (FR-TRANSIT-*, FR-SEC-*, FR-AUTH-*, FR-DEPLOY-*, FR-OBS-*). No drift.
- **NFR-IDs** follow `{CATEGORY}-{N}` (no `FR-` prefix) consistently across PERF/SEC/PRIV/REL/COMP/MAINT/DEP/OPS/OBS. No drift.
- **A-* / OQ-* / SEC-* / MAINT-* / OPS-* / REL-* / DEP-* / COMP-*** cross-references resolve correctly (e.g., `REL-2`, `OPS-2`, `OQ-4`, `A-1`).
- One numbering note: OQ IDs jump from `OQ-10` (resolved) to `OQ-11` (open), with `OQ-4` and `OQ-11` open and `OQ-1..OQ-3, OQ-5..OQ-10` resolved. The gap (no `OQ-1, 2, 3` shown as open, but they appear in the resolved list) is fine — just confirming the IDs are internally consistent.

No FR-ID/NFR-ID action items.

---

## Items checked and cleared (no change needed)

- **"payload-transparent"** — hyphenated consistently everywhere (prd.md:39, 79, 96, 235, 261, etc.).
- **"credential-free"** — consistent.
- **"fail-closed"** (adj) vs **"fails closed"** (verb) — both used in grammatically correct contexts.
- **"from scratch"** (adverb) vs **"from-scratch"** (adjective) — both used correctly per role.
- **Em-dash usage** (`—` with surrounding spaces) — consistent across both docs.
- **Section/cross-reference numbering** (§6.1, §7.1, §7.9, §8, §10, §11, §13) — all resolve.
- **Backtick/code-fence discipline** (`system_id`, `/metrics`, `submit_sm`, `deliver_sm`, etc.) — consistent.
- **`[ASSUMPTION]` / `→ addendum` markers** — used consistently per the legend at prd.md:17.

---

## Top fixes (if only doing five)

1. **H1** — standardize the form-factor phrase (biggest repetition issue).
2. **H2 / H3** — add the two missing articles (one-line each).
3. **M1** — resolve the `≤ ~` operator conflict (meaning-bearing; needs a one-word author call).
4. **M3** — fix `is unpublished anywhere` (grammar).
5. **M7** — canonicalize the bind-scope phrase (spec-reader clarity).
