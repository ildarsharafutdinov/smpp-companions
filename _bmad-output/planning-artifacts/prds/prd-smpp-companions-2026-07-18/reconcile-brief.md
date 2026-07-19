---
title: Reconcile — Brief vs PRD + Addendum (Companions v1)
project: smpp-companions
status: review
created: 2026-07-19
role: brief-reconciler
sources:
  brief: _bmad-output/planning-artifacts/briefs/brief-smpp-companions-2026-07-18/brief.md
  brief_addendum: _bmad-output/planning-artifacts/briefs/brief-smpp-companions-2026-07-18/addendum.md
  prd: _bmad-output/planning-artifacts/prds/prd-smpp-companions-2026-07-18/prd.md
  prd_addendum: _bmad-output/planning-artifacts/prds/prd-smpp-companions-2026-07-18/addendum.md
---

# Reconcile: Brief → PRD + Addendum

> Brief = authoritative for *what/why*. This file surfaces (a) brief content not captured in the PRD/addendum and (b) intentional divergences the PRD made away from the brief, so the author can confirm or redirect. Calibration: hobby/portfolio — lean, not investor-grade. Findings are ranked most consequential first.

## Overall assessment

The PRD faithfully carries the brief's *core* intent: the credential-free trust model, both-sides-of-the-wire dual role, modes A/B/C, OIDC-delegated auth, source-agnostic certs, from-scratch-on-JDK-25 originality, Apache-2.0, headless, and the portfolio-piece success framing ("proud to show, actually uses, adoption is a bonus"). Stakeholders were *expanded* (added operator/deployer, security-architect, future-contributors) without dropping any brief stakeholder. Success-criteria tone is well preserved, including the counter-metric against adoption-chasing.

The divergences are concentrated in three places where the PRD deliberately moved off the brief's literal wording. Two were flagged upstream (MT-only removal, library→application rename) and are confirmed here with the brief-addendum's extra weight. A third — pulling baseline metrics/observability *into* v1 — contradicts the brief in **two** places and is the one most worth an explicit author sign-off. Plus two minor qualitative gaps.

## Findings

### INTENTIONAL DIVERGENCE (confirm) — form-factor: "library core" → "application (runnable JAR)"

**Severity: low.**

- **Brief (brief.md:26):** "Two deployment shapes, both first-class: **embed as a library**, or run as a Docker image."
- **Brief addendum (addendum.md:12):** "keeping the library-vs-container story clean (**library core, thin Docker wrapper**)."
- **Brief addendum (addendum.md:23):** "keep companions as **pluggable modules** with a **clean SMPP library core**, not a hard-coded single-purpose proxy" + "v1's SMPP internals should factor toward [the future SMPP library]."
- **PRD (FR-DEPLOY-1, §2:40, §2:44, MAINT-2):** ships a standalone **application (runnable JAR)** + Docker image packaging that JAR; MAINT-2 explicitly states "**v1 ships an application, not a published library artifact**"; modularity demoted to "structured for future extraction … not a v1 product surface."

**Nature of the divergence.** Not merely a rename. The brief's intent is **library-centric** (library is the core, Docker is a thin wrapper around it, companions are pluggable modules on a clean SMPP-library core). The PRD is **application-centric** (runnable JAR is the product; the library is a future extraction; "pluggable companion platform" is explicitly disclaimed as a v1 surface). The future "modern JVM SMPP library" sibling stays in the brief's family list in both, so the outcome is compatible with the family plan — but the *v1 shape* is inverted.

**Recommendation.** Confirm the inversion is desired. If yes, no edit needed (PRD states the rationale cleanly). If the author still wants a *first-class embeddable library* in v1, FR-DEPLOY-1 and MAINT-2 need to be re-opened. The task brief already flagged this one — recorded here for completeness with the brief-addendum evidence.

---

### INTENTIONAL DIVERGENCE (confirm) — "MT-only" removed; reframed as payload-transparent

**Severity: low.**

- **Brief (brief.md:45):** scope In = "**MT-only** (submit path + DLRs on existing binds)."
- **Brief (brief.md:47):** scope Out = "**no MO / inbound user-message routing**."
- **Brainstorm (brainstorm-intent.md:38, :94):** "Traffic is **MT-only** … No MO/inbound"; declined "MO/inbound support (MT-only)."
- **PRD (FR-TRANSIT-1:96, :109, §13:261):** the proxy is **payload-transparent** — "all other PDUs are spliced transparently as opaque bytes — not inspected, not filtered"; "MT-only is a **deployment expectation, not a proxy-enforced filter**."

**Nature of the divergence.** Brief scopes the proxy to MT traffic; PRD declines to enforce any MT/MO distinction on the wire (it cannot, given the opaque-splice design) and downgrades MT-only to a deployment expectation. This is internally consistent with the byte-splice decision (OQ-2) — a proxy that splices opaque bytes cannot also enforce MT-only — so the divergence is a logical consequence of FR-TRANSIT-1, not an oversight.

**Recommendation.** Confirm. If the author wants MT-only *enforced*, that conflicts with payload-transparency and must be resolved at architecture (would require PDU-type inspection of `submit_sm`/`deliver_sm`, breaking the opaque-splice invariant). The task brief already flagged this one.

---

### INTENTIONAL DIVERGENCE (confirm) — "no metrics/observability" → PRD adds `/metrics` + structured logging in v1

**Severity: low** (but the most substantive of the intentional divergences — recommend explicit author sign-off).

- **Brief (brief.md:47):** scope Out = "**no management API, no metrics/observability**, no Windows build."
- **Brief addendum (addendum.md:23):** lists "**metrics/observability**" among the *earlier-candidate future companions* that "remain on the table" (i.e., not v1).
- **PRD (FR-OBS-1:131, FR-OBS-2:132, §7.9:186–189, §5:87):** baseline JSON-lines operational logging **and** a read-only Prometheus `/metrics` scrape endpoint are **in-scope for v1**.
- **PRD reconciliation (§13:271, OBS-2:188):** reinterprets the brief's "no observability" as "no dashboard / no telemetry backend," asserting "`no observability` never reads as `the proxy is silent`."
- **Provenance:** the addition traces to brainstorm's "Should (recommended, uncommitted)" item (brainstorm-intent.md:84: "Audit/logging of binds + PDUs (granularity open)"), promoted into v1 FRs.

**Nature of the divergence.** Both brief sources (the non-goal line and the future-sibling line) consistently place metrics/observability *outside* v1. The PRD pulls a slice of it (Prometheus counters/gauges + structured bind logging) into v1. The PRD's reconciliation is a deliberate reinterpretation, and it is *defensible* — a headless security boundary with zero observability is operationally suspect, and what the PRD adds is genuinely minimal (read-only scrape, no dashboard, message content never emitted). But it does contradict the brief's explicit wording in two places.

**Recommendation.** This is the one divergence most worth an explicit author decision:
- If the author agrees minimal observability belongs in v1 → update the brief's non-goal wording (or add a one-line note) so brief and PRD agree, and the divergence stops being a divergence of record.
- If the author wants to honor the brief literally → drop FR-OBS-2 (the `/metrics` endpoint) and keep only FR-OBS-1 (startup/error/bind logging to stdout), or push both to a future companion.

Either way, the current state has the PRD contradicting the authoritative brief, which should not be left implicit.

---

### GAP — "structured concurrency" named technique not surfaced

**Severity: low.**

- **Brief (brief.md:28):** "JDK 25, Netty, **virtual threads / structured concurrency**."
- **Brief addendum (addendum.md:9):** "**Virtual threads + structured concurrency** (Project Loom), where applicable."
- **PRD/addendum:** mention virtual threads throughout (§2:15, PERF-2:141, addendum A4:44–46) but **never name structured concurrency**. Structured concurrency is finalized in JDK 25 (JEP 505), so it is a real, demonstrable portfolio signal the brief explicitly calls out.

**Why it matters (qualitative intent).** The brief elevates structured concurrency as part of the "demonstrates modern Java (concurrency, networking)" portfolio story. The PRD's "Loom concurrency" phrasing is generic enough to drop it.

**Recommendation.** Add one line — either a NFR (e.g., MAINT-2.x or a new MAINT item: "use structured concurrency where a request/session scope benefits from it") or an addendum note tying per-connection virtual-thread handling to structured-concurrency scopes. Keeps the portfolio intent captured. Autofix not safe (product wording decision).

---

### MINOR — native-image rationale shifts from "perf-triggered" to "effort-stretch"

**Severity: low.**

- **Brief (brief.md:28):** "GraalVM native-image **if perf demands it**."
- **Brief addendum (addendum.md:10):** "GraalVM native-image (AOT) **if performance or footprint demands it**."
- **PRD (MAINT-5:173, OQ-11:246, addendum A4:48):** "**opt-in future path** … Not a v1 commitment (stretch only)"; "AOT constraints **must not leak into v1 design decisions**."

**Nature.** Brief frames native-image as a *conditional perf response* (build it if metrics demand it); PRD frames it as an *effort stretch* and adds a guardrail that AOT must not shape v1 design. The v1 outcome is identical (not committed); only the trigger rationale differs. The PRD's guardrail is slightly more conservative than the brief.

**Recommendation.** No action required for v1. If desired, add a half-sentence to MAINT-5 noting the original perf/footprint trigger so the brief's framing isn't lost.

---

### MINOR (for completeness) — "no Windows build" expanded to "Linux only (no macOS, no Windows)"

**Severity: low.**

- **Brief (brief.md:47):** "no Windows build."
- **PRD (COMP-3:165, §13:264):** "**Linux only** (x86/ARM). No macOS or Windows build in v1."

**Nature.** PRD tightens scope further than the brief (also excludes macOS). This is a stricter scope, not a loosening, and is consistent with the deployment target (containerized Linux). Noting only so the author is aware the brief's wording was narrowed.

**Recommendation.** None — tightening scope is safe. Optionally reflect "Linux only" back into the brief for consistency.

---

## Well captured (no action — listed so the author can see the core carried forward)

Credential-free invariant + fail-closed (FR-SEC-1/5); both-sides dual role (FR-DEPLOY-2); modes A/B/C incl. Mode B accepted-risk posture (§8); OIDC delegation with Keycloak-as-reference (FR-AUTH-1); runtime source-agnostic certs (FR-SEC-4); from-scratch-on-JDK-25 originality (MAINT-3, SEC-4); Cloudhopper/jSMPP positioning (§2); Apache-2.0 (§4); headless + documentation-is-the-surface (OPS-1); family plan incl. SMPP-library and JMeter siblings (§13); "proud to show, actually uses" + "adoption is a bonus, not the bar" success tone (§4); stakeholders expanded, none dropped (§3); the "non-invasive augmentation pattern" framing (§1); no bundled IdP / no cert issuance (FR-SEC-4, §13).

## Recommended author actions (in priority order)

1. **Sign off on the metrics/observability divergence** (Finding 3) — the only place the PRD contradicts explicit brief intent in two sources. Either bless the PRD's minimal observability and update the brief wording, or pull `/metrics` back out of v1.
2. **Confirm the library→application inversion** (Finding 1) and the MT-only→payload-transparent reframing (Finding 2) — both already flagged upstream; recorded here with brief-addendum evidence.
3. **Optional:** add a one-line structured-concurrency mention (Finding 4) to preserve the portfolio-intent signal.
