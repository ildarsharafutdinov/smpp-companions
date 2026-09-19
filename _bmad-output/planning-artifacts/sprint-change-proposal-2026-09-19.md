---
title: Sprint Change Proposal — Correctness-First Re-Prioritization
project: smpp-companions
date: 2026-09-19
trigger: owner direction, issued at the Epic 6 → Epic 7 seam ("favour correctness proof over performance")
workflow: bmad-correct-course
mode: incremental (each proposal approved individually, 2026-09-19)
scope-classification: Moderate (backlog reorganization)
status: approved (2026-09-19, owner "yes" at the correct-course final gate; artifacts applied same day)
artifacts-to-edit:
  - _bmad-output/planning-artifacts/epics.md
  - _bmad-output/implementation-artifacts/sprint-status.yaml
  - _bmad-output/implementation-artifacts/7-1-perf-validation-harness.md
  - _bmad-output/planning-artifacts/prds/prd-smpp-companions-2026-07-18/addendum.md
---

# Sprint Change Proposal — Correctness-First Re-Prioritization (2026-09-19)

## 1. Issue Summary

**Problem statement.** The remaining plan was performance-first: Epic 7 (performance
validation harness) was next, with Story 7.1 sitting `ready-for-dev`. The owner
directed (2026-09-19) a priority inversion — **correctness proof before performance
proof** — adding four work items ahead of Epic 7:

1. **Observability/measurability close-out** — audit the proxy's signals against
   operator needs; close measurable gaps (candidate: latency/timer histograms, the
   spine-Deferred "Prometheus histogram buckets" item).
2. **Prometheus in the sandbox** — the docker-compose rig gains a scraper so the
   proxy's metrics are actually consumed and the rig demonstrates the observability
   story end-to-end.
3. **Docker Hub publishing via GitHub Actions CI** — build + test gate + automatic
   push, so `docker compose up` works from a pull instead of a local build.
   *(Reverses the 2026-09-11 no-CI stance.)*
4. **Whole-codebase meaty review** — owner-sliced into its **own distinct epic**:
   review-prep package (change inventory, hot-spot map, risk annotations, reading
   order) → the owner's human read of code and tests → findings triage.

Plus one deferral: **Epic 7 runs last**, and at its start a **JMeter SMPP plugin**
is evaluated against the custom open-model harness before anything is built
("performance proofs vs jmeter plugin considered after that" — consistent with the
PRD §13 future-family-sibling mention of a JMeter plugin).

**Discovery context.** Issued the day Epic 6 closed (`faec93d`, 2026-09-19), before
any Epic 7 work started — nothing to unwind.

**Evidence.**
- `sandbox/compose.yml` runs pg + 7 Kannel boxes + Keycloak — **no Prometheus**,
  nothing scrapes the proxy.
- The proxy **is** observable at exposition level: structured JSON logs + read-only
  loopback Prometheus-text `/metrics` on a dedicated event loop (Epic 4, AD-19);
  histogram buckets are a spine-Deferred item (never landed).
- The distroless image (Story 5.2) is **local-build only**; **zero CI exists**
  (owner declined 2026-09-11; Story 7.1's Never-list bakes that in).
- Reviews to date are per-story; no whole-codebase meaty pass exists.

## 2. Impact Analysis

**Epic impact.**
- Epics 1–6: **done, untouched** (no rollback; Epic 6 is not reopened).
- Epic 7: **deferred to last** — priority change, not scope change; substance
  intact; gains a start-of-epic load-gen decision gate.
- **New Epic 8** (observability/installability — items 1–3) and **new Epic 9**
  (whole-codebase meaty review — item 4, distinct epic per owner slicing).
- Execution order: **E6 (done) → E8 → E9 → E7**. Build graph: E8 depends on
  E5 (image) + E6 (sandbox/docs); E9 depends on E8 (the read reviews its output);
  E7's "depends on E5" unchanged.
- CM-1 counter-metric check: CI + publishing = delivery polish of the existing
  shape, not adoption-chasing platform-building — passes.

**Story impact.**
- Story 7.1 stays `ready-for-dev`; gains a dated amendment block (deferral, CI
  Never-item supersession, JMeter gate, baseline re-pin at start).
- New story keys under 8-x / 9-x appended to the tracker as story files are
  created (the file's standing mechanic).

**Artifact conflicts.**
- PRD §13 "no metrics dashboard / telemetry backend" vs sandbox Prometheus →
  scoped as **fixture-vs-product** (PRD addendum note; `prd.md` untouched,
  status `final`).
- AD-19 loopback-only `/metrics` vs a Prometheus container scrape → **sandbox-only
  fixture pattern** (recommended: shared network namespace), no product change,
  no spine amendment.
- Story 7.1 frozen Never-list "No CI scaffolding (none exists, owner 2026-09-11)"
  → superseded by this proposal's amendment block.
- AD-24 (test/conformance toolchain) — **potential future amendment only**: if the
  Epic 7 gate adopts a JMeter load-gen, decided then.
- Docs touched at story time (`deployment-guide.md`, `runbooks.md`, sandbox
  `README.md`/`README.ru.md`) — **RU conformance sweep** required for mirrored
  pages, owner terminology glossary applies.

**Technical impact.**
- `.github/workflows/` CI: build + test gate + Docker Hub push; credentials via
  GitHub Actions secrets (DOCKERHUB namespace/token — owner decision at story
  time); no product code change.
- Sandbox: Prometheus service + scrape config joining the proxy's network
  namespace (AD-19-preserving); packaged-container posture otherwise unchanged.
- `proxy/observability/`: audit-first gap close; any histogram work sits under
  AD-19's cardinality rules (no new label dimensions).
- Docker Hub repo/tag strategy; compose/runbooks switch from local-build to pull.

## 3. Recommended Approach

**Selected: Option 1 — Direct Adjustment** (modify/add stories within the plan;
no rollback, no MVP/scope reduction).

- Rollback: not applicable — nothing failed; no completed work is reverted.
- MVP review: not needed — PERF-1..4 and SM-3 stay locked; this re-sequences,
  and arguably *completes* SM-1 ("shippable OSS release") via publishing.

**Effort estimate:** Medium overall —
- Epic 8: three small/medium stories (observability close-out; sandbox
  Prometheus; CI + publish).
- Epic 9: review-prep package (medium), the owner's human read (owner time),
  findings triage + fix round (size depends on findings).

**Risk assessment:** Low–Medium —
- Docker Hub credential handling in CI (Actions secrets; no secrets in env per
  AD-18 spirit).
- Loopback/Prometheus networking quirk (netns pattern needs a story-level proof).
- Amendment discipline: frozen-story text stays byte-identical; dated blocks only.
- Owner-read findings may spawn unplanned fix work (bounded by triage).

**Timeline impact:** Epic 7 shifts by the duration of Epics 8–9. No external
deadlines exist; the portfolio claim (SM-3) lands later but stronger — on
reviewed, installable ground.

## 4. Detailed Change Proposals (all approved 2026-09-19, incremental mode)

### Proposal 1 — `epics.md`

**(a) Dependency chain (Epic List header):**

```
OLD:
**Dependency chain:** Epic 1 → Epic 2 → Epic 3 → Epic 4 → Epic 5 → {Epic 6, Epic 7}
(linear spine through Epic 5, then two independent successors — re-scoped 2026-09-12
from the former single Epic 6; no forward references; every epic standalone.)

NEW:
**Dependency chain (build graph):** Epic 1 → Epic 2 → Epic 3 → Epic 4 → Epic 5 →
{Epic 6, Epic 7}; Epic 8 → Epic 9 (added 2026-09-19, owner direction "favour
correctness proof over performance": Epic 8 depends on Epic 5 + Epic 6, Epic 9
depends on Epic 8). **Execution priority (2026-09-19):** E6 → E8 → E9 → E7 —
Epic 7 is deferred to last, unchanged in substance.
```

**(b) Insert two epic sections after Epic 7, before the template comment:**

```
### Epic 8: Make it observable and installable — measurability close-out, sandbox Prometheus, Docker Hub publishing via CI

*(Added 2026-09-19, owner direction — the correctness-first half of the
re-prioritization that defers Epic 7 to last.)*

**Goal:** The proxy's observability surface is audited against operator needs and
closed where measurable gaps remain (candidate: latency/timer histograms — the
spine-Deferred "Prometheus histogram buckets" item — under AD-19's cardinality
rules, no new labels); the docker-compose sandbox gains a Prometheus service that
actually scrapes the packaged proxy's loopback-only `/metrics` via a sandbox-only,
AD-19-preserving access pattern (recommended: the Prometheus compose service joins
the proxy's network namespace; story-owned detail — the product's loopback-only
binding and fail-closed posture are untouched); and the distroless image is
PUBLISHED to Docker Hub automatically by a GitHub Actions workflow (build + test
gate + push), so `docker compose up` works from a pull instead of a local build.
Operator docs follow: deployment-guide publish path, runbook scrape section,
sandbox README (+ ru mirror, terminology glossary). Reverses the 2026-09-11
no-CI stance (owner direction 2026-09-19) — Story 7.1's "No CI scaffolding"
Never-item is amended accordingly.

- **FRs covered:** *(none new — FR-DEPLOY-1 execution completed by publishing;
  FR-OBS-2 close-out where the audit finds gaps)*
- **NFRs:** OBS-1, OBS-2, DEP-1 (published shape), OPS-1 (doc updates), SEC-5
  (CI pins the toolchain the CVE policy points at)
- **Key ADs:** AD-19 (loopback-only + cardinality + the deferred histogram-buckets
  item), AD-16 (Micrometer model), AD-31 (docs as operator surface), AD-23
- **Depends on:** Epic 5, Epic 6
- **Packages owned:** `proxy/observability/` (gap close only — audit first),
  `sandbox/` (Prometheus service + conf + README/ru), `.github/workflows/` (CI),
  Docker Hub publish path, `docs/` updates (deployment-guide, runbooks + ru)

### Epic 9: The whole-codebase meaty review — review prep and the human read

*(Added 2026-09-19, owner direction — the review lives in its own distinct epic,
sliced from the correctness-first re-prioritization.)*

**Goal:** The owner performs ONE meaty human read of the WHOLE codebase — code and
tests, every epic's output including Epic 8's — prepared by a review-prep package
(change inventory, hot-spot map, risk annotations, recommended reading order) so
the read is systematic instead of archaeological. Findings land in a triage ledger
and bounce to their owning area (the epics.md honest-exception pattern: the review
never patches what it reviews); fixes taken in a follow-up round inside this epic.
Partially serves SM-2 (the trust model read hardening) and precedes Epic 7 —
performance proofs are built on reviewed ground.

- **FRs covered:** *(none — process epic)*
- **NFRs:** MAINT-4 (test-strategy review), SEC-2/SEC-4 posture read
- **Key ADs:** *(none new — the review reads all of them; AD-24 test posture)*
- **Depends on:** Epic 8
- **Packages owned:** no main source — review-prep artifact + findings/triage
  ledger; fix rounds touch owning packages only
```

**(c) Epic 7 section — append after the existing re-scope parenthetical:**

```
*(DEFERRED 2026-09-19, owner direction "favour correctness proof over performance":
Epic 7 runs AFTER Epics 8–9. Additionally, at epic start a load-gen decision gate
is mandatory — evaluate a JMeter SMPP plugin (an existing one, or the PRD §13
future-family sibling) against Story 7.1's custom open-model harness BEFORE
building; adopting JMeter is an AD-24 amendment decided then. Story 7.1 carries
the matching amendment block.)*
```

### Proposal 2 — `sprint-status.yaml`

```
OLD:
  # --- Epic 7: Validate all performance — the measurement harness and the published evidence ---
  epic-7: in-progress
  7-1-perf-validation-harness: ready-for-dev
  epic-7-retrospective: optional

NEW:
  # --- Epic 7: Validate all performance — the measurement harness and the published evidence ---
  # DEFERRED 2026-09-19 (owner direction "favour correctness proof over performance",
  # sprint-change-proposal-2026-09-19): execution runs AFTER Epics 8–9; status stays
  # in-progress (story file exists) — the deferral is priority, not regression. At epic
  # start: mandatory load-gen decision gate (JMeter SMPP plugin vs Story 7.1's custom
  # open-model harness; adopting JMeter = AD-24 amendment decided then).
  epic-7: in-progress
  7-1-perf-validation-harness: ready-for-dev
  epic-7-retrospective: optional

  # --- Epic 8: Make it observable and installable — measurability close-out, sandbox
  #     Prometheus, Docker Hub publishing via CI ---
  # (Added 2026-09-19 — depends on Epic 5 + Epic 6; execution priority E6 → E8 → E9 → E7.
  # Story keys appended here as story files are created, per the project note above.)
  epic-8: backlog
  epic-8-retrospective: optional

  # --- Epic 9: The whole-codebase meaty review — review prep and the human read ---
  # (Added 2026-09-19, owner direction — the review sliced into its own distinct epic;
  # depends on Epic 8; review-prep package → owner's human read → findings triage,
  # fixes bounce to owning areas per the honest-exception pattern.)
  epic-9: backlog
  epic-9-retrospective: optional
```

### Proposal 3 — `7-1-perf-validation-harness.md` amendment block

Inserted immediately after the `</frozen-after-approval>` closing tag; frozen text
stays byte-identical:

```
## Amendment 2026-09-19 — sprint-change-proposal (correctness-first re-prioritization)

*(Owner direction 2026-09-19, ratified via `sprint-change-proposal-2026-09-19.md`.
The frozen block above stays byte-identical; this amendment is the sanctioned
renegotiation its header requires.)*

1. **Deferral:** Epic 7 / this story execute AFTER Epic 8 (observability close-out,
   sandbox Prometheus, Docker Hub via CI) and Epic 9 (whole-codebase meaty review).
   Priority change only — scope and status (ready-for-dev) unchanged.
   `baseline_commit` is re-pinned at story start, after Epics 8–9 land.

2. **Never-list supersession — CI:** "No CI scaffolding (none exists, owner
   2026-09-11)" is SUPERSEDED: GitHub Actions CI exists from Epic 8 (build + test
   gate + Docker Hub publish). Residual constraint: this story authors no CI
   workflow of its own and leaves the Epic-8 pipeline untouched unless a task
   explicitly requires it — any such change is a visible edit, never a side effect.

3. **Load-gen decision gate (mandatory before building the harness):** evaluate a
   JMeter SMPP plugin (an existing one, or the PRD §13 future-family sibling)
   against the Approach's custom open-model harness BEFORE implementation.
   Adopting JMeter is an AD-24 amendment decided at that time and reopens this
   story's Approach for a further owner-approved amendment; rejection is recorded
   with reasons. Either way the methodology bar survives unchanged — percentile
   tables (never a peak alone), the coordinated-omission self-proof, saturation
   knee + first-failure-mode, full environment disclosure (PERF-070/071).
```

### Proposal 4 — PRD `addendum.md` appended note

Appended after A6, end of file; `prd.md` untouched (status `final`):

```
## A7. Post-final notes — 2026-09-19 (sprint-change-proposal, correctness-first
     re-prioritization)

*Owner direction 2026-09-19; ratified via
`_bmad-output/planning-artifacts/sprint-change-proposal-2026-09-19.md`. No PRD
contract text changes — these notes scope and trace; they do not amend
requirements.*

- **Sandbox Prometheus is fixture scope, not product surface.** §13's non-goal
  ("no metrics dashboard / telemetry backend") governs the PRODUCT. The
  repo-local docker-compose sandbox (a debugging playground — the same category
  as its bundled Keycloak vs "no bundled authority provider") gains a Prometheus
  scraper service in Epic 8. Product posture unchanged: read-only, loopback-only
  `/metrics` exposition (A2, architecture AD-19); no dashboard, no backend, no
  management API.
- **Docker Hub publishing is FR-DEPLOY-1 execution, not a new requirement.** The
  distroless image published automatically via GitHub Actions CI (Epic 8)
  completes "two first-class shapes" (§6.4) and SM-1's "shippable OSS release";
  the published image honors the DEP-1 secrets contract unchanged.
- **Re-sequencing, not descoping.** PERF-1..4 (§7.1) and SM-3 stay locked;
  Epics 8–9 (observability/installability, whole-codebase review) precede
  Epic 7 by owner priority. A JMeter-plugin load-gen option is evaluated at
  Epic 7's start (story-level gate; an architecture AD-24 matter if adopted).
```

## 5. Implementation Handoff

**Scope classification: Moderate** — backlog reorganization (two new epics,
re-sequencing, story amendment, tracker + planning-artifact updates), then
routine per-story development.

**Sequence after approval:**
1. **This workflow applies the four approved artifact edits** (epics.md,
   sprint-status.yaml, Story 7.1 amendment, PRD addendum). Changes remain
   uncommitted — owner commit discipline applies (no auto-commit).
2. **Epic 8 stories** created and executed via the standard implementation flow
   (`bmad-build`, fresh context per story; one task per conversational step).
   Suggested slicing: 8.1 observability/measurability audit + close; 8.2 sandbox
   Prometheus; 8.3 GitHub CI + Docker Hub publish (Docker Hub namespace decision
   is an owner input to 8.3).
3. **Re-run `bmad-sprint-planning`** after story files exist, to auto-detect new
   story keys and refresh the tracker.
4. **Epic 9**: review-prep package story → owner's human read → findings-triage
   (+ fix round) story. Findings bounce to owning areas; nothing is patched
   in-passing.
5. **Epic 7 starts last**: re-pin `baseline_commit`, run the JMeter-vs-custom
   load-gen gate, record the decision (AD-24 amendment if JMeter is adopted),
   then execute.
6. Retrospectives optional per epic, per tracker.

**Success criteria.**
- `docker compose up` in the sandbox pulls the published image and Prometheus
  scrapes the proxy's `/metrics` (loopback-only binding intact).
- CI builds + tests + publishes on the owner's trigger; no secrets outside the
  Actions secret store.
- Observability audit lands with cited evidence; every gap found is closed or
  explicitly ledgered.
- Review-prep package exists; the owner's read is completed; every finding is
  triaged (fixed / ledgered / declined-with-reason).
- Epic 7 begins only after Epics 8–9, with the load-gen gate decision recorded.
