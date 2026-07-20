# Brief Reconciliation Review — ARCHITECTURE-SPINE.md vs brief

- **Workspace:** `architecture-smpp-companions-2026-07-19`
- **Target:** `ARCHITECTURE-SPINE.md`
- **Authority:** brief at `briefs/brief-smpp-companions-2026-07-18/brief.md` (+ `addendum.md`) — the product-framing authority (the PRD refines it; the spine defers to the PRD as the binding product contract)
- **Reviewer:** BRIEF RECONCILER
- **Date:** 2026-07-19
- **Verdict:** PASS-WITH-FINDINGS — the spine honors every load-bearing brief framing; the one stack addition (Spring Boot) is explicitly flagged as a cross-artifact item rather than silently diverged. Findings below are confirmations + finalize-tracking items; none is a spine defect.

## Method

The brief is the *what & why* authority; the spine is the *architecture-level invariants* substrate.
For each load-bearing brief framing, this review asks one question: **does the spine honor it, and
where it departs, does it flag the departure rather than paper over it?** Six framing-authority items
were checked, plus the explicitly-requested Spring Boot flag check:

1. Dual-role single codebase (one product, ingress + egress at runtime — not two products)
2. Payload-transparency (vs the older MT-only framing the brief explicitly corrected)
3. Companions family boundary — v1 = one companion, not a platform; modularity = code quality, not a product surface
4. BYO trust — IdP + PKI external; proxy consumes trust, never provides it
5. From-scratch SMPP layer (not a fork, not derived from Cloudhopper/jSMPP)
6. Spring Boot ADDED to the stack — confirm the spine flags this cross-artifact item rather than silently diverging

## Per-item reconciliation

| # | Brief framing (authority) | Spine handling | Verdict |
| --- | --- | --- | --- |
| 1 | "One codebase, two roles" — one tool plays enterprise/ingress *and* carrier/egress (brief §"What it is", §"Scope"). | Frontmatter `scope: "Dual-role single-codebase runtime"`. AD-17: one instance = one role (`ingress` \| `egress`) + one mode, mutually exclusive — a runtime/config switch, not a separate build. Two Gradle modules live in one repo/product (one JAR/image). | HONORED |
| 2 | Payload-transparent transit; "MT-only is the expected deployment, not a proxy-enforced filter" (brief §"Scope"; addendum). The brief explicitly corrects the older MT-only framing. | AD-3: "all other PDUs are opaque framed bytes… The proxy is payload-transparent; MT-only is a deployment expectation, not a proxy-enforced filter." Cross-artifact items cite the prior MT-only → payload-transparent fix as the model for the Spring Boot reconciliation. | HONORED |
| 3 | "Companions is a family; v1 is the security-transit companion." Modularity as code quality — "structured for future extraction, not a v1 extension-point surface" (brief §"The family"; addendum). | AD-7 frames the codec seam as *extractable* (PURE, inward-only) — a code-quality boundary, not a v1 extension-point surface. Deferred: "Scaffolding for future Companions siblings — out of v1; the only forward-looking invariant is the inward-only codec seam (AD-7)." | HONORED |
| 4 | "Consumes external trust, doesn't provide it." IdP + PKI are operator-provided; Keycloak is reference, not part of the project (brief §"What it is"; addendum). | AD-10 (credential-free proxy tier: no passwords/vault/CA/issuing keys; SMSC = sole credential authority), AD-12 (OIDC ROPC delegation via swappable `BindCredentialVerifier` port), AD-13 (Mode C trust store = operator issuing-CA roots only, never `cacerts`). | HONORED |
| 5 | "Built entirely from scratch for JDK 25 — not a fork, not derived from their code" (brief §"What it is", §"Inspiration"; addendum). | AD-24: author a from-scratch SMPP 3.4 conformance suite; jSMPP 3.0.2 used only as a test/interop counterpart — "never the production codec." Codec/PDU/framing authored in `companions-codec`. | HONORED |
| 6 | Spring Boot is **unnamed** in the brief's stack positioning ("JDK 25, Netty, virtual threads / structured concurrency; GraalVM native-image"). Task: confirm the spine **flags** this addition rather than silently diverging. | Cross-artifact items (lines ~330): "Spring Boot is now part of the stack (AD-16) but is unnamed in the brief's positioning… Reconcile the brief/PRD stack framing to name Spring Boot as the config/DI/lifecycle/Micrometer substrate. Not a Decision-B violation ('from scratch' is scoped to the SMPP layer)." | FLAGGED (not silent) |

## Findings

### F1 — Spring Boot addition correctly flagged, not silently diverged (the requested check)
**Severity:** low · **Status:** confirmed (spine behaved correctly); action is brief-side.

The spine explicitly carries Spring Boot as a cross-artifact reconciliation item and scopes "from
scratch" to the SMPP layer, so AD-16 (Spring Boot platform, Netty driven directly, NO WebFlux/Reactor)
is not a "from scratch" violation. This is exactly the handling the task asked to confirm. The
remaining action is downstream of the spine: at finalize, the **brief's** stack framing should be
updated to name Spring Boot (brief §"What it is" bullet 4 and addendum §"Tech stack" currently list
only "JDK 25, Netty, virtual threads / structured concurrency; GraalVM native-image"). The spine has
done its part by flagging it; the brief is the artifact still behind.

### F2 — Structured-concurrency framing: minor tension between brief and spine, defensibly handled
**Severity:** low · **Status:** disclose at finalize.

The brief/addendum say "Virtual threads + structured concurrency (Project Loom), where applicable."
The spine's AD-5 builds the control plane on **stable** primitives (virtual threads JEP 444,
`ScopedValue` JEP 506, `ExecutorService`/try-with-resources for structured fan-out) and treats
`StructuredTaskScope` (JEP 505) as **preview-only on JDK 25** — opt-in behind a thin seam, never
load-bearing, never in the default build path. This is a defensible LTS-stability call (AD-5 binds
COMP-2: "Prevents: LTS-stability break via a preview API") and is explicitly disclosed, not hidden.
The tension is only that "structured concurrency" colloquially points at STS, which the spine
deliberately does not adopt as load-bearing. Suggested finalize step: confirm the brief's "where
applicable" wording covers the spine's stable-primitives-only reading, or add a one-line note that
STS is hedged for LTS stability.

### F3 — "virtual-thread relay" reconciles PRD/addendum language, not brief language (informational)
**Severity:** low · **Status:** no brief-side action.

The spine's first Cross-artifact item reconciles the phrase "virtual-thread relay" to "Netty
event-loop relay; virtual threads + structured concurrency own the control plane." That phrase
originates in the PRD/addendum, not the brief — the brief only lists virtual threads as part of the
stack without claiming they own the relay. So the spine's reconciliation target is already consistent
with the brief's framing; no brief-side change is needed for this item. Noted only so the finalize
step doesn't conflate the two cross-artifact items.

### F4 — Dual-role single codebase: two Gradle modules is consistent with "one codebase"
**Severity:** low · **Status:** confirmed.

Sanity-check (potential trap): the brief says "One codebase, two roles," and the spine splits into
*two* Gradle modules (`companions-codec` + `companions-proxy`). This is **not** a divergence — the
brief/addendum explicitly endorse modularity ("keep a clean, extractable SMPP library core"), and
both modules ship as one product (one runnable JAR + one Docker image) configured to one role at
runtime. The spine's frontmatter `scope: "Dual-role single-codebase runtime"` echoes the brief's
wording directly. Confirmed consistent.

### F5 — Family boundary: modularity framed as extractability, not extension-point surface (confirmed)
**Severity:** low · **Status:** confirmed.

The brief's sharpest boundary is "modularity as code quality — structured for future extraction, not
a v1 extension-point surface." The spine honors this on both axes: AD-7 describes the codec seam as
PURE/inward-only/extractable (a code-quality boundary), and the Deferred section explicitly excludes
sibling scaffolding from v1 ("Scaffolding for future Companions siblings — out of v1… the only
forward-looking invariant is the inward-only codec seam"). No "platform"/"plugin"/"extension-point"
language creeps into v1's contract. Confirmed.

### F6 — BYO trust + credential-free tier + from-scratch SMPP layer: all honored (confirmed)
**Severity:** low · **Status:** confirmed.

Bundle-confirmation for items 4 and 5 above. The proxy holds no SMPP passwords / vault / CA / issuing
keys (AD-10); the SMSC is the sole credential authority; OIDC/JWKS and the Mode C trust store are
operator-supplied, with `cacerts` explicitly excluded as a peer-trust source (AD-13). The from-scratch
codec is authored in `companions-codec` with a from-scratch conformance suite (AD-24); jSMPP is
test/interop-only and "never the production codec." All consistent with the brief's "consumes external
trust" and "built entirely from scratch" framings.

## What was NOT found

- **No silent stack divergence.** Spring Boot is the only stack addition vs the brief, and it is
  flagged. Generational ZGC, Nimbus JOSE+JWT, and the jlink runtime image are spine-level
  implementation choices consistent with the brief's "modern JVM stack" framing — not divergences.
- **No MT-only backslide.** AD-3 carries the corrected payload-transparent framing verbatim; the
  spine even cites the MT-only → payload-transparent fix as the precedent for the Spring Boot
  reconciliation.
- **No platform-creep.** v1 stays one companion; the codec seam is the only forward-looking
  invariant, framed as extractability.
- **No "from scratch" violation.** Spring Boot is a platform substrate (config/DI/lifecycle/Micrometer),
  not an SMPP library; "from scratch" is scoped to the SMPP layer, and the spine says so explicitly.

## Verdict rationale

The spine treats the brief as the framing authority and either honors each load-bearing framing
verbatim or — in the single case of departure (Spring Boot) — flags it as a cross-artifact item with
a clear reconciliation target and an explicit non-violation rationale. No silent divergences were
found. The findings are confirmations plus two low-severity finalize-tracking items (F1: brief stack
wording still needs Spring Boot; F2: optionally confirm the STS hedge is in scope of "where
applicable"). None requires a spine edit; the spine is reconcilable with the brief as it stands.
