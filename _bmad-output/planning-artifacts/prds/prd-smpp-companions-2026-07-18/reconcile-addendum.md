---
title: Reconcile — Brief Addendum (source) vs PRD + PRD Addendum
project: smpp-companions
status: done
role: reconcile-addendum
source: _bmad-output/planning-artifacts/briefs/brief-smpp-companions-2026-07-18/addendum.md
checked_against:
  - prd.md
  - addendum.md
updated: 2026-07-19
---

# Reconcile — Source Brief Addendum vs PRD run (prd.md + addendum.md)

> Did every technical-how item and every accepted-risk in the **source brief addendum** land in either `prd.md` or `addendum.md` (captured), or get explicitly deferred (open question / out-of-scope / resolved-and-kept-for-audit)? This file lists the items that did **not** — plus framing notes where substance survived but the label shifted.
>
> Stakes = hobby/portfolio. Findings are calibrated lean: nothing here is load-bearing for the trust model or the build. All gaps are LOW severity.

## Verdict

**Substantially reconciled.** Every load-bearing technical-how and every accepted-risk from the source brief addendum is captured somewhere in the PRD run, usually with deliberate refinement. **Two genuine (low-severity) gaps** where a source item is absent from *both* `prd.md` and `addendum.md`, plus **two framing/staleness notes** where the substance survived but the source's label did not. No critical or high-severity losses.

## Coverage matrix (source → where it landed)

### Tech stack (source §"Tech stack")

| Source item | Captured in | Notes |
|---|---|---|
| JDK 25 | prd COMP-2 | — |
| Netty (async-I/O / SMPP wire) | prd §2; addendum A1, A4 | — |
| Virtual threads | prd §2, §7.1; addendum A4 | — |
| **Structured concurrency** | **NEITHER** | **Gap F-1** |
| GraalVM native-image (escape hatch) | prd MAINT-5, OQ-11; addendum A4 | Explicitly downgraded to stretch — correct deferral |
| Originality (from scratch; Cloudhopper/jSMPP = inspiration only) | prd §4 Goals, MAINT-3, SEC-4 | — |
| Rationale: "library core, thin Docker wrapper" | prd §8, MAINT-2 (substance); addendum A4 (container) | **Note F-4** — "library core" phrasing is stale; form-factor became "application JAR + Docker" |

### Authority provider & certificates (source §"Authority provider & certificates")

| Source item | Captured in | Notes |
|---|---|---|
| Authority provider = external / BYO (Keycloak = reference) | prd FR-AUTH-1, FR-SEC-4 | — |
| Integration protocol = OIDC (standard, pluggable) | prd FR-AUTH-1 | — |
| Certificates are environmental / source-agnostic | prd FR-SEC-4, FR-DEPLOY-4, DEP-2 | — |
| Principle: proxy tier only; IdP + PKI are operator infra | prd §9 narrative, FR-SEC-1, FR-SEC-4 | — |

### Suite context — the family (source §"Suite context")

| Source item | Captured in | Notes |
|---|---|---|
| Companions is a family; v1 = security-transit | prd §2 (Family boundary guardrail), §5, §13 | — |
| Named siblings (SMPP library, JMeter plugin) + earlier candidates | prd §13 Reconciliations | Correctly deferred to non-v1 |
| "v1 architecture should keep companions as pluggable modules with a clean SMPP library core" | prd MAINT-2 | Deliberately refined: "internal modularity is a code-quality goal, not a v1 product surface" (§2 guardrail). Intent preserved, commitment scope narrowed — a product decision, captured. |

### Architecture pointer (source §"Architecture (pointer, not re-derivation)")

| Source item | Captured in | Notes |
|---|---|---|
| Two-proxy topology (legacy → proxy1 → proxy2 → SMSC + direct Option B) | prd §8; addendum A5 | — |
| Deployment modes A/B/C | prd §5, §8; addendum A5 | — |
| Password-grant forwarded end-to-end (legacy `system_id` == carrier `system_id`) | prd FR-SEC-3, §9 | — |
| Auth delegated to authority provider **that is also the mTLS CA (unified trust root)** | addendum A5 | Deliberately refined: "Unified-trust-root structure is the operator's environment, **not a v1 integration**." Captured + bounded — not lost. |
| SMSC stateful (multi-bind, session-affinity DLRs); proxy2 stateless relay | prd A-1, REL-4; addendum A5 | — |
| proxy1 mTLS client cert via deploy-time bake | prd FR-DEPLOY-4, FR-AUTH-3, OPS-2 | — |

### Accepted risks (source §"Accepted risks (carried forward)")

| Source accepted-risk | Captured in | Notes |
|---|---|---|
| Password-only as sole ingress factor | prd §11 | — |
| Option B sends the password plaintext over the public internet | prd §11, §8 (Mode B posture) | — |
| Trusted-network assumption on the legacy↔proxy1 leg | prd A-3, §8 (precondition) | **Note F-3** — captured as assumption/precondition, NOT listed in §11 Accepted Risks. Substance present; framing differs. |
| Long-lived baked certs forfeit short-lived-cert revocation | prd §11, OPS-2, OQ-5 (resolved) | — |

### Open items (source §"Open items (carried forward)")

| Source open item | Captured in | Notes |
|---|---|---|
| Revocation (CRL/OCSP) vs scheduled re-bake | prd OQ-5 (resolved → re-deploy-to-rotate), OPS-2 | Correctly resolved |
| **proxy2 server-cert provisioning** | **NEITHER (explicitly)** | **Gap F-2** — plausibly absorbed by general cert FRs, but the specific open question is dropped, not deferred |
| HA/failover | prd §11, §13 (single-instance v1; statelessness as future-HA enabler) | Correctly deferred |
| bind/PDU audit logging | prd §13 Reconciliations (baseline logging IN; PDU-level audit OUT, future companion) | Correctly resolved |
| authority-provider↔SMSC relationship (deliberately pluggable) | addendum A5 (unified-trust-root = operator environment, not a v1 integration) | Correctly deferred |

## Findings

### F-1 — "Structured concurrency" named in source, absent from both PRD artifacts  (LOW)

**Source (brief addendum, Tech stack):** "*Concurrency:* **Virtual threads + structured concurrency** (Project Loom), where applicable."

**State:** `grep` for "structured concurrency" returns **zero hits** in both `prd.md` and `addendum.md`. The PRD speaks only of "virtual threads" (§2, §7.1) and "Loom-era concurrency"; addendum A4 describes the actual concurrency model as "Virtual threads carry per-connection work; Netty event loops remain a fixed pool of platform threads."

**Why it matters (a little):** The source names a specific technique. The PRD's actual design (one VT per connection + a fixed Netty event-loop pool) is arguably *incompatible* with a structured-concurrency scope-tree model — which is a legitimate reason to drop it. But the PRD never says so; the term simply vanishes. For a portfolio piece whose headline is "modern-JVM engineering," silently dropping a named Loom feature is the kind of thing a reviewer asks about.

**Recommendation:** One line in addendum A4 — either (a) state that structured concurrency was evaluated and is **not** used because the VT-per-connection + Netty-pool model doesn't benefit from it, or (b) if it *is* intended (e.g., for bind-lifecycle supervision), say where. Cheapest fix: explicit "not used, and why."

### F-2 — "proxy2 server-cert provisioning" open item dropped without explicit deferral  (LOW)

**Source (brief addendum, Open items):** "proxy2 server-cert provisioning" listed under "Open items (carried forward)."

**State:** No explicit mention in either `prd.md` or `addendum.md`. Addendum A5 names proxy2 ("carrier runs proxy2") and notes it is stateless, but the *server-cert provisioning* question — who provisions the carrier-side egress proxy's server cert, and is that Companions' concern or the carrier's — is neither surfaced as an OQ nor explicitly deferred.

**Likely resolution (inferring):** It is almost certainly absorbed by the general cert-provisioning stance (FR-DEPLOY-4 / DEP-2 / FR-SEC-4: certs are deploy-time, source-agnostic, operator-provisioned). On the carrier/egress side the carrier is the operator, so the same rule applies.

**Recommendation:** Make the absorption explicit — one clause in addendum A5 ("proxy2's server cert is provisioned by the carrier-operator under the same deploy-time, source-agnostic rule as all certs; no special handling"), or fold it into OQ-4's architecture-phase cert work. Not a content gap so much as an unmarked checkbox.

## Framing / staleness notes (substance present — no action required, surfaced for awareness)

### F-3 — "Trusted-network assumption" framed as precondition, not accepted-risk

The source lists "trusted-network assumption on the legacy↔proxy1 leg" as an **accepted risk**. The PRD captures the substance thoroughly — A-3 ("Trusted-network isolation on the legacy leg is the deployer's responsibility"), §8 ("Trusted-network precondition … the sole ingress gate … deployer's responsibility — stated explicitly, not buried"), FR-SEC-2 — but classifies it as an **assumption/precondition**, not as one of the §11 Accepted Risks.

This is a defensible framing choice (it is a deploy precondition, not a risk the product accepts), and the substance is fully visible. Flagged only because the source's classification did not carry. No action needed unless the author wants §11 to mirror the source's "accepted-risk" labeling for parity.

### F-4 — "library core, thin Docker wrapper" rationale is stale relative to the PRD's form-factor decision

The source addendum's tech-stack rationale reads: "…keeping the **library-vs-container story clean (library core, thin Docker wrapper)**." The companion **brief.md** (`brief-smpp-companions-2026-07-18/brief.md`) also shipped "library" as a first-class deployment shape ("embed as a library, or run as a Docker image").

The PRD **deliberately changed the form-factor**: §5 / §8 / FR-DEPLOY-1 standardize on **"application (runnable JAR) + Docker image (packaging the same JAR)"** — no library deployment shape in v1. The "library" lives on only as an *internal* modularity goal (MAINT-2: "clean, separable, independently-tested module … structured for future extraction").

So the source addendum's rationale text ("library core") is partially obsolete: there is no library *deployment shape* in v1, only a separable internal core. The substance (clean, extractable SMPP core) is preserved in MAINT-2 and the §2 Family boundary guardrail. The tech-stack *rationale sentence itself* is not mirrored in the PRD addendum.

No action strictly required — this is a brief→PRD refinement, captured in substance. Surfaced because the source addendum's rationale wording would read as inconsistent to anyone diffing the two addenda directly.

## Items correctly deferred / resolved (no action)

For completeness — these source items were all handled correctly (resolved-and-kept-for-audit, explicitly out-of-scope, or pushed to architecture):

- Revocation CRL/OCSP vs re-bake → resolved (OQ-5 / OPS-2).
- HA/failover → out (single-instance v1; §11, §13).
- bind/PDU audit logging → resolved (§13 Reconciliations: baseline IN, PDU-audit OUT/future companion).
- authority-provider↔SMSC relationship → deferred (addendum A5: operator environment, not a v1 integration).
- Unified-trust-root (provider-as-CA) → refined + bounded (addendum A5).
- GraalVM native-image → downgraded to stretch (MAINT-5 / OQ-11 / addendum A4).
- "Pluggable modules / clean SMPP core" → refined to internal modularity (MAINT-2, §2 guardrail).

## Summary

Two low-severity gaps, both cheap to close with a single sentence each:
1. **F-1:** say whether structured concurrency is used or why not (addendum A4).
2. **F-2:** explicitly state that proxy2's server cert follows the general deploy-time/source-agnostic rule (addendum A5 or OQ-4).

Two framing notes (F-3, F-4) where substance survived but the source's label/wording did not — no action required unless parity with the source's framing is desired. No trust-model, performance, or scope content was lost between the source brief addendum and the PRD run.
