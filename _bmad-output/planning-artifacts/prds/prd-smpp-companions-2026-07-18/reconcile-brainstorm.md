# Reconcile: brainstorm-intent → PRD + addendum

**Source of truth (intent):** `_bmad-output/brainstorming/brainstorm-smpp-security-proxy-2026-07-18/brainstorm-intent.md`
**Target:** `prd.md` + `addendum.md` (Companions v1, 2026-07-19)
**Role:** brainstorm reconciliation — surface product-relevant intent the FR/NFR structure silently dropped; flag intentional divergences so they are not mistaken for gaps.
**Calibration:** hobby/portfolio OSS, lean not investor-grade. Findings are weighted toward *design rationale* and *qualitative threat color* the source owned explicitly.

---

## Verdict (summary)

The PRD/addendum capture the brainstorm's load-bearing architecture and decisions well: the credential-free invariant, end-to-end `system_id`, the three modes, deploy-time bake, stateless splice, OIDC delegation, fail-closed, and the accepted-risk posture. The voice ("the trust model is the product," "a security product owns its accepted risks") preserves the source's security-purist tone.

What is silently dropped is mostly **design rationale** (the *why* behind the two-proxy split, the disproved TLS/mTLS constraint) and **two specific threat scenarios** the source owned vividly (system_id spoofing → cross-carrier steering on the trusted net; provider compromise = full impersonation). There is also one **functional capability** in the source architecture — proxy1's per-carrier routing — that has no FR and is in tension with the "single-instance v1" constraint. Two intentional divergences (MT-only → payload-transparent; unified-trust-root → operator-env) are acknowledged below.

---

## A. Intentional divergences (confirm) — NOT gaps to fix

These are places the PRD knowingly diverges from the source. Surfaced only so the author can confirm the divergence is deliberate; severity low by design.

### AD-1 — INTENTIONAL DIVERGENCE (confirm): MT-only softened to "payload-transparent"
- **Source:** §4 line 38 ("Traffic is MT-only"); §9 Won't-this-time ("MO/inbound support (MT-only)").
- **PRD:** §6.1 ("MT-only is a deployment expectation, not a proxy-enforced filter"); §11 ("it does not inspect, filter, or enforce message type (MT/MO)"); constraints say "MT-oriented."
- **Nature:** source treats MT-only as a product-enforced scope boundary; PRD keeps MT as orientation only and makes the proxy payload-agnostic. Consistent with the hybrid-splice decision (OQ-2). **Confirm intended** — appears deliberate and well-reasoned.

### AD-2 — INTENTIONAL DIVERGENCE (confirm): "unified trust root" not a v1 integration
- **Source:** §3 line 32 + §7 line 65 — the authority provider is *also* the mTLS CA, so in Mode C "both ingress factors chain to one thing." Presented as an intended architecture property.
- **PRD/addendum:** addendum A5 — Companions does **not** call the provider for cert-trust decisions and does **not** issue certs; unified-trust-root structure is "the operator's environment, not a v1 integration." PRD §9 trust narrative is silent on it.
- **Nature:** the source's integrated unified-trust-root goal is scoped to the operator's environment; the proxy consumes trust source-agnostically and treats password-validation and cert-trust independently. **Confirm intended.** Optional follow-up: decide whether §9 should still *recommend* operator-side unification as a deployment pattern (the source treated it as a goal, not just a possibility).

---

## B. Gaps — qualitative intent / design rationale dropped

### Medium

#### G-1 — proxy1's per-carrier routing function has no FR (functional gap, in tension with "single-instance v1")
- **Source:** §2 line 26 — "Proxy1 = stateless routing tier (read `system_id` → pick per-carrier proxy2)"; §7 line 62 — the split "turns the per-carrier credential problem into a single concentrator per carrier."
- **PRD:** the ingress role is described abstractly (§2, §5, FR-DEPLOY-2) but no FR captures "read `system_id` → route to the matching per-carrier egress." The `single-instance v1` constraint (§10) further clouds whether one ingress instance may front multiple carriers at all.
- **Why it matters:** this is a concrete capability in the source architecture, not just rationale. Without an FR (or an explicit non-goal), it is unclear whether v1 supports multi-carrier routing on the ingress side or is strictly 1:1. Tie this to the trusted-net spoofing risk (G-2): routing-on-`system_id` is what makes spoofing steer traffic across carriers.
- **Recommendation:** add either an FR for ingress routing-on-`system_id` (multi-carrier) or an explicit non-goal stating v1 is 1:1 per instance, with routing deferred.

#### G-2 — specific "system_id spoofing → cross-carrier steering" risk on the trusted net is generalized away
- **Source:** §8 line 74 — "proxy1 routes on an unauthenticated `system_id`, so any host on that net can claim any `system_id` and be steered toward any carrier's proxy2 before any check."
- **PRD:** §8 names the trusted-network precondition ("the proxy does not authenticate that leg") and §11 lists "Password-only ingress on the legacy leg," but the *specific* cross-carrier-steering consequence is absent.
- **Why it matters:** the source owned a concrete, reviewable attack scenario. The PRD's accepted-risk line is generic enough to lose it. A security-branded product should preserve the specific threat (spoofed `system_id` → mis-steered traffic) so reviewers and operators see it.
- **Recommendation:** add one line to §11 (or §8) naming the system_id-spoofing / cross-carrier-steering consequence explicitly, tied to trusted-network isolation being the sole control.

### Low

#### G-3 — "carriers do NOT mandate TLS/mTLS" (disproved constraint) rationale dropped
- **Source:** §7 line 68 — "Disproved constraints: carriers do NOT mandate TLS/mTLS (C1=no) → upstream TLS is our choice."
- **PRD:** absent. The PRD presents upstream-TLS-as-a-choice (modes) without the empirical finding that motivates it.
- **Why it matters:** this is the key rationale for *why* TLS is a product choice rather than a hard requirement. Cheap to preserve; useful for future contributors.
- **Recommendation:** one sentence in §7 decisions or §10 constraints noting the carrier-mandate question was investigated and found negative.

#### G-4 — two-proxy-split *rationale* (confinement + per-carrier concentration) dropped
- **Source:** §7 line 62 — "Two-proxy split confines L2 (legacy can't do mTLS) to the trusted zone; turns the per-carrier credential problem into a single concentrator per carrier."
- **PRD:** §2/§5 describe the two roles but not the *why* (weakness confinement + one concentrator per carrier). §9 covers confinement of the password weakness but not the concentration rationale.
- **Recommendation:** add a one-line rationale to §2 or §9 preserving the "single concentrator per carrier" intent. Pairs with G-1.

#### G-5 — "provider compromise = full impersonation" threat not in the trust narrative
- **Source:** §3 line 33 — "compromise of the provider = mint valid client certs + approve any grant = full impersonation (protect + make HA)."
- **PRD:** §3 stakeholder mentions the crown jewel lives in the provider; §9 ("Delegated, not assumed, trust") and A-2 cover provider outage. But the specific *compromise* threat (mint certs + approve grants → full impersonation) — the reason the provider must be protected/HA — is not stated.
- **Why it matters:** this is the "protect the crown jewel" argument. Without it, the reader sees "provider outage blocks binds" but not "provider compromise = total break." Source §9 also recommended a dedicated pre-mortem on the provider (line 89); PRD's generic "threat modeling deferred" (§9) does not single it out.
- **Recommendation:** one sentence in §9 naming provider-compromise → full impersonation as the threat that motivates operator-side provider hardening/HA.

#### G-6 — cert-lifecycle operational guidance (re-bake cadence + bake-pipeline lockdown) dropped
- **Source:** §9 Should — line 81 ("scheduled re-bake (7–30d lifetime, automated re-deploy pipeline)"); line 82 ("lock down bake pipeline + image distribution; key storage on proxy1 (file perms / sealed secret)").
- **PRD:** per-instance keys captured (FR-AUTH-3); re-deploy-to-rotate captured (OPS-2). But the recommended cert-lifetime cadence (7–30d) and the bake-pipeline / key-storage hardening guidance are absent.
- **Why it matters:** OPS-2 says "re-deploy to rotate" without saying *how often* or *how to protect the bake pipeline* — both are operator-actionable and were "Should" items in the source.
- **Recommendation:** add a recommended re-bake cadence and bake-pipeline/key-storage hardening note to OPS-2 or an ops subsection (mechanism can stay in addendum).

#### G-7 — "where does brute-force protection live?" left ambiguous
- **Source:** §7 line 64 — delegating to the authority provider "restores proxy2 credential-free status without losing pre-filter / brute-force protection."
- **PRD:** §11 — "No local brute-force / rate-limit protection … v1 ships no local throttle." Not strictly contradictory (protection could live in the provider), but the PRD never states that brute-force protection is *expected* at the authority provider.
- **Why it matters:** a reader of §11 alone cannot tell whether brute-force protection is (a) the operator's provider's job, or (b) simply absent everywhere. The source's intent was (a).
- **Recommendation:** one clarifying clause in §11 noting brute-force protection is expected at the operator's authority provider, not the proxy.

#### G-8 — proxy2 server-cert provisioning was an open item in source; PRD treats it as resolved
- **Source:** §9 line 83 — "Proxy2 server-cert provisioning (lifecycle unspecified)" listed under Should/open.
- **PRD:** "source-agnostic certs at runtime" (FR-SEC-4, §2) treats server-cert sourcing generically; the *lifecycle* (rotation/provisioning flow for proxy2's own server cert) is not called out.
- **Recommendation:** minor — either note proxy2 server-cert lifecycle as an architecture/open item, or state explicitly it follows the same source-agnostic + re-deploy model as client certs.

---

## C. Verified covered (no action)

For audit — brainstorm items confirmed present in PRD/addendum, so they are NOT gaps: credential-free invariant + SMSC-as-sole-authority (FR-SEC-1, §9); end-to-end `system_id` (FR-SEC-3); three modes A/B/C incl. Mode B opt-in+warning (OQ-7, §8); deploy-time bake, no ACME/SPIFFE (FR-DEPLOY-4, §13); per-instance keys (FR-AUTH-3); long-lived-cert accepted risk (§11); stateless splice + no `message_id` correlation (REL-4); carrier multi-bind + DLR affinity assumption (A-1); DLRs on existing binds (FR-TRANSIT-2); provider outage blocks binds (A-2); proxy→provider link secured (SEC-3); fail-closed (FR-SEC-5); trusted-network precondition stated-not-buried (§8); proxy tier holds no vault (FR-SEC-1); mTLS optional not mandated (FR-AUTH-2); C > A > B ordering implied (§8 "Mode C strongest"); "single deployment-wide mode" (FR-DEPLOY-2, §8); rate-limit / anomaly detection OUT (§13); native-image stretch (MAINT-5); Apache-2.0 (§4); Linux/IPv4-only (COMP-3/4).
