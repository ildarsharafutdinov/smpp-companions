---
review: security-architect (re-verification, SM-2)
target: ARCHITECTURE-SPINE.md (revised after the 8-lens gate; 31 ADs)
reviewer_role: SM-2 trust-model / security-architect
prior_review: reviews/review-security.md (findings S1..S15, pass-with-findings)
verdict: pass-with-findings
posture: hostile — re-assume the reviewer wants to break the revised trust model
created: 2026-07-19
---

# Security-Architect Re-Verification — Companions v1 (Revised Spine)

> SM-2: *the trust model survives a security-architect review.* The prior review (S1..S15) returned pass-with-findings; the spine was revised (AD-10/11/12/13/15/17/19/20/22/24 reworded, AD-25..31 added). This run (a) closes S1..S15 against the revised text and (b) pressure-tests the reworded + new ADs for any new hole, overclaim, or accept-on-indeterminate path introduced by the revision.

## Verdict: **pass-with-findings**

The revision landed. All three HIGHs from the prior run are closed at the spine altitude:

- **The credential-free-AT-REST claim is now exactly right** (AD-10 reworded to "credential-free at rest," runtime-held items enumerated, blast radius stated honestly as "network position + transient in-flight secrets, not network position only"). The headline invariant survives a hostile re-read.
- **The ROPC hard-dependency is honestly owned** (AD-12 "Honesty" clause + register entry: "does not by itself mitigate the architectural dependency on ROPC … single most fragile external dependency"). No mitigation theater.
- **Egress trust is now anchored** (new AD-26: operator-supplied trust store, same posture as AD-13, never `cacerts` by default, explicit opt-in for public-PKI SMSC trust). The ingress-side collapse AD-13 forbade is no longer replicated silently on the egress side.

The 7 new ADs and ~14 tightenings are sound. The credential-free invariant, the fail-closed default, and the trust-root boundaries hold under hostile scrutiny.

What survives this re-read are **four new gaps introduced (or left unowned) by the rewording itself** — none break the trust model, none block the run, but an SM-2 reviewer will surface them. Most load-bearing: **N1** — the AD-12 two-proxy flow clause names the *safe* trust direction (egress trusts ingress) and is silent on the *vulnerable* one (ingress trusts egress), which in Mode A is impossible (one-way TLS), so a peer that reaches the ingress's internet-port listener is relayed every plaintext password. **N2** — the new RFC 7662 introspection fallback is not folded into AD-11's fail-closed enumeration. **N3/N4** are precision nits on AD-10's runtime-hold list and AD-12's startup probe claim.

Findings ranked most-severe first.

---

## (1) Closure of prior findings S1..S15

All fifteen are CLOSED at the spine altitude. Citing the closing AD for each.

| # | Prior finding (severity) | Status | Closed by |
| --- | --- | --- | --- |
| **S1** | AD-10 "credential-free" stated absolutely; blast radius overclaimed (HIGH) | **CLOSED** | AD-10 reworded: title now "credential-free proxy tier **(at rest)**"; enumerates runtime-held items (OIDC client cred, JWKS public keys, per-bind password in-memory only); blast radius now "a *live memory* compromise exposes only the passwords of sessions active during the compromise window — materially 'network position + transient in-flight secrets,' not 'network position only.'" Exactly the S1 fix. |
| **S2** | Egress TLS trust unowned; AD-20 disabled hostname verification without naming the egress trust root (HIGH) | **CLOSED** | New **AD-26** "Egress TLS trust anchoring": operator-supplied trust store, same posture as AD-13, never `cacerts`, fail-fast if absent/empty, explicit opt-in + loud warning for public-PKI SMSC trust. AD-20 reworded to defer SMSC-leg auth to AD-26 and condition hostname-verification disable on (a) IP-SAN certs w/ verification on or (b) the SMSC trust store as sole gate. |
| **S3** | `BindCredentialVerifier` port presented as a ROPC-deprecation hedge (HIGH) | **CLOSED** | AD-12 "**Honesty**" clause: "the port decouples adjudication from a specific IdP token API; **it does not by itself mitigate the architectural dependency on ROPC**, for which no standard replacement grant exists." Register entry rewritten: "hard-depends on ROPC … port localizes a future rework to one adapter; **it does not eliminate the dependency**." |
| **S4** | AD-24 "only parsed surface" wrong; frame decoder not in fuzz target (MEDIUM) | **CLOSED** | AD-24 reworded: "structurally fuzz **both the bind-family parser AND the framing decoder** — the framing decoder runs on every PDU on both legs for the connection lifetime and is the more-exposed surface." New **AD-30** adds the parser-level guard S4 asked for: pinned max `command_length` (65 536), reject lengths < 16, guard overflow/underflow **before allocation**. |
| **S5** | Accept-on-indeterminate gap: non-401 bodies + verdict-vs-JWT precedence (MEDIUM) | **CLOSED** | AD-11 reworded with the full enumeration (200-with-non-JWT/HTML/empty, 200-with-malformed-JWT, 3xx, 4xx≠401, 5xx, timeout, network error → DENY) AND the load-bearing precedence rule: "**a 200 verdict overridden by failed local JWT verification → DENY (DENY always wins on disagreement between verdict and defense-in-depth)**." |
| **S6** | Two-proxy auth flow underspecified; AD-12 vs AD-15 contradiction; routing on unknown `system_id` (MEDIUM) | **CLOSED** | AD-15 reworded ("performs **no local password check and holds no local password store** — password validation is delegated per AD-12"). AD-12 "**Two-proxy flow**" clause names which proxy ROPCs (ingress). AD-11 adds "**Ingress routing:** a `system_id` not in the routing table → DENY (no default route)." (The two-proxy clause itself opens **N1** below — a new gap, not a re-opening of S6.) |
| **S7** | OIDC confidential-client credential not enumerated in AD-10 (MEDIUM) | **CLOSED** | AD-10 runtime-hold enumeration now lists "(1) the OIDC client credential (one operational secret, file-path-injected per AD-18)." |
| **S8** | `/metrics` handler hardening + binding policy (MEDIUM) | **CLOSED** | AD-19 reworded: `HttpServerCodec` + `HttpObjectAggregator` (no hand-rolled parsing), GET-only / exact-path `/metrics` / 404-405 on mismatch, bounded max header/body. Binding policy resolved stricter than PRD A2 (loopback IPv4 only in v1; A2 opt-in superseded — Cross-artifact item). |
| **S9** | `system_id` metrics cardinality has no mechanism (MEDIUM) | **CLOSED** | AD-19: "`system_id` labels emitted **only for `system_id` values present in the routing table** (cardinality = routing-table size, bounded at startup); unknown/rejected `system_id` values increment an unlabeled counter (`binds.rejected.unknown_system_id`) — **no free-form `system_id` is ever a label**." Bounded by AD-29's 1:1 routing. |
| **S10** | SslHandler delegated-task executor "bounded" with no rejection policy (LOW) | **CLOSED** | AD-4 reworded: "on saturation the executor **fails the TLS handshake** (deny the connection, AD-11) — never `CallerRunsPolicy` … and never unbounded queueing." AD-28 fixes the executor as one hand-managed fixed platform-thread pool, abort-and-fail-handshake. |
| **S11** | No explicit zeroization of in-memory password/token (LOW) | **CLOSED** | AD-12 "**Secret hygiene**": "password and access token are held in `char[]`/`byte[]` (never `String`), zeroized on adjudication completion, connection teardown, JVM shutdown, and any exception path." AD-10 references it ("zeroized on completion/teardown (AD-12)"). |
| **S12** | ROPC rationalization appeals to authority, not architecture (LOW) | **CLOSED** | Register rewritten to own the normative text plainly: "deprecated grant (RFC 9700 'MUST NOT'; OAuth 2.1 removes) … does **not** neutralize the normative language or the trajectory … single most fragile external dependency in the trust model." |
| **S13** | JWKS `kid`-not-in-cache policy unspecified (LOW) | **CLOSED** | AD-11: "JWT with a `kid` absent from the cached JWKS → DENY (a background refresh is scheduled; **no foreground refresh-and-retry on the bind path**)." |
| **S14** | Trust-store validation not enumeration-complete (LOW) | **CLOSED** | AD-13: "Trust-store startup validation: refuse if absent, empty, wrong format, wrong password, or containing zero `trustedCertEntry` entries." |
| **S15** | Graceful shutdown drains splices but not in-flight adjudications (LOW) | **CLOSED** | AD-22 reworded: "stop the Netty SMPP acceptor (no new binds) → **DENY in-flight bind adjudications** (fail-closed; no new adjudications after the acceptor stops) → drain in-flight splices …" |

**Closure: 15/15 CLOSED.** No prior finding survived the revision.

---

## (2) New findings (introduced or left unowned by the rewording)

### N1 — Mode A two-proxy: the egress is unauthenticated to the ingress on the internet leg; the AD-12 two-proxy clause names the safe direction and is silent on the vulnerable one · **MEDIUM**

**The hole.** AD-12 (Two-proxy flow): *"the ingress role performs OIDC verification; the egress role trusts the ingress role's authenticated identity over the internet leg (Mode A/C mTLS or server-cert) and forwards to the SMSC."* AD-26 confirms the egress is the TLS **client** connecting to the ingress as TLS **server** ("the egress TLS client validates the peer (P1 / SMSC) server cert"), and the AD-17 matrix agrees (ingress Mode A: *server cert+key*; egress Mode A: *client trust store*).

The clause addresses the **safe** trust direction — the egress validating the ingress's server cert. It is silent on the direction that actually matters for password relay: **the ingress authenticating the egress before forwarding the ORIGINAL bind (with the plaintext SMPP password) to it.** In Mode A (one-way TLS) the egress is the unauthenticated TLS client. One-way TLS authenticates only the server (the ingress) to the client (the egress); the ingress has no client-cert to validate, no identity to bind the connecting peer to.

So: any peer that can reach the ingress role's internet-port listener connects, passes the (one-way) TLS handshake, and is treated as the egress. AD-12 then relays the ORIGINAL bind — **plaintext `system_id` + password, and the full SMS traffic thereafter** — to that peer. A fake egress positioned on the internet leg harvests every bind's plaintext password and all SMS content for the lifetime of the compromise. This is the same class of exposure the register owns for Mode B (plaintext over the public internet), but for Mode A two-proxy it is **not owned anywhere** — not in AD-12, not in AD-26, not in the register, not in AD-17's warning posture.

**Why it survives the revision but fails a hostile re-read.** The S6 fix asked for "which proxy authenticates what." The revision answered "the ingress ROPCs; the egress trusts the ingress" — but the load-bearing question for the internet leg in the weak mode is the *reverse*: does the ingress trust the egress? In Mode C the answer is yes (mTLS client cert); in Mode A the answer is no, and the spine does not say so. "Mode A/C mTLS or server-cert" reads as if both modes are equally acceptable for the internet leg; they are not. Mode C authenticates both directions; Mode A authenticates only the ingress-as-server and leaves the egress anonymous.

**Why MEDIUM, not HIGH.** The exposure is conditional on (a) a two-proxy deployment, (b) Mode A chosen for the internet leg, and (c) the ingress's internet-port listener being reachable by the attacker. The operator controls all three, and the SMSC remains the final password authority (the fake egress cannot itself log into the SMSC without a separate path). But plaintext-password exfiltration from a security-transit proxy is severe, and the spine owns strictly-weaker Mode B with a loud warning while leaving this unmentioned — the asymmetry is the defect.

**Suggested fix.** One of:
1. **Prefer:** extend AD-12's Two-proxy flow to name both directions and own the Mode A gap: *"the egress validates the ingress's server cert; in Mode C the ingress reciprocally validates the egress's mTLS client cert. In Mode A the ingress **cannot** authenticate the egress (one-way TLS) — the ingress's internet-port listener MUST be ACL-isolated to the operator's egress hosts (deployer's responsibility, mirroring A-3), or Mode C MUST be used for the internet leg. A Mode A two-proxy deployment without ACL isolation is an accepted risk requiring an explicit opt-in + loud startup warning (the Mode B pattern)."*
2. Add a register entry: *"Mode A two-proxy internet leg — the egress is unauthenticated to the ingress; a peer reaching the ingress listener receives relayed plaintext passwords/SMS. Mitigated only by network ACL isolation of the ingress internet port. Accept with explicit opt-in, or require Mode C."*

---

### N2 — RFC 7662 introspection fallback: indeterminate cases absent from AD-11's enumeration, result-caching not explicitly forbidden, defense-in-depth asymmetry unowned · **MEDIUM**

**The hole.** AD-12 adds: *"Opaque tokens fall back to RFC 7662 introspection."* This introduces a **second auth-adjudication path** — and it is the effective verdict for opaque tokens (the introspection endpoint's `active:true/false` is the decision; there is no local JWT to verify, because opaque tokens are not JWTs). Three sub-gaps:

1. **AD-11's fail-closed enumeration is token-endpoint-flavoured and does not cover the introspection-endpoint response space.** AD-11 lists "200-with-non-JWT/HTML/empty, 200-with-malformed-JWT, 3xx, 4xx≠401, 5xx, timeout, network error." That enumeration is built around the ROPC token endpoint. For introspection, the indeterminate surface is different and unnamed: introspection-endpoint 5xx / timeout / network error; 200 with non-JSON body; 200 with `active` missing; 200 with `active` of the wrong type (string `"true"` instead of boolean); 3xx. AD-11's blanket "every auth-adjacent decision denies on indeterminate" arguably catches these, but the enumeration an implementer will code to is token-endpoint-specific, and the introspection endpoint is a *different* endpoint with *different* malformed-response modes.
2. **Introspection-result caching is not explicitly forbidden.** AD-12 says "Re-validate every bind (no verdict cache; cache JWKS only)." For JWT tokens, "verdict" unambiguously means the token-endpoint verdict + the local JWT check. For opaque tokens, an implementer could reasonably read "no verdict cache" as covering only the JWT-verdict path and cache the (expensive, online) introspection result — re-opening the exact verdict-cache hole the JWT path was corrected to close. The "no verdict cache" rule should be stated to cover introspection results explicitly.
3. **The defense-in-depth asymmetry vs. the JWT path is not owned.** For JWT tokens, the local JWKS verification is an *offline, cryptographic* backstop that catches token-endpoint misbehavior (captive-portal 200-HTML, an LB returning 200 on `/token`, a buggy IdP) independent of the token endpoint. For opaque tokens, the introspection endpoint is *online to the same IdP* — there is no cryptographic backstop. The two paths have materially different defense-in-depth profiles, and an operator whose IdP issues opaque tokens gets strictly weaker adjudication than one whose IdP issues JWTs. The spine presents introspection as a flat "fallback" without acknowledging the asymmetry.

**Why it matters at SM-2.** The verdict-cache hole was the single most important correction in the prior run (the research-forced fix). The introspection path is a new way to re-open it (sub-gap 2), and a new accept-on-indeterminate surface (sub-gap 1) — both introduced by this revision's wording.

**Suggested fix.**
- Extend AD-11 with an introspection clause: *"Introspection (RFC 7662, for opaque tokens): any introspection-endpoint response other than 200 with a JSON body whose `active` field is boolean `true` → DENY (5xx, timeout, network error, 3xx, 4xx, 200-with-non-JSON, 200-with-missing-`active`, 200-with-non-boolean-`active`, `active:false`)."*
- Add to AD-12: *"Introspection results are never cached — re-introspect every bind (the 'no verdict cache' rule covers the introspection verdict identically to the JWT verdict)."*
- Add to AD-12 or the register: *"Opaque tokens yield strictly weaker adjudication than JWTs (introspection is online to the IdP with no offline cryptographic backstop); operators should configure the IdP to issue JWTs for the ROPC flow. The IdP can always mint verdicts regardless of token type (register, provider-compromise entry)."*

---

### N3 — AD-10's runtime-hold enumeration omits the proxy's own TLS end-entity private key(s) · **LOW**

**The hole.** AD-10's revised "what it *does* hold at runtime" list is: (1) OIDC client credential, (2) cached JWKS public verification keys, (3) per-bind plaintext SMPP password. It omits **the proxy's own TLS end-entity private key(s)** — the internet-leg server cert+key (ingress role, per AD-17), the egress client cert+key (Mode C, per AD-17/AD-29), and, if RFC 8705 mTLS is chosen for the provider link, the IdP client cert+key (per AD-12). These are operational private keys held in memory for the life of the process, file-path-injected per AD-18.

This is the same class of enumeration gap that S7 flagged for the OIDC client credential (and which the revision correctly closed by adding item (1)). The "at rest" claim itself is unaffected — the end-entity key is not an *issuing* (CA) private key, and the spine's careful scoping ("no issuing private keys") is technically correct. But the *runtime-hold enumeration* should be complete; a hostile reviewer reads the list of three, notes the TLS private key is a fourth held secret, and asks why it was omitted from an enumeration that was just corrected for completeness.

**Suggested fix.** Add item (4) to AD-10's runtime-hold list: *"(4) the proxy's own TLS end-entity private key(s) — internet-leg server/client cert per AD-17/AD-29, and the optional IdP mTLS client cert per AD-12; file-path-injected per AD-18, held by the `SslContext`, not an issuing/CA key."*

---

### N4 — AD-12 "fail-fast at startup if the provider lacks Direct Access Grants" may be an overclaim; the detection mechanism is unreliable · **LOW**

**The hole.** AD-12: *"fail-fast at startup if the provider URL is not `https` or the provider lacks Direct Access Grants (non-default since Keycloak 26.2)."* The `https` check is trivially implementable. The "lacks Direct Access Grants" check is not. Detection options: (a) OIDC discovery (`.well-known/openid-configuration`) — `grant_types_supported` is an *optional* discovery field, absent from many providers; (b) a probe ROPC call at startup — requires test credentials the proxy does not have (it adjudicates with *per-bind* end-user credentials); (c) the IdP admin API — requires admin credentials the proxy must not hold. None is reliable.

In practice the proxy discovers Direct-Access-Grants-disabled at **runtime**, on the first bind's ROPC call (the IdP returns a grant-type error, which AD-11 maps to DENY). So the actual behavior is *start successfully, then deny every bind* — not *refuse to start with a clear error*. The spine states "fail-fast at startup" as if the condition is startup-checkable; for the `https` predicate it is, for the Direct-Access-Grants predicate it generally is not. The result is still safe (fail-closed at runtime), but the stated startup behavior is an overclaim, and an operator will see a confusing "started OK, all binds denied" instead of a clean startup refusal.

**Suggested fix.** Reword AD-12 to separate the two predicates honestly: *"fail-fast at startup if the provider URL is not `https`. If the provider does not support Direct Access Grants, this is detected at runtime on the first ROPC call (the grant-type error → DENY per AD-11); the startup check probes OIDC discovery `grant_types_supported` **when the field is present** and otherwise defers to runtime deny-all."*

---

## Things re-checked and found sound (re-verification)

For the record, the following revised / new material was pressure-tested again and held:

- **AD-10 credential-free-at-rest + blast radius.** The "at rest" scoping is now exactly right; the runtime-hold enumeration is honest (subject to N3); the blast-radius clause ("live memory compromise exposes only active-window passwords") is the strongest honest claim and matches the zeroization rule in AD-12. The SM-2 headline invariant survives.
- **AD-11 precedence rule ("DENY always wins on disagreement between verdict and defense-in-depth").** This is the load-bearing rule from S5 and it is stated as a precedence rule, not just an enumeration. Correct.
- **AD-11 ingress-routing corollary ("`system_id` not in routing table → DENY, no default route").** Closes the S6(c) runtime gap. Consistent with AD-29's bounded 1:1 routing.
- **AD-13 blanket "never `cacerts` for ANY peer path."** Correctly extended beyond Mode C ingress to *every* peer-cert validation path, with the AD-26 egress anchor making it real rather than aspirational. `REQUIRE never WANT`, no custom `PKIXBuilderParameters`, no custom chain-validation code, per-instance client certs, enumeration-complete trust-store validation — all retained.
- **AD-24 fuzz scope + AD-30 frame-decoder guard.** The framing decoder is now explicitly the more-exposed surface and is in the fuzz target; AD-30's pre-allocation length guard is the parser-level control S4 asked for, independent of `-XX:MaxDirectMemorySize`. The single named `MaxDirectMemorySize` formula (AD-30) prevents codec/allocator budget drift.
- **AD-25 single-flipper state machine.** Exactly one unit (the data-plane `RelayHandler`) flips; trigger is the decoded `bind_*_resp` ROK on the ingress channel's event loop; non-ROK → tear down; control plane never mutates a data-plane flag. Sound.
- **AD-19 handler hardening + cardinality mechanism.** `HttpServerCodec`+`HttpObjectAggregator`, GET/exact-path, bounded sizes, loopback-only, `system_id` labels bounded to the routing-table set with an unlabeled reject counter. The PRD-A2 opt-in is superseded (stricter). Clean.
- **AD-22 SIGTERM ordering.** Acceptor stop → DENY in-flight adjudications → drain splices → close JWKS → VT drain. The S15 fix landed in the right place in the sequence.
- **AD-28 executor model.** One hand-managed fixed platform-thread pool for `SslHandler` delegated tasks (not VTs — SSLEngine tasks are CPU-bound and may pin carriers), abort-and-fail-handshake on saturation; JWKS refresh on a hand-rolled VT registered with graceful-drain. Resolves the S10 rejection-policy gap and the orphaned-refresh-on-shutdown gap.
- **ROPC hard-dependency ownership (AD-12 Honesty + register).** The strongest honest framing: normative text quoted, trajectory owned, port scoped to "localizes rework, does not eliminate dependency," flagged as the single most fragile external dependency. This is exactly the S3+S12 correction.
- **Consistency Conventions row.** "`cacerts` is never a trust source for peer auth (AD-13, AD-26)" — the convention now carries both anchors. Passwords/tokens in `char[]`/`byte[]` zeroized. Monotonic counters only. All retained.

## Answers to the three headline questions

1. **Is the credential-free-AT-REST claim now exactly right?** **Yes** — for the at-rest claim itself. AD-10's title, enumeration, and blast-radius clause are the strongest honest form. The runtime-hold enumeration is one item short of complete (N3: the proxy's own TLS end-entity key is omitted), but that is a completeness nit on the *runtime* list, not a defect in the *at-rest* claim.
2. **Is the ROPC hard-dependency honestly owned?** **Yes** — AD-12's Honesty clause and the register entry own the normative language, the trajectory, the port's actual scope (localizes, doesn't eliminate), and the "single most fragile external dependency" framing. No mitigation theater remains.
3. **Is egress trust now anchored?** **Yes** — AD-26 anchors the egress TLS client to an operator-supplied trust store with the same posture as AD-13, conditions hostname-verification disable correctly, and requires an explicit opt-in for any `cacerts`/public-PKI SMSC trust. The S2 collapse is closed on the egress side.

## Bottom line for the orchestrator

The revision closed **15/15** prior findings and the three headline trust claims (credential-free at rest, ROPC hard-dependency, egress trust anchoring) are honestly stated. The spine can proceed to the walkthrough artifact after **N1** (Mode A two-proxy egress-unauthenticated gap — the only finding that touches a password-exfiltration path) is addressed at the spine altitude, because AD-12's new Two-proxy flow clause is the place a reviewer will look for exactly this and find the safe direction named but the vulnerable one absent. **N2** (introspection fail-closed enumeration + no-cache rule + defense-in-depth asymmetry) should ride with N1 — it is the other new auth path introduced by the revision and it is not yet held to AD-11's standard. **N3** and **N4** are precision tightenings that can ride into the walkthrough's threat-model section if the spine altitude is kept lean, though both are single-sentence fixes.
