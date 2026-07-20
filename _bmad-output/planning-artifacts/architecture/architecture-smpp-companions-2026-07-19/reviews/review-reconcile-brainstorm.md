# Brainstorm Reconciliation Review — ARCHITECTURE-SPINE.md vs brainstorm-intent

- **Workspace:** `architecture-smpp-companions-2026-07-19`
- **Target:** `ARCHITECTURE-SPINE.md`
- **Authority:** brainstorm at `brainstorm-smpp-security-proxy-2026-07-18/brainstorm-intent.md` — the load-bearing security-architecture detail (two-proxy topology, per-leg TLS posture, authority-provider auth model, DLR handling)
- **Reviewer:** BRAINSTORM RECONCILER
- **Date:** 2026-07-19
- **Verdict:** PASS-WITH-FINDINGS — the spine carries the large majority of the brainstorm's load-bearing security detail verbatim (topology, all three per-leg postures, credential-free tier, DLR session affinity, A-1 multi-bind, identity-forwarded, fail-closed, the full accepted-risk set). Two substantive gaps survived: the brainstorm's **unified-trust-root** invariant was deliberately relaxed to three trust roots (user-confirmed in `.memlog.md` line 54) but is **not disclosed as a departure** and leaves the Accepted-Risk Register internally inconsistent; and the **proxy→provider link transport security** (the path that carries the ROPC password grant) was captured in the memlog but dropped from the spine's invariants. Plus two lower-severity topology/clarity items. None requires a redesign; all are reconcile-before-finalize edits.

## Method

The brainstorm is the *load-bearing security-architecture* authority; the spine is the
*architecture-level invariants* substrate. For each load-bearing security detail the task named, this
review asks one question: **is the detail preserved as an invariant (or faithfully carried into the
Accepted-Risk Register), and where it changed, is the change disclosed rather than papered over?**

Items checked (from the task brief):

1. Two-proxy topology — legacy → proxy1 → proxy2 → SMSC + Mode B direct
2. Per-leg TLS posture — (a) legacy leg unauthenticated-by-proxy / trusted-net gate;
   (b) internet leg mode-dependent; (c) SMSC leg password-grant
3. Authority-provider auth model — provider = trust root for password validation **and** mTLS CA;
   proxy2 credential-free
4. DLR handling — session affinity; multiple concurrent binds under one `system_id`

The memlog (`.memlog.md` in this workspace) was consulted to distinguish *deliberate, user-confirmed
departures* from *silent weakenings* — a deliberate departure that is undisclosed in the spine is still
a reconciliation gap, but a different kind than an accidental drop.

## Per-item reconciliation

| # | Brainstorm detail (authority) | Spine handling | Verdict |
| --- | --- | --- | --- |
| 1 | Two-proxy topology: legacy → proxy1/ingress → proxy2/egress → SMSC; Mode B = legacy direct to proxy2 over public internet (§1, §2, §5). | Structural Seed mermaid carries both shapes verbatim (`L→P1→P2→S` + `L -.-> P2` Mode-B-only). AD-17 fixes one-instance/one-role/one-mode. | HONORED (topology); see F2 for the Mode-B-vs-role rule gap. |
| 2a | Legacy leg: trusted net, **no TLS**, **no authn by proxy1**; proxy1 reads `system_id` and routes on it; trusted network is the **sole ingress gate** (§2, §7). | AD-15 verbatim ("the proxy reads `system_id` from the bind and routes on it without validating the legacy password. Trusted-network isolation (A-3) is the deployer's responsibility"). Mermaid: "trusted net — SMPP plaintext / proxy does NOT authn this leg". | HONORED |
| 2b | Internet leg mode-dependent: A = one-way TLS, B = plaintext, C = mTLS (§5). | AD-17 (modes A/B/C, Mode-B acknowledgment gate); mermaid labels all three. | HONORED |
| 2c | SMSC leg: trusted net, **no TLS**, SMPP password-grant, `system_id` == carrier `system_id` (§2, §3). | Mermaid "trusted net — SMPP password-grant / system_id preserved end-to-end"; AD-14 (identity forwarded not mapped); AD-12 (relay ORIGINAL bind to SMSC, sole credential authority). **No-TLS default not restated** as an invariant; AD-20 implies egress TLS may be used. | HONORED (posture); see F4 for the no-TLS-default clarity gap. |
| 3a | **Unified trust root**: the authority provider is **both** the password-grant validator **and** the mTLS CA → "in Option C both ingress factors chain to the same provider" (§3, §7). | AD-10 lists **three separate** trust roots: "operator's OIDC provider (verdicts), the operator's PKI/trust store (Mode C client certs), and the SMSC". Per `.memlog.md` line 54 this three-root model is **user-confirmed deliberate** — but the spine does **not** flag it as a brainstorm departure, and the Accepted-Risk Register still presumes unification. | DEPARTED (deliberate per memlog) — see F1. |
| 3b | proxy2 credential-free: holds only TLS certs + provider-call creds; trust crown jewel migrates off proxy2 onto the provider (§3, §7). | AD-10 ("holds no SMPP passwords, no vault, no CA, no issuing keys … Proxy compromise yields network position only"); AD-12 (discard token, relay original bind). | HONORED |
| 4a | DLRs return on existing binds; SMSC routes DLRs by **session-affinity**; proxy2 holds only socket-pairing state (§4). | AD-9 ("`deliver_sm`/DLRs ride the splice back to the originating bind via the coupled channel pair (that coupling *is* the session affinity)"). | HONORED |
| 4b | SMSC supports **multiple concurrent binds under one `system_id`**; each legacy bind gets its own spliced upstream session (§4, §9 assumption). | AD-9 ("Load-bearing on A-1 (carrier allows multiple concurrent binds under one `system_id` + DLR affinity …)"); AD-24 smoke-tests A-1. | HONORED |

## Findings

### F1 — Unified-trust-root invariant silently replaced by three trust roots; Accepted-Risk Register now inconsistent
**Severity:** high · **Status:** spine edit needed (disclose departure + reconcile register entry).

The brainstorm's load-bearing security invariant (§3, §7) was that the authority provider is the
**unified trust root** — it is *both* the password-grant validator *and* the mTLS client-cert CA, so
that "in Option C both ingress factors chain to the same provider." This was an explicit architectural
property (single crown jewel; single compromise point for full Mode-C impersonation).

The spine's AD-10 replaces this with **three** independent trust roots — "the operator's OIDC provider
(verdicts), the operator's PKI/trust store (Mode C client certs), and the SMSC (sole password
authority)." Per `.memlog.md` line 54 this was a **deliberate, user-confirmed** threat-model decision
("trust roots = OIDC provider + operator PKI + SMSC"). So the change itself is not an oversight.

Two problems remain, both spine-side:

1. **The departure is undisclosed.** The spine flags the Spring Boot stack addition as a cross-artifact
   reconciliation item (Cross-artifact items, line ~330) but flags **nothing** for the brainstorm's
   unified-trust-root → three-trust-roots change. A reader reconciling spine against brainstorm sees
   the single load-bearing security invariant of §3/§7 silently swapped for a different model. The
   brainstorm should have been named as a reconcile target the way the brief was.

2. **The Accepted-Risk Register is now internally inconsistent.** It still carries (inherited from
   PRD §11): *"Authority-provider compromise = full impersonation — mint verdicts/certs; the provider
   is the trust root."* Under AD-10's three-root model the OIDC provider can mint **verdicts** but
   cannot mint client **certs** unless it *also is* the operator PKI CA. The "mint certs" claim only
   holds under the brainstorm's unified model. The register entry needs scoping: either
   "mint verdicts (and certs iff the operator runs the same entity as its PKI CA)" or split into two
   entries (provider-compromise → verdict forgery; PKI-CA-compromise → cert forgery).

**Fix:** add a Cross-artifact item disclosing the brainstorm §3/§7 unified-trust-root → AD-10
three-trust-roots change (with the user-confirmed rationale from memlog line 54), and rewrite the
Authority-provider-compromise register entry so "mint certs" is conditioned on the provider also being
the operator PKI CA. (If the decoupling was *not* intended — i.e., the operator is expected to run one
entity as both — then restore the unified invariant in AD-10 and state it as a Mode-C coupling rule.)

### F2 — Proxy→provider link transport security (ROPC password-grant path) dropped from the spine
**Severity:** medium · **Status:** spine edit needed (add invariant or deferred-with-operator-must-secure note).

The ROPC flow sends the intercepted legacy password (in-memory, per-bind) to the OIDC provider's token
endpoint. The link that carries that grant is load-bearing security detail. The brainstorm flagged it
as an open assumption ("Proxy2 → authority-provider link security (TLS/mTLS/token/service acct) —
parked," §9). The **memlog captured the resolution** — line 36: *"ROPC POST /token with proxy
confidential-client cred (mTLS RFC8705 or client_secret)."* So the design *did* settle that the
proxy↔provider leg is mTLS (RFC 8705) or client-secret authenticated.

That decision **did not make it into the spine.** AD-12 describes the ROPC verdict mechanics and AD-18
file-path-injects the "OIDC client credential," but **no invariant states the proxy→provider transport
security** (TLS / mTLS RFC 8705) that protects the password grant in transit. The Capability Map
references **SEC-3 ("provider link")** but assigns no AD to govern it — SEC-3 is bound only by
AD-3/AD-4/AD-13/AD-20/AD-24, none of which addresses the provider-link transport.

This is the one place where memlog-level load-bearing security detail was thinned on the way into the
spine. Without an invariant, two downstream units (the ROPC adapter; the OIDC/TLS wiring) could diverge
on whether the provider leg is TLS-protected.

**Fix:** add a one-line rule to AD-12 (or a short AD) — "the proxy→provider leg (ROPC token endpoint +
JWKS) MUST be TLS-protected; the proxy authenticates as a confidential client via mTLS (RFC 8705) or
client-secret, credential file-path-injected (AD-18)." Fail-closed (AD-11) already covers provider
unreachability; this closes the transport-security gap.

### F3 — Mode B is structurally egress-only; AD-17's role×mode orthogonality leaves an unaddressed combo
**Severity:** medium · **Status:** spine edit needed (one-line clarification in AD-17).

The brainstorm's Mode B is structurally distinct from A/C: in Mode B the legacy client connects
**directly to proxy2/egress** over the public internet, and **proxy1/ingress does not exist** in the
deployment (§2 diagram, §5). The spine's mermaid preserves this (`L -.->|Mode B only| P2`). But AD-17
treats role and mode as orthogonal — "One instance = one role (`ingress` | `egress`) + one mode
(`A` | `B` | `C`), mutually exclusive" — which per memlog line 12 was the user-confirmed framing
("role and mode are deployment-time config of that JAR").

Consequence: "ingress role + Mode B" is a syntactically valid but **semantically nonsensical** config
(there is no proxy1 in a Mode B deployment). AD-17's fail-fast validation catalog (role/mode unset;
cert material missing per mode; routing table empty; etc.) does not reject or even address this combo.
An operator could configure an ingress-role instance in Mode B and the spine's stated rules would not
flag it.

**Fix:** add to AD-17 — "Mode B is egress-only: an ingress-role instance configured in Mode B is
rejected at fail-fast (no ingress leg exists in a Mode B topology)." This preserves the brainstorm's
topology clarity inside the rule that the spine actually governs config with.

### F4 — SMSC-leg "no TLS by default" not restated as an invariant
**Severity:** low · **Status:** optional spine edit (one-liner alongside AD-20).

The brainstorm §2 stated the SMSC leg crisply: "trusted network, **no TLS**, SMPP password-grant bind."
The spine's AD-20 ("Egress TLS endpoint-identification explicit") implies TLS **may** be used on the
SMSC leg, and memlog line 40 confirms egress TLS to the SMSC is anticipated ("Netty = TLS client to
carrier SMSC, frequently a raw IP"). The brainstorm itself allowed this ("carriers do NOT mandate
TLS/mTLS … upstream TLS is our choice," §7), so this is **not a weakening** — but the spine's per-leg
posture is now less crisp than the brainstorm's: the SMSC leg's default (off, trusted-net assumption)
is implicit only.

**Fix (optional):** add a one-liner to AD-20 clarifying SMSC-leg TLS is operator-choice with a default
of off under the trusted-net assumption (mirroring AD-15's stance on the legacy leg), so the per-leg
posture table reads as cleanly as the brainstorm's §2.

## What was preserved (no action)

For completeness, the following load-bearing brainstorm detail is carried into the spine verbatim or
faithfully, and needs no change:

- **Two-proxy topology + Mode B direct** — Structural Seed mermaid (lines ~243-253).
- **Legacy-leg unauthenticated-by-proxy / trusted-net gate** — AD-15, word-for-word.
- **Internet leg A/B/C mode-dependence + security ordering implied** — AD-17 + mermaid.
- **SMSC leg password-grant, identity preserved end-to-end** — AD-12, AD-14, mermaid.
- **proxy2 credential-free (no passwords/vault/CA/issuing keys)** — AD-10.
- **DLR session affinity via the coupled channel pair** — AD-9 ("that coupling *is* the session affinity").
- **Multiple concurrent binds under one `system_id` (A-1)** — AD-9 load-bearing + AD-24 smoke-test.
- **Trusted-network isolation = deployer's responsibility** — AD-15 ("stated explicitly").
- **Fail-closed universal default** — AD-11.
- **Identity forwarded, not mapped (no pooling/surrogation)** — AD-14.
- **Accepted-Risk Register** — password-only legacy ingress; `system_id` spoofing on the trusted net;
  Mode B plaintext; payload transparency = no content protection; long-lived baked Mode C certs;
  provider outage blocks new binds; no brute-force/rate-limit; no dashboard/mgmt API; single-instance
  no HA — all carried. (Only the *authority-provider-compromise* entry is stale — F1.)

## Verdict rationale

The spine treats the brainstorm's security architecture as load-bearing and carries the large majority
of it verbatim — topology, all three per-leg TLS postures, the credential-free tier, DLR session
affinity, A-1, identity-forwarding, fail-closed, and the accepted-risk set. The reconcile gate the task
asked for ("none of that load-bearing security detail was silently dropped or weakened") surfaces four
items, two of them substantive:

- **F1 (high)** is the sharpest: the brainstorm's *unified-trust-root* invariant — explicitly named in
  the task as load-bearing — was deliberately replaced by a three-trust-root model (user-confirmed in
  memlog), but the spine neither discloses the departure nor reconciles the now-stale Accepted-Risk
  Register entry that still claims the provider can "mint certs." That stale entry is the kind of thing
  that misleads story-level work downstream.
- **F2 (medium)** is a genuine drop: the memlog settled the proxy→provider transport (mTLS RFC 8705 /
  client-secret) for the link that carries the ROPC password grant, and the spine omits it — SEC-3 is
  referenced but ungoverned by any AD.
- **F3 (medium)** and **F4 (low)** are clarity/topology items (Mode B egress-only rule; SMSC-leg TLS
  default), each closeable with a one-line edit.

None of the four requires a redesign; all four are reconcile-before-finalize edits to the spine (F1
optionally also touches the brief/PRD framing if the unified-vs-split decision is to be re-litigated).
With F1 and F2 reconciled the spine is faithful to the brainstorm's load-bearing security architecture.
