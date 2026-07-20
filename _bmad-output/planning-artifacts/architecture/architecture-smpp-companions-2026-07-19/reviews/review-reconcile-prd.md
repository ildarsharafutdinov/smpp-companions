# PRD Reconciliation Review — ARCHITECTURE-SPINE.md vs PRD

- **Workspace:** `architecture-smpp-companions-2026-07-19`
- **Target:** `ARCHITECTURE-SPINE.md`
- **Authority:** PRD at `prds/prd-smpp-companions-2026-07-18/prd.md` (status: **final** — the binding product contract) + `addendum.md` (the *how*)
- **Reviewer:** PRD RECONCILER
- **Date:** 2026-07-19
- **Verdict:** PASS-WITH-FINDINGS — every load-bearing PRD requirement is either landed in an AD, landed structurally, or explicitly carried in the Accepted-Risk Register / Deferred list, with one true contradiction (Mode B refusal) and one security-precision gap that a security-architect review (SM-2) will press on. Nothing load-bearing was silently dropped, but two items were quietly *weakened* and one explicit PRD sentence is contradicted.

## Method

For each load-bearing PRD item the review asks one question: **did it land in the spine (AD, Structural
Seed, Accepted-Risk Register), or is it explicitly under Deferred — and where it landed, did it land
at full strength?** Three passes:

1. **Coverage pass** — every `FR-*`, every NFR id (`PERF/SEC/PRIV/REL/COMP/MAINT/DEP/OPS/OBS`), every
   resolved OQ, the two deferred OQs (4, 11), the OIDC-flow and threat-model resolutions, the §11
   accepted risks, and assumption A-1.
2. **Strength pass** — where an item landed, did the spine preserve its qualifier/tone, or quietly
   weaken/reinterpret it?
3. **Contradiction pass** — any spine AD that asserts something the PRD denies (or vice-versa).

## Coverage pass — did it land?

### Functional requirements

| FR | PRD requirement (load-bearing part) | Spine home | Landed? |
| --- | --- | --- | --- |
| FR-TRANSIT-1 | Hybrid model: inspect/handle bind+unbind only; splice all else opaque | AD-3 (+ AD-2) | YES |
| FR-TRANSIT-2 | DLRs ride the splice back on session affinity; no separate DLR path | AD-9 (loads A-1) | YES |
| FR-TRANSIT-3 | Pass an SMPP 3.4 conformance suite on both legs | AD-24 (from-scratch suite) | YES |
| FR-TRANSIT-4 | Bind/unbind implements SMPP **3.4**; **5.x not implemented** | AD-3 implies (codec = "SMPP 3.4"); **"5.x not implemented" not stated** | PARTIAL — see F8 |
| FR-SEC-1 | No passwords / no vault; SMSC sole authority; compromise = network position only | AD-10 (+ risk register) | YES (precision — see F2) |
| FR-SEC-2 | Confine legacy weakness to trusted zone (Mode B excepted) | AD-15 | YES |
| FR-SEC-3 | End-to-end identity preserved; no pooling/mapping/surrogate | AD-14 | YES |
| FR-SEC-4 | Consume trust at runtime; no bundled IdP/CA/issuance | AD-10 (+ AD-12, AD-13) | YES |
| FR-SEC-5 | Fail-closed: DENY on unavailable/indeterminate verdict | AD-11 | YES |
| FR-AUTH-1 | Delegate password-grant validation to operator OIDC provider | AD-12 (ROPC + JWT + JWKS + `BindCredentialVerifier` port) | YES (narrowed — see F11) |
| FR-AUTH-2 | Support mTLS (Mode C); do not mandate (A/B password-grant) | AD-13 + three-mode structure | YES |
| FR-AUTH-3 | Per-instance baked client certs; never a shared golden-image key | Capability Map + risk register ("per-instance keys bound the blast radius") | YES — but not an AD rule (see F8-class) |
| FR-AUTH-4 | mTLS terminates handshake; chain depth/trust-anchor = OQ-4 (arch) | AD-13 ("resolves OQ-4") | YES |
| FR-DEPLOY-1 | Two **feature-equivalent** shapes (JAR + Docker): same config/modes/auth | Deployment diagram ("Docker packages the JAR") | YES structurally — parity-by-construction; no AD rule (low) |
| FR-DEPLOY-2 | One codebase both roles; role+mode = deployment-time config | AD-17 | YES |
| FR-DEPLOY-3 | Startup validation; fail-fast on ambiguous/insecure/missing config | AD-17 | YES |
| FR-DEPLOY-4 | Deploy-time cert provisioning; no runtime ACME/SPIFFE | Structural Seed ("no runtime ACME/SPIFFE") | YES — structural, not an AD rule (low) |
| FR-OBS-1 | Baseline JSON-lines logging; full PDU/body only at TRACE | AD-19 | YES |
| FR-OBS-2 | Read-only `/metrics`; per-`system_id` dimensioning; loopback IPv4 | AD-19 | YES |

### Non-functional requirements

| NFR | Spine home | Landed? |
| --- | --- | --- |
| PERF-1 (≥10K/s; "virtual-thread relay" condition) | AD-1, AD-2, AD-21 | YES — but see F4 (the *condition* was reinterpreted) |
| PERF-2 (10K idle pairs <1 GB / <1 vCPU) | AD-1, AD-21 | YES |
| PERF-3 (p99 ~250 ms warm; ≤2 s cold; fail-closed 2–5 s) | AD-11 (timeout→DENY); exact budget Deferred | YES (cold ≤2 s limit not preserved as invariant — low) |
| PERF-4 (sub-ms per-PDU added latency) | AD-1, AD-2 | YES |
| SEC-1 (TLS 1.2 min / 1.3 preferred; publish cipher allowlist) | AD-17 fail-fast ("TLS floor violated"); specifics Deferred | PARTIAL — floor is an invariant; **"publish a cipher allowlist policy" not landed** (F8-class) |
| SEC-2 (parser robustness; splice vs oversized frames) | AD-3, AD-24 (fuzz), AD-2/AD-21 (backpressure) | YES |
| SEC-3 (provider link authenticated **and encrypted**) | AD-4 binds SEC-3 — but AD-4 is threading, not link security | PARTIAL — see F5 |
| SEC-4 (no rolled crypto; mature libs) | Consistency Conventions ("Crypto & libs") | YES |
| SEC-5 (CVE/vuln policy for Netty, JDK) | Stack version pins + Nimbus CVE note | YES as a process posture; no AD rule (acceptable) |
| **PRIV-1** (no persist bodies; `system_id` may be logged/labeled; TRACE-only body; no content in metrics) | AD-8 (no persistence) + AD-19 (no content emitted) cover substance | **NOT in `binds:`** — see F3 |
| REL-1 (no silent drop/duplicate/corrupt) | Capability Map → AD-2; **no AD's "Binds:" line claims REL-1** | PARTIAL — see F7 |
| REL-2 (backpressure) | AD-2 | YES |
| REL-3 (graceful shutdown: stop new binds, drain, exit) | AD-22 | YES |
| REL-4 (statelessness; no `message_id`→`system_id`) | AD-8, AD-9 | YES |
| COMP-1 (interop with unmodified SMPP 3.4 both legs) | AD-24 | YES |
| COMP-2 (JDK 25 floor; JVM-only) | AD-5, Stack | YES |
| COMP-3 (Linux only x86/ARM) | Stack, Deployment diagram | YES |
| COMP-4 (IPv4 only) | Stack, Deployment diagram | YES |
| MAINT-1 (single codebase both roles) | AD-17 | YES |
| MAINT-2 (codec structured for extraction) | AD-7 | YES |
| MAINT-3 (from-scratch; no Cloudhopper/jSMPP derivation) | AD-7 + AD-24 ("never the production codec") | YES |
| MAINT-4 (test strategy: mock/conformance, TLS/OIDC vectors, fuzz) | AD-24 | YES |
| MAINT-5 (native-image compatibility stretch) | AD-23 | YES |
| DEP-1 (Docker secrets contract) | AD-18 | YES |
| OPS-1 (**documentation is the operator surface**) | Capability Map mentions "docs"; **no AD/structural element governs docs deliverables** | PARTIAL — see F6 |
| OPS-2 (cert rotation = re-deploy; CRL/OCSP OUT) | AD-13, risk register | YES |
| OBS-1 (read-only metrics; no dashboard/backend/UI) | AD-19 | YES |
| OBS-2 (proxy not silent) | AD-19 | YES |
| OBS-3 (no management API — no query/drain/reload/rotate) | AD-19 | YES |

### Resolved OQs, deferred OQs, OIDC flow, threat model, §11 risks, A-1

| Item | Spine home | Landed? |
| --- | --- | --- |
| ~~OQ-1~~ (carrier multi-bind + DLR affinity confirmed) | AD-9 (A-1) | YES |
| ~~OQ-2~~ (hybrid splice) | AD-3 | YES |
| ~~OQ-3~~ (app↔topology dissolved: one JAR, role+mode) | AD-17 | YES |
| ~~OQ-5~~ (revocation OUT) | AD-13 | YES |
| ~~OQ-6~~ (graceful drain) | AD-22 | YES |
| ~~OQ-7~~ (Mode B: ship + opt-in + loud warning) | AD-17 | **CONTRADICTS §8** — see F1 |
| ~~OQ-8~~ (PDU matrix) | AD-3 | YES |
| ~~OQ-9~~ (IPv4 only, Linux only) | Stack | YES |
| ~~OQ-10~~ (Apache-2.0) | Stack | YES |
| **OQ-4** (mTLS chain depth — deferred to arch) | AD-13 (PKIX defaults; no custom chain code; trust store never `cacerts`) | YES — resolved |
| **OQ-11** (native-image build target — deferred to arch) | AD-23 (no v1 build; stretch; revisit trigger) | YES — resolved |
| OIDC flow resolution | AD-12 (ROPC, disposable JWT, JWKS, `BindCredentialVerifier` port, introspection fallback) | YES |
| Threat model | Spine carries load-bearing trust invariants + Accepted-Risk Register; full STRIDE/DFD explicitly Deferred to the walkthrough | YES — partial-by-design (the PRD itself deferred it) |
| §11 accepted risks (all 10) | Accepted-Risk Register (all 10 carried verbatim; + ROPC-deprecation risk added) | YES — all 10 |
| A-1 (carrier multi-bind + DLR affinity) | AD-9 (named; smoke-test via AD-24) | YES — strongest coverage in the spine |
| A-2 / A-3 | Referenced in risk register | YES |
| A-4 (NTP / accurate clocks) | Not referenced, though JWT `exp` validation (AD-12) depends on it | LOW — see F8-class |

**Coverage verdict:** nothing load-bearing was silently dropped. The gaps are (a) one contradiction
(F1), (b) two quiet weakenings (F2, F4), (c) PRIV-1 missing from the formal `binds:` list (F3), and
(d) a cluster of low-severity "landed structurally but not as an AD rule" items (F7, F8).

## Findings

### F1 — CONTRADICTION: AD-17 refuses Mode B startup; PRD §8 explicitly says "Not refused at startup"
**Severity:** high · **Status:** spine defect — contradicts the binding product contract on a security-relevant behavior.

PRD §8 (the authoritative Mode B posture, reaffirmed by OQ-7):
> "Mode B is shipped and documented … but it is **not the default**, emits a **loud startup warning**,
> and requires an **explicit opt-in acknowledgment**. **Not refused at startup, but never silent.**"

AD-17:
> "Mode B requires explicit acknowledgment (**else refuse**; with it, a loud startup warning + proceed)."

These are directly opposed. The PRD considered exactly this question and chose "warn loudly, do not
refuse"; the spine overrides that to "refuse unless acknowledged." The spine is *stricter*, which
sounds aligned with the fail-closed philosophy — but fail-closed (AD-11) governs *auth-adjacent
decisions*, and Mode B is a deployment-mode selection, not an auth verdict. The PRD owns Mode B
posture and the spine may not tighten it without flagging the departure.

This is the kind of item a security-architect review (SM-2) will flag as "the artifact contradicts
itself on a security gate," and the kind an operator will hit as "the PRD said this would start with
a warning and it refused instead." Either reconcile the PRD (§8 + OQ-7) to authorize refusal, or
restore AD-17 to "loud warning, never silent, starts anyway." Pick one; do not leave them opposed.

### F2 — Security-precision gap: "holds no SMPP passwords / never working credentials" is overstrong vs the in-memory relay reality
**Severity:** medium-high · **Status:** spine internal tension; weakens a crown-jewel claim of a security-branded product.

FR-SEC-1 / AD-10 assert, in absolute form:
> "the proxy holds no SMPP passwords, no vault …" and "Proxy compromise yields network position only."
> (PRD §9 narrative sharpens to: "never working carrier credentials.")

But AD-12 requires the proxy to **"relay the ORIGINAL bind to the SMSC"** (the bind PDU carries the
password), and the Accepted-Risk Register (ROPC item) honestly states the password is **"held
in-memory per-bind."** So a live process-memory compromise of a running proxy *does* yield the
passwords of currently-active binds — contradicting the unqualified "never working carrier
credentials" / "yields network position only."

The *design* is coherent and the *intent* (no vault, no persistence, no stash) is sound and faithful
to the PRD's actual concern (the §1 "password vault backfire"). The defect is that AD-10 inherits
the PRD's absolute phrasing while AD-12 + the risk register quietly acknowledge the transient
holding — leaving the spine internally inconsistent at exactly the claim a reviewer will probe.
SM-2 ("the credential-free invariant holds under review") is the success criterion most exposed
here.

**Fix:** sharpen AD-10's rule to match the risk register's honesty — e.g. "holds no SMPP passwords
*at rest* and no vault/CA/issuing keys; the legacy password is held **transiently in-memory per-bind**
solely to relay the original bind to the SMSC, and is never persisted, logged, or cached." And
qualify the blast-radius line: "compromise yields no *stealable-at-rest* credentials — a live
memory compromise exposes only the passwords of sessions active at compromise time." The PRD's
"never working carrier credentials" should be reconciled to the same qualified form.

### F3 — PRIV-1 is missing from the spine's `binds:` list (privacy not a formally-tracked concern)
**Severity:** medium · **Status:** formal/traceability gap; substance is covered.

The frontmatter `binds:` enumerates PERF/SEC/REL/COMP/MAINT/DEP/OPS/OBS — **PRIV is absent**. The
substance of PRIV-1 is in fact covered: AD-8 restricts mutable state to connection-pair/metrics/JWKS
(no message persistence), and AD-19 forbids message-content emission and gates full PDU/body at
TRACE. But a reader auditing the `binds:` list — or a downstream unit deriving its test obligations
from it — would conclude privacy is not a bound NFR. For a transit proxy carrying SMS content, that
is a meaningful traceability hole even if the behavior is right.

**Fix:** add `PRIV-1` to `binds:` and add a one-line invariant (or a note under AD-8/AD-19) stating
the privacy contract explicitly: "no SMS body is persisted; `system_id` may be logged and used as a
metrics label; full PDU/body only at TRACE; message content never emitted in metrics."

### F4 — "virtual-thread relay" (PRD §2 positioning + PERF-1 condition + addendum A1 harness) reinterpreted by AD-1; PRD text still un-reconciled
**Severity:** medium · **Status:** flagged by the spine (Cross-artifact items) but not yet reconciled into the PRD — and it touches the perf-proof methodology, not just framing.

AD-1 decides: "Netty event loops own the steady-state byte splice; virtual threads own the control
plane … Virtual threads never carry steady-state bytes." This reinterprets three PRD/addendum
load-points that all say "virtual-thread relay":

- PRD §2 positioning ("Built from scratch on JDK 25 + Netty + virtual threads" / "virtual-thread
  relay paradigm")
- **PERF-1's benchmark condition** — "Sustain ≥ 10,000 submit_sm/sec … with mTLS on both legs, OIDC
  validation cached, **virtual-thread relay**"
- Addendum A1's harness plan — "**virtual-thread relay**; publish a percentile table"

The spine's Cross-artifact section flags the framing wording for reconcile-at-finalize, which is
honest. But the load-bearing consequence is larger than wording: PERF-1's *proof conditions* and the
A1 harness both assume the VT carries the relay, so the benchmark methodology (and the SM-3
"first-of-kind published benchmark" claim) is now described against an architecture the spine no
longer builds. The reconcile must extend to PERF-1's condition clause and addendum A1, not just §2's
prose.

**Fix:** at finalize, update PRD §2, PERF-1's condition, and addendum A1 to "Netty event-loop
relay; virtual threads own the control plane" (the spine's AD-1 form), and restate the SM-3 harness
against the event-loop relay so the published benchmark matches what is built.

### F5 — SEC-3 (provider link authenticated **and encrypted**) is not an explicit invariant
**Severity:** medium · **Status:** quiet weakening — the binding is asserted but the rule is missing.

SEC-3: "The proxy→authority-provider link is authenticated and encrypted (TLS/mTLS or
service-account token)." AD-4's `Binds:` line claims SEC-3, but AD-4's rule is "no blocking work on
the event loop" — threading, not link security. AD-12 implies *authentication* (the OIDC client
credential, AD-18) but nowhere states the link is **encrypted** (TLS/mTLS to the provider). For a
product whose entire value is "the password leaves the trusted zone only over a protected path to a
delegated authority," the encryption of that path is load-bearing and should be a named invariant,
not an implication.

**Fix:** add to AD-12 (or a new one-line rule) an explicit clause: "the proxy→provider link is
authenticated and encrypted (TLS 1.2+/mTLS or an equivalent service-account-token bearer over TLS);
the link is fail-fast at startup if the provider URL is not `https`/not reachable with the
configured credential." Then move the SEC-3 bind off AD-4.

### F6 — OPS-1 (documentation is the operator surface) has no governing AD or structural element
**Severity:** medium · **Status:** quiet drop — load-bearing for a headless product, absent from the spine.

OPS-1: "Because the product is headless with no UI/management API, **documentation is the operator
surface**: config reference, deployment-mode guide, troubleshooting/runbooks must exist." The
Capability Map row gestures at "docs" ("OPS/OBS … `observability` + docs"), but no AD fixes
documentation as a deliverable, and the Structural Seed's source tree has no docs location. For a
headless product this is the primary operator interface — its absence from the architecture spine
means no downstream unit inherits a docs obligation, and SEC-1's "publish a cipher allowlist policy"
and Mode A/B/C operational guidance (all operator-facing docs) have no home.

**Fix:** add a short AD (or a Structural-Seed entry) fixing the docs surface as a v1 deliverable —
config reference, per-mode deployment guide, runbooks/troubleshooting — and point SEC-1's cipher
allowlist and the Mode B warning text at it. (This is also where the Deferred "A-1 real-carrier
operational test plan" and OPS-1 naturally dock.)

### F7 — REL-1 (transit integrity) is not claimed by any AD's "Binds:" line
**Severity:** low · **Status:** covered via the Capability Map, but not formally owned.

REL-1 — "do not silently drop, duplicate, or corrupt spliced traffic or DLRs" — is the most
fundamental reliability guarantee. AD-2 (framed-PDU ByteBufs, write-complete-gates-read
backpressure), AD-9 (DLR affinity), and AD-22 (drain) together deliver it, and the Capability Map
maps "REL-1..4 → AD-2, AD-8, AD-9, AD-22." But no AD's `Binds:` line claims REL-1, so it reads as
incidentally served rather than owned. The framing-splice decision in AD-2 ("framed-PDU ByteBufs,
not raw stream bytes") is precisely what prevents corruption at PDU boundaries — worth making
REL-1's ownership explicit there.

**Fix:** add `REL-1` to AD-2's `Binds:` and add a clause: "the framed-PDU splice forwards each PDU
exactly once, preserving PDU boundaries (no partial/duplicate forwarding) — transit integrity
(REL-1)."

### F8 — Cluster of "landed structurally, not as an AD rule" + small absences
**Severity:** low · **Status:** minor; tracked for completeness.

- **FR-TRANSIT-4 ("SMPP 5.x not implemented")** — implied by "SMPP 3.4 codec/PDU/framing" but never
  stated; add a one-line negative scope note under AD-3 or the Stack.
- **FR-AUTH-3 (per-instance baked client certs; never a shared golden-image key)** — appears in the
  risk register ("per-instance keys bound the blast radius") and Capability Map, but is not an AD
  rule. For a security product the "never a shared golden-image key" prohibition is worth a one-line
  invariant under AD-13.
- **SEC-1 "publish a cipher allowlist policy"** — the allowlist config is Deferred (fine), but the
  *publication* (operator-facing docs) obligation isn't landed; folds into F6.
- **A-4 (NTP / accurate clocks)** — JWT `exp`/`iss`/`aud` validation (AD-12) is clock-dependent;
  A-4 is an unspoken precondition. Add a one-line note under AD-12 that accurate clocks (NTP) are
  required for JWT-exp adjudication, or cite A-4.
- **FR-DEPLOY-1 / FR-DEPLOY-4** — JAR↔Docker parity and deploy-time cert provisioning land
  structurally (Deployment diagram: "Docker packages the JAR"; "no runtime ACME/SPIFFE") but not as
  AD rules. Parity is protected by construction (same JAR), so this is informational, not a risk.

### F11 (informational) — AD-12 narrows FR-AUTH-1's "OIDC" to "ROPC-primary"; defensibly handled
**Severity:** low (informational) · **Status:** acceptable resolution; recorded for transparency.

FR-AUTH-1 says "Delegate … to an operator-run **OIDC** authority provider." AD-12 resolves the flow
to **ROPC** (token-endpoint status = verdict) with RFC 7662 introspection only as an opaque-token
fallback, and fail-fasts if the provider lacks Direct Access Grants. This narrows "OIDC" to a
specific grant and excludes providers that offer only other grants. It is a legitimate architecture
resolution (the task explicitly asked the spine to resolve the OIDC flow), and the swappable
`BindCredentialVerifier` port (AD-12) plus the ROPC-deprecation hedge in the risk register mitigate
the narrowing. Recorded only so the narrowing is a conscious, visible choice rather than an
accidental one.

## Contradiction pass — summary

| # | Spine assertion | PRD assertion | Verdict |
| --- | --- | --- | --- |
| F1 | AD-17: Mode B "else refuse" | §8 + OQ-7: "Not refused at startup, but never silent" | **CONTRADICTION** (high) |
| F2 | AD-10: "holds no SMPP passwords … yields network position only" | §9: "never working carrier credentials" — vs AD-12/risk register "held in-memory per-bind" | **Overstrong claim** (medium-high); internal spine tension |
| F4 | AD-1: "VTs never carry steady-state bytes" | §2/PERF-1/A1: "virtual-thread relay" | **Reinterpretation** (medium); flagged but PRD un-reconciled |

No other spine AD contradicts a PRD requirement. The remaining findings are weakenings/absences
(F3, F5, F6, F7, F8), not contradictions.

## Verdict

**PASS-WITH-FINDINGS.** Coverage is essentially complete: every FR, every NFR, both deferred OQs
(resolved), the OIDC flow, the §11 risk register (all 10, plus a research-derived 11th), and A-1
landed or are explicitly Deferred. The spine did not silently drop any load-bearing requirement.
Three items demand action before the spine is treated as reconciled:

1. **F1 (high, contradiction)** — AD-17 vs PRD §8 on Mode B refusal. Must pick one posture; cannot
   ship opposed.
2. **F2 (medium-high)** — credential-handling precision. AD-10's absolute "holds no passwords /
   network position only" must be qualified to match AD-12 + the risk register's honest
   "in-memory per-bind" reality. This is the SM-2-exposed claim.
3. **F4 (medium)** — the "virtual-thread relay" reinterpretation must be reconciled into PERF-1's
   *proof condition* and addendum A1's harness, not just §2's prose.

F3 (PRIV-1 out of `binds:`), F5 (SEC-3 link encryption), and F6 (OPS-1 docs surface) are quiet
weakenings worth fixing in the same pass; F7/F8 are low-severity traceability tidy-ups.
