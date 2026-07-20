---
review: security-architect
target: ARCHITECTURE-SPINE.md (Companions v1, 2026-07-19)
reviewer_role: SM-2 trust-model / security-architect
verdict: pass-with-findings
posture: hostile — assume the reviewer wants to find a hole
created: 2026-07-19
---

# Security-Architect Review — Companions v1 Architecture Spine

> SM-2 says: *the trust model survives a security-architect review.* This review assumes the reviewer is hostile and is trying to break the credential-free invariant (AD-10), the fail-closed default (AD-11), and the trust-root boundaries (AD-13/AD-14) by finding any path that quietly accepts-on-indeterminate, leaks a trust root, or overclaims a hedge.

## Verdict: **pass-with-findings**

The load-bearing invariants are correct and well-motivated. The decisions a security architect most worries about got made the right way:

- **Fail-closed is the universal default** (AD-11), not just for OIDC — the enumeration includes Mode C `REQUIRE never WANT`, trust-store-absent fail-fast, JWKS refresh-failure deny.
- **The verdict-cache hole is closed** — re-validate every bind, cache JWKS only (research-forced correction in the memlog is reflected).
- **`cacerts` is never a peer-auth trust source** (AD-13) — the classic trust-root collapse is explicitly forbidden for Mode C ingress.
- **No custom PKIX / chain-validation code** (AD-13) — don't roll your own applies even to "just an algorithm tweak."
- **JWT verification is defense-in-depth, not source of truth** (AD-12) — the IdP token-endpoint status is the verdict, so a local-JWT bypass can't stand alone.
- **File-path secret injection** (AD-18), explicit `system_id`-spoofing and provider-compromise risks owned in the register.

Those choices would not survive a sloppy author. They survive here.

But under hostile scrutiny, the spine has **real holes** — one overclaim that mis-describes the trust model to its own reviewers (AD-10), one unowned trust boundary on the egress side that mirrors the very collapse AD-13 forbids on the ingress side (AD-20), one hedge that is structural theater presented as risk mitigation (the `BindCredentialVerifier` port vs. ROPC deprecation), and a handful of accept-on-indeterminate gaps and surface-area omissions that an SM-2 reviewer will surface. None block the run; all should be fixed at the spine altitude before the walkthrough artifact inherits them.

Findings ranked most-severe first.

---

## Findings

### S1 — AD-10 "credential-free" is true at rest; the spine states it absolutely and the blast-radius claim is too strong · **HIGH**

**The hole.** AD-10: *"the proxy holds no SMPP passwords, no vault, no CA, no issuing keys … Proxy compromise yields network position only."* This is the spine's headline security claim and SM-2 is the success criterion that probes it. It is also overclaimed in two ways:

1. **The proxy TRANSITS the plaintext SMPP password on every bind.** AD-12 makes it explicit: the password is read off the legacy bind, used to build a ROPC token request, and then *"the ORIGINAL bind [is] relaid to the SMSC."* The password therefore lives in memory on `proxy1` during ROPC adjudication, on the wire between `proxy1` and `proxy2` (Mode B: cleartext; Mode A: TLS; Mode C: mTLS), in memory on `proxy2`, and on the wire to the SMSC. The spine's own accepted-risk register says "in-memory per-bind only (no vault)" — the absolute "holds no SMPP passwords" in AD-10 contradicts the register's careful qualification. A heap dump, `kill -3` thread dump, `gcore`, `/proc/<pid>/maps`+`grep`, or a JVM agent attached during bind adjudication yields the plaintext password. None of those require root on a misconfigured operator host.
2. **The blast-radius claim is wrong on two of three trust roots.** `proxy1` (ingress) compromise also yields: the OIDC confidential-client credential (`client_secret` or mTLS client cert — see S7), which can be used to attempt ROPC enumeration off-host; the JWKS cache; live in-flight passwords; and the ability to capture every future bind's password by sniffing the in-process path. That is materially worse than "network position only."

**Why it survives lint but fails a hostile reviewer.** A friendly reader infers "credential-free at rest." A hostile reviewer reads "holds no SMPP passwords" as a verifiable claim, finds an in-memory password, and downgrades the whole trust-model section.

**Suggested fix.** Reword AD-10 to the strongest honest form: *"credential-free **at rest** — no persisted passwords, no vault, no CA, no issuing private keys. Plaintext passwords transit the proxy in-memory per-bind (legacy → proxy1 → proxy2 → SMSC); they are never persisted, never logged, never cached, and are zeroized on bind-adjudication completion and on connection teardown (see S11). The proxy holds one operational credential: the OIDC client credential used to authenticate to the operator's token endpoint."* Restate blast radius as: *"proxy compromise yields no persisted credential stash; in-flight and near-future passwords are exposed during the compromise window."*

---

### S2 — Egress TLS trust anchoring is unowned; AD-20 disables hostname verification without naming the egress trust root · **HIGH**

**The hole.** AD-13 carefully forbids `cacerts` fallback for **Mode C ingress client-cert validation** — exactly the right call, because `cacerts`-as-peer-trust-root collapses the trust boundary to "any publicly-trusted cert." AD-20 then says: on the egress leg, *"`endpointIdentificationAlgorithm` — `null` for IP-addressed SMSC targets,"* because Netty 4.2 defaults the algorithm to `HTTPS` and breaks raw-IP connects. That is a correct bring-up observation — but it **disables hostname verification on the egress TLS client without naming what authenticates the SMSC.** Neither AD-13 nor AD-20 says which trust store the egress TLS client uses.

If the egress side uses JDK `cacerts` (Netty's default when no `trustManager` is supplied), then **any publicly-trusted cert authenticates a MitM-positioned fake SMSC**, and with hostname verification explicitly disabled there is no second check. This is precisely the trust-root collapse AD-13 forbids on the ingress side, replicated on the egress side and not owned.

**Why this matters even in "trusted-network egress" deployments.** The spine's own deployment topology (Structural Seed) shows the egress proxy (`proxy2`) connecting to a carrier SMSC; the legacy↔proxy1 leg is the only one asserted to be on a trusted network. The proxy2→SMSC leg is its own trust boundary. Even if the SMSC endpoint is "trusted" by network position, the TLS authentication of the SMSC is what makes that assertion non-vacuous, and the spine is silent on it.

**Suggested fix.** Add an AD (or extend AD-20) that requires an **operator-supplied SMSC trust store** for the egress TLS client, with the same posture as AD-13: never fall back to `cacerts`, fail-fast if absent/empty, no custom chain-validation code, accept the SMSC cert only if it reaches the operator's SMSC trust anchor. If the deployment genuinely wants `cacerts` for SMSC trust (some operators will), require an **explicit operator opt-in with a loud startup warning** — the same pattern used for Mode B. Disabling hostname verification should be conditional on either (a) IP-SAN-provisioned SMSC certs with verification ON, or (b) explicit operator acknowledgment that the SMSC trust store is the sole gate.

---

### S3 — The `BindCredentialVerifier` port is a structural seam, not a ROPC-deprecation hedge; AD-12 and the register overstate the mitigation · **HIGH**

**The hole.** AD-12: *"Acquire every verdict through a pluggable `BindCredentialVerifier` port so the ROPC adapter is swappable."* Accepted-Risk Register: *"ROPC deprecation … Hedged by the swappable `BindCredentialVerifier` port (AD-12)."* The memlog itself admits the architectural reality: *"the ONLY standard grant validating a raw username+password (no browser, no pre-existing token; Auth-Code/Client-Creds/Token-Exchange/JWT-Bearer/Device-Code/Introspection all need a browser or an existing token)."*

So the port mitigates **implementation coupling to a particular IdP's token API** — useful, real architecture. It does **not** mitigate the **architectural dependency on ROPC**, because there is no off-the-shelf standard OIDC grant to swap in. If Keycloak follows the RFC 9700 / OAuth 2.1 trajectory and removes Direct Access Grants (the memlog flags it is *non-default since 26.2*), the v1 architecture breaks and no alternative adapter exists without inventing a non-standard mechanism (e.g., a credential-bridging sidecar that issues short-lived tokens out-of-band — itself a new trust root the credential-free invariant would have to reckon with).

**Why this matters at SM-2.** A hostile reviewer reads "hedged by the swappable port" as a claim that deprecation is mitigated. It is not. The claim as written is the kind of mitigation theater that erodes reviewer trust in the rest of the register.

**Suggested fix.** (1) Reword AD-12: *"The port decouples adjudication from a specific IdP token API; it does not by itself mitigate the architectural dependency on ROPC, for which no standard replacement grant exists."* (2) Reword the register entry to own the dependency plainly: *"v1 architecture has a hard dependency on ROPC (Direct Access Grants). If ROPC is removed from mainstream IdPs, v1 must be reworked; the `BindCredentialVerifier` port localizes that rework to one adapter but does not eliminate it. Keycloak 26.7 still ships Direct Access Grants; we accept the dependency for v1 and revisit if/when the grant is removed."* (3) Optionally: name a non-ROPC adapter design (out-of-band credential-bridging sidecar, SCIM-provisioned short-lived tokens) as a v1.1 stretch so the hedge becomes real rather than theoretical.

---

### S4 — AD-24's "only parsed surface" claim is wrong; the frame decoder is the continuously-exposed parser and is not in the fuzz target · **MEDIUM**

**The hole.** AD-24: *"structurally fuzz the bind-PDU parser (JQF/jqwik — the only parsed surface)."* AD-2: *"`SmppFrameDecoder` stays active"* during splice, on both legs, for the entire connection lifetime. The frame decoder parses the 4-byte PDU length prefix on **every** PDU — bind, splice, both legs, until unbind. It is more exposed than the bind parser (which runs once per session). The parenthetical "the only parsed surface" is incorrect.

Frame-decoder exploit surface that AD-24 does not name and that SEC-2 only gestures at:
- Oversized declared `command_length` → memory exhaustion before any byte is forwarded.
- Integer overflow / underflow in length arithmetic (declared length < 16, declared length wrapping the 4-byte field).
- Partial-frame re-entrancy and mid-frame connection close.
- Zero-length declared command_length in a tight loop (CPU exhaustion without memory pressure).

AD-21 bounds direct memory via `-XX:MaxDirectMemorySize` (a backstop, not a parser-level control). REL-2 backpressure handles slow egress but not declared-length inflation on the ingress side.

**Suggested fix.** (1) Extend AD-24 to explicitly include the frame decoder in the fuzz target: *"structurally fuzz the bind-family parser **and** the framing decoder (the framing decoder runs on every PDU on both legs for the lifetime of the connection — the more exposed surface)."* (2) Add a parser-level rule (belonging to AD-2 or AD-3) requiring an explicit hard cap on declared `command_length` in the framing decoder, rejecting oversized frames **before** allocation (a guard independent of `-XX:MaxDirectMemorySize`).

---

### S5 — Accept-on-indeterminate gap: non-401 IdP responses with non-conformant bodies, and precedence when token-endpoint says YES but local JWT says NO · **MEDIUM**

**The hole.** AD-11 enumerates 5xx/timeout/malformed → DENY. AD-12 says *"the token-endpoint status (200/401) is the verdict."* Several real-world indeterminate cases are not enumerated:

- **200 with HTML body** (captive portal upstream of the IdP, misconfigured ingress LB returning a login page on `/token`).
- **200 with empty / non-JSON body.**
- **302 redirect** from `/token` (some IdPs redirect on session expiry; a token endpoint should not, but a misconfigured one will).
- **200 with a JWT that fails local verification** (sig mismatch, exp, iss, aud) — AD-12 calls JWT verification "defense-in-depth, not source of truth." But what wins when the verdict says YES and defense-in-depth says NO? The spine does not state precedence. The classic OIDC-validation bypass is a misconfigured IdP returning 200 to anything; under AD-11's enumeration that case is not named and a future implementer could read "200 = verdict = valid" and skip the JWT step.
- **3xx/4xx other than 401** (400 malformed-request, 429 rate-limited, 403 forbidden) — should all DENY; not enumerated.

**Suggested fix.** Tighten AD-11 to enumerate the remaining cases explicitly: *"any non-401 response that does not yield a locally-verifiable JWT (200-with-non-JWT, 200-with-malformed-JWT, 3xx, 4xx other than 401, 5xx, timeout, network error) → DENY. No redirect following. Local JWT verification failure overrides a 200 verdict — DENY always wins on disagreement between verdict and defense-in-depth."* This last rule is the load-bearing one — state it as a precedence rule, not just an enumeration.

---

### S6 — Two-proxy authentication flow is underspecified; AD-12 vs AD-15 contradiction and AD-14 routing on unknown `system_id` · **MEDIUM**

**The hole (a).** AD-15: *"the proxy reads `system_id` from the bind and routes on it **without validating the legacy password**."* AD-12: *"Validate the SMPP password-grant via ROPC."* A reviewer reads these as contradictory: does the proxy validate the password, or not? The intended reconciliation is that AD-15 means "no **local** password check / no local credential store," with validation delegated to the IdP per AD-12 — but the spine does not say so.

**The hole (b).** In the two-proxy topology, which proxy runs ROPC? `proxy1` (ingress) presumably. What does `proxy2` (egress) do when it receives the forwarded bind over Mode C mTLS — re-run ROPC, or trust `proxy1`'s mTLS-authenticated identity and forward to the SMSC? This flow is the load-bearing authentication story for the two-proxy deployment and is silent in the spine. AD-14 ("identity forwarded, not mapped") describes identity continuity; it does not describe which proxy authenticates what.

**The hole (c).** AD-17 fail-fasts on "ingress routing table empty/invalid" but does not say what happens at runtime when a `system_id` arrives that is **not in the routing table**. DENY is the fail-closed answer; the spine should say so explicitly. The accepted-risk register already owns `system_id`-spoofing on the trusted net, so this is consistent — but the runtime behavior should be stated as an AD-11 corollary, not left to implementer judgment.

**Suggested fix.** (1) Reword AD-15: *"the proxy performs no **local** password check and holds no local password store; password validation is delegated per AD-12."* (2) Add a short Two-Proxy Authentication Flow subsection (or extend AD-12) naming which proxy ROPCs (ingress), what authenticates the proxy1→proxy2 leg (mTLS identity in Mode C, server-cert in Mode A, nothing in Mode B), and whether `proxy2` re-validates (recommend: no — trust the mTLS identity and forward; the SMSC remains the authoritative checker). (3) Add to AD-11: *"ingress role: a `system_id` not present in the routing table → DENY (no default route)."*

---

### S7 — The OIDC confidential-client credential is a held credential that AD-10 does not enumerate · **MEDIUM**

**The hole.** To call the token endpoint with ROPC the proxy authenticates as a confidential client — either a `client_secret` or an mTLS client cert (RFC 8705). Both are persistent credentials the proxy holds at runtime. AD-18 correctly lists the OIDC client credential among file-path-injected secrets. But AD-10's enumeration — *"no SMPP passwords, no vault, no CA, no issuing keys"* — does not mention it, leaving the register and AD-10 inconsistent on what the proxy actually holds.

This is not a fatal hole — the credential is necessary and AD-18 handles it correctly — but AD-10 is the headline trust claim and its enumeration should be complete. A reviewer will notice that the proxy holds (a) an OIDC client credential, (b) the JWKS public keys (which are "issuing keys" in the public-half sense), and (c) the per-bind password in transit — none of which appear in AD-10's enumeration.

**Suggested fix.** Reword AD-10's enumeration to be exhaustive: *"the proxy holds: (1) the OIDC client credential (a single operational secret, file-path-injected per AD-18); (2) cached JWKS public verification keys; (3) the per-bind plaintext SMPP password in memory only during adjudication and forward. The proxy holds no SMPP password store, no vault, no CA private key, no issuing private key, no `cacerts`-rooted peer trust."*

---

### S8 — `/metrics` HTTP handler is bespoke attack surface; AD-19 under-specifies the handler and the binding policy · **MEDIUM**

**The hole.** AD-19: *"a tiny loopback HTTP handler on our own Netty calling `PrometheusMeterRegistry.scrape()` — no Actuator web stack, no embedded Tomcat, no WebFlux."* Loopback-only is the right default, but it is not a free pass:

- **A bespoke HTTP parser** is exactly the kind of code that has historically produced request-smuggling, header-DoS, and malformed-method vulnerabilities. AD-19 does not say whether the handler uses Netty's mature `HttpServerCodec` + `HttpObjectAggregator` (correct) or hand-rolled line/state parsing (wrong).
- **Method/path/size bounds** are not specified. GET `/metrics` only? Hard reject on other paths/methods? Bounded max header / max request body?
- **Binding policy tension.** AD-19 says "Bind loopback IPv4 only." The PRD addendum A2 says "explicit opt-in to bind elsewhere." The spine either dropped the opt-in or made the policy stricter than the PRD — a Cross-artifact reconciliation item.
- **Authentication.** Loopback is the sole auth — any local process (and any SSRF reachable from inside the proxy) can scrape. For a security-branded product the posture is acceptable but should be explicit: "the loopback binding is the sole authentication of the metrics endpoint; the operator's host process model is the trust boundary."
- **`system_id` cardinality.** See S9.

**Suggested fix.** Extend AD-19 with handler hardening: *"The `/metrics` handler uses Netty's `HttpServerCodec` + `HttpObjectAggregator` (no hand-rolled HTTP parsing). Method MUST be GET, path MUST be exactly `/metrics`, all other method/path combinations are hard-rejected with 404/405. Max header size and max request size are bounded. The loopback binding is the sole authentication; the operator's host process model is the trust boundary; non-loopback binding is forbidden in v1 (reconcile with PRD addendum A2 opt-in language — drop the opt-in or carry it forward explicitly)."*

---

### S9 — `system_id` metrics cardinality is attacker-influenced; "cardinality-controlled" has no mechanism · **MEDIUM**

**The hole.** AD-19: *"system_id tags permitted (cardinality-controlled)."* `system_id` is attacker-influenced — any peer that can reach the SMPP port can issue a bind with an arbitrary `system_id` string. There is no upper bound on distinct `system_id` values the proxy will accept and label. A malicious peer (or a buggy ESME that generates a fresh `system_id` per bind) explodes Prometheus cardinality, exhausting metrics-backend memory — a DoS that does not touch the proxy's own heap and so is not bounded by `-XX:MaxDirectMemorySize`.

**Suggested fix.** State the cardinality mechanism explicitly: *"`system_id` labels are emitted only for `system_id` values present in the routing table (the ingress role's authoritative `system_id` set); unknown / rejected `system_id` values increment an unlabeled counter (`binds.rejected.unknown_system_id`) without a per-value label. No free-form `system_id` is ever used as a label."* This makes the cardinality equal to the routing-table size, which is bounded at startup validation.

---

### S10 — SslHandler delegated-task executor (AD-4) is "bounded" without a rejection policy · **LOW**

AD-4: *"SslHandler is constructed with a bounded delegating Executor so handshake-crypto delegated tasks do not run on the event loop."* Bounded how, and what happens on overflow? `CallerRunsPolicy` would run crypto on the event loop (the exact thing AD-4 forbids). `AbortPolicy` throws, leaving the handshake in an indeterminate state. `DiscardPolicy` silently drops the task and the handshake hangs.

**Suggested fix.** Specify the rejection policy: *"The delegating executor uses an abort-and-fail-handshake rejection policy — a saturated executor fails the TLS handshake (deny the connection) rather than running crypto on the event loop or queueing unbounded."*

---

### S11 — No explicit zeroization of in-memory password material on bind completion / connection teardown · **LOW**

AD-8(a): per-bind connection-pair state is "ephemeral … gone on teardown." AD-12: "discard the token." Neither addresses the password (or the access token) explicitly. Java GC does not guarantee timely clearing; the password string lives in heap until the next collection of that generation. AD-10's strengthened claim (S1) requires this to be more than GC-eventual.

**Suggested fix.** Add to AD-12 (and reference from AD-10): *"The per-bind password and the IdP access token are held in mutable `byte[]`/`char[]` buffers (not `String`), explicitly zeroized on (a) bind-adjudication completion, (b) connection teardown, (c) JVM graceful shutdown, (d) any exception path. The token is discarded immediately after local JWT verification; the password is discarded immediately after the bind is forwarded to the SMSC."*

---

### S12 — ROPC-deprecation rationalization is defensible but appeals to authority rather than architecture · **LOW**

The register's defense — *"the deprecation targets 3rd-party end-user apps; it does not map to a first-party headless M2M broker"* — is a reasonable framing. But:

- RFC 9700 §4.1.2 normative language is unconditional ("MUST NOT be used"); the end-user-app concern is *rationale*, not *scope*. The first-party framing doesn't neutralize the normative text.
- *"Keycloak maintainer stianst endorsed this framing"* and *"Keycloak 26.7 still ships it"* are timeline observations, not architectural defenses. They will age.

Combined with S3 (the hedge is structural, not deprecation-mitigating), the rationalization is honest but thin. It is owned, which is what SM-2 asks; the fix is to own it more sharply.

**Suggested fix.** Tighten the register entry to: *"v1 architecture hard-depends on ROPC, a deprecated grant (RFC 9700 MUST NOT; OAuth 2.1 removes). The first-party/headless/in-memory framing places us outside the deprecation's primary rationale, but does not neutralize the normative language or the trajectory. v1 accepts this dependency; if Direct Access Grants are removed from the operator's IdP, v1 must be reworked (see S3). This is the single most fragile external dependency in the trust model."*

---

### S13 — JWKS `kid`-not-in-cache policy is unspecified · **LOW**

AD-11 covers "JWKS refresh-failure with no cached match → DENY." It does not cover the normal key-rotation case: a valid token whose `kid` is not in the cache because rotation just happened. The fail-closed answer (deny on first miss, refresh on next, succeed thereafter) is safe; the spine should say so. Otherwise an implementer may (wrongly) trigger refresh-and-retry, introducing a blocking call on the bind path.

**Suggested fix.** Add to AD-11: *"JWT with a `kid` not present in the cached JWKS → DENY (fail-closed). A background refresh is scheduled; subsequent binds see the refreshed cache. No foreground refresh-and-retry on the bind path."*

---

### S14 — Trust-store validation enumerates "absent/empty/unreadable" but not "no trustedCertEntry" / "wrong password" / "wrong format" · **LOW**

AD-13 + AD-17 enumerate "absent/empty" and "unreadable" trust-store conditions. They do not enumerate:

- Trust-store file exists, parses as a `KeyStore`, contains zero entries of type `trustedCertEntry` (e.g., contains only `PrivateKeyEntry` rows from a misconfiguration).
- Wrong trust-store password (the file is "readable" in the sense that it exists, but cannot be loaded).
- Wrong trust-store type (operator supplies a JCEKS file, code expects PKCS12, or vice versa).

All of these should fail-fast. They are not enumeration-complete in AD-17.

**Suggested fix.** Extend AD-17's fail-fast list to: *"trust store absent, empty, wrong format, wrong password, or containing zero `trustedCertEntry` entries → refuse to start."*

---

### S15 — Graceful shutdown (AD-22) drains in-flight splices but not in-flight bind adjudications · **LOW**

AD-22 drains in-flight splices up to a timeout. It does not say what happens to a bind mid-ROPC when SIGTERM arrives. The fail-closed answer is to DENY in-flight adjudications on SIGTERM (do not let a shutdown race complete a partial verdict).

**Suggested fix.** Extend AD-22: *"On SIGTERM, in-flight bind adjudications are DENYed (fail-closed); in-flight splices drain up to the configured timeout. No new adjudications begin after the acceptor stops."*

---

## Things explicitly checked and found sound

For the record, the following were pressure-tested and held:

- **AD-13 PKIX defaults (no custom `PKIXBuilderParameters`, no custom chain-validation code).** Correct — don't roll your own extends to "don't tweak the validator." `maxPathLength 5` default with `BasicConstraints`-tightening is the right posture.
- **AD-13 `REQUIRE never WANT`.** Correct — `WANT` makes the cert optional and creates exactly the accept-on-indeterminate path AD-11 forbids.
- **AD-12 no verdict cache (JWKS only).** Correct — closes the obvious "cached-valid survives credential revoke" hole. The research-forced correction in the memlog made it into the spine.
- **AD-12 token-endpoint-status-as-verdict with local JWT as defense-in-depth.** Correct layering. (Subject to precedence rule in S5.)
- **AD-14 identity forwarded end-to-end, no pooling/mapping/surrogate.** Correct and consistent with AD-15 once S6's wording fix is applied.
- **AD-3 payload transparency honestly framed as a non-control.** The accepted-risk register and AD-3 itself both own "no content-level protection" — this is the right honesty.
- **AD-18 file-path secret injection.** Correct — avoids `/proc/<pid>/environ` and `docker inspect` leakage of env-var secrets.
- **Accepted-Risk Register completeness.** `system_id`-spoofing, provider-compromise, Mode B plaintext, payload-transparency, baked-cert rotation, provider-outage, single-instance, no-rate-limit, no-management-API are all owned. With S3 and S12 tightened, the register is audit-ready.
- **Stack hygiene.** Nimbus ≥10.0.2 (CVE-2025-53864), Netty 4.2.16.Final, JDK 25 pin — appropriate CVE posture.

## Cross-artifact items surfaced

- **PRD addendum A2 `/metrics` opt-in to bind elsewhere vs AD-19 "loopback IPv4 only."** Reconcile — either drop the opt-in (stricter, recommended for v1) or carry it forward in AD-19 with the same explicit-acknowledgment posture as Mode B (S8).
- **PRD §11 / spine register wording on ROPC.** Reconcile — both should carry the strengthened S3+S12 framing, not just the spine.
- **Brief/PRD stack positioning (already in spine Cross-artifact items).** Adding Spring Boot is already flagged; no new item here.

---

## Bottom line for the orchestrator

The spine can go to the walkthrough artifact after **S1, S2, S3, S5, S6, S7, S8, S9** are addressed at the spine altitude (rewording + one or two new short ADs), because those either mis-describe the trust model to its own reviewers or leave a load-bearing boundary unowned. **S4, S10–S15** are correctness/completeness tightenings that can ride into the walkthrough's threat-model section if the spine altitude is kept lean, but S4 (frame-decoder fuzz gap) and S11 (password zeroization) are cheap enough to fix in the spine and worth the additional precision.

The credential-free invariant **holds at rest** and that is the strongest honest claim available to this architecture; making the spine say exactly that — and nothing stronger — is the single highest-leverage edit.
