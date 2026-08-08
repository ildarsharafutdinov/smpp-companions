---
baseline_commit: c771a0e
epic: 2
story: 1
story_key: 2-1-security-port-contract-validation-slice
status: ready-for-dev
---

# Story 2.1: Security Port Contract-Shape Validation Slice (BindCredentialVerifier ratification)

Status: ready-for-dev

> **The Epic 2 opener — the gating slice.** Before `relay/` finalizes against the seeded `BindCredentialVerifier` port
> (epics.md:366–367), this story (a) authors the AD-12 `proxy/security/` port contract and (b) **ratifies its shape
> against a real Keycloak 26.7.0 ROPC call across all four AD-12 paths**, including `cancelHttp()` per AD-32. The
> contract is validated *before* it is consumed — which is what earns the **"immutable henceforth"** claim. It folds
> in the two open retro action items that existed only because this story hadn't been created: **AI-3** (the ≥26.7.0
> DAG-enabled Keycloak fixture) and **AI-4** (the `proxy/security/` port types).
>
> **Story 3.1 ROPC viability was MET 2026-08-08** (Keycloak 26.7.0 ships Direct Access Grants; no removal/deprecation
> in 26.x; not removable before KC 27) — **no fallback DECISION invoked** (see ARCHITECTURE-SPINE.md §Accepted-Risk
> Register, ROPC entry; sprint-status.yaml AI-2 = done). This story consumes that verdict: it proceeds ROPC-conditional
> against a pinned **≥26.7.0** fixture. The two riskiest external dependencies — deprecated ROPC (RFC 9700 "MUST NOT")
> and the preview StructuredTaskScope API (JEP 505) — are de-risked *here*, while the change is still cheap.
>
> **Scope discipline (non-negotiable):** the **full production ROPC adapter stays in Epic 3**. This story ships the
> *immutable port types + an always-allow stub* in main, and a *test-tier validation slice* that proves the port shape
> works end-to-end against real ROPC. It does NOT build relay wiring, the production adapter, or the SpliceObserver
> contract (separate Epic 2 story). **If any of the 4 paths proves the port shape cannot express it, the story's
> deliverable is a contract REVISION finding — not a silent fallback or a workaround.**

## Story

**As a** platform engineer on the smpp-companions codebase (architect Winston + developer Amelia),
**I want** the AD-12 `proxy/security/` port contract (`BindCredentialVerifier` / `sealed Verdict` / `BindCredential` /
`VerdictRequest` / `RequestContext`) authored, and its shape ratified against a real Keycloak 26.7.0 ROPC call across
all four AD-12 paths (incl. `cancelHttp()` per AD-32, on StructuredTaskScope + ScopedValue per AD-5),
**so that** the port becomes **immutable henceforth** — locked *before* `relay/` commits against it — and the riskiest
external dependencies (deprecated ROPC, preview STS, the undocumented ROPC+mTLS pairing) are either de-risked or a
contract revision is proposed while the change is still cheap.

## Acceptance Criteria

> **The load-bearing evidence is AC2** (a real-ROPC validation slice that exercises all four AD-12 paths and yields the
> correct `Verdict` permit for each) **and AC3** (`cancelHttp()` actually aborts the wire call). The rest wire the port,
> the concurrency model, the fail-closed/secret-hygiene invariants, and the standing RED-on-neuter gate. **AC8 is the
> story's actual goal**: the immutable-henceforth DECISION, recorded — pass *or* contract revision.

1. **[AC1] Port types authored in `proxy/security/`, matching AD-12 exactly.** All in package
   `smpp.companion.proxy.security`:
   - `BindCredentialVerifier` — `interface` with the single seam method
     `VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx)`.
   - `sealed interface Verdict permits Allow, DenyInvalid, DenyIndeterminate` — **no `Throwable`, no free-form reason
     string, no Nimbus type crosses the port** (the ROPC adapter absorbs Nimbus). Each permit is a final
     record/class (e.g. `record Allow()`, `record DenyInvalid()`, `record DenyIndeterminate()`).
   - `record BindCredential(SystemId systemId, char[] password)` — **`char[]`, never `String`**; the record defensive-copies
     the array on construct and on read (records expose components by reference — override `password()` to return a copy,
     and zeroize is the holder's responsibility). `SystemId` holds the SMPP `system_id` (max-16 C-octet). **Reinvention
     guardrail:** first check whether `codec` (Story 1.2 bind parser) already exposes a `system_id`/`SystemId` type to
     convert from — do **NOT** re-parse the C-octet; the codec→`BindCredential` conversion itself happens at the relay
     seam (a later `relay/` story), so this port only needs the type. Choose `CharSequence`/`AsciiString` backing
     consistently with the codec. **Flag the AsciiString→char[] password seam** (CODEC-024 P2 / retro AI-5) — the port
     establishes the `char[]` boundary here; full redaction + no-String-from-password enforcement lands with relay
     logging (AI-5).
   - `VerdictRequest` — exposes `CompletableFuture<Verdict> future()` **and** `void cancelHttp()` (AD-32: the handle that
     aborts the underlying HTTP ROPC call, not only the `CompletableFuture`).
   - `RequestContext` — carries per-bind `system_id`, `ChannelId`, deadlines (AD-5); **bound via `ScopedValue`, never
     `ThreadLocal`**.
   - `AlwaysAllowBindCredentialVerifier implements BindCredentialVerifier` — the production stand-in (`@Component` via
     Spring DI) returning a `VerdictRequest` whose `future()` completes with `Allow` and whose `cancelHttp()` is a no-op.
     This is what `relay/` wires against until Epic 3 swaps in the real adapter behind the **unchanged** port.
   - **Verify `@NullMarked` is present** on `proxy/src/main/java/smpp/companion/proxy/security/package-info.java`
     (Story 1.4 added it to all six packages — confirm it survived; JSpecify `@NullMarked` does **not** propagate to
     sub-packages — any NEW sub-package under `security/` gets its own). *(AD-12:135–141, AD-35.)*

2. **[AC2 — LOAD-BEARING] Real-ROPC contract-shape validation slice exercises all four AD-12 paths** against a pinned
   **≥26.7.0** DAG-enabled Keycloak fixture, asserting each yields the correct `Verdict` permit. The slice is a **test-tier**
   adapter (under `proxy/src/test`) implementing `BindCredentialVerifier` with `java.net.http.HttpClient` + Nimbus — it
   proves the port shape can express every path; it is NOT the production adapter (Epic 3).
   - **Path (1) JWT happy path** — valid creds → token endpoint **200** + JWT → local JWKS defense-in-depth verify
     (Nimbus: `JWKSet.load(certsEndpoint)`, `getKeyByKeyId(kid)`, `SignedJWT.parse`, verify signature, check
     `iss`/`aud`/`exp`/`nbf` per AD-11) → **`Allow`**. Token is discarded; the original bind is what gets relayed (AD-12).
   - **Path (2) opaque-token RFC 7662 introspection** — fixture issues an opaque token; introspection
     (`POST /realms/{r}/protocol/openid-connect/token/introspect`) returns `active:true` → **`Allow`**; introspection
     `active:false` / non-200 / malformed → **DENY** per AD-11 (introspection results are never cached, same as verdicts).
   - **Path (3) RFC 8705 mTLS provider auth — MOST LIKELY TO FAIL** (no primary doc gives an ROPC+mTLS example; inferred
     from general token-endpoint client-auth support). Fixture client configured with **`tls_client_auth`** (RFC 8705),
     X.509 subject DN mapped to the client; the proxy authenticates via an **`SSLContext` carrying the client cert**
     (PKIX defaults, AD-13; **trust store never `cacerts`**) and the ROPC call is made **WITHOUT `client_secret`** (the
     cert authenticates) → **`Allow`**. **If the ROPC+mTLS pairing proves unsupported by Keycloak 26.7.x, this is the
     AC8 contract-revision trigger** — record the finding; do NOT silently degrade to `client_secret`-only.
   - **Path (4) ≥1 DENY branch end-to-end** — invalid creds → token endpoint **401** → **`DenyInvalid`**; simulated
     timeout / network-error / `kid`-miss → **`DenyIndeterminate`** (AD-11 fail-closed: any non-401 non-verifiable-JWT
     response, 5xx, timeout, network error, kid absent from JWKS → DENY). **DENY always wins** on verdict/defense-in-depth disagreement.
   - **No verdict cache** (re-validate every bind); **JWKS cached only** (AD-12).

3. **[AC3 — LOAD-BEARING] `cancelHttp()` actually aborts the underlying HTTP ROPC call (AD-32)** — not only the
   `CompletableFuture`. Bind `cancelHttp()` to the `HttpClient` exchange abort: `HttpClient.sendAsync(...)` returns a
   `CompletableFuture` whose `cancel(true)` aborts the underlying request (the documented JDK behavior — verify on impl);
   `cancelHttp()` drives that abort. **Test:** start a slow ROPC call (e.g. a fixture/proxy that delays the token
   response), invoke `cancelHttp()` mid-flight, assert the HTTP exchange is aborted (connection closed / no token
   consumed) and the owning `StructuredTaskScope` tears down — sparing the IdP the abandoned ROPC (the IdP-amplification
   mitigation, otherwise unreachable through the seam). **RED-on-neuter:** removing the abort binding makes this test
   fail. *(AD-32:245+, ARCHITECTURE-SPINE AD-12 cancellation clause.)*

4. **[AC4] Structured-concurrency shape (AD-5).** The validation adapter demonstrates the bind-adjudication fan-out on
   **`StructuredTaskScope` (JEP 505, JDK 25 *fifth preview*) + `ScopedValue` (JEP 506, final)** — fork the ROPC token call
   and the local JWKS defense-in-depth verify concurrently, join, collapse to one `Verdict`. **CRITICAL GUARDRAIL:** use
   the **JEP 505 Joiner API** — `StructuredTaskScope.open(Joiner)` + `fork` + `join` (e.g.
   `Joiner.awaitAllSuccessfulOrThrow()` / `Joiner.awaitAnySuccessfulOrThrow()`). **Do NOT copy JDK 21/22 tutorials** that
   show the deprecated `new StructuredTaskScope.ShutdownOnFailure() { … }` subclass-override pattern — the joiner shape
   changed in preview and the architecture register warns the shape may change again (AD-5/AD-35). **Verify the exact
   method signatures against the live JDK 25 preview API at impl time.** `RequestContext` is bound with
   `ScopedValue.where(ctx, …).run(...)` — **never `ThreadLocal`**. `--enable-preview` honored on COMPILE and RUN (not
   just the test-JVM path — retro AI-8). *(AD-5:87–90.)*

5. **[AC5] Fail-closed + secret hygiene (AD-11/AD-12).** The adapter holds password and access token in `char[]`/`byte[]`
   (**never `String`**), zeroized on adjudication completion, connection teardown, JVM shutdown, and any exception path
   (AD-12). No verdict cache (re-validate every bind); JWKS cached only. The `BindCredential` `char[]` seam is established
   at the port here; full `toString()`-redaction + no-String-from-password bytecode enforcement (CODEC-024 P2) is AI-5
   (before relay logging) and is **out of this story's scope** — but the port boundary must not leak the password to
   `String`.

6. **[AC6] Runs on the AD-28(4) bounded hand-managed VT executor owned by `security/`.** The adapter's concurrency
   contract: adjudication runs on **one bounded hand-managed virtual-thread `ExecutorService` (JEP 444) owned by
   `security/`**, shared across binds, fail-closed on saturation (AD-11), never `@Async`, never a bare VT spawned per
   bind. The validation harness may construct a test executor, but it must match this contract (bounded, fail-closed,
   drainable). *(AD-28:225–228.)*

7. **[AC7] No rolled crypto / purity (SEC-099 `NoRolledCryptoArchitectureTest`).** TLS via JDK `SSLEngine`/`SSLContext`,
   JWT/JWKS via **Nimbus 10.9.1** (≥10.0.2, CVE-2025-53864), HTTP via `java.net.http.HttpClient` — **no hand-rolled
   crypto/JWT**. Extend `proxy/src/test/java/smpp/companion/proxy/security/NoRolledCryptoArchitectureTest.java` if needed
   so it asserts the ROPC client uses `java.net.http.HttpClient` + Nimbus (and that no `javax.crypto`/`MessageDigest`
   hand-rolling creeps into `security/`). *(AD-13:143–146, spine "Crypto & libs".)*

8. **[AC8] Immutable-henceforth DECISION recorded (the story's actual goal).** At story close, update
   ARCHITECTURE-SPINE.md AD-12 with a dated (2026-08-..) note that the port contract was ratified (validation passed) and
   is **immutable henceforth** — OR, if AC2 path (3) mTLS or any other path proved the shape cannot express it, record a
   **contract REVISION finding** (what must change in `Verdict`/`BindCredential`/`VerdictRequest`/`verify(...)`, and the
   AD-12 + architect implication) — explicitly, not silently. This mirrors the Story 3.1 fallback-decision discipline:
   **no silent closure**. The opener's whole purpose is this decision.

9. **[AC9] Green build + RED-on-neuter (standing gate AI-1).** `./gradlew clean build :buildSrc:test` green on JDK 25 +
   `--enable-preview`. **Every fail-closed guard** in this story — `cancelHttp()` abort (AC3), the DENY branches (AC2
   path 4), zeroization (AC5), fail-closed-on-saturation (AC6) — is backed by a test that goes **RED when the guard is
   removed** (a mutation/neuter pass), per the Epic 1 retro's systemic lesson. **No test is removed or `@Disabled` to make
   the build pass.** All currently-green tests stay green.

## Tasks / Subtasks

**0. Keycloak ≥26.7.0 fixture (retro AI-3) — provision OR verify.** (AC2)
- [ ] If not yet provisioned: stand up a local Docker Keycloak **≥26.7.0** (note: no upstream LTS; pin the patch),
  a realm, a test user, and clients:
  - Client A: **confidential**, **Direct Access Grants Enabled = true** (off by default since KC 26.2, #30226), used
    for paths (1) JWT + (2) opaque-token issuance + RFC 7662 introspection.
  - Client B: **`tls_client_auth`** (RFC 8705) with the X.509 subject DN mapped to the client + a generated client
    cert/trust, used for path (3) mTLS provider auth (NO `client_secret`).
  - Realm JWKS/certs endpoint reachable from the test JVM.
- [ ] If Winston already provisioned AI-3, verify it meets the above (esp. DAG enabled + the `tls_client_auth` client +
  opaque-token setup) before relying on it.
- [ ] Location: a fixture directory under `proxy/src/test/resources/keycloak/` (compose + realm import JSON + certs) —
  confirm placement with the existing test layout; do not pollute main resources.

**1. Author the port types in `proxy/security/`.** (AC1)
- [ ] `BindCredentialVerifier.java`, `Verdict.java` (sealed) + `Allow`/`DenyInvalid`/`DenyIndeterminate`, `BindCredential.java`
  (`char[]`, defensive copy), `VerdictRequest.java` (`future()` + `cancelHttp()`), `RequestContext.java`, `SystemId.java`.
- [ ] `AlwaysAllowBindCredentialVerifier.java` (`@Component`, no-op `cancelHttp`, completed-`Allow` future).
- [ ] Verify `@NullMarked` on `security/package-info.java`.

**2. Validation slice — real ROPC adapter (test-tier).** (AC2, AC4, AC5, AC6)
- [ ] A test `BindCredentialVerifier` impl using `java.net.http.HttpClient` (mTLS-capable `SSLContext`) + Nimbus JWKS verify,
  exercising all 4 paths on `StructuredTaskScope` (JEP 505 Joiner API) + `ScopedValue`-bound `RequestContext`, on the
  bounded VT executor, `char[]`/zeroize.
- [ ] Per-path assertions: Allow (JWT), Allow (introspection active:true), Allow (mTLS, no secret), DenyInvalid (401),
  DenyIndeterminate (timeout/network/kid-miss).

**3. `cancelHttp()` abort test.** (AC3)
- [ ] Slow-ROPC fixture; invoke `cancelHttp()` mid-flight; assert wire abort + scope teardown. RED-on-neuter.

**4. Fail-closed + secret-hygiene tests + mutation/RED-on-neuter pass.** (AC2 path4, AC5, AC6, AC9)
- [ ] DENY-branch tests; zeroization test; saturation/fail-closed test. Run a neuter pass on each guard — assert RED.

**5. NoRolledCrypto extension.** (AC7)
- [ ] Extend `NoRolledCryptoArchitectureTest` to assert `java.net.http.HttpClient` + Nimbus in `security/`.

**6. Record the immutable-henceforth decision (AC8).**
- [ ] Update ARCHITECTURE-SPINE.md AD-12: dated ratification note (immutable henceforth) OR contract-revision finding.

**7. Green build + final mutation sweep.** (AC9)
- [ ] `./gradlew clean build :buildSrc:test` green; confirm no test removed/`@Disabled`.

## Dev Notes

### Architecture compliance (MUST follow)

- **AD-12 (port contract, verbatim):** `smpp.companion.proxy.security.BindCredentialVerifier` —
  `VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx)`; `BindCredential(SystemId, char[] password)`
  in `security`; `sealed interface Verdict permits Allow, DenyInvalid, DenyIndeterminate` (no `Throwable`, no free-form
  reason, no Nimbus type crosses the port — the ROPC adapter absorbs Nimbus). Runs on the relay's hand-managed VT pool
  (AD-6/AD-28); **never `@Async`**. Cancellation (AD-32): `verify` returns a `VerdictRequest` exposing
  `CompletableFuture<Verdict> future()` + `void cancelHttp()` (the ROPC adapter binds `cancelHttp()` to the HTTP client's
  abort). *(ARCHITECTURE-SPINE.md:135–141.)*
- **AD-11 (fail-closed):** 401 → DENY; any non-401 non-verifiable-JWT (200-non-JWT/HTML/empty, malformed JWT, 3xx,
  4xx≠401, 5xx, timeout, network error) → DENY; JWT `kid` absent from JWKS → DENY (background refresh, no foreground
  retry); introspection non-(200+JSON+`active:true`) → DENY; DENY wins on disagreement. Deny-on-ambiguous, always.
- **AD-5 (STS + ScopedValue):** control plane on `StructuredTaskScope` (JEP 505 preview) + `ScopedValue` (JEP 506 final);
  `ScopedValue` carries `RequestContext`; never `ThreadLocal`; `--enable-preview` process-wide (accepted risk). **STS API
  shape is preview and changed in JEP 505 — use the Joiner API, verify against the live JDK 25 API.**
- **AD-13 (mTLS):** PKIX defaults; **trust store never `cacerts`**; minimal single-purpose trust store; no custom
  `PKIXBuilderParameters`, no custom chain-validation code.
- **AD-28(4) (executor):** one bounded hand-managed VT `ExecutorService` owned by `security/`, fail-closed on saturation;
  never `@Async`; never a bare VT per bind.
- **AD-32 (cancelHttp):** the handle aborts the underlying HTTP ROPC call so AD-32 case-3 teardown spares the IdP the
  abandoned ROPC.
- **AD-35 (null-safety):** JSpecify `@NullMarked` (does NOT propagate to sub-packages — new sub-packages need their own);
  NullAway on Error Prone, `JSpecifyMode=true`, `AnnotatedPackages=smpp.companion`, fail-closed.

### Library / framework specifics

- **HTTP client:** `java.net.http.HttpClient` (JDK builtin) for the ROPC token + introspection calls — mTLS-capable via
  `SSLContext` (path 3), cancellable via `sendAsync()` + `CompletableFuture.cancel(true)` (binds to `cancelHttp()`), no
  purity/dependency concern. **Do not** pull a third-party HTTP client.
- **JWT/JWKS:** Nimbus JOSE+JWT **10.9.1** — `JWKSet.load(<realm>/protocol/openid-connect/certs)`, `getKeyByKeyId(kid)`,
  `SignedJWT.parse(token)`, `RSASSAVerifier`/appropriate `JWSVerifier`, claim checks (`iss`/`aud`/`exp`/`nbf`).
- **STS:** JEP 505 Joiner API (see AC4 guardrail). `ScopedValue.where(...).run(...)` for `RequestContext`.
- **Keycloak fixture endpoints:** token `POST /realms/{r}/protocol/openid-connect/token` (`grant_type=password`,
  `client_id`, and `client_secret` for path 1/2 OR mTLS for path 3, `username`, `password`); introspection
  `POST /realms/{r}/protocol/openid-connect/token/introspect`; certs `GET /realms/{r}/protocol/openid-connect/certs`.
- **Verify endpoints against the real fixture, not assumptions** (retro discovery #4) — the token/introspection/certs
  paths and the `tls_client_auth` client behavior must be confirmed against the running ≥26.7.0 instance.

### Epic 1 retro — discoveries that shape this story (bake in by default)

- **#3** Password `AsciiString→char[]` is a genuine seam — the port takes `char[]`; never `toString()` the password (CODEC-024 P2 / AI-5 lands with relay logging).
- **#4** Catalog/spec literals can be wrong on load-bearing values — verify ROPC/mTLS/introspection behavior against the real fixture + primary sources before coding.
- **#7** `@ConstraintValidator` runs before `@NotNull` field guarantees — every helper needs its own null guard.
- **#9** `@NullMarked` does NOT propagate to sub-packages — new `security/` sub-packages each need their own `package-info.java`.
- **Standing gate (AI-1):** RED-on-neuter on every fail-closed guard — re-verify every `RESOLVED`-style claim against the codebase; no marker closes without a cited biting test. (This story's headline risk is the same failure mode the retro surfaced.)

### Out of scope (explicitly — do not expand into these)

- The **full production ROPC adapter** (Epic 3 — replaces the always-allow stub behind the *unchanged* port).
- **`relay/` wiring** (BindInterceptor, RelayHandler, ConnectionRegistry) — later Epic 2 stories; `relay/` does NOT commit in this story.
- **`SpliceObserver` contract seed** (AD-27) — separate Epic 2 story.
- **CODEC-024 P2 full enforcement** (`toString()` redact + no-String-from-password bytecode scan) — retro AI-5, before relay logging.
- **AD-30 live `ByteBufAllocatorMetric` startup self-check** — retro AI-6, with relay wiring.

### Risk notes carried from Story 3.1 / the register

- **ROPC is deprecated** (RFC 9700 §2.4 "MUST NOT"; OAuth 2.1 draft-15 omits it) — v1 ships explicitly ROPC-conditional; this story does not change that.
- **Pin ≥26.7.0** (no upstream LTS; minors EOL ~3 months). **CVE-2026-9792** (alleged unauth bypass of `reject-ropc-grant`, fix 26.7.0/26.6.3/26.4.13) is recorded **UNVERIFIED** in the register — the ≥26.7.0 pin stands independently; primary-check the CVE before relying on it as patch-floor justification.
- **Path (3) mTLS is the most likely to fail** — if it does, AC8 is the contract-revision trigger, not a silent `client_secret` fallback.

### Project Structure Notes

- **NEW (main, `proxy/src/main/java/smpp/companion/proxy/security/`):** `BindCredentialVerifier`, `Verdict` (+ `Allow`/`DenyInvalid`/`DenyIndeterminate`), `BindCredential`, `VerdictRequest`, `RequestContext`, `SystemId`, `AlwaysAllowBindCredentialVerifier`.
- **EXISTS (verify, don't clobber):** `security/package-info.java` (`@NullMarked` from Story 1.4).
- **NEW (test, `proxy/src/test/java/smpp/companion/proxy/security/`):** the real-ROPC validation slice, `cancelHttp` abort test, DENY/zeroization/saturation tests, `NoRolledCryptoArchitectureTest` extension.
- **NEW (fixture, `proxy/src/test/resources/keycloak/`):** Docker Compose + realm import + client configs + certs (confirm placement with existing test layout).
- Naming/package conventions per ARCHITECTURE-SPINE.md §Consistency Conventions: `smpp.companion.proxy.security.*`; config keys `companion.*`.

### References

- [Source: ARCHITECTURE-SPINE.md#AD-12 (135–141)], [#AD-11 (130–133)], [#AD-5 (87–90)], [#AD-28 (225–228)], [#AD-32 (245+)], [#AD-13 (143–146)], [#AD-35 (264–267)], [§Accepted-Risk Register — ROPC entry + Story 3.1 verdict (285)], [§Consistency Conventions (288–)], [tech stack (300–316)]
- [Source: epics.md#Epic-2-opener (366–367)], [#Story-3.1-split (377)]
- [Source: epic-1-retro-2026-08-08.md#Discoveries-That-Shape-Epic-2 (154–180)], [#Action-Items AI-1/AI-3/AI-4/AI-5 (202–214)]
- [Source: sprint-status.yaml — AI-2 done, AI-3/AI-4 open (105–119)]
- [JEP 505 (Structured Concurrency, 5th preview)](https://openjdk.org/jeps/505) · [JEP 506 (ScopedValue, final)](https://openjdk.org/jeps/506)
- [RFC 8705 (mTLS client auth)](https://datatracker.ietf.org/doc/html/rfc8705) · [RFC 7662 (token introspection)](https://datatracker.ietf.org/doc/html/rfc7662) · [RFC 9700 (OAuth 2.0 Security BCP)](https://datatracker.ietf.org/doc/rfc9700/)
- [Keycloak — Configuring trusted certificates for mTLS](https://www.keycloak.org/server/mutual-tls) · [Keycloak securing-apps — ROPC / Direct Grant](https://www.keycloak.org/securing-apps/oidc-layers)
- [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt) (10.9.1; ≥10.0.2 for CVE-2025-53864)

## Dev Agent Record

### Agent Model Used

_(filled by dev agent)_

### Debug Log References

_(filled by dev agent)_

### Completion Notes List

_(filled by dev agent)_

### File List

_(filled by dev agent)_
