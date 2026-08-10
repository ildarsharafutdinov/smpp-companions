---
baseline_commit: c771a0e
epic: 2
story: 1
story_key: 2-1-security-port-contract-validation-slice
status: done
---

# Story 2.1: Security Port Contract-Shape Validation Slice (BindCredentialVerifier ratification)

Status: done

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
- [x] If not yet provisioned: stand up a local Docker Keycloak **≥26.7.0** (note: no upstream LTS; pin the patch),
  a realm, a test user, and clients:
  - Client A: **confidential**, **Direct Access Grants Enabled = true** (off by default since KC 26.2, #30226), used
    for paths (1) JWT + (2) opaque-token issuance + RFC 7662 introspection.
  - Client B: **`tls_client_auth`** (RFC 8705) with the X.509 subject DN mapped to the client + a generated client
    cert/trust, used for path (3) mTLS provider auth (NO `client_secret`).
  - Realm JWKS/certs endpoint reachable from the test JVM.
- [x] If Winston already provisioned AI-3, verify it meets the above (esp. DAG enabled + the `tls_client_auth` client +
  opaque-token setup) before relying on it.
- [x] Location: a fixture directory under `proxy/src/test/resources/keycloak/` (compose + realm import JSON + certs) —
  confirm placement with the existing test layout; do not pollute main resources.

**1. Author the port types in `proxy/security/`.** (AC1)
- [x] `BindCredentialVerifier.java`, `Verdict.java` (sealed) + `Allow`/`DenyInvalid`/`DenyIndeterminate`, `BindCredential.java`
  (`char[]`, defensive copy), `VerdictRequest.java` (`future()` + `cancelHttp()`), `RequestContext.java`, `SystemId.java`.
- [x] `AlwaysAllowBindCredentialVerifier.java` (`@Component`, no-op `cancelHttp`, completed-`Allow` future).
- [x] Verify `@NullMarked` on `security/package-info.java` (present from Story 1.4 — confirmed surviving; AD-35 holds).

**2. Validation slice — real ROPC adapter (test-tier).** (AC2, AC4, AC5, AC6)
- [x] A test `BindCredentialVerifier` impl using `java.net.http.HttpClient` (mTLS-capable `SSLContext`) + Nimbus JWKS verify,
  exercising all 4 paths on `StructuredTaskScope` (JEP 505 Joiner API) + `ScopedValue`-bound `RequestContext`, on the
  bounded VT executor, `char[]`/zeroize.
- [x] Per-path assertions: Allow (JWT), Allow (introspection active:true), Allow (mTLS, no secret), DenyInvalid (401),
  DenyIndeterminate (timeout/network/kid-miss).

**3. `cancelHttp()` abort test.** (AC3)
- [x] Slow-ROPC fixture; invoke `cancelHttp()` mid-flight; assert wire abort + scope teardown. RED-on-neuter.

**4. Fail-closed + secret-hygiene tests + mutation/RED-on-neuter pass.** (AC2 path4, AC5, AC6, AC9)
- [x] DENY-branch tests; zeroization test; saturation/fail-closed test. Run a neuter pass on each guard — assert RED.

**5. NoRolledCrypto extension.** (AC7)
- [x] Extend `NoRolledCryptoArchitectureTest` to assert `java.net.http.HttpClient` + Nimbus in `security/`.

**6. Record the immutable-henceforth decision (AC8).**
- [x] Update ARCHITECTURE-SPINE.md AD-12: dated ratification note (immutable henceforth) OR contract-revision finding.

**7. Green build + final mutation sweep.** (AC9)
- [x] `./gradlew clean build :buildSrc:test` green; confirm no test removed/`@Disabled`.

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

Claude Code — `bmad-dev-story` workflow (model: glm-5.2).

### Debug Log References

- `verify-fixture.sh` output (2026-08-08, against `quay.io/keycloak/keycloak:26.7.0`) — captured all 4 AD-12 paths.
- Keycloak `docker logs smpp-keycloak` DEBUG (`org.keycloak.authentication.authenticators.client`):
  `X509ClientCertificateAuthenticator` — `Checked Subject DN: CN=smpp-mtls-client`; `CA Subject DN: O=…, CN=smpp-test-ca`
  (RDN reordering); `x509.subjectdn is null or empty` (when legacy `x509cert` attr was used).
- `docker exec … kc.sh show-config` — confirmed `kc.https-client-auth` / `kc.truststore-paths` applied.
- `openssl s_client` — confirmed Keycloak requests + accepts the client cert at TLS (`Verify return code: 0 (ok)`).
- `kc.sh start --help` — `--https-client-auth` values `none|request|required`; `--hostname-strict-https` removed in 26.7.

### Implementation Plan (Task 1 — port types)

Design decisions for the AD-12 port contract authored in `proxy/security/` (AC1):

- **`SystemId` wraps the codec's `AsciiString`** (reinvention guardrail — no C-octet re-parse at the port; the relay
  seam will be `new SystemId(bindRequest.systemId())`). Enforces **≤15 value octets** (SMPP 3.4 §3.2 caps `system_id`
  at 16 octets, §3.1 counts the NUL terminator → 15 value octets). The codec does NOT cap per-field length, so this is
  the typed-boundary fail-fast. `SystemId` is NOT secret (ROPC username / forwarded identity, AD-14) — no defensive copy.
- **`BindCredential(SystemId, Password)`** — composes the two typed records; no defensive copy of its own (both
  components are immutable). `toString()` overridden to `password=***` (self-contained boundary hygiene; the primary
  secrecy boundary is `Password.toString()`). **Revised 2026-08-09 (see Change Log):** the password is the typed
  `Password` over a Netty `AsciiString` (was `char[]`) — CODEC-024/PRIV-1 type-uniformity with the codec; the
  `AsciiString→char[]` relay-seam conversion is eliminated. No more `@SuppressWarnings("ArrayRecordComponent")` (no
  array component).
- **`Password`** — the typed SMPP secret, the typed counterpart to `SystemId`: `AsciiString`-backed (wraps the codec's
  same backing — `new Password(bindRequest.password())`), ≤8 value octets (SMPP 3.4 §3.2 max-9-incl-NUL). No defensive
  copy (mirrors `SystemId`); the shared backing array means the holder's single `AsciiString.array()` wipe covers the
  record's own copy — closing the internal-copy zeroization gap a `char[]` clone-on-read design could not (AC5 / AD-12).
  `toString()` overridden to `Password[***]` — the load-bearing secret-hygiene guard: without it the record's auto-
  `toString` calls `AsciiString.toString()`, rendering the cleartext AND caching an immortal `String` the wipe cannot
  reach (CODEC-024 P2 / AI-5).
- **`Verdict`** — `sealed interface` over three **nested payload-less record permits** (`Allow`/`DenyInvalid`/`DenyIndeterminate`);
  nesting owns the closed hierarchy (no external subtype can extend it) and guarantees no `Throwable`/reason/Nimbus type
  crosses the port. The two DENY permits are informative; both deny (AD-11).
- **`VerdictRequest`** — interface `CompletableFuture<Verdict> future()` + `void cancelHttp()` (AD-32 — aborts the
  underlying HTTP call, not only the future). The test-tier adapter (Task 2) implements it.
- **`RequestContext`** — `SystemId` + Netty `ChannelId` (AD-8 ingress-keyed registry) + `Instant deadline` (AD-5, NTP A-4);
  `ScopedValue`-bound, never `ThreadLocal`.
- **`BindCredentialVerifier`** — `VerdictRequest verify(BindCredential, ScopedValue<RequestContext>)`.
- **`AlwaysAllowBindCredentialVerifier`** — `@Component`, a stateless `VerdictRequest` (completed-`Allow` future, no-op
  `cancelHttp`); the stand-in `relay/` wires against until Epic 3.

**Redundant-null-guard finding (RED-on-neuter nuance):** `SystemId.value` and `Password.value` `requireNonNull` are
message-clarity only — the `.length()` deref in their length checks (+ JDK 25 helpful-NPE) still fails fast on null
without the guard, so their null tests bite-by-NPE rather than by-guard. The **load-bearing** null guards are the
no-downstream-deref fields — `BindCredential.systemId`, **`BindCredential.password`** (its compact ctor no longer
clones, so null is stored silently without the guard — verified by mutation: removing it → `rejectsNullPassword` RED),
and all three `RequestContext` fields — removing those → no NPE at all → test goes RED. (Revised 2026-08-09:
`BindCredential.password` moved from message-clarity to load-bearing when the defensive copy was removed for the typed
`Password`.)

### Implementation Plan (Task 2 — validation slice)

Design decisions for the test-tier ROPC adapter that ratifies the AD-12 port shape across all four paths (AC2/AC4/AC5/AC6).
The slice lives under `proxy/src/test` (NOT the production adapter — Epic 3); it proves the `BindCredentialVerifier` port
can *express* every path before `relay/` commits against it.

- **`RopcSlice implements BindCredentialVerifier` (test-tier).** A per-path `SliceConfig` record selects the OAuth
  mode: `clientId` + `clientSecret` (paths 1/2/4), `useMtlsClientAuth` + no secret (path 3, RFC 8705 — the transport
  cert authenticates the client), `introspect` (path 2, RFC 7662). The `username` for ROPC is the `BindCredential`
  `SystemId`; `client_id` is the configured client (see the bug-fix note below — these were conflated on first cut).
- **Concurrency (AC4/AD-5):** each adjudication runs on one bounded hand-managed virtual-thread `ExecutorService`
  owned by the slice (AD-28(4)) with a `Semaphore` admission gate that is **fail-closed on saturation** (AC6 — a
  saturated pool returns `DenyIndeterminate` without starting work). The adjudication fans the ROPC token call and the
  JWKS fetch out on a `StructuredTaskScope` (JEP 505 preview) and `join`s them; the `RequestContext` is re-bound on the
  pool thread via the **same `ScopedValue` handle** the caller used (JEP 506 final — `ScopedValue.where(ctx, rc).call(...)`),
  so the STS subtasks inherit it (never `ThreadLocal`). `StructuredTaskScope.open(Joiner)` + `Joiner.awaitAllSuccessfulOrThrow()`
  + `Subtask.get()` were verified against the live JDK 25 (the JEP 505 shape — the AC4 guardrail).
- **Verdict mapping (AD-11):** 4xx → `DenyInvalid` (covers fixture finding #6: 400 `invalid_grant` for a bad user AND
  401 `invalid_client` for a bad secret — "4xx≠200 → DENY", do not key off 401 alone); 5xx / non-200-non-4xx / timeout /
  network error / scope cancellation / malformed response / JWKS `kid`-miss / signature-or-claim failure →
  `DenyIndeterminate` (fail-closed); DENY always wins. JWKS cached only; verdicts never cached; kid-miss triggers a
  background refresh with no foreground retry.
- **Secret hygiene (AC5) — KNOWN GAP, test-tier slice (code review 2026-08-10, Review Findings F1):** the `Password`
  octets are currently form-encoded via `pw.toString()` + `URLEncoder` + `BodyPublishers.ofString` — NOT from the raw
  `AsciiString` backing array. This renders the secret into a `String` and lets `AsciiString.toString()` cache an
  immortal internal `String` the `zeroize()` wipe cannot reach (the CODEC-024 P2 / AI-5 hazard) — flagged as an ACCEPTED
  HAZARD in the in-code comment for this throwaway slice; the Epic 3 production adapter MUST encode from the raw
  `byte[]` (never `toString()`). The backing array IS zeroized on adjudication completion (success and failure). The access token is held
  as a transient `char[]` working copy, zeroized after verify/introspect (full token byte-array hygiene is the Epic 3
  production adapter's concern; the test tier's AC5 focus is the password).
- **Cancellation (AC3/AD-32, wired now; the wire-abort test is Task 3):** `cancelHttp()` drives
  `HttpClient.sendAsync(...).cancel(true)` (aborts the underlying exchange, not only the `CompletableFuture`) and
  completes the verdict `DenyIndeterminate`; the STS tears its subtasks down with the scope.
- **Live-fixture gating (Testcontainers, 2026-08-09):** the Keycloak &ge;26.7.0 fixture is now a
  Testcontainers-managed container (`KeycloakContainer`) — the test JVM owns its lifecycle, bound **fixed** to
  `localhost:8443` (parity with the original compose's `8443:8443`); the external `docker-compose.yml` + `verify-fixture.sh`
  + the `KeycloakLiveCondition` TCP-probe gate were removed. `RopcSliceLiveTest` declares `@Container static KeycloakContainer`
  + `@Testcontainers(disabledWithoutDocker = true)`: the container starts (and reaches OIDC-discovery readiness) before the
  5 per-path assertions, which use the `KeycloakFixture` `:8443` coordinates; the class is **skipped with an explicit reason
  when Docker is absent (CI)** — an environment gate, NOT a "disable-to-make-the-build-pass" dodge (AC9). Two always-on tests
  in `RopcSliceUnitTest` enforce the fail-closed mapping (unreachable endpoint → `DenyIndeterminate`; JWKS kid-miss →
  `DenyIndeterminate`, matching kid → `Allow`) **without** the container, so the slice's AD-11 collapse is never silently
  unverified (retro: no false-RESOLVED).
- **Real bugs found + fixed during the live run (the value of ratifying against the real fixture, retro discovery #4):**
  (1) the ROPC form body set `client_id` to the `SystemId` (the username `testuser`) instead of `cfg.clientId()` — every
  valid-creds request returned 4xx → `DenyInvalid` (path 4b "passed" for the wrong reason: a wrong client_id 401s
  regardless); (2) the path-4a wrong-password literal `"WRONG-PASS"` exceeded `Password`'s 8-octet cap. Both fixed;
  all 5 paths then went green against the running `keycloak:26.7.0`.

### Completion Notes List

- **Task 0 DONE — Keycloak ≥26.7.0 fixture provisioned AND verified against the running instance** (retro AI-3 was
  `open`/unprovisioned; sprint-status AI-3 still open — Winston had not provisioned it, so this task provisioned it).
  Pinned `quay.io/keycloak/keycloak:26.7.0` (the ≥26.7.0 floor; 26.7.1 also available). Ephemeral FS → fresh realm
  re-import on every `up`. Placed under `proxy/src/test/resources/keycloak/` (compose + realm JSON + certs + README +
  `verify-fixture.sh`); main resources untouched.
- **All 4 AD-12 paths verified at the fixture level:** Path 1 ROPC JWT (RS256, kid in JWKS); Path 2 introspection
  `active:true`; **Path 3 ROPC+mTLS (RFC 8705 `tls_client_auth`, no client_secret) → 200 JWT** — the "most likely to
  fail" path WORKS, so the AD-12 port shape can express all four paths (strong signal for AC8); Path 4 bad-client-secret
  → 401 `invalid_client`, bad-user-password → 400 `invalid_grant`; JWKS reachable (2 keys).
- **Six real-fixture findings baked into the fixture README for Task 2 / AC8** (retro discovery #4 — verify against the
  real fixture, not assumptions): (1) `--hostname-strict-https` removed in 26.7; (2) `https-client-auth=required` is
  mandatory — `request`/WANT does NOT expose the peer cert to the `client-x509` authenticator (design-consistent with
  AD-12/AD-29: the proxy presents its cert on every IdP call); (3) KC 26 `client-x509` uses `x509.subjectdn` +
  `x509.casubjectdn` (NOT legacy `x509cert`), checks CA/issuer DN first, reorders RDNs → CA cert kept CN-only; (4) KC 26
  User Profile requires email/firstName/lastName or ROPC fails "Account is not fully set up"; (5) DAG is per-client
  (off by default since 26.2); (6) **AC2 path-4 refinement** — bad user creds → 400 `invalid_grant`, bad client secret →
  401 `invalid_client`; the slice must map BOTH → `DenyInvalid` (AD-11 "4xx≠200 → DENY" covers both; do not key on 401).
- **RED-on-neuter relevance (AC9, AI-1):** Task 0 is fixture provisioning (no production guard to neuter); the RED-on-
  neuter tests attach to Tasks 2/3/4 (cancelHttp abort, DENY branches, zeroization, saturation). The path-4a finding is
  a preemptive correctness input for those DENY-branch tests.
- Task 0 does NOT author port types (Task 1), the validation slice (Task 2), or any production code — scope held.
- **Task 1 DONE — all 7 AD-12 port types + `AlwaysAllowBindCredentialVerifier` authored in
  `proxy/src/main/java/smpp/companion/proxy/security/`** (AC1), matching AD-12/AD-32 verbatim. See the Implementation
  Plan above for the per-type decisions. `@NullMarked` confirmed present on `security/package-info.java` (Story 1.4;
  survived — AD-35 holds); `SystemId` is the only NEW public type surface, no new sub-package, so no additional
  `package-info.java` needed.
- **6 new tests (26 security-test methods total) ratify the port SHAPE + behavior:**
  `VerdictShapeTest` (sealed, exactly 3 payload-less permits), `SecurityPortShapeTest` (reflection: `verify` signature,
  `future()`/`cancelHttp()`), `SystemIdTest`, `BindCredentialTest` (defensive copy construct+read, `toString` non-leak,
  null guards, `char[]` component), `RequestContextTest`, `AlwaysAllowBindCredentialVerifierTest` (`@Component`,
  completed-`Allow`, no-op `cancelHttp`, `ScopedValue`-bound call). All green.
- **RED-on-neuter mutation pass run (AC9 / AI-1) on the Task-1 guards** — every load-bearing guard neutered → its test
  went RED, then reverted → GREEN (verified no `MUTATION` markers leaked, full `:proxy:test` green):
  (1) `toString` redaction removed → `toStringDoesNotLeakPassword` RED (auto record-`toString` renders the cleartext password);
  (2) SystemId ≤15-octet bound removed → `rejectsOverlongSystemId` RED;
  (3) AlwaysAllow `Allow`→`DenyInvalid` → 4 verdict tests RED;
  (4) Verdict 4th permit added → `permitsExactlyTheThreeVerdicts` RED;
  (5) load-bearing null guards removed (`BindCredential.systemId`, `RequestContext.channelId`) → `rejectsNull*` RED.

  *(Code review 2026-08-10 correction: two claims formerly listed here — `defensiveCopyOnConstruct` and
  `defensiveCopyOnRead` RED-on-neuter — were struck as FALSE. Those tests never existed; they described the superseded
  `char[]`-with-defensive-copy design, and the 2026-08-09 `Password`-over-`AsciiString` revision deliberately removed
  the defensive copy, so there is no such invariant to bite. `BindCredentialTest`'s actual 4 tests:
  `toStringDoesNotLeakPassword`, `passwordComponentIsPasswordType`, `rejectsNullPassword`, `rejectsNullSystemId`. See Review Findings → F4.)*
  Reflection-shape tests (`SecurityPortShapeTest`) bite by construction (assert exact signatures). The redundant
  null guards (SystemId.value / BindCredential.password) are message-clarity, not load-bearing — documented above.
- **Build: `./gradlew clean build :buildSrc:test` GREEN** on JDK 25 + `--enable-preview` (one non-fatal
  `ArrayRecordComponent` ErrorProne warning, suppressed with justification on `BindCredential` — AD-12 mandates the
  `char[]`; concern fully addressed). No test removed or `@Disabled`.
- Task 1 does NOT build the validation slice (Task 2), `cancelHttp` wire-abort (Task 3), the production ROPC adapter
  (Epic 3), or `relay/` wiring — scope held. The port types are ready for Task 2 to ratify against the real fixture.

- **Task 2 DONE — the test-tier ROPC validation slice ratifies the AD-12 port shape across all four paths against the
  real `keycloak:26.7.0`** (AC2/AC4/AC5/AC6). `RopcSlice implements BindCredentialVerifier` (under `proxy/src/test`)
  drives the actual `verify(cred, ScopedValue<RequestContext>)` port, fanning the token call + the JWKS fetch out on a
  `StructuredTaskScope` (JEP 505) with the `RequestContext` re-bound via `ScopedValue` (JEP 506), on a bounded VT
  executor with fail-closed-on-saturation admission. Verdict mapping per AD-11: 4xx → `DenyInvalid`, else →
  `DenyIndeterminate`. Password octets taken raw from the `AsciiString` (never `toString()`'d) + zeroized on completion.
- **All 4 AD-12 paths GREEN through the real port** (fixture now Testcontainers-managed — `:proxy:test` starts `KeycloakContainer` on fixed `:8443`; was `docker compose … up -d --wait` at the original T2 time):
  path 1 ROPC JWT + local JWKS defense-in-depth verify → **Allow**; path 2 RFC 7662 introspection `active:true` →
  **Allow**; path 3 RFC 8705 mTLS provider auth (client cert, **no `client_secret`**) → **Allow** (the most-likely-to-
  fail path works end-to-end — the port shape expresses all four paths, a strong signal for AC8); path 4a bad user →
  400 `invalid_grant` → **DenyInvalid**; path 4b bad client secret → 401 `invalid_client` → **DenyInvalid** (finding #6).
  Plus 2 always-on fail-closed tests (unreachable endpoint → `DenyIndeterminate`; JWKS kid-miss → `DenyIndeterminate`,
  matching kid → `Allow`) that run without the fixture.
- **JEP 505 API verified against the live JDK 25** (AC4 guardrail) before coding: `StructuredTaskScope` is now generic
  `<T,R>`; `static open(Joiner)`, `R join()`, `Subtask<U> fork(Callable)`, `close()`, `isCancelled()`; `Joiner.awaitAllSuccessfulOrThrow()`
  (→ `Void`) / `allSuccessfulOrThrow()` / `anySuccessfulResultOrThrow()` / `awaitAll()` / `allUntil(Predicate)`;
  `ScopedValue` is JEP 506 **final** (`newInstance`, `get`, `where(k,v)`→`Carrier.call`). No JDK-21/22 deprecated
  `ShutdownOnFailure` subclass pattern (the AC4 guardrail held).
- **AC9 build:** `./gradlew clean build :buildSrc:test` GREEN on JDK 25 + `--enable-preview` (Jazzer/JNI warnings are
  pre-existing codec-fuzz noise, unrelated). The 5 live tests **skip cleanly (explicit reason) when the fixture is down
  (CI)** and **run + pass when it is up** — an environment gate, not a disable-to-pass dodge; the always-on unit tests
  keep the fail-closed mapping verified in every build. No test removed or `@Disabled`.
- **Out of scope, deferred to later tasks (scope held):** Task 3 — the `cancelHttp()` wire-abort test (the adapter
  already binds `cancelHttp` to `HttpClient.sendAsync.cancel(true)` + STS teardown; T3 adds the slow-ROPC RED-on-neuter
  assertion); Task 4 — the dedicated zeroization assertion, saturation/fail-closed test, and the full RED-on-neuter
  mutation pass across all guards; Task 5 — the `NoRolledCryptoArchitectureTest` extension; Task 6 — the AC8
  immutable-henceforth DECISION; Task 7 — final green build. The slice implements every guard those tasks will test.

- **Task 3 DONE — `cancelHttp()` wire-abort test ratifies AC3 / AD-32** (the load-bearing slice: a mid-flight abort
  that actually tears the wire call down, sparing the IdP the abandoned ROPC). New always-on
  `RopcSliceCancelTest` drives the real `verify` port against a slow in-process `com.sun.net.httpserver.HttpServer`
  stand-in IdP, invokes `cancelHttp()` while the token call is in flight, and asserts (a) the underlying exchange was
  aborted and (b) the verdict collapses to `DenyIndeterminate`. RED-on-neuter verified (see below).
- **JDK-25 `HttpClient` cancel mechanism verified against the source (the "verify on impl" caveat in AC3 — resolved
  IN FAVOR of the slice's binding, no AC8 contract revision needed for AC3):** `cancel(true)` on the `sendAsync`
  future is a `MinimalFuture` whose override delegates to `MultiExchange.cancel(true)` → `exchange.cancel()` →
  `connection.close()` — **but only when `mayInterruptIfRunning == true`** (the slice calls `cancel(true)`, correct).
  The aborted exchange completes the response future EXCEPTIONALLY with a `CancellationException` ("Request cancelled",
  via `MultiExchange.wrapIfCancelled`); `reportGet` surfaces it as `ExecutionException → CancellationException → IOException`.
  Two false starts the test caught and corrected: (1) `isCancelled()` is **false** by design (the future was completed
  exceptionally, not via `Future.cancel`'s path) — not a usable signal; (2) a small IdP-side token write is **not** a
  reliable abort signal (TCP half-close lets the server's write succeed into the kernel buffer; the RST surfaces only on a
  subsequent blocked write). The test therefore asserts a `CancellationException` **anywhere in the cause chain**
  (`tokenExchange.get()` throws one) — deterministic and race-free.
- **Test shape:** (PRIMARY, deterministic) after `cancelHttp()`, `tokenExchange.get(5s)` throws a throwable whose cause
  chain contains a `CancellationException` — proves the exchange aborted instead of delivering a token. Plus a
  precondition (the call was in flight when cancel fired) + the verdict → `DenyIndeterminate` (evidences the STS `join`
  threw on the cancelled exchange → scope closed — AD-32 case-3 teardown, the scope is local so observed via the verdict).
  Plus CORROBORATION (genuine "IdP spared"): the slow IdP streams a 1 MiB body that exceeds the socket send buffer, so
  its write blocks; after `cancelHttp()` tore the wire down that write fails with `IOException` (no token consumed).
  A delegating `RecordingHttpClient` (returns the JDK's `MinimalFuture` unwrapped) lets the test observe the real
  exchange future the slice stored.
- **RED-on-neuter mutation pass (AC9 / AI-1) — the bite:** neutered `cancelHttp()` (commented out
  `tokenExchange.cancel(true)`, leaving only `pin.complete(DenyIndeterminate)`) → PRIMARY went RED ("Expecting code to
  raise a throwable" — the server responded normally and delivered the token) and the corroboration (`clientAborted`/
  `wroteToken`) RED; reverted → GREEN. The verdict-only path would NOT bite (the pin still completes), which is exactly
  why the exchange-future assertion is load-bearing. Confirmed reliable (6/6 green runs post-revert) and no `MUTATION`
  markers leaked.
- **Build:** `./gradlew :proxy:test` GREEN (incl. the 5 live Keycloak Testcontainers tests — Docker up) +
  `./gradlew clean build :buildSrc:test` GREEN (Jazzer/JNI warnings pre-existing codec-fuzz noise). No test removed
  or `@Disabled`.
- Task 3 adds only a test + a test-only recording client; it touches no production code (the `cancelHttp` binding was
  wired in T2 and confirmed correct here) — scope held. Tasks 4–7 remain (zeroization/saturation + full mutation pass,
  NoRolledCrypto extension, the AC8 immutable-henceforth DECISION, final green build).

- **Task 4 DONE — the always-on fail-closed test battery + the standing RED-on-neuter mutation pass (AC2 path4 / AC5 / AC6 / AC9).**
  - **DENY-branch tests (AC2 path4, AD-11):** 8 new always-on forged-JWT deny tests in `RopcSliceUnitTest` bite the six
    `verifyWithJwks` guards the kid-miss test did not cover — unverifiable signature (kid present, signed by a different
    key), issuer mismatch, audience mismatch, missing-exp, expired, nbf-future — plus behavior tests for the no-kid-header
    and malformed-JWT cases. New `RopcSliceFailClosedTest` (always-on, in-process `com.sun.net.httpserver.HttpServer`
    stand-in IdP — no Docker) drives the real `verify` port for the 4xx→`DenyInvalid` and 5xx→`DenyIndeterminate`
    `mapNon200` collapse (previously only live-tested), the RFC 7662 introspection `active:false` + non-200 deny branches,
    password zeroization on adjudication completion, the bounded-pool saturation fail-closed deny + saturation-path
    zeroize, and the `maxInflight < 1` admission-capacity fail-fast. The 4xx/5xx/introspection tests serve a fixed
    parseable JWKS on `/certs` so the STS fan-out's JWKS subtask always succeeds and the token status is what decides.
  - **RED-on-neuter mutation pass (AC9 / AI-1):** a scripted pass neutered each load-bearing guard and confirmed the
    matching test goes RED (then reverted → GREEN). **All 13 bite** (mapNon200 4xx/else, introspection active:false +
    non-200, JWKS sig/iss/aud/exp/nbf, malformed-JWT catch, password-zeroize-on-completion, saturation-tryAcquire,
    saturation-path-zeroize, `maxInflight<1` fail-fast). The pass caught + fixed a real test-harness flaw: the saturation
    test's `holdPermit` release wasn't exception-safe, so a mutation that made the 2nd `verify` time out stranded the
    in-process IdP handlers and hung the test JVM — fixed by moving `holdPermit.countDown()` into a `finally`. The
    malformed-JWT catch bites harder than first claimed (the test calls `verifyWithJwks` directly, so removing the catch
    propagates `ParseException` → RED — not merely defense-in-depth).
  - **Scope residues (transparently documented, NOT silently closed — retro discipline):** (a) access-token `char[]`
    zeroize (line 168) — a bearer-secret wipe with no direct test; the story explicitly scopes the test-tier AC5 focus to
    the PASSWORD, with full token byte-array hygiene owned by the Epic 3 production adapter. (b) saturation-path
    `tokenExchange.cancel(true)` (line 118) — the AD-32 IdP-sparing cancel on the saturation path; low-severity (the
    orphaned call is bounded by `callTimeout`) and the identical `cancel(true)`→exchange-abort mechanism is proven biting
    by T3's `cancelHttp` wire-abort test (line 348); a dedicated saturation-path biting test would duplicate T3's
    `RecordingHttpClient` for a secondary path — deferred. Both surfaced by the independent audit (below).
  - Build: `./gradlew :proxy:test` GREEN (incl. 5 live Keycloak Testcontainers tests, Docker up) + `./gradlew clean build
    :buildSrc:test` GREEN. No test removed or `@Disabled`.

- **Task 5 DONE — `NoRolledCryptoArchitectureTest` extended (AC7).** The scaffold rule (forbid `sun.security..`) is
  strengthened to also forbid `javax.crypto..` + `java.security.MessageDigest` (hand-rolled ciphers/MACs/digests;
  `java.security.KeyStore`/PKCS12 loading stays allowed), a new rule forbids third-party HTTP/JWT stacks into `security/`
  (Apache/OkHttp/Spring-web/auth0/jose4j/jsonwebtoken — vacuous today, a future-regression guard per AD-36), and two
  positive AC7 rules assert `RopcSlice` depends on `java.net.http..` (JDK `HttpClient` — the `cancelHttp` abort + AC5
  zeroization depend on it) and `com.nimbusds..` (Nimbus — no hand-rolled JWT). 4 ArchUnit rules, all green; ArchUnit
  sees the test-tier `RopcSlice` (the positive rules are non-vacuous).

- **Task 6 DONE — AC8 immutable-henceforth DECISION recorded.** ARCHITECTURE-SPINE.md AD-12 gains a dated (2026-08-10)
  **Ratification (AC8)** bullet: the `BindCredentialVerifier` port contract is ratified and **immutable henceforth** —
  all four AD-12 paths validated against Keycloak ≥26.7.0 (JWT happy / RFC 7662 introspection / RFC 8705 mTLS no-secret —
  the "most likely to fail" path works / ≥1 DENY branch incl. `cancelHttp` per AD-32), **no contract-revision finding**
  (the shape expresses every path unchanged, incl. the 2026-08-09 `Password`-over-`AsciiString` revision; the AC3
  `cancelHttp` binding, verified against the JDK 25 source, needs no revision). The Accepted-Risk Register ROPC entry's
  scope-residue is updated: Epic 2's opener validated all four paths; Epic 3 ships the production adapter behind the
  unchanged port. No silent closure (mirrors the Story 3.1 fallback-decision discipline).

- **Task 7 DONE — final green build + adversarial verification.** `./gradlew clean build :buildSrc:test` GREEN on JDK 25
  + `--enable-preview` (Jazzer/JNI warnings are pre-existing codec-fuzz noise). No test removed or `@Disabled`; the only
  gating is `@Testcontainers(disabledWithoutDocker = true)` on `RopcSliceLiveTest` (an environment gate, not a disable-
  to-pass dodge). Security tests: 27 total (`RopcSliceUnitTest` 10 + `RopcSliceFailClosedTest` 7 + `RopcSliceCancelTest`
  1 + `NoRolledCryptoArchitectureTest` 4 + `RopcSliceLiveTest` 5), all green. An independent read-only adversarial audit
  (2 agents: a fail-closed guard gap-finder + an AC-coverage mapper) confirmed all 12 then-known load-bearing guards
  bite, mapped every T4-relevant AC (AC2-path4/AC5/AC6/AC7/AC9 → satisfied), and surfaced the `maxInflight` admission gap
  (fixed + bite-verified) plus the two documented scope residues above. Story status: in-progress → review.

- `proxy/src/test/resources/keycloak/realm-smpp-companions.json` — realm + full-profile user + Client A (confidential/DAG) + Client B (`client-x509`/DAG). (Imported by `KeycloakContainer` — the former `docker-compose.yml` + `verify-fixture.sh` were removed when the fixture moved to Testcontainers.)
- `proxy/src/test/resources/keycloak/README.md` — run/verify docs + the 6 real-fixture findings.
- `proxy/src/test/resources/keycloak/certs/generate.sh` — test-PKI provenance script (CA/server/client certs, truststore.p12, client-keystore.p12).
- `proxy/src/test/resources/keycloak/certs/ca.pem`, `ca-key.pem`, `server.pem`, `server-key.pem`, `client.pem`, `client-key.pem`, `truststore.p12`, `client-keystore.p12`, `keycloak-truststore.pem` — generated test-only TLS material.
- `proxy/src/main/java/smpp/companion/proxy/security/BindCredentialVerifier.java` — the port interface: `VerdictRequest verify(BindCredential, ScopedValue<RequestContext>)` (AD-12).
- `proxy/src/main/java/smpp/companion/proxy/security/Verdict.java` — sealed interface + nested `Allow`/`DenyInvalid`/`DenyIndeterminate` payload-less record permits (AD-12).
- `proxy/src/main/java/smpp/companion/proxy/security/BindCredential.java` — composes `(SystemId, Password)`; both immutable records (no defensive copy); redacting `toString` (CODEC-024 P2 boundary).
- `proxy/src/main/java/smpp/companion/proxy/security/VerdictRequest.java` — interface `future()` + `cancelHttp()` (AD-32).
- `proxy/src/main/java/smpp/companion/proxy/security/RequestContext.java` — `(SystemId, ChannelId, Instant deadline)` (AD-5).
- `proxy/src/main/java/smpp/companion/proxy/security/SystemId.java` — `AsciiString`-backed SMPP system_id, ≤15 value octets (SMPP 3.4 §3.2).
- `proxy/src/main/java/smpp/companion/proxy/security/Password.java` — `AsciiString`-backed SMPP password (the typed secret), ≤8 value octets; no defensive copy (shared backing array → zeroization coverage); redacting `toString` (CODEC-024/PRIV-1).
- `proxy/src/main/java/smpp/companion/proxy/security/AlwaysAllowBindCredentialVerifier.java` — `@Component` stand-in (completed-`Allow`, no-op `cancelHttp`).
- `proxy/src/test/java/smpp/companion/proxy/security/VerdictShapeTest.java` — ratifies the sealed 3-permit shape (reflection).
- `proxy/src/test/java/smpp/companion/proxy/security/SecurityPortShapeTest.java` — ratifies the `verify`/`future`/`cancelHttp` signatures (reflection).
- `proxy/src/test/java/smpp/companion/proxy/security/SystemIdTest.java`, `PasswordTest.java`, `BindCredentialTest.java`, `RequestContextTest.java`, `AlwaysAllowBindCredentialVerifierTest.java` — behavior + fail-fast guard tests (RED-on-neuter biting).
- **Task 2 files (NEW):**
- `proxy/src/test/java/smpp/companion/proxy/security/RopcSlice.java` — the test-tier ROPC adapter (`BindCredentialVerifier`): `java.net.http.HttpClient` (mTLS `SSLContext`) + Nimbus JWKS verify; `StructuredTaskScope.open(Joiner)` fan-out; `ScopedValue`-rebound `RequestContext`; bounded VT executor + fail-closed admission; raw-password-byte form body + zeroize; AD-11 verdict mapping; `VerdictRequest` with `cancelHttp()` bound to the `HttpClient` exchange abort (AC2/AC4/AC5/AC6).
- `proxy/src/test/java/smpp/companion/proxy/security/KeycloakFixture.java` — immutable fixture coordinates (realm endpoints on the fixed `:8443`, client ids/secrets, test user) + the mTLS `SSLContext` (truststore.p12 + client-keystore.p12) + the shared `HttpClient` (AD-12/AD-13).
- `proxy/src/test/java/smpp/companion/proxy/security/KeycloakContainer.java` — Testcontainers-managed Keycloak 26.7.0 (replaces `docker-compose.yml`): replicates the HTTPS/mTLS/realm-import config, binds the port **fixed** `8443:8443` (parity with the compose), and waits for OIDC-discovery readiness over mTLS. Gating moved here from the removed `KeycloakLiveCondition`.
- `proxy/src/test/java/smpp/companion/proxy/security/RopcSliceLiveTest.java` — the 5 per-path integration assertions through the real port: Allow (JWT), Allow (introspection), Allow (mTLS), DenyInvalid (bad user), DenyInvalid (bad client) — `@Container static KeycloakContainer` + `@Testcontainers(disabledWithoutDocker = true)` (AC2/AC9).
- `proxy/src/test/java/smpp/companion/proxy/security/RopcSliceUnitTest.java` — 2 always-on fail-closed tests (no fixture): unreachable endpoint → `DenyIndeterminate`; JWKS kid-miss → `DenyIndeterminate`, matching kid → `Allow` (AD-11).
- **Task 3 files (NEW):**
- `proxy/src/test/java/smpp/companion/proxy/security/RopcSliceCancelTest.java` — the AC3 / AD-32 `cancelHttp()` wire-abort test: slow in-process `HttpServer` stand-in IdP + a delegating `RecordingHttpClient` that exposes the real `sendAsync` future; invokes `cancelHttp()` mid-flight and asserts the exchange aborts (a `CancellationException` in the cause chain — the JDK-verified `cancel(true)` → `exchange.cancel()` → `connection.close()` path) + the verdict → `DenyIndeterminate`, corroborated by the IdP's blocked write failing (no token consumed). RED-on-neuter.
- **Task 4–7 files (NEW/MODIFIED):**
- `proxy/src/test/java/smpp/companion/proxy/security/RopcSliceUnitTest.java` — MODIFIED (Task 4): +8 forged-JWT JWKS-claim deny tests (unverifiable signature / issuer / audience / missing-exp / expired / nbf-future / no-kid-header / malformed) biting the `verifyWithJwks` guards (AC2 path4 / AC9).
- `proxy/src/test/java/smpp/companion/proxy/security/RopcSliceFailClosedTest.java` — NEW (Task 4): 7 always-on tests via an in-process `HttpServer` stand-in IdP (4xx/5xx `mapNon200`, introspection `active:false`/non-200, password zeroize-on-completion, saturation fail-closed + saturation-path zeroize, `maxInflight<1` admission fail-fast) (AC2/AC5/AC6/AC9).
- `proxy/src/test/java/smpp/companion/proxy/security/NoRolledCryptoArchitectureTest.java` — MODIFIED (Task 5): 4 ArchUnit rules — forbid `javax.crypto`/`MessageDigest`/`sun.security` + third-party HTTP/JWT stacks; positive `RopcSlice`→`java.net.http`+Nimbus (AC7).
- `_bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/ARCHITECTURE-SPINE.md` — MODIFIED (Task 6): AD-12 **Ratification (AC8)** bullet + Accepted-Risk Register ROPC scope-residue update (all four paths validated; immutable henceforth).

## Change Log

- 2026-08-10 — Code review (3-layer: Blind Hunter + Edge Case Hunter + Acceptance Auditor; all findings re-verified
  against source) closed. The ratified `proxy/security/` **port contract is clean** — no `Allow` leak anywhere in the
  AD-11 verdict mapping (all three layers walked it), sealed `Verdict`, exact `verify`/`future`/`cancelHttp` signatures
  reflection-pinned; every finding was in the test-tier `RopcSlice` slice / its tests / the story's own evidence
  claims. **7 patches applied + verified** (`./gradlew clean build :buildSrc:test` GREEN; security suite green incl.
  the 5 live Keycloak Testcontainers paths re-run; 0 `@Disabled`):
  - **(F2)** saturation now defers `http.sendAsync` until AFTER `admission.tryAcquire()` — a denied/saturated bind no
    longer transmits the ROPC request (with the password) to the IdP, so AC6 "denies **without starting work**" is now
    true; `cancelHttp()` restructured around an `activeCall` exchange holder; new `tokenHits == 1` biting assertion in
    `saturation_deniesWithoutWork_andZeroizes` (RED if the wire call fires pre-admission).
  - **(F3)** introspection switched from a blocking `http.send` to `sendAsync` + registered in `activeCall`, so
    `cancelHttp()` aborts the path-2 introspection call too (AD-32 IdP-sparing gap closed; same proven `cancel(true)`
    mechanism as the token call).
  - **(F5)** `SliceConfig` gains a compact constructor: `requireNonNull` on the endpoint/URI/issuer/clientId fields
    (prevents a null-endpoint NPE escaping `verify()` as a raw Throwable — fail-open + no zeroize) and rejects
    `introspect=true` without a `clientSecret` or mTLS (prevents Basic-auth `clientId:null`).
  - **(F6)** `fetchJwks` is now forked only when `!cfg.introspect()` — introspection is the JWKS-free RFC 7662
    fallback, so a down JWKS endpoint no longer denies every introspection-mode bind.
  - **(F12)** `Objects.requireNonNull(ctx, "ctx")` — the `@param ctx non-null` contract now fails fast instead of
    silently degrading to a synthetic deadline.
  - **(F1)** the false Dev-Notes "password octets taken raw — never `AsciiString.toString()`'d" narrative corrected to
    match the in-code ACCEPTED HAZARD (resolved option B — hazard accepted for the throwaway slice; Epic 3 production
    adapter owns raw-`byte[]` encoding).
  - **(F4)** two stale FALSE RED-on-neuter claims struck from the Task-1 notes (`defensiveCopyOnConstruct` /
    `defensiveCopyOnRead` — those tests never existed; they described the superseded `char[]` design).
  6 LOW test-tier-hardening items deferred to the Epic 3 production adapter (429/404/403 semantic label; use-after-close
  permit leak; JWT `typ` check; `AlwaysAllow` zeroize ownership; `close()` awaitTermination; `asyncRefreshJwks` gating) —
  see deferred-work.md. Story status: review → done.

- 2026-08-10 — Tasks 4–7: closed the Epic 2 opener's test-hardening tail. T4: 8 forged-JWT JWKS-claim deny tests in
  `RopcSliceUnitTest` + new `RopcSliceFailClosedTest` (7 always-on, in-process-IdP tests: 4xx/5xx `mapNon200`,
  introspection `active:false`/non-200, password zeroize-on-completion, saturation fail-closed + saturation-zeroize,
  `maxInflight<1` admission fail-fast) + a scripted RED-on-neuter mutation pass (**13 load-bearing guards bite**); the
  pass caught + fixed a saturation-test exception-safety hang (moved `holdPermit.countDown()` into `finally`). T5:
  `NoRolledCryptoArchitectureTest` → 4 ArchUnit rules (forbid `javax.crypto`/`MessageDigest`/`sun.security` + 3rd-party
  HTTP/JWT; positive `RopcSlice`→HttpClient+Nimbus). T6: AC8 immutable-henceforth ratification recorded in AD-12 + the
  ROPC register (no contract revision — all 4 paths expressible). T7: `clean build :buildSrc:test` GREEN; 27 security
  tests, 0 `@Disabled`; an independent adversarial audit (gap-finder + AC-mapper) confirmed every guard bites + every AC
  satisfied, surfaced+fixed the `maxInflight` gap, documented 2 scope residues (token zeroize = Epic 3; saturation-path
  cancel = callTimeout-bounded, mechanism covered by T3). Story status: in-progress → review.

- 2026-08-09 — Task 3: authored `RopcSliceCancelTest` — the AC3 / AD-32 `cancelHttp()` wire-abort test. Drives the real
  `verify` port against a slow in-process `HttpServer` stand-in IdP, invokes `cancelHttp()` mid-flight, and asserts the
  underlying exchange aborts (a `CancellationException` in `tokenExchange.get()`'s cause chain) + the verdict →
  `DenyIndeterminate`, corroborated by the IdP's blocked 1 MiB write failing (no token consumed). A delegating
  `RecordingHttpClient` exposes the real `sendAsync` future. Verified the JDK-25 cancel mechanism against the source
  (`MinimalFuture.cancel(true)` → `MultiExchange.cancel(true)` → `exchange.cancel()` → `connection.close()`, only when
  `mayInterruptIfRunning==true`) — the slice's binding is correct; **no AC8 contract revision needed for AC3**. Caught two
  false starts via the test: `isCancelled()` is false by design (the future completes exceptionally, not via
  `Future.cancel`'s path), and a small IdP-side write is not a reliable abort signal (TCP half-close buffering). RED-on-
  neuter: neutering `tokenExchange.cancel(true)` → PRIMARY RED ("Expecting code to raise a throwable") + corroboration
  RED; reverted → GREEN (6/6 reliable). `./gradlew :proxy:test` + `clean build :buildSrc:test` GREEN. Story status:
  in-progress (T3 complete; Tasks 4–7 remain).

- 2026-08-09 — Fixture migration: replaced the external `docker-compose.yml` Keycloak fixture with a
  Testcontainers-managed `KeycloakContainer` (the test JVM owns the lifecycle; the compose file, `verify-fixture.sh`, and
  the `KeycloakLiveCondition` TCP-probe gate were removed). The container binds the port **fixed** `8443:8443` (parity
  with the original compose) and waits for OIDC-discovery readiness over mTLS. `RopcSliceLiveTest` uses `@Container static
  KeycloakContainer` + `@Testcontainers(disabledWithoutDocker = true)` — live tests run + bite when Docker is present
  (container starts ~17s) and skip with an explicit reason when it's absent (AC9); the slice keeps using the
  `KeycloakFixture` `:8443` coordinates. All 4 AD-12 paths re-verified through the container; `./gradlew clean build
  :buildSrc:test` GREEN. Version note: Testcontainers 2.x (versionless, managed by Spring Boot 4.1's imported
  `testcontainers-bom`; the `junit-jupiter` module was renamed `testcontainers-junit-jupiter` in 2.x). Finding #7 in the
  fixture README: fixed port + bare `KC_HOSTNAME=localhost` → a deterministic `:8443` issuer (sidesteps the
  dynamic-port `iss`-reflection concern, [#49967](https://github.com/keycloak/keycloak/issues/49967)).

- 2026-08-09 — Task 2: authored the test-tier ROPC validation slice (`RopcSlice implements BindCredentialVerifier`,
  `proxy/src/test`) + `KeycloakFixture` (mTLS `SSLContext`/endpoints) + `KeycloakLiveCondition` + the 5 per-path live
  tests + 2 always-on fail-closed tests. Ratified all four AD-12 paths through the real `keycloak:26.7.0` (path 1 JWT +
  JWKS verify → Allow; path 2 introspection `active:true` → Allow; path 3 RFC 8705 mTLS, no secret → Allow; path 4a/4b
  → `DenyInvalid`). STS fan-out (JEP 505 `open(Joiner.awaitAllSuccessfulOrThrow)` + `fork` + `join`, verified live) +
  `ScopedValue`-rebound `RequestContext` (JEP 506 final); bounded VT executor + fail-closed admission; raw-password-byte
  form body + zeroize; AD-11 mapping (4xx→`DenyInvalid`, else→`DenyIndeterminate`). Two real bugs caught by ratifying
  against the live fixture (retro #4): form `client_id` was the `SystemId`/username not `cfg.clientId()` (all valid
  paths → 4xx); path-4a wrong-password exceeded `Password`'s 8-octet cap — both fixed. `./gradlew clean build
  :buildSrc:test` GREEN; live tests skip cleanly without the fixture (CI). Story status: in-progress (T2 complete;
  Tasks 3–7 remain — `cancelHttp` wire-abort test, zeroization/saturation + RED-on-neuter mutation pass,
  NoRolledCrypto extension, the AC8 immutable-henceforth DECISION, final green build).

- 2026-08-09 — Password type switched to a typed `Password` record over a Netty `AsciiString` (AD-12 contract revision,
  user-directed, pre-AC8-ratification; supersedes the `char[]` in AC1 / the Implementation Plan / retro discovery #3).
  `BindCredential(SystemId, Password password)` now mirrors the codec's CODEC-024/PRIV-1 2026-07-28 override (full
  type-uniformity); the fragile `AsciiString→char[]` relay-seam conversion is eliminated. `Password` is the typed
  counterpart to `SystemId`: `AsciiString`-backed, ≤8 value octets (SMPP 3.4 §3.2 max-9-incl-NUL), no defensive copy
  (the shared backing array means a single `AsciiString.array()` wipe covers the record's own copy — closing the
  internal-copy zeroization gap a `char[]` clone-on-read design could not), redacting `toString()`. Accepted hazard
  (CODEC-024 P2 / AI-5): `AsciiString.toString()` lazily caches an immortal `String`; the `Password`/`BindCredential`
  `toString()` overrides redact, and the standing AI-5 bytecode scan must forbid `toString()` on the password across
  codec + port. New `Password.java` + `PasswordTest.java` (6 tests; RED-on-neuter verified on the length bound + the
  `toString` redaction + the now-load-bearing `BindCredential.password` null guard); `BindCredentialTest` slimmed to 4
  (composition + component-type reflection + redaction + nulls); `AlwaysAllowBindCredentialVerifierTest` construction
  updated. Spine AD-12 (§138 secret hygiene, §139 port-contract literal + revision note) + §Consistency-Conventions §297
  updated. `:proxy:test` GREEN (30 security tests). Story status: in-progress (Task 1 port-type revision; Tasks 2–7 remain).

- 2026-08-08 — Task 0: provisioned + verified the Keycloak ≥26.7.0 fixture (retro AI-3). All 4 AD-12 paths verified
  against `keycloak:26.7.0`, incl. ROPC+mTLS (path 3) → 200. 6 real-fixture findings recorded for Task 2 / AC8.
  Story status: ready-for-dev → in-progress (T0 complete; Tasks 1–7 remain).
- 2026-08-08 — Task 1: authored the 7 AD-12 port types + `AlwaysAllowBindCredentialVerifier` in `proxy/security/`
  (AC1); added 6 shape/behavior tests (26 security-test methods). RED-on-neuter mutation pass run on every load-bearing
  guard (all bite). `./gradlew clean build :buildSrc:test` GREEN. Story status: in-progress (T1 complete; Tasks 2–7 remain).

## Review Findings

> Code review 2026-08-10 (3 parallel layers: Blind Hunter + Edge Case Hunter + Acceptance Auditor; all findings
> re-verified against source). **Headline: the ratified `proxy/security/` PORT CONTRACT (the thing AC8 declares
> immutable henceforth) is clean** — sealed `Verdict`, exact `verify`/`future`/`cancelHttp` signatures, `@NullMarked`,
> reflection-pinned shapes, no `Allow` leak in the AD-11 verdict mapping. **All findings below are in the test-tier
> `RopcSlice` adapter / its tests / the story's own evidence claims** — i.e. they bear on whether the *ratification
> pattern* Epic 3 will copy is correct, not on the port shape itself. Defects concentrated where the story overstates
> what was verified (AC5 secret hygiene, AC6 "without starting work", AC9 RED-on-neuter claims).

### Decision-needed

- [x] [Review][Decision] **Password rendered to `String` in the ROPC form body (AC5 "never String" violated; story narrative claims the opposite)** — `RopcSlice.java:269-276` builds `&password=...URLEncoder.encode(pw.toString())` then `BodyPublishers.ofString(body.toString())`. `AsciiString.toString()` caches an immortal `String` of the secret the `zeroize()` wipe cannot reach (CODEC-024 P2 / AI-5 hazard). The in-code comment is honest ("ACCEPTED HAZARD … fine for throwaway test slice; Epic 3 MUST encode from raw byte[]") BUT the Dev Notes Implementation-Plan (Task 2) states the opposite — "Password octets are taken raw from the AsciiString backing array — never AsciiString.toString()'d." Decision: (A) fix the slice to percent-encode from `pw.array()` byte-level (honor AC5 literally; sets the right pattern for Epic 3) AND correct the doc; or (B) accept the hazard for the throwaway slice and correct only the false narrative claim. (Blind Hunter + Acceptance
Auditor.) **Resolved 2026-08-10 — option B:** hazard accepted for the throwaway test slice (Epic 3 production adapter owns raw-byte encoding); the false "never `toString()`'d" Dev-Notes narrative corrected to match the in-code ACCEPTED HAZARD comment.

### Patch

- [x] [Review][Patch] **Saturation fires the ROPC wire call (with the password) to the IdP BEFORE the admission check — AC6 "without starting work" is false** [`RopcSlice.java:112-122`] — `http.sendAsync(tokenRequest(...))` (line 113) precedes `admission.tryAcquire()` (line 117); a denied/saturated bind has already transmitted the full ROPC request (form body incl. password) before `cancel(true)` fires (line 118). Undercuts the AD-32 IdP-amplification mitigation AC6 exists to enforce. The test `saturation_deniesWithoutWork_andZeroizes` asserts only `elapsedMs < 1000` + zeroize — its own IdP handler blocks on `holdPermit` for verify#2's request, proving the wire call reaches the IdP, but the test cannot catch it. Fix: defer `sendAsync` until after `tryAcquire()` succeeds (restructure `cancelHttp` to hold the exchange handle). (Blind Hunter + Acceptance Auditor.)
- [x] [Review][Patch] **`cancelHttp()` does not abort the introspection (path 2) wire call — AD-32 gap** [`RopcSlice.java:222,346-350`] — introspection uses a blocking `http.send(...)` with no stored handle; `cancelHttp()` cancels only `tokenExchange` (already complete post-token-success → no-op). The verdict is correct (`DenyIndeterminate`) but the IdP is not spared the abandoned introspection call. `RopcSliceCancelTest` uses `introspect=false`, so path-2 cancellation is never exercised. Fix: make introspection `sendAsync` + store its future; cancel both in `cancelHttp()`. (Blind Hunter + Edge Case Hunter.)
- [x] [Review][Patch] **False RED-on-neuter claim: Task-1 completion notes cite `defensiveCopyOnConstruct`/`defensiveCopyOnRead` mutation tests that do not exist** [`2-1-...slice.md:410-417`] — `BindCredentialTest` has only 4 tests (`toStringDoesNotLeakPassword`, `passwordComponentIsPasswordType`, `rejectsNullPassword`, `rejectsNullSystemId`); no `defensiveCopy*` tests. The notes describe the superseded `char[]` design (the 2026-08-09 Password-over-AsciiString revision deliberately removed the defensive copy). Shipped code is correct-by-design; the AC9 evidence record is stale/false. Fix: strike the two bogus mutation claims from the Task-1 notes. (Blind Hunter.)
- [x] [Review][Patch] **`SliceConfig` has no fail-fast validation → null endpoint/URI fields NPE out of `verify()` (fail-open + password never zeroized)** [`RopcSlice.java:64-76,112-113`] — the record has no compact constructor; a null `tokenEndpoint` makes `HttpRequest.newBuilder(null)` throw synchronously at line 113, BEFORE `tryAcquire`/the pool task/any `finally` → caller gets a raw NPE (not `DenyIndeterminate`) and `cred.password().zeroize()` never runs (AD-11 fail-open + AC5 hygiene miss + no AD-17 fail-fast). Same root leaves `introspectRequest` emitting Basic-auth `clientId:null` when `clientSecret` is null (line 282). Fix: `SliceConfig` compact-ctor `requireNonNull` on URI/String fields + validate the introspect/secret/mTLS combinations. (Edge Case Hunter + Blind Hunter.)
- [x] [Review][Patch] **Introspection path hard-depends on JWKS fetch success — JWKS down blocks introspection** [`RopcSlice.java:150-166`] — `adjudicate()` forks `fetchJwks` unconditionally and `Joiner.awaitAllSuccessfulOrThrow()` requires it; a JWKS failure collapses to `DenyIndeterminate` even when `cfg.introspect()` is true (the JWKS result is unused on that branch). An introspection-mode deployment with JWKS down denies every bind — introspection is supposed to be the JWKS-free fallback (RFC 7662). Fix: fork JWKS only when `!cfg.introspect()`, or use a joiner that tolerates JWKS failure in introspect mode. (Edge Case Hunter + Acceptance Auditor.)
- [x] [Review][Patch] **`ctx` null silently degraded — `@param ctx non-null` contract violation hidden** [`RopcSlice.java:106-107`] — `verify(cred, null)` skips the `requireNonNull` and silently substitutes a 30s synthetic deadline + skips the `ScopedValue` rebind (line 130 `else`), hiding the caller's bug. Fix: `Objects.requireNonNull(ctx, "ctx")`. (Edge Case Hunter.)

### Defer (low-severity test-tier hardening — owned by the Epic 3 production adapter)

- [x] [Review][Defer] **HTTP 429/404/403 → `DenyInvalid` semantic misclassification** [`RopcSlice.java:253`] — conforms to the story's explicit AD-11 refinement ("4xx → DenyInvalid"); both deny, so the security outcome is identical; only the permit label differs. Semantic refinement (429=rate-limit/404=config/403=authz → arguably `DenyIndeterminate`) belongs to the Epic 3 production mapping. (Edge Case Hunter.)
- [x] [Review][Defer] **`execute()` after `close()` leaks the admission permit + skips zeroize** [`RopcSlice.java:117-126`] — use-after-close: `tryAcquire()` succeeds then `execute()` throws `RejectedExecutionException` outside the task's `try/catch` → permit permanently leaked (silent permanent saturation after `maxInflight` such calls) + password not zeroized. Requires use-after-close; trivial `try/catch` hardening for Epic 3. (Edge Case Hunter.)
- [x] [Review][Defer] **JWT `typ` header not validated** [`RopcSlice.java:183-196`] — RFC 8725 §3.9 defense-in-depth (token-type confusion); signature + iss/aud/exp/nbf are checked, so no `Allow` leak. Not an AC requirement (AC2 path 1 lists iss/aud/exp/nbf). Epic 3 hardening. (Edge Case Hunter.)
- [x] [Review][Defer] **`AlwaysAllowBindCredentialVerifier` does not zeroize the password** [`AlwaysAllowBindCredentialVerifier.java:20-22`] — the stand-in never inspects the secret (always-allow, documented no-op `cancelHttp`); AC5 "on adjudication completion" ownership (verifier vs caller/relay) is ambiguous. Resolve with `relay/` wiring / Epic 3. (Edge Case Hunter + Acceptance Auditor.)
- [x] [Review][Defer] **`close()` does `shutdownNow()` with no `awaitTermination`** [`RopcSlice.java:353-356`] — cosmetic for the throwaway test slice (pool-task `finally` blocks still eventually run on daemon VTs); Epic 3 production adapter should drain. (Blind Hunter + Edge Case Hunter.)
- [x] [Review][Defer] **`asyncRefreshJwks` bypasses the admission gate + unconditionally nulls the cache** [`RopcSlice.java:312-321`] — submitted without `tryAcquire` (can exceed `maxInflight` under kid-rotation) and `jwksCache.set(null)` runs before re-fetch succeeds. Fail-closed holds; undermines the bound/cache invariants under the exact load the cache smooths. Epic 3 hardening. (Blind Hunter.)

### Dismissed

- **`BindCredential` uses typed `Password` (AsciiString) not the literal `char[]` of AC1** — NOT a defect: this is the user-directed 2026-08-09 contract revision, the ARCHITECTURE-SPINE.md AD-12 Port-contract + secret-hygiene clauses were updated to match, and AC8's ratification formally blesses the revised shape. Residue: AC1's literal `char[]` text in this story is now stale (could be amended for internal consistency). (Acceptance Auditor.)
