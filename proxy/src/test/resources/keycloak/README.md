# Keycloak ≥26.7.0 fixture — Story 2.1 security-port contract-shape validation slice

The Epic 2 opener ratified the AD-12 `proxy/security/` port contract against this fixture — a
**real Keycloak 26.7.0** instance exercising all four AD-12 paths (Story 2.1 Task 0), **managed by
Testcontainers** (`KeycloakContainer`) — the test JVM owns its lifecycle, so `./gradlew :proxy:test` brings
it up automatically on a **fixed** `localhost:8443` (parity with the original compose's `8443:8443`; the
former external `docker-compose.yml` is gone).

> **Amended (Story 3.4 T8, 2026-08-29):** the slice's 2.1-era interop arms are removed EVERYWHERE — local JWT
> signature verification (JWKS), RFC 7662 opaque-token introspection, and RFC 8705 `tokenRequest` mTLS client
> auth (the historical-ratification exemption ended; the 2026-08-27 T1/T2 "deliberately UNCHANGED"
> dispositions are superseded). The fixture now serves the **amended contract**: ROPC with a mandatory
> `client_secret` whose verdict derives from the token-endpoint response + the structural three-segment gate
> alone. The client **cert stays as transport identity** (the container demands it on every handshake) — only
> the OAuth-level cert-auth use is gone.

Provisioned here (not pre-provisioned by Winston) and **verified against the running instance** (retro
discovery #4 — verify endpoints/behavior against the real fixture, never assumptions).

> Test-only. Every cert is self-signed for this local fixture; the credentials below are NOT production secrets.

## Run / verify

The live tests start the container themselves (no manual `docker compose`):

```bash
./gradlew :proxy:test --tests "smpp.companion.proxy.security.RopcSliceLiveTest"   # Docker present → 3 paths green
./gradlew :proxy:test --tests "smpp.companion.proxy.security.RopcSliceUnitTest"   # always-on, no Docker needed
```

When Docker is absent (e.g. a CI lane with no Docker daemon), the live class is **skipped with an explicit
reason** (`@Testcontainers(disabledWithoutDocker = true)`) — never a silent green — and the always-on unit
tests still enforce the fail-closed mapping. Image pin: `quay.io/keycloak/keycloak:26.7.0` (the ≥26.7.0
floor; re-validate each minor — no LTS).

## Realm: `smpp-companions`

| Principal | Value | Notes |
| --- | --- | --- |
| User | `testuser` / `testpass` | First/last/email set — Keycloak 26 User Profile requires them (see finding #4). |
| Client A | `smpp-client-confidential` / secret `smpp-confidential-secret` | confidential, `directAccessGrantsEnabled=true`. Paths 1 (JWT) + 4 (DENY) — the amended contract's sole client (the client-x509 Client B died with the mTLS arm, Story 3.4 T8). |

> The OIDC endpoints are served at the fixed `https://localhost:8443/realms/smpp-companions/...` — the container
> binds `8443:8443` (parity with the original compose), so the slice uses the `KeycloakFixture` `:8443`
> coordinates directly. (Path shape: `/realms/smpp-companions/protocol/openid-connect/token` — the slice's only
> provider wire call.)

## Verified outcomes (the live tests, against keycloak:26.7.0)

| Path | Request | Verified result |
| --- | --- | --- |
| **1** JWT happy path | Client A + testuser ROPC | **200** + RS256 JWT → the structural three-segment gate → `Allow` on the endpoint verdict alone |
| **4a** DENY invalid user creds | Client A + wrong password | **400 `invalid_grant`** (see finding #6) |
| **4b** DENY invalid client | Client A + wrong secret | **401 `invalid_client`** |

Paths 2 (RFC 7662 introspection) and 3 (RFC 8705 mTLS provider auth) were retired from the slice by Story 3.4
T8 (2026-08-29); the D6 opaque-token deny and the D7 endpoint-verdict-alone allow are pinned always-on by
`RopcSliceFailClosedTest`'s in-process IdP. The original four-path ratification (2026-08-10) stands as the
AC8 historical record — see the spine's AD-12 amendment markers.

## TLS material (`certs/`, regenerate with `generate.sh`)

| File | Purpose |
| --- | --- |
| `ca.pem` / `ca-key.pem` | Local test CA. **CN-only subject** (`CN=smpp-test-ca`) — see finding #5. |
| `server.pem` / `server-key.pem` | Keycloak HTTPS server cert (SAN: `localhost`, `keycloak`, `127.0.0.1`). |
| `client.pem` / `client-key.pem` | The test JVM's **transport client cert** (`CN=smpp-mtls-client`) — presented on every IdP call; no OAuth-level use remains (removed Story 3.4 T8). PEM form for curl. |
| `truststore.p12` (pw `smpp-test`) | **Test-JVM trust anchor for the Keycloak server** — AD-13: minimal, single CA, never JDK `cacerts`. |
| `client-keystore.p12` (pw `smpp-test`) | **Test-JVM transport client identity** (client cert + key) for the `SSLContext` the slice presents on every call. |
| `keycloak-truststore.pem` | CA PEM Keycloak trusts to verify transport client certs (`KC_TRUSTSTORE_PATHS`). |

## How the validation slice consumes this

The test-tier ROPC adapter (`java.net.http.HttpClient` + Nimbus) connects to the fixed
`https://localhost:8443/...` (`KeycloakFixture` coordinates), with an `SSLContext` that trusts `ca.pem` (via
`truststore.p12`) **and presents the client cert** (via `client-keystore.p12`) on every call — transport
identity (the container's `KC_HTTPS_CLIENT_AUTH=required` demands it). OAuth-level client auth is
`client_secret` only (Client A's secret, always sent — the amended contract's whole client-auth surface).
For the `DenyIndeterminate` branch, the unit tests point the token endpoint at an unreachable URL, and the
always-on in-process-IdP suite drives the D6 opaque-token deny directly.

## Container config (`KeycloakContainer` ↔ the former docker-compose, byte-identical)

`KeycloakContainer` (`proxy/src/test/…/security/KeycloakContainer.java`) replicates the verified compose
config verbatim: pinned `quay.io/keycloak/keycloak:26.7.0`, `start --import-realm --hostname-strict=false`,
`KC_HTTPS_CLIENT_AUTH=required` (NEED — the transport demands the client cert on every handshake), the mounted
server cert (`server.pem`) + key (`server-key.pem`, copied mode `0400`) + mTLS truststore
(`keycloak-truststore.pem`), the realm import (`realm-smpp-companions.json` → `/opt/keycloak/data/import/`),
and a **fixed** port bind `8443:8443` (`setPortBindings`, parity with the original compose). Readiness = OIDC
discovery served over mTLS HTTPS — the built-in `Wait.forHttps` cannot be used (`KC_HTTPS_CLIENT_AUTH=required`
rejects a cert-less handshake), so a custom `AbstractWaitStrategy` reuses the slice's `SSLContext` to poll
the discovery doc (and self-enforces its startup deadline; see the class Javadoc).

## Findings (the dated Story-2.1 discovery record — bake-in target of its time; paths 2/3/JWKS read historically, those arms were removed everywhere 2026-08-29 by Story 3.4 T8)

1. **`--hostname-strict-https` was removed** in KC 26.7 (unknown-option exit). Use `--hostname-strict=false`.
2. **`https-client-auth` valid value is `required`** (`require` is rejected). And **`request` (WANT) does NOT expose
   the peer cert to the `client-x509` authenticator** — the TLS handshake completes and the cert is accepted, but
   Vert.x/Quarkus only surfaces it to the app in `required` (NEED) mode. The fixture runs `required`; this is
   design-consistent (the proxy always presents its cert per AD-12/AD-29), so Client A also presents it for transport.
3. **KC 26 `client-x509` uses attributes `x509.subjectdn` + `x509.casubjectdn`**, NOT the legacy `x509cert` (the
   authenticator logs `x509.subjectdn is null or empty` if `x509cert` is used). It checks the **CA/issuer DN first**;
   both must match the DN string **as Keycloak reads it** (it reorders RDNs), hence the CA cert is kept **CN-only**.
4. **KC 26 User Profile requires `email`/`firstName`/`lastName`** for the `user` role — omit them and ROPC fails with
   the opaque *"Account is not fully set up"* (`resolve_required_actions`), even with DAG enabled and a valid password.
5. **DAG is per-client** (`directAccessGrantsEnabled=true`; off by default since KC 26.2, #30226). Realm discovery
   advertising `password` ≠ per-client DAG.
6. **AC2 path-4 assumption refined (AC8 input):** Keycloak ROPC returns **400 `invalid_grant`** for bad *user*
   credentials and **401 `invalid_client`** for bad *client secret*. AC2 path 4's "invalid creds → 401 → DenyInvalid"
   must therefore map **both** 400-invalid_grant and 401-invalid_client to `DenyInvalid` (AD-11's "4xx≠200 → DENY"
   already covers both; do not key off HTTP 401 alone).
7. **Fixed port + bare `KC_HOSTNAME=localhost` → a deterministic `:8443` issuer.** The container binds `8443:8443`
   (so the host address is always `localhost:8443`), and with `KC_HOSTNAME=localhost` (a bare hostname) +
   `hostname-strict=false` + `KC_HTTPS_PORT=8443`, Keycloak's issuer and the token `iss` claim are both
   `https://localhost:8443/realms/smpp-companions` — the deterministic issuer the live tests rely on (the slice no
   longer asserts it locally; the issuer check died with local claim verification, Story 3.4 T2 + T8). The fixed bind
   also sidesteps the dynamic-port `iss`-reflection concern
   ([#49967](https://github.com/keycloak/keycloak/issues/49967)): keep the bind fixed and `KC_HOSTNAME` bare. If a
   future run binds a different port, restore the runtime discovery approach (or update the constants); the
   `26.7.0` pin + per-minor live-slice re-run is the standing mitigation.
