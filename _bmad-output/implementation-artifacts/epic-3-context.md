# Epic 3 Context: Secure the transit — TLS modes A/B/C and OIDC ROPC password-grant adjudication

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Configure per-leg TLS by mode and delegate legacy password-grant validation to an operator-run OIDC provider (Keycloak ROPC), so the proxy fail-closed-denies every bind on indeterminate verdicts, holds zero persisted credentials, and preserves `system_id` end-to-end. The adjudication half is complete (3.1 probe: MET; 3.2: production ROPC adapter behind the ratified-immutable port). The TLS half — Modes A/B/C on the internet leg, the forward-role landing, and the routing-miss deny arm — landed with Story 3.3 (done 2026-08-27), closing the two-proxy transit-security story and unblocking Epic 4.

## Stories

- Story 3.1: ROPC deprecation/viability probe (done, out-of-band; verdict MET 2026-08-08)
- Story 3.2: OIDC ROPC bind adjudicator — production adapter behind the AD-12 port (done)
- Story 3.3: TLS modes A/B/C + forward-role landing (done 2026-08-27; [B] topology — the forward dials the reverse per session)

## Requirements & Constraints

- **Mode semantics ([B] two-proxy topology, ratified 2026-08-21 — the reverse holds the internet-leg listener; the forward dials it per SMPP session).** Mode A = one-way TLS on the internet leg (the reverse's listener presents a cert; it never validates peers — the reverse CANNOT authenticate the connecting forward: loud `CompanionModeAWarning` startup banner, restored 2026-08-27); Mode B = plaintext internet leg, **reverse-only** (forward×B rejected at startup; the legacy client connects directly to the reverse, which still adjudicates) — loud startup warning + explicit opt-in ack, then starts; Mode C = mTLS on the internet leg. The reverse→SMSC leg is **plaintext in every mode**; the forward's trusted leg is plaintext (trusted network is the sole gate — no local password check or store).
- **Fail-closed on every auth-adjacent decision.** Routing-miss (`system_id` not in the routing table) → DENY, no default route. Mode C: no client cert or cert not reaching the configured anchor → handshake failure (`REQUIRE`, never `WANT`). Trust store absent/empty/wrong-format/wrong-password/zero trusted entries → refuse startup. Empty cipher-suite intersection at startup → refuse.
- **TLS floor + pinned allowlist (operator-tunable).** TLS 1.2 minimum, 1.3 preferred. TLS-1.2 default set = ECDHE-ECDSA/RSA AES-GCM suites only (no CBC, no static-RSA, no legacy ciphers; ChaCha20 optional); TLS 1.3 = the JDK AEAD set. Every SSL context (ingress server, egress targets, IdP client) intersects the configured set at startup; empty → fail-fast.
- **Trust is consumed, never manufactured.** Operator-provided certs/trust stores at runtime; the proxy never acts as a CA, issues certs, or bundles an authority provider. Mode C client certs are **per-instance** (per-target via explicit TLS-context IDs) — never a shared golden-image key. Rotation = re-deploy; CRL/OCSP revocation is out of v1.
- **Identity forwarded, never mapped:** legacy `system_id` == carrier `system_id`; no pooling or surrogate identity.
- **Credential-free at rest.** No SMPP passwords, no vault; the transient per-bind password is zeroized. Secrets (certs, keys, trust stores, provider client secret) are **file paths** in config — never a secret value in an env var; missing/unreadable file → fail-fast.
- **Denial wire collapse.** All proxy-side bind denials collapse to one generic `bind_*_resp` failure code (already shipped); SMSC-originated `generic_nack`/non-ROK `bind_resp` pass through verbatim; rich outcomes go to logs/metrics only, never the wire.
- **Accepted risks constraining scope:** Mode A two-proxy without ACL isolation (the reverse cannot authenticate the connecting forward in one-way TLS — loud `CompanionModeAWarning` startup banner) and Mode B plaintext passwords over the internet (opt-in).
- **Bind latency budget:** p99 ~250 ms warm, ≤2 s cold, fail-closed DENY beyond a 2–5 s timeout.

## Technical Decisions

- **Reverse-adjudicates topology (amended 2026-08-18; supersedes older "forward adjudicates" wording still in story-3.2 AC prose and the unswept walkthrough narrative — the spine + memlog are authoritative).** The reverse is the sole enforcement point (ROPC before anything reaches the SMSC); the forward is a trusted-side relay with no OIDC material. TLS contexts to build under [B]: the **reverse's internet-leg server** context (the listener on `bind.host:port`; Mode A presents its cert, Mode C adds client-auth REQUIRE) and the **forward's per-session client** context (dials the routing target; validates the reverse's server cert against the operator trust store, Mode C presents the per-instance client cert). No TLS on the trusted legacy or SMSC legs.
- **mTLS = PKIX defaults:** `trustManager(operatorStore)` + `clientAuth(REQUIRE)`; no custom `PKIXBuilderParameters`, no custom chain-validation code; rely on default chain depth. The trust store **never falls back to JDK `cacerts`** on any peer-validation path; public-PKI/cacerts trust is an explicit opt-in with a loud warning in any mode, never the default.
- **Egress endpoint identification:** on the forward's internet-leg client connect (the per-session dial), set `endpointIdentificationAlgorithm` explicitly (`null` for valid raw-IP literals — octets ≤ 255, else hostname-ON per the fail-closed rule — or IP-SAN certs with verification on) — Netty 4.2 defaults it to HTTPS and fails raw-IP connects. The reverse→IdP link is JDK `HttpClient` with verification always on.
- **SslHandler handshake-crypto tasks** run on ONE hand-managed fixed platform-thread pool (shared ingress+egress, bounded queue, abort-and-fail-handshake on saturation) — never on event loops, never `CallerRunsPolicy`, never virtual threads.
- **One instance = one role × one mode**, validated at startup against the required/forbidden-per-cell matrix (forward: server cert+key, routing table, no OIDC, no SMSC endpoint, +trust store in C; forward+B forbidden; reverse: OIDC provider + SMSC endpoint, +trust store in A, +client cert+key+trust store in C, +opt-in ack in B). TLS material is immutable after startup.
- **Routing is 1:1 in v1:** a `system_id` allow-list mapping to the single egress; value schema `{host, port, tlsContextId?}` with the `companion.forward.tls-contexts` map for per-target Mode C certs (re-keyed from top-level `tls.contexts`, memlog 2026-08-26).
- **Verifier wiring is Spring-DI-only** (already shipped: reverse cells → ROPC adapter, forward cells → always-allow). No vendor OIDC SDK anywhere (JDK HttpClient + Nimbus only); no WebFlux/Reactor/Spring web server on the SMPP path — Netty is driven directly.
- **Main-tier TLS gate in force (SEC-090):** `javax.net.ssl` is sanctioned for JDK `SSLContext`/`SSLParameters` use only — hand-rolled PKIX, custom `X509TrustManager` logic, or `com.sun.net.httpserver` in main sources are arch-test violations.
- **Keycloak pinned ≥26.7.0** (no LTS; re-validate each minor); ROPC removal-watch is live — v1 is explicitly ROPC-conditional (deployment-guide disclosure belongs to Epic 6).

## Cross-Story Dependencies

- **Story 3.3 is the first `relay/` change since Epic 2.** It owns: forward-role acceptor wiring (the acceptor currently mounts the reverse.mode-b cell only), the `BindInterceptor` role-split (seam chosen in Epic 2, execution held for "when the forward role lands"), the routing-miss deny arm, per-target `tlsContextId`, ingress TLS, the remaining per-context cipher intersections (the IdP client context landed in 3.2), and wildcard-listener/connection-cap hardening (F13).
- Story 3.2's file text predates two mid-story amendments — adjudication moved to the reverse role, and the RFC 8705 provider-mTLS arm was removed (provider client auth is `client_secret` only) — trust the spine/`.memlog.md` over story AC prose in any conflict.
- Epic 4 (metrics + structured-log impls) depends on this epic; Epic 6 owns the perf harness, the ROPC-conditional operator disclosure, and the per-mode deployment docs.
- Deferred relay items F1/F10/F14/F16 were owner-deferred to the relay-timeout round / Epic 4 — check the deferred-work ledger at story-creation time for current owners.
