package smpp.companion.proxy.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.netty.channel.DefaultChannelId;
import io.netty.util.AsciiString;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.testsupport.OidcDiscoveryStandIn;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Story 3.2 T3 (AC2/AC5) — the <b>production</b> ROPC adapter core, driven through the real
 * {@link BindCredentialVerifier#verify} port against in-process {@link HttpsServer} stand-in IdPs
 * (fixture-cert TLS — the same trust story as the shared discovery stand-in; no container, no
 * network beyond loopback). The adapter is constructed exactly as the T7 wiring will construct it:
 * {@code new RopcBindCredentialVerifier(new IdpSslContextFactory(properties),
 * new OidcStartupDiscovery(properties, factory))} — real trust-store load, real TLS discovery at
 * bean-init time, real shared client.
 *
 * <p><b>AC2 — the refined (normative) verdict table.</b> {@code DenyInvalid} is reserved for the
 * provider's POSITIVE invalid-credential signals: a bare 401 (RFC 6749 &sect;5.2 — even with an
 * unparseable body) and a 400 whose parsed OAuth {@code error} is {@code invalid_grant} or
 * {@code invalid_client}. Everything else — 3xx, 403/404/429, other/absent 400 errors, 5xx,
 * timeout, network error — is {@code DenyIndeterminate} (rate-limit/config/authz errors are not
 * credential verdicts). This supersedes the test slice's crude "4xx &rarr; DenyInvalid" shorthand.
 *
 * <p><b>AC5 — admission, capture, hardening.</b> Saturation denies WITHOUT a wire call (F2:
 * {@code sendAsync} only after {@code tryAcquire} — asserted by the stand-in's request counter),
 * the context is captured on the caller's thread (an unbound handle fails CLOSED, never throws),
 * an exhausted adjudication deadline denies without a wire call, and a closed adapter
 * (use-after-close, deferred-work &sect;2.1 item 2) settles every verify fail-closed — never
 * hangs, never throws out of {@code verify()}.
 *
 * <p><b>RED-on-neuter (AI-1):</b> every assertion is load-bearing — neuter the 400-error-semantics
 * branch (make 400 unconditionally DenyInvalid) and the other-400 test goes RED; fire sendAsync
 * before admission and the saturation counter goes RED; skip the secret-file load guard and the
 * constructor test goes RED. Every stand-in handler releases its latch / stops its server in a
 * {@code finally} — a stranded handler thread hangs the test JVM.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AD-12/AD-11 RopcBindCredentialVerifier — AC2 verdict table + AC5 admission/capture core")
class RopcBindCredentialVerifierTest {

    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";
    private static final String REALM_PATH = "/realms/smpp-companions/protocol/openid-connect";
    private static final String TOKEN_PATH = REALM_PATH + "/token";
    private static final String JWKS_PATH = REALM_PATH + "/certs";

    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    // ── AC2: the token-endpoint status rows (the refined production table) ─────────────────────

    @Test
    @DisplayName("bare 401 (unparseable body) → DenyInvalid — RFC 6749 §5.2 positive auth-layer rejection")
    void bare401YieldsDenyInvalid(@TempDir Path dir) throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 401, "not-json-at-all");
        }, null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a bare 401 IS the provider's positive invalid-credential signal (AC2)")
                    .isInstanceOf(Verdict.DenyInvalid.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("400 invalid_grant (bad USER credentials) → DenyInvalid")
    void badUser400InvalidGrantYieldsDenyInvalid(@TempDir Path dir) throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 400, "{\"error\":\"invalid_grant\",\"error_description\":\"Invalid user credentials\"}");
        }, null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("400 + parsed error=invalid_grant is a positive invalid-credential signal (finding #6)")
                    .isInstanceOf(Verdict.DenyInvalid.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("400 invalid_client → DenyInvalid (some providers send 400, not 401, for a bad client)")
    void badClient400InvalidClientYieldsDenyInvalid(@TempDir Path dir) throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 400, "{\"error\":\"invalid_client\"}");
        }, null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("400 + parsed error=invalid_client is a positive invalid-credential signal")
                    .isInstanceOf(Verdict.DenyInvalid.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("400 with OTHER error / unparseable body → DenyIndeterminate (key on error semantics, not status)")
    void other400ErrorsYieldDenyIndeterminate(@TempDir Path dir) throws Exception {
        AtomicInteger rotation = new AtomicInteger();
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 400, rotation.getAndIncrement() == 0
                    ? "{\"error\":\"unauthorized_client\"}"
                    : "not-json");
        }, null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            // The load-bearing refinement: under the test slice's crude "4xx → DenyInvalid" shorthand both
            // of these were misclassified — rate-limit/config/authz 400s are NOT credential verdicts.
            assertThat(awaitVerdict(verify(adapter)))
                    .as("400 unauthorized_client is an authorization error, not an invalid-credential signal (AC2)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat(awaitVerdict(verify(adapter)))
                    .as("an unparseable 400 body carries no OAuth error semantics → not a credential verdict (AC2)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("403 / 404 / 429 → DenyIndeterminate (rate-limit, config and routing errors are not verdicts)")
    void rateLimitAndConfig4xxYieldDenyIndeterminate(@TempDir Path dir) throws Exception {
        AtomicInteger rotation = new AtomicInteger();
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, new int[] {403, 404, 429}[rotation.getAndIncrement()], "{\"error\":\"misc\"}");
        }, null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            for (int i = 0; i < 3; i++) {
                assertThat(awaitVerdict(verify(adapter)))
                        .as("403/404/429 must deny indeterminate, never invalid (AC2 — the 429/404/403 refinement)")
                        .isInstanceOf(Verdict.DenyIndeterminate.class);
            }
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("5xx → DenyIndeterminate (provider error, not a credential verdict)")
    void serverError5xxYieldsDenyIndeterminate(@TempDir Path dir) throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 500, "{\"error\":\"server_error\"}");
        }, null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("5xx → fail-closed indeterminate (AD-11)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("3xx (redirect never followed) → DenyIndeterminate")
    void redirect3xxYieldsDenyIndeterminate(@TempDir Path dir) throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            ex.getResponseHeaders().set("Location", "https://localhost:1/elsewhere");
            ex.sendResponseHeaders(302, -1);
            ex.close();
        }, null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a redirecting token endpoint is not a credential verdict (AC2; redirects never followed)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("200 with empty / HTML body → DenyIndeterminate (no token issued → unverifiable)")
    void emptyOrHtml200YieldsDenyIndeterminate(@TempDir Path dir) throws Exception {
        AtomicInteger rotation = new AtomicInteger();
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 200, rotation.getAndIncrement() == 0 ? "" : "<html>login page</html>");
        }, null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("200 with an empty body carries no token → unverifiable (AC2)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat(awaitVerdict(verify(adapter)))
                    .as("200 with an HTML body carries no token → unverifiable (AC2)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    // ── AC3: JWT defense-in-depth against the cached JWKS (T4) ────────────────────────────────

    @Test
    @DisplayName("200 + JWT passing local defense-in-depth (typ/kid/sig/iss/aud/exp/nbf) → Allow")
    void issuedJwtPassingDefenseInDepthYieldsAllow(@TempDir Path dir) throws Exception {
        HttpsServer server = jwtIdP(key("t4-key"), new JOSEObjectType("JWT"), null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            awaitCachePopulated(adapter);   // the background initial refresh, before the bind
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a 200 verdict confirmed by local defense-in-depth stands (AC3)")
                    .isEqualTo(new Verdict.Allow());
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("200 + JWT with NO typ header → Allow (absent typ is tolerated, RFC 8725 §3.9 / AC3)")
    void typHeaderAbsentToleratedYieldsAllow(@TempDir Path dir) throws Exception {
        HttpsServer server = jwtIdP(key("t4-key"), null, null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            awaitCachePopulated(adapter);
            assertThat(awaitVerdict(verify(adapter)))
                    .as("absent typ is tolerated (AC3); only present-but-unexpected denies")
                    .isEqualTo(new Verdict.Allow());
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("200 + JWT with an UNEXPECTED typ header → DenyIndeterminate (cross-JWT confusion must not verify)")
    void typHeaderUnexpectedYieldsDenyIndeterminate(@TempDir Path dir) throws Exception {
        // "Bearer" is the PAYLOAD-claim value training data conflates with the header; the pinned
        // fixture's HEADER literal is "JWT" (live-verified 2026-08-19 — see EXPECTED_TYP).
        HttpsServer server = jwtIdP(key("t4-key"), new JOSEObjectType("Bearer"), null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            awaitCachePopulated(adapter);
            assertThat(awaitVerdict(verify(adapter)))
                    .as("typ=Bearer in the HEADER is unexpected for this provider (its header literal is JWT)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("kid miss → DenyIndeterminate NOW, background refresh scheduled, verdict never waits for it")
    void kidMissDeniesNowAndRefreshesInBackground(@TempDir Path dir) throws Exception {
        RSAKey key = key("t4-key");
        AtomicReference<String> servedKid = new AtomicReference<>("rotated-in");   // NOT in the JWKS
        CountDownLatch refreshGate = new CountDownLatch(1);
        AtomicInteger jwksHits = new AtomicInteger();
        HttpsServer server = standInIdP(
                ex -> {
                    drain(ex);
                    respond(ex, 200, tokenBody(jwt(key, servedKid.get(), new JOSEObjectType("JWT"),
                            b -> validClaims(b, issuerOf(ex)))));
                },
                null,
                ex -> {
                    // The INITIAL fetch (hit 1) serves; every later refresh BLOCKS — the bind's
                    // verdict must settle without waiting for the refresh it triggered.
                    if (jwksHits.incrementAndGet() > 1) {
                        try {
                            refreshGate.await();
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        }
                    }
                    respond(ex, 200, jwksBody(key));
                });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            awaitCachePopulated(adapter);   // hit 1: the JWKS holds kid "t4-key" only
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a kid miss is UNVERIFIABLE, not invalid — deny now (AC3, no foreground retry)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat(refreshGate.getCount())
                    .as("the kid-miss refresh is still held — the verdict above did NOT wait on it")
                    .isEqualTo(1);
            awaitCondition("the kid-miss background refresh to reach the gated endpoint",
                    () -> jwksHits.get() >= 2);
            assertThat(jwksHits.get())
                    .as("the kid miss scheduled the background refresh (hit 2, currently gated)")
                    .isGreaterThanOrEqualTo(2);
            servedKid.set("t4-key");   // a matching-kid token on the SAME cached set
            assertThat(awaitVerdict(verify(adapter)))
                    .as("the miss denied only the absent kid — a cached kid still Allows")
                    .isEqualTo(new Verdict.Allow());
        } finally {
            refreshGate.countDown();   // ALWAYS release the held handler (exception-safe cleanup)
            server.stop(0);
        }
    }

    @Test
    @DisplayName("kid present but signature by a DIFFERENT key → DenyIndeterminate (unverifiable, not invalid)")
    void wrongSignerYieldsDenyIndeterminate(@TempDir Path dir) throws Exception {
        HttpsServer server = jwtIdP(key("forger"), new JOSEObjectType("JWT"), key("t4-key"));
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            awaitCachePopulated(adapter);
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a 200 overruled by failed local signature verification → DenyIndeterminate (DENY wins)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("claim failures: wrong iss / wrong aud / missing exp / expired exp / future nbf → DenyIndeterminate")
    void claimFailuresYieldDenyIndeterminate(@TempDir Path dir) throws Exception {
        RSAKey key = key("t4-key");
        AtomicReference<Consumer<JWTClaimsSet.Builder>> servedSpec = new AtomicReference<>(b -> { });
        HttpsServer server = standInIdP(
                ex -> {
                    drain(ex);
                    respond(ex, 200, tokenBody(jwt(key, "t4-key", new JOSEObjectType("JWT"), servedSpec.get())));
                },
                null,
                jwksHandler(key));
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            awaitCachePopulated(adapter);
            String iss = base(server);   // the base is known only now — the handler serves the spec
            servedSpec.set(b -> validClaims(b, iss).issuer("https://evil-issuer.example"));
            assertThat(awaitVerdict(verify(adapter))).as("issuer mismatch").isInstanceOf(Verdict.DenyIndeterminate.class);

            servedSpec.set(b -> validClaims(b, iss).audience("wrong-audience"));
            assertThat(awaitVerdict(verify(adapter))).as("audience mismatch").isInstanceOf(Verdict.DenyIndeterminate.class);

            servedSpec.set(b -> b.issuer(iss).audience("smpp-client-confidential"));   // no exp claim at all
            assertThat(awaitVerdict(verify(adapter))).as("missing exp").isInstanceOf(Verdict.DenyIndeterminate.class);

            servedSpec.set(b -> validClaims(b, iss).expirationTime(Date.from(Instant.now().minusSeconds(600))));
            assertThat(awaitVerdict(verify(adapter))).as("expired (past the 60s skew)").isInstanceOf(Verdict.DenyIndeterminate.class);

            servedSpec.set(b -> validClaims(b, iss).notBeforeTime(Date.from(Instant.now().plusSeconds(600))));
            assertThat(awaitVerdict(verify(adapter))).as("nbf in the future (past the 60s skew)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("200 + three-segment-but-malformed token → DenyIndeterminate; opaque token → DenyIndeterminate (T5 boundary)")
    void malformedAndOpaqueTokensYieldDenyIndeterminate(@TempDir Path dir) throws Exception {
        AtomicInteger rotation = new AtomicInteger();
        HttpsServer server = standInIdP(
                ex -> {
                    drain(ex);
                    // "aaa.bbb.ccc" IS three segments but does not parse as a JWS; the opaque token is
                    // zero-segment — the introspection arm's (T5, not yet landed) territory.
                    respond(ex, 200, tokenBody(rotation.getAndIncrement() == 0 ? "aaa.bbb.ccc" : "opaque-secret-token"));
                },
                null,
                null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a malformed JWT is unverifiable → DenyIndeterminate (AC2)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat(awaitVerdict(verify(adapter)))
                    .as("an opaque token cannot be locally verified — fail-closed until T5 lands")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("cold cache: the bind denies against an EMPTY cache without waiting for the JWKS fetch")
    void coldCacheDeniesWithoutWaitingForJwks(@TempDir Path dir) throws Exception {
        RSAKey key = key("t4-key");
        CountDownLatch jwksGate = new CountDownLatch(1);
        HttpsServer server = standInIdP(
                ex -> {
                    drain(ex);
                    respond(ex, 200, tokenBody(jwt(key, "t4-key", new JOSEObjectType("JWT"),
                            b -> validClaims(b, issuerOf(ex)))));
                },
                null,
                ex -> {
                    try {
                        jwksGate.await();   // the JWKS endpoint NEVER answers until released
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                    respond(ex, 200, jwksBody(key));
                });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server, Duration.ofSeconds(4), 8,
                Duration.ofMillis(200)))) {   // short TTL — the periodic refresh recovers the cold cache
            // The initial refresh is gated: the cache is cold, and the bind must STILL settle fast —
            // the bind path verifies against the CACHED set only (AC3: no foreground fetch, ever).
            long start = System.nanoTime();
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a cold cache is unverifiable → fail-closed, no wire wait on the bind path")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat((System.nanoTime() - start) / 1_000_000)
                    .as("the bind did not block on the held JWKS fetch")
                    .isLessThan(2_000L);
        } finally {
            jwksGate.countDown();   // release the held refresh before the adapter/server go away
            server.stop(0);
        }
        // A fresh adapter against a healthy JWKS endpoint Allows the same token: the cold deny was
        // the cache's STATE, not a verdict (no verdict caching, AD-12).
        HttpsServer recovered = jwtIdP(key, new JOSEObjectType("JWT"), null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, recovered))) {
            awaitCachePopulated(adapter);
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a populated cache flips the same token's verdict to Allow (re-validate every bind)")
                    .isEqualTo(new Verdict.Allow());
        } finally {
            recovered.stop(0);
        }
    }

    @Test
    @DisplayName("bind saturation does not starve the JWKS refresh (§2.1 item 6a — separate schedulers)")
    void bindSaturationDoesNotStarveJwksRefresh(@TempDir Path dir) throws Exception {
        RSAKey key = key("t4-key");
        CountDownLatch requestReceived = new CountDownLatch(1);
        CountDownLatch hold = new CountDownLatch(1);
        AtomicInteger jwksHits = new AtomicInteger();
        HttpsServer server = standInIdP(
                ex -> {
                    try {
                        requestReceived.countDown();
                        drain(ex);
                        hold.await();   // bind #1 parks here, holding the lone admission permit
                        respond(ex, 401, "{}");
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    } catch (IOException ioe) {
                        // best-effort late write after release — not a verdict signal
                    }
                },
                null,
                ex -> {
                    jwksHits.incrementAndGet();
                    respond(ex, 200, jwksBody(key));
                });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server, Duration.ofSeconds(4), 1,
                Duration.ofMillis(150)))) {   // max-in-flight = 1; refresh-ahead every 75ms
            VerdictRequest held = verify(adapter);   // acquires the lone permit and parks
            assertTrue(requestReceived.await(5, TimeUnit.SECONDS), "bind #1 must reach the token endpoint");
            try {
                awaitCondition("≥3 JWKS refreshes while every admission permit is held by binds",
                        () -> jwksHits.get() >= 3);
            } finally {
                hold.countDown();   // ALWAYS release (exception-safe cleanup)
            }
            awaitVerdict(held);   // drain the pool task before close
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("per-request timeout → DenyIndeterminate (a timed-out exchange is not a credential verdict)")
    void requestTimeoutYieldsDenyIndeterminate(@TempDir Path dir) throws Exception {
        CountDownLatch hold = new CountDownLatch(1);
        HttpsServer server = standInIdP(ex -> {
            try {
                drain(ex);
                hold.await();
                respond(ex, 200, "{}");
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } catch (IOException ioe) {
                // best-effort late write after release — not a verdict signal
            }
        }, null);
        try (RopcBindCredentialVerifier adapter =
                adapter(properties(dir, server, Duration.ofMillis(250), 4))) {
            try {
                assertThat(awaitVerdict(verify(adapter)))
                        .as("HttpTimeoutException → fail-closed indeterminate (AC2 timeout row)")
                        .isInstanceOf(Verdict.DenyIndeterminate.class);
            } finally {
                hold.countDown();   // ALWAYS release the stand-in handler (exception-safe cleanup)
            }
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("unreachable token endpoint (connection refused) → DenyIndeterminate")
    void unreachableTokenEndpointYieldsDenyIndeterminate(@TempDir Path dir) throws Exception {
        // The discovery document (provider-controlled) points token_endpoint at a dead port — discovery
        // itself stays well-formed, so the adapter builds; the token exchange then fails at connect.
        HttpsServer server = standInIdP(
                ex -> {
                    drain(ex);
                    respond(ex, 200, "{}");
                },
                "https://localhost:" + RelayTestFixtures.freePort());
        try (RopcBindCredentialVerifier adapter =
                adapter(properties(dir, server, Duration.ofSeconds(1), 4))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("network error → fail-closed indeterminate (AC2)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            server.stop(0);
        }
    }

    // ── AC5: admission, capture, hardening ─────────────────────────────────────────────────────

    @Test
    @DisplayName("saturation: max-in-flight=1 denies a 2nd bind DenyIndeterminate fast, with NO wire call (F2)")
    void saturationDeniesWithoutWireCall(@TempDir Path dir) throws Exception {
        CountDownLatch requestReceived = new CountDownLatch(1);
        CountDownLatch hold = new CountDownLatch(1);
        AtomicInteger tokenHits = new AtomicInteger();
        HttpsServer server = standInIdP(ex -> {
            tokenHits.incrementAndGet();
            try {
                requestReceived.countDown();
                drain(ex);
                hold.await();
                respond(ex, 401, "{}");
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } catch (IOException ioe) {
                // best-effort late write after release — not a verdict signal
            }
        }, null);
        try (RopcBindCredentialVerifier adapter =
                adapter(properties(dir, server, Duration.ofSeconds(4), 1))) {   // max-in-flight = 1
            VerdictRequest first = verify(adapter);   // acquires the lone permit, blocks at hold
            assertTrue(requestReceived.await(5, TimeUnit.SECONDS), "verify#1 must reach the token endpoint");

            // try/finally so hold is ALWAYS released — a stranded handler thread hangs the test JVM
            try {
                long start = System.nanoTime();
                Verdict second = awaitVerdict(verify(adapter));   // permit exhausted → fail-closed deny
                long elapsedMs = (System.nanoTime() - start) / 1_000_000;

                assertThat(second).as("a saturated pool denies DenyIndeterminate (AD-28(4)/AD-11)")
                        .isInstanceOf(Verdict.DenyIndeterminate.class);
                assertThat(elapsedMs).as("saturation must DENY without starting work").isLessThan(1_000L);
                // F2 RED-on-neuter: if sendAsync fired before tryAcquire, the denied bind would hit the
                // handler and transmit the password-bearing form to the IdP → tokenHits == 2.
                assertThat(tokenHits.get())
                        .as("a saturated bind must not transmit the ROPC form (F2 ordering)")
                        .isEqualTo(1);
            } finally {
                hold.countDown();
            }
            awaitVerdict(first);   // DenyInvalid after release — drain the pool task before close
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("an exhausted adjudication deadline denies without a wire call (the context budget, AC5)")
    void deadlineExhaustedDeniesWithoutWireCall(@TempDir Path dir) throws Exception {
        AtomicInteger tokenHits = new AtomicInteger();
        HttpsServer server = standInIdP(ex -> {
            tokenHits.incrementAndGet();
            drain(ex);
            respond(ex, 401, "{}");
        }, null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            VerdictRequest request = verify(adapter, cred(), Instant.now().minusSeconds(1));
            assertThat(awaitVerdict(request))
                    .as("the adjudication deadline is the verifier's whole budget (RequestContext) — "
                            + "an expired one denies without a wire call")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat(tokenHits.get()).as("no wire call may start past the deadline").isEqualTo(0);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("an unbound ScopedValue handle fails CLOSED (settled deny, no throw, no wire call)")
    void unboundContextFailsClosed(@TempDir Path dir) throws Exception {
        AtomicInteger tokenHits = new AtomicInteger();
        HttpsServer server = standInIdP(ex -> {
            tokenHits.incrementAndGet();
            drain(ex);
            respond(ex, 401, "{}");
        }, null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            // Deliberately NOT wrapped in ScopedValue.where — the relay always binds the handle for the
            // dynamic extent of verify() (BindInterceptor); a caller that does not gets a settled
            // fail-closed deny, never an exception out of verify() and never a wire call (AC5 capture rule).
            VerdictRequest request = adapter.verify(cred(), CTX);
            assertThat(awaitVerdict(request))
                    .as("no captured RequestContext → fail-closed (AD-11)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat(tokenHits.get()).as("an adjudication without a captured context must never reach the IdP")
                    .isEqualTo(0);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("a closed adapter settles every verify fail-closed (use-after-close, §2.1 item 2)")
    void closedAdapterSettlesFailClosed(@TempDir Path dir) throws Exception {
        AtomicInteger tokenHits = new AtomicInteger();
        HttpsServer server = standInIdP(ex -> {
            tokenHits.incrementAndGet();
            drain(ex);
            respond(ex, 401, "{}");
        }, null);
        RopcBindCredentialVerifier adapter = adapter(properties(dir, server));
        try {
            adapter.close();
            // The pool/client are shut: each verify must still return a SETTLED fail-closed verdict —
            // never throw out of verify(), never hang, never transmit (and the admission permit is
            // released, so repeated verifies keep settling rather than saturating forever).
            assertThat(awaitVerdict(verify(adapter)))
                    .as("use-after-close settles DenyIndeterminate (fail-closed)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat(awaitVerdict(verify(adapter)))
                    .as("the closed-state deny is repeatable (no permit leak strands later verifies)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat(tokenHits.get()).isEqualTo(0);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("the ROPC form is percent-encoded from RAW bytes; the file-loaded secret arrives trimmed")
    void formEncodesIdentityAndSecretFromRawBytes(@TempDir Path dir) throws Exception {
        StringBuilder captured = new StringBuilder();
        HttpsServer server = standInIdP(ex -> {
            captured.append(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respond(ex, 401, "{}");   // any settling verdict — the form is what this test asserts
        }, null);
        // Secret file WITH the conventional trailing newline — the trimmed value, not the raw file
        // content, must reach the wire (the '&' pins the boundary: a %0A would sit before it).
        Path store = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        Path secret = Files.writeString(dir.resolve("oidc-client-secret"), "smpp-confidential-secret\n");
        try (RopcBindCredentialVerifier adapter = adapter(reverseBProperties(store, secret, base(server),
                Duration.ofSeconds(4), 8, Duration.ofMinutes(5)))) {
            // Reserved-octet identity and password prove the encoder percent-encodes from the raw bytes
            // (space → %20, '@' → %40, '+' → %2B) — a toString/URLEncoder route would render differently.
            BindCredential credential = new BindCredential(
                    new SystemId(new AsciiString("test user")), new Password(new AsciiString("p@ss+w")));
            awaitVerdict(verify(adapter, credential, Instant.now().plusSeconds(15)));
            String form = captured.toString();
            assertThat(form).as("the grant type and client id arrive verbatim")
                    .contains("grant_type=password")
                    .contains("client_id=smpp-client-confidential");
            assertThat(form).as("the username is percent-encoded from its raw bytes")
                    .contains("username=test%20user");
            assertThat(form).as("the password is percent-encoded from its raw bytes (F1)")
                    .contains("password=p%40ss%2Bw");
            assertThat(form).as("the client secret arrives trimmed — no %0A between value and '&'")
                    .contains("client_secret=smpp-confidential-secret&");
        } finally {
            server.stop(0);
        }
    }

    // ── constructor fail-fast (the T2 bean pattern: a bad config refuses construction) ────────

    @Test
    @DisplayName("constructor fail-fast: max-in-flight < 1, missing secret file, blank secret file")
    void constructorFailsFastOnBadConfig(@TempDir Path dir) throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 401, "{}");
        }, null);
        try {
            Path store = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
            Path secret = Files.writeString(dir.resolve("oidc-client-secret"), "smpp-confidential-secret");

            // maxInFlight < 1 — direct construction bypasses the @Min(1) annotation; without this guard
            // Semaphore(0) is valid and EVERY bind silently denies (fail-closed but broken).
            assertThatThrownBy(() -> adapter(reverseBProperties(store, secret, base(server),
                    Duration.ofSeconds(4), 0, Duration.ofMinutes(5))))
                    .as("the typed admission-capacity guard (AD-28(4))")
                    .isInstanceOf(IllegalArgumentException.class);

            // Missing client-secret file — AD-18: read at bean init, fail-closed refuse. The assertion
            // pins the NOT-READABLE arm specifically (not just the shared refusal substrings) so the
            // two guard arms cannot mask each other under mutation.
            assertThatThrownBy(() -> adapter(reverseBProperties(store, dir.resolve("missing"), base(server),
                    Duration.ofSeconds(4), 8, Duration.ofMinutes(5))))
                    .as("a missing client-secret file refuses startup")
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("client-secret-path")
                    .hasMessageContaining("does not exist or is not readable")
                    .hasMessageContaining("refusing to start");

            // Blank/whitespace secret file — an empty credential is a misconfiguration, not a secret.
            Path blank = Files.writeString(dir.resolve("blank-secret"), " \n");
            assertThatThrownBy(() -> adapter(reverseBProperties(store, blank, base(server),
                    Duration.ofSeconds(4), 8, Duration.ofMinutes(5))))
                    .as("a blank client-secret file refuses startup")
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("client-secret-path")
                    .hasMessageContaining("empty")
                    .hasMessageContaining("refusing to start");
        } finally {
            server.stop(0);
        }
    }

    // ── fixtures ──────────────────────────────────────────────────────────────────────────────

    /**
     * Drives the port the way the relay does: the context bound via {@link ScopedValue} for the
     * dynamic extent of the call, with the given absolute adjudication deadline.
     */
    private static VerdictRequest verify(RopcBindCredentialVerifier adapter, BindCredential credential,
            Instant deadline) {
        RequestContext rc = new RequestContext(
                credential.systemId(), DefaultChannelId.newInstance(), deadline);
        return ScopedValue.where(CTX, rc).call(() -> adapter.verify(credential, CTX));
    }

    private static VerdictRequest verify(RopcBindCredentialVerifier adapter) {
        return verify(adapter, cred(), Instant.now().plusSeconds(15));
    }

    private static BindCredential cred() {
        return new BindCredential(
                new SystemId(new AsciiString("testuser")), new Password(new AsciiString("testpass")));
    }

    private static Verdict awaitVerdict(VerdictRequest request) throws Exception {
        return request.future().get(15, TimeUnit.SECONDS);
    }

    /** The adapter exactly as the T7 wiring constructs it: real factory + real discovery over TLS. */
    private static RopcBindCredentialVerifier adapter(ProxyCompanionProperties properties) {
        IdpSslContextFactory tlsFactory = new IdpSslContextFactory(properties);
        return new RopcBindCredentialVerifier(tlsFactory, new OidcStartupDiscovery(properties, tlsFactory));
    }

    private static ProxyCompanionProperties properties(Path dir, HttpsServer server) throws IOException {
        return properties(dir, server, Duration.ofSeconds(4), 8);
    }

    private static ProxyCompanionProperties properties(Path dir, HttpsServer server, Duration timeout,
            int maxInFlight) throws IOException {
        return properties(dir, server, timeout, maxInFlight, Duration.ofMinutes(5));
    }

    private static ProxyCompanionProperties properties(Path dir, HttpsServer server, Duration timeout,
            int maxInFlight, Duration jwksCacheTtl) throws IOException {
        Path store = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        Path secret = Files.writeString(dir.resolve("oidc-client-secret"), "smpp-confidential-secret");
        return reverseBProperties(store, secret, base(server), timeout, maxInFlight, jwksCacheTtl);
    }

    /** A reverse&times;B properties record (full AD-34 TLS lists, yml-template oidc budgets). */
    private static ProxyCompanionProperties reverseBProperties(Path idpStore, Path secretPath,
            String providerUrl, Duration timeout, int maxInFlight, Duration jwksCacheTtl) {
        return new ProxyCompanionProperties(
                new ProxyCompanionProperties.Bind(2775, RelayTestFixtures.DEFAULT_ADJUDICATION_DEADLINE),
                new ProxyCompanionProperties.Memory(1, 1, 1.0, ProxyCompanionProperties.Memory.BudgetCheck.FAIL),
                new ProxyCompanionProperties.Tls(
                        List.of("TLSv1.3", "TLSv1.2"),
                        List.of("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
                        List.of("TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256")),
                null,
                new ProxyCompanionProperties.Reverse(null, new ProxyCompanionProperties.ReverseModeB(
                        new ProxyCompanionProperties.Smsc("smsc.example", 2775), true,
                        new ProxyCompanionProperties.Oidc(
                                URI.create(providerUrl), "smpp-client-confidential", secretPath.toString(),
                                new ProxyCompanionProperties.TrustStore(idpStore.toString(),
                                        RelayTestFixtures.IDP_STORE_PASSWORD),
                                timeout, maxInFlight, jwksCacheTtl)), null));
    }

    /**
     * An ad-hoc stand-in IdP: {@code /.well-known/openid-configuration} echoing its own base as issuer
     * (the AC7 equality check) with the Keycloak realm endpoint layout, and {@code tokenEndpointBase}
     * (default: own base) controlling where the discovered {@code token_endpoint} points — a dead-port
     * base yields an unreachable token endpoint with a well-formed discovery document. The optional
     * {@code jwksHandler} serves the discovered {@code jwks_uri} (the T4 refresh target). The CALLER
     * owns {@code stop(0)} — always in a {@code finally}.
     */
    private static HttpsServer standInIdP(HttpHandler tokenHandler, String tokenEndpointBase)
            throws IOException {
        return standInIdP(tokenHandler, tokenEndpointBase, null);
    }

    private static HttpsServer standInIdP(HttpHandler tokenHandler, String tokenEndpointBase,
            @Nullable HttpHandler jwksHandler) throws IOException {
        HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(OidcDiscoveryStandIn.fixtureServerSslContext()));
        // A real pool, not the default single dispatcher thread: several tests park ONE handler on a
        // latch while OTHER contexts must keep serving (the JWKS refresh during a held bind, the
        // token call during a gated refresh) — with the default executor the parked handler starves
        // them all. Daemon threads so a parked handler can never hold the test JVM open (stop(0)
        // does not shut an explicit executor down); latches are still released in finally regardless.
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(8, r -> {
            Thread t = new Thread(r, "stand-in-idp");
            t.setDaemon(true);
            return t;
        }));
        server.createContext(DISCOVERY_PATH, exchange -> {
            String tokenBase = tokenEndpointBase == null ? base(server) : tokenEndpointBase;
            byte[] document = ("{\"issuer\": \"" + base(server) + "\", \"token_endpoint\": \""
                    + tokenBase + TOKEN_PATH + "\", \"introspection_endpoint\": \"" + tokenBase
                    + REALM_PATH + "/token/introspect\", \"jwks_uri\": \"" + tokenBase + REALM_PATH
                    + "/certs\", \"grant_types_supported\": [\"password\"]}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, document.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(document);
            }
        });
        server.createContext(TOKEN_PATH, tokenHandler);
        if (jwksHandler != null) {
            server.createContext(JWKS_PATH, jwksHandler);
        }
        server.start();
        return server;
    }

    // ── AC3 fixtures: forged JWTs + the stand-in JWKS endpoint ─────────────────────────────────

    /** A fresh 2048-bit RSA signing key with the given {@code kid} (the forged-token workhorse). */
    private static RSAKey key(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        } catch (Exception e) {
            throw new IllegalStateException("could not generate RSA key", e);
        }
    }

    /**
     * A stand-in IdP that issues a VALID, properly-signed JWT (kid = the signing key's own) whose
     * claims carry the serving server's issuer, against a JWKS endpoint serving {@code jwksKey}'s
     * public half (default: the signing key's — pass a different key to forge a wrong signature).
     */
    private static HttpsServer jwtIdP(RSAKey signingKey, @Nullable JOSEObjectType typ,
            @Nullable RSAKey jwksKey) throws IOException {
        return standInIdP(
                ex -> {
                    drain(ex);
                    respond(ex, 200, tokenBody(jwt(signingKey, signingKey.getKeyID(), typ,
                            b -> validClaims(b, issuerOf(ex)))));
                },
                null,
                jwksHandler(jwksKey == null ? signingKey : jwksKey));
    }

    /** Serves {@code key}'s public half as the JWKS document (what a real provider publishes). */
    private static HttpHandler jwksHandler(RSAKey key) {
        return ex -> {
            drain(ex);
            respond(ex, 200, jwksBody(key));
        };
    }

    private static String jwksBody(RSAKey key) {
        return JSONObjectUtils.toJSONString(new JWKSet(List.of(key.toPublicJWK())).toJSONObject(true));
    }

    /**
     * The issuer a handler's OWN server echoes — resolved from the exchange at request time, so
     * lambdas never capture the not-yet-assigned {@code server} local (self-reference initializer).
     */
    private static String issuerOf(HttpExchange ex) {
        return "https://localhost:" + ex.getLocalAddress().getPort();
    }

    /** Signs a JWT (kid + optional typ header) carrying exactly the claims {@code spec} adds. */
    private static String jwt(RSAKey key, String kid, @Nullable JOSEObjectType typ,
            Consumer<JWTClaimsSet.Builder> spec) {
        try {
            JWTClaimsSet.Builder b = new JWTClaimsSet.Builder();
            spec.accept(b);
            JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid);
            if (typ != null) {
                header.type(typ);
            }
            SignedJWT jwt = new SignedJWT(header.build(), b.build());
            jwt.sign(new RSASSASigner(key.toPrivateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("could not forge the JWT", e);
        }
    }

    /** The valid claim set every deny row perturbs: correct issuer + audience + a non-expired exp. */
    private static JWTClaimsSet.Builder validClaims(JWTClaimsSet.Builder b, String issuer) {
        return b.issuer(issuer)
                .audience("smpp-client-confidential")
                .expirationTime(Date.from(Instant.now().plusSeconds(300)));
    }

    /** A 200 token-endpoint body carrying the given access token. */
    private static String tokenBody(String accessToken) {
        return "{\"access_token\":\"" + accessToken + "\",\"token_type\":\"Bearer\",\"expires_in\":300}";
    }

    /** Polls until the adapter's background initial JWKS refresh has landed (the bind-ready gate). */
    private static void awaitCachePopulated(RopcBindCredentialVerifier adapter) {
        awaitCondition("the adapter's initial JWKS refresh", () -> adapter.jwksCache().current() != null);
    }

    /** Polls {@code condition} every 10ms up to 5s — background refreshes land on their own scheduler. */
    private static void awaitCondition(String what, java.util.function.BooleanSupplier condition) {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) {
                return;
            }
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted while awaiting " + what, e);
            }
        }
        throw new IllegalStateException("timed out awaiting " + what);
    }

    private static String base(HttpsServer server) {
        return "https://localhost:" + server.getAddress().getPort();
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static void drain(HttpExchange exchange) throws IOException {
        exchange.getRequestBody().readAllBytes();
    }
}
