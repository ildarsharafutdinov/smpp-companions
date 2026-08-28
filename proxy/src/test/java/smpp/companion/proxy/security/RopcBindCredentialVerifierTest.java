package smpp.companion.proxy.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
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
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.BodySubscriber;
import java.net.http.HttpResponse.PushPromiseHandler;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

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
 * <p><b>AC4 (amended by Story 3.4 T1/D6, 2026-08-27) — JWT-only adjudication.</b> The 3.2-era
 * opaque-token RFC 7662 introspection fallback is REMOVED: a 200 body whose token is not a
 * three-segment JWS is not adjudicable — {@code DenyIndeterminate} plus a WARN naming the policy
 * and the operator remediation, and NO second wire arm exists (the arm's rows — active-rows,
 * request shape, budget clamp, F3 round-2 cancellation, F6, never-cached, path zeroization — were
 * retired with it; the surviving pin below drives a REGISTERED, ALLOWING introspection handler
 * that must never be hit, so the deny is provably the policy arm, not a wire failure).
 *
 * <p><b>AC5 — admission, capture, hardening.</b> Saturation denies WITHOUT a wire call (F2:
 * {@code sendAsync} only after {@code tryAcquire} — asserted by the stand-in's request counter),
 * the context is captured on the caller's thread (an unbound handle fails CLOSED, never throws),
 * an exhausted adjudication deadline denies without a wire call, and a closed adapter
 * (use-after-close, deferred-work &sect;2.1 item 2) settles every verify fail-closed — never
 * hangs, never throws out of {@code verify()}.
 *
 * <p><b>AC3 (amended by Story 3.4 T2/D7, 2026-08-27) — TLS-as-sole-trust-anchor.</b> The 3.2-era
 * local JWT defense-in-depth (signature, {@code typ}/{@code kid}, {@code iss}/{@code aud}/
 * {@code exp}/{@code nbf}, the cached provider key set and its refresh) is REMOVED — the HTTPS
 * client-authenticated provider link is the sole trust anchor, the proxy being the token's only
 * consumer. The surviving gate is STRUCTURAL: a three-segment token allows on the endpoint verdict
 * alone (hostile signature and claims change nothing), and the retired rows (typ absent/unexpected,
 * kid miss, wrong signer, claim failures, cold cache, refresh-scheduler isolation — plus the
 * component-level cache suite) were retired with the arm. The never-hit pins keep a REGISTERED,
 * ALLOWING key-set handler reachable through the advertised discovery URI — zero hits proves no
 * fetch path exists.
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
@ExtendWith(OutputCaptureExtension.class)
@DisplayName("AD-12/AD-11 RopcBindCredentialVerifier — AC2 verdict table + AC4 JWT-only deny + AC5 admission/capture core")
class RopcBindCredentialVerifierTest {

    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";
    private static final String REALM_PATH = "/realms/smpp-companions/protocol/openid-connect";
    private static final String TOKEN_PATH = REALM_PATH + "/token";
    private static final String JWKS_PATH = REALM_PATH + "/certs";
    private static final String INTROSPECTION_PATH = REALM_PATH + "/token/introspect";

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

    // ── AC3 (amended by Story 3.4 T2/D7, 2026-08-27): TLS-as-sole-trust-anchor — the structural gate ──

    @Test
    @DisplayName("200 + three-segment JWT → Allow from the endpoint verdict ALONE (D7): hostile signature + "
            + "claims ignored, ZERO provider-key fetches")
    void jwtVerdictDerivesFromTheEndpointAlone(@TempDir Path dir) throws Exception {
        // The row that replaced the whole 3.2-T4 defense-in-depth matrix: the served token fails
        // EVERY former local check at once — signed by a FORGER key whose kid is advertised nowhere,
        // typ "Bearer" in the header (the former unexpected value), wrong iss, wrong aud, expired
        // exp — and STILL allows, because the verdict is the token endpoint's own HTTPS-authenticated
        // response. The key-set endpoint (reachable via the advertised discovery URI) is registered
        // with a counting, ALLOWING handler: zero hits proves no fetch path exists at all.
        RSAKey forger = key("forger");
        AtomicInteger keySetHits = new AtomicInteger();
        HttpsServer server = standInIdP(
                ex -> {
                    drain(ex);
                    respond(ex, 200, tokenBody(jwt(forger, "cached-nowhere", new JOSEObjectType("Bearer"),
                            b -> b.issuer("https://evil-issuer.example")
                                    .audience("wrong-audience")
                                    .expirationTime(Date.from(Instant.now().minusSeconds(600))))));
                },
                null,
                countingHandler(keySetHits),
                null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a three-segment token allows on the endpoint verdict alone — no signature "
                            + "verification, no claim checks (D7/AC3 amended)")
                    .isEqualTo(new Verdict.Allow());
            assertThat(keySetHits.get())
                    .as("the provider-key endpoint must never be fetched — the whole cache arm is gone")
                    .isEqualTo(0);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("200 + three-segment-but-garbage token → Allow (the structural gate never parses content; "
            + "no wire round 2)")
    void threeSegmentTokenIsNeverLocallyParsed(@TempDir Path dir) throws Exception {
        AtomicInteger introHits = new AtomicInteger();
        HttpsServer server = standInIdP(
                ex -> {
                    drain(ex);
                    // "aaa.bbb.ccc" IS three segments — structurally a JWS. Under D7 the content is
                    // never parsed (the 3.2-era local SignedJWT.parse deny died with verification),
                    // so the endpoint verdict alone decides. The retired arm's endpoint is still
                    // registered and counting — nothing may be sent there (Story 3.4 T1).
                    respond(ex, 200, tokenBody("aaa.bbb.ccc"));
                },
                null,
                null,
                ex -> {
                    introHits.incrementAndGet();
                    drain(ex);
                    respond(ex, 200, "{\"active\":true}");   // would ALLOW — must never be reached
                });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a JWT-SHAPED token is adjudicable on shape alone — the gate counts segments, "
                            + "it never parses (D7/AC3 amended)")
                    .isEqualTo(new Verdict.Allow());
            assertThat(introHits.get())
                    .as("a JWT-SHAPED token never reaches the retired round-2 endpoint (the dispatch boundary)")
                    .isEqualTo(0);
        } finally {
            server.stop(0);
        }
    }

    // ── AC4 (amended by Story 3.4 T1/D6, 2026-08-27): JWT-only adjudication — no second wire arm ──

    @Test
    @DisplayName("200 + OPAQUE token → DenyIndeterminate + WARN naming the JWT-only policy, NO wire round 2 (D6)")
    void opaqueTokenDeniesFailClosedWithoutAWireRound2(@TempDir Path dir, CapturedOutput out) throws Exception {
        AtomicInteger introHits = new AtomicInteger();
        // The retired arm's endpoint stays ADVERTISED (the discovery doc below) and REGISTERED with
        // an ALLOWING handler (200 + active:true — the row that once ALLOWed): any hit would flip
        // this row's meaning, so introHits == 0 proves the deny is the D6 policy arm itself, not a
        // wire failure misread as fail-closed.
        HttpsServer server = opaqueIdP(countingHandler(introHits));
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a non-JWT (opaque) token is not adjudicable under the JWT-only policy (D6/AD-11)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat(introHits.get())
                    .as("the retired RFC 7662 arm must stay retired — a registered, allowing handler "
                            + "is never hit")
                    .isEqualTo(0);
            assertThat(out.getAll())
                    .as("the WARN names the token shape and the JWT-only policy (D6)")
                    .contains("non-JWT (opaque) access token")
                    .contains("JWT-only");
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
    @DisplayName("AC5/F12: a null ScopedValue handle fails FAST (requireNonNull guards the handle itself)")
    void nullContextHandleFailsFast(@TempDir Path dir) throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 401, "{}");
        }, null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            // F12 (a 2-1 review MUST-keep): the HANDLE is a programming artifact, not a verdict input —
            // a null one is a wiring bug and must fail fast with the guard's name, not fall into any
            // fail-closed verdict row (contrast unboundContextFailsClosed: an UNBOUND handle denies).
            assertThatThrownBy(() -> adapter.verify(cred(), null))
                    .isInstanceOf(NullPointerException.class)
                    // EXACT match (a Story 3.2 T10 mutation-pass finding): the JDK's helpful-NPE
                    // message for the unguarded dereference quotes the parameter name
                    // ("...because \"ctx\" is null"), so a substring assertion passes WITHOUT the
                    // guard — only requireNonNull's literal "ctx" message distinguishes the guard
                    // from the JVM diagnostic.
                    .hasMessage("ctx");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("AC6: the bind password's zeroization stays CALLER-OWNED — the adapter never wipes it")
    void passwordZeroizationStaysCallerOwned(@TempDir Path dir) throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 401, "{}");   // the fast bare-401 deny row — one complete wire adjudication
        }, null);
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            Password password = new Password(new AsciiString("testpass"));
            assertThat(awaitVerdict(verify(adapter, new BindCredential(cred().systemId(), password),
                    Instant.now().plusSeconds(15))))
                    .as("the wire row ran to a settled verdict before the wipe assertion")
                    .isInstanceOf(Verdict.DenyInvalid.class);
            // Read the shared backing bytes directly (never toString — F1). If any adapter path wiped
            // the password, every octet would be zero here.
            AsciiString value = password.value();
            boolean allZero = true;
            for (int i = value.arrayOffset(); i < value.arrayOffset() + value.length(); i++) {
                if (value.array()[i] != 0) {
                    allZero = false;
                    break;
                }
            }
            assertThat(allZero)
                    .as("the adapter NEVER zeroizes the caller-owned password (the relay's continuation "
                            + "finally + teardown own the wipe, 2.2 T7) — after a settled adjudication "
                            + "the bytes must still be live")
                    .isFalse();
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
                Duration.ofSeconds(4), 8))) {
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

    // ── AC5/AC6: cancellation + zeroization (T6 — the RecordingHttpClient proofs) ────────────

    @Test
    @DisplayName("cancelHttp() mid-token-exchange: SYNCHRONOUS DenyIndeterminate settlement (F7) + real wire abort + wiped form")
    void cancelHttpSettlesSynchronouslyAbortsTheWireAndWipesTheForm(@TempDir Path dir) throws Exception {
        CountDownLatch tokenReceived = new CountDownLatch(1);
        CountDownLatch hold = new CountDownLatch(1);
        HttpsServer server = standInIdP(ex -> {
            tokenReceived.countDown();
            drain(ex);
            try {
                hold.await(10, TimeUnit.SECONDS);   // park: the token exchange is in-flight at cancel time
                respond(ex, 401, "{}");   // released by the test — bind 2 reads it; the aborted bind 1 never does
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException e) {
                // best-effort late write on the torn connection — not a verdict signal
            }
        }, null);
        try {
            ProxyCompanionProperties props = properties(dir, server, Duration.ofSeconds(4), 1);   // max-in-flight = 1
            RecordingHttpClient recording = recordingClient(props);
            try (RopcBindCredentialVerifier adapter = adapter(props, recording)) {
                VerdictRequest request = verify(adapter);
                assertTrue(tokenReceived.await(5, TimeUnit.SECONDS),
                        "the token exchange must be in-flight when cancelHttp() fires");
                RecordingHttpClient.Exchange token = recording.exchange(TOKEN_PATH);
                assertThat(token.future.isDone())
                        .as("the token exchange must still be in-flight (the cancel is meaningful)")
                        .isFalse();

                request.cancelHttp();

                // F7 (this story's decision): settlement is SYNCHRONOUS with cancelHttp() — the pin is
                // complete the moment the call returns. The guarantee is deliberately DOUBLE-COVERED
                // (cancelHttp completes the pin AND every pool path settles fail-closed), so neutering
                // either single arm is masked by the other — verified during the T6 mutation pass: a
                // drop-the-completion mutation stays green across repeated runs because the pool task's
                // unwind wins the race. This assertion pins the CONTRACT; the bite-able control for
                // the cancel arm is the wire-abort assertions below.
                assertThat(request.future().isDone())
                        .as("cancelHttp() itself settles the future (the F7 guarantee, AC5)")
                        .isTrue();
                assertThat(request.future().getNow(null))
                        .as("the guaranteed post-cancel verdict is fail-closed")
                        .isInstanceOf(Verdict.DenyIndeterminate.class);

                // The REAL wire exchange aborted — cancel(true) reached the JDK's sendAsync future
                // (MinimalFuture → MultiExchange.cancel → connection close). isCancelled() is false by
                // JDK design; a CancellationException anywhere in the cause chain is the abort signal.
                assertThatThrownBy(() -> token.future.get(5, TimeUnit.SECONDS))
                        .as("cancelHttp() must abort the underlying HttpClient exchange, not just the pin")
                        .matches(t -> hasCauseInChain(t, CancellationException.class),
                                "a CancellationException in the cause chain (the JDK wraps the abort)");

                // The adjudication unwound (join threw → scope closed → task finally ran): the form is
                // zeroized, and with max-in-flight=1 the freed permit admits bind 2 to a real verdict.
                awaitCondition("the token form zeroized", () -> allZero(token.requestBody));
                hold.countDown();
                assertThat(awaitVerdict(verify(adapter)))
                        .as("the cancelled adjudication released its permit — bind 2 runs (no saturation)")
                        .isInstanceOf(Verdict.DenyInvalid.class);
            }
        } finally {
            hold.countDown();   // exception-safe: never strand the parked handler thread
            server.stop(0);
        }
    }

    @Test
    @DisplayName("AC6 zeroization on the Allow path: the ROPC form and the access-token response body are wiped")
    void buffersZeroizedOnAllow(@TempDir Path dir) throws Exception {
        HttpsServer server = jwtIdP(key("t6-allow"));
        try {
            ProxyCompanionProperties props = properties(dir, server);
            RecordingHttpClient recording = recordingClient(props);
            try (RopcBindCredentialVerifier adapter = adapter(props, recording)) {
                assertThat(awaitVerdict(verify(adapter)))
                        .as("the JWT happy path allows (precondition)")
                        .isInstanceOf(Verdict.Allow.class);

                RecordingHttpClient.Exchange token = recording.exchange(TOKEN_PATH);
                awaitCondition("the ROPC form zeroized after Allow", () -> allZero(token.requestBody));
                awaitCondition("the access-token response body zeroized",
                        () -> allZero(token.responseBody.get()));
            }
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("AC6 zeroization on a deny row: the password-bearing form is wiped even on DenyInvalid")
    void requestBufferZeroizedOnDenyInvalid(@TempDir Path dir) throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 401, "{}");
        }, null);
        try {
            ProxyCompanionProperties props = properties(dir, server);
            RecordingHttpClient recording = recordingClient(props);
            try (RopcBindCredentialVerifier adapter = adapter(props, recording)) {
                assertThat(awaitVerdict(verify(adapter))).isInstanceOf(Verdict.DenyInvalid.class);
                awaitCondition("the ROPC form zeroized after the deny",
                        () -> allZero(recording.exchange(TOKEN_PATH).requestBody));
            }
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
                    Duration.ofSeconds(4), 0)))
                    .as("the typed admission-capacity guard (AD-28(4))")
                    .isInstanceOf(IllegalArgumentException.class);

            // Missing client-secret file — AD-18: read at bean init, fail-closed refuse. The assertion
            // pins the NOT-READABLE arm specifically (not just the shared refusal substrings) so the
            // two guard arms cannot mask each other under mutation.
            assertThatThrownBy(() -> adapter(reverseBProperties(store, dir.resolve("missing"), base(server),
                    Duration.ofSeconds(4), 8)))
                    .as("a missing client-secret file refuses startup")
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("client-secret-path")
                    .hasMessageContaining("does not exist or is not readable")
                    .hasMessageContaining("refusing to start");

            // Blank/whitespace secret file — an empty credential is a misconfiguration, not a secret.
            Path blank = Files.writeString(dir.resolve("blank-secret"), " \n");
            assertThatThrownBy(() -> adapter(reverseBProperties(store, blank, base(server),
                    Duration.ofSeconds(4), 8)))
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
        Path store = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        Path secret = Files.writeString(dir.resolve("oidc-client-secret"), "smpp-confidential-secret");
        return reverseBProperties(store, secret, base(server), timeout, maxInFlight);
    }

    /** A reverse&times;B properties record (full AD-34 TLS lists, yml-template oidc budgets). */
    private static ProxyCompanionProperties reverseBProperties(Path idpStore, Path secretPath,
            String providerUrl, Duration timeout, int maxInFlight) {
        return new ProxyCompanionProperties(
                new ProxyCompanionProperties.Bind(2775, "127.0.0.1", RelayTestFixtures.DEFAULT_ADJUDICATION_DEADLINE),
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
                                timeout, maxInFlight)), null));
    }

    /**
     * An ad-hoc stand-in IdP: {@code /.well-known/openid-configuration} echoing its own base as issuer
     * (the AC7 equality check) with the Keycloak realm endpoint layout, and {@code tokenEndpointBase}
     * (default: own base) controlling where the discovered {@code token_endpoint} points — a dead-port
     * base yields an unreachable token endpoint with a well-formed discovery document. The optional
     * {@code keySetHandler} and {@code introHandler} serve the two RETIRED discovery fields —
     * {@code jwks_uri} (removed with local JWT verification, Story 3.4 T2) and
     * {@code introspection_endpoint} (removed with the opaque-token arm, Story 3.4 T1) — which the
     * document below still advertises DELIBERATELY: the never-hit pins need a reachable, allowing
     * endpoint, and every boot through this stand-in also proves omission-tolerance is not required
     * (extra fields are ignored, absent fields are accepted). The CALLER owns {@code stop(0)} —
     * always in a {@code finally}.
     */
    private static HttpsServer standInIdP(HttpHandler tokenHandler, String tokenEndpointBase)
            throws IOException {
        return standInIdP(tokenHandler, tokenEndpointBase, null, null);
    }

    private static HttpsServer standInIdP(HttpHandler tokenHandler, String tokenEndpointBase,
            @Nullable HttpHandler keySetHandler, @Nullable HttpHandler introHandler) throws IOException {
        HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(OidcDiscoveryStandIn.fixtureServerSslContext()));
        // A real pool, not the default single dispatcher thread: several tests park ONE handler on a
        // latch while OTHER contexts must keep serving — with the default executor the parked
        // handler starves them all. Daemon threads so a parked handler can never hold the test JVM
        // open (stop(0) does not shut an explicit executor down); latches are still released in
        // finally regardless.
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
        if (keySetHandler != null) {
            server.createContext(JWKS_PATH, keySetHandler);
        }
        if (introHandler != null) {
            server.createContext(INTROSPECTION_PATH, introHandler);
        }
        server.start();
        return server;
    }

    /** A stand-in IdP issuing an OPAQUE access token; {@code introHandler} serves the retired round 2. */
    private static HttpsServer opaqueIdP(HttpHandler introHandler) throws IOException {
        return standInIdP(
                ex -> {
                    drain(ex);
                    respond(ex, 200, tokenBody("opaque-secret-token"));
                },
                null,
                null,
                introHandler);
    }

    /** A counting handler answering {@code status}/{@code body} on every hit (the never-hit pins). */
    private static HttpHandler countingHandler(AtomicInteger hits) {
        return ex -> {
            hits.incrementAndGet();
            drain(ex);
            respond(ex, 200, "{\"keys\":[],\"active\":true}");   // would satisfy either retired arm
        };
    }

    // ── AC3 fixtures: forged JWTs (the token body is what matters now — content is never parsed) ──

    /** A fresh 2048-bit RSA signing key with the given {@code kid} (the forged-token workhorse). */
    private static RSAKey key(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        } catch (Exception e) {
            throw new IllegalStateException("could not generate RSA key", e);
        }
    }

    /**
     * A stand-in IdP that issues a properly-signed JWT (kid = the signing key's own, typ
     * {@code JWT}) whose claims carry the serving server's issuer — a shape-faithful happy-path
     * provider. Since Story 3.4 T2 the adapter never parses the token, but the fixture keeps
     * minting real JWTs so the Allow rows exercise exactly what a pinned Keycloak serves. No
     * key-set endpoint is registered — none may be fetched.
     */
    private static HttpsServer jwtIdP(RSAKey signingKey) throws IOException {
        return standInIdP(
                ex -> {
                    drain(ex);
                    respond(ex, 200, tokenBody(jwt(signingKey, signingKey.getKeyID(),
                            new JOSEObjectType("JWT"), b -> validClaims(b, issuerOf(ex)))));
                },
                null);
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

    /** Polls {@code condition} every 10ms up to 5s — asynchronous effects land on their own threads. */
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

    // ── T6 fixtures: the recording client (the 2-1 RopcSliceCancelTest pattern, production-tier)

    /**
     * Delegates to the real TLS-configured client but records every exchange the adapter fires,
     * with three observables the T6 suites assert on: (a) the adapter's EXACT request-body array —
     * {@link RopcBindCredentialVerifier.FormPublisher} publishes the form buffer itself, zero-copy,
     * so the captured reference is the array the adjudication must wipe; (b) the UNWRAPPED JDK
     * {@code sendAsync} future — {@code cancelHttp()}'s {@code cancel(true)} must reach the real
     * exchange (a {@code CancellationException} in its cause chain is the abort proof); (c) the
     * response {@code byte[]} BY REFERENCE — the handler-wrapping {@code thenApply} passes the
     * same array the adapter's {@code response.body()} returns, i.e. the access-token bytes the
     * wipe must clear. Callers filter recorded exchanges by URI path.
     */
    private static final class RecordingHttpClient extends HttpClient {

        private final HttpClient delegate;
        final List<Exchange> exchanges = new CopyOnWriteArrayList<>();

        RecordingHttpClient(HttpClient delegate) {
            this.delegate = delegate;
        }

        /** The first recorded exchange whose request path matches (the adapter fires one per round). */
        Exchange exchange(String path) {
            return exchanges.stream()
                    .filter(e -> e.uri.getPath().equals(path))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("no recorded exchange for " + path));
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, BodyHandler<T> handler) {
            byte[] body = null;   // null for body-less exchanges (GETs carry no form)
            if (request.bodyPublisher().orElse(null)
                    instanceof RopcBindCredentialVerifier.FormPublisher publisher) {
                body = publisher.buffer();   // the adapter's exact form array, by reference
            }
            Exchange exchange = new Exchange(request.uri(), body);
            BodyHandler<T> recording = responseInfo -> {
                BodySubscriber<T> subscriber = handler.apply(responseInfo);
                return new BodySubscriber<>() {
                    @Override
                    public void onSubscribe(Flow.Subscription subscription) {
                        subscriber.onSubscribe(subscription);
                    }

                    @Override
                    public void onNext(List<ByteBuffer> buffers) {
                        subscriber.onNext(buffers);
                    }

                    @Override
                    public void onError(Throwable throwable) {
                        subscriber.onError(throwable);
                    }

                    @Override
                    public void onComplete() {
                        subscriber.onComplete();
                    }

                    @Override
                    public CompletionStage<T> getBody() {
                        // Same reference the adapter's response.body() returns — the wipe target.
                        return subscriber.getBody().thenApply(received -> {
                            if (received instanceof byte[] bytes) {
                                exchange.responseBody.set(bytes);
                            }
                            return received;
                        });
                    }
                };
            };
            CompletableFuture<HttpResponse<T>> future = delegate.sendAsync(request, recording);
            exchange.future = future;   // unwrapped: cancelHttp()'s cancel(true) reaches MultiExchange
            exchanges.add(exchange);
            return future;
        }

        @Override
        public void close() {
            delegate.close();
        }

        @Override
        public <T> HttpResponse<T> send(HttpRequest request, BodyHandler<T> handler)
                throws IOException, InterruptedException {
            return delegate.send(request, handler);
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(
                HttpRequest request, BodyHandler<T> handler, PushPromiseHandler<T> pushPromiseHandler) {
            return delegate.sendAsync(request, handler, pushPromiseHandler);
        }

        @Override
        public Optional<CookieHandler> cookieHandler() {
            return delegate.cookieHandler();
        }

        @Override
        public Optional<Duration> connectTimeout() {
            return delegate.connectTimeout();
        }

        @Override
        public Redirect followRedirects() {
            return delegate.followRedirects();
        }

        @Override
        public Optional<ProxySelector> proxy() {
            return delegate.proxy();
        }

        @Override
        public SSLContext sslContext() {
            return delegate.sslContext();
        }

        @Override
        public SSLParameters sslParameters() {
            return delegate.sslParameters();
        }

        @Override
        public Optional<Authenticator> authenticator() {
            return delegate.authenticator();
        }

        @Override
        public Version version() {
            return delegate.version();
        }

        @Override
        public Optional<Executor> executor() {
            return delegate.executor();
        }

        /** One recorded adapter exchange: the exact request form, the wire future, the response body. */
        private static final class Exchange {
            final URI uri;
            final byte[] requestBody;   // null for body-less exchanges (GETs carry no form)
            final AtomicReference<byte[]> responseBody = new AtomicReference<>();
            volatile CompletableFuture<?> future;

            Exchange(URI uri, byte[] requestBody) {
                this.uri = uri;
                this.requestBody = requestBody;
            }
        }
    }

    /** A recording client around the factory's own build — the adapter's exact TLS posture. */
    private static RecordingHttpClient recordingClient(ProxyCompanionProperties properties) {
        return new RecordingHttpClient(new IdpSslContextFactory(properties).newClient());
    }

    /** The adapter over a recording client — the T6 seam ({@code verify} behaves identically). */
    private static RopcBindCredentialVerifier adapter(ProxyCompanionProperties properties,
            RecordingHttpClient recording) {
        IdpSslContextFactory tlsFactory = new IdpSslContextFactory(properties);
        return new RopcBindCredentialVerifier(tlsFactory,
                new OidcStartupDiscovery(properties, tlsFactory), recording);
    }

    /** True if every byte is zero (a null buffer is "not wiped yet") — the AD-10(3) wipe state. */
    private static boolean allZero(byte[] buffer) {
        if (buffer == null) {
            return false;
        }
        for (byte b : buffer) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    /** True if {@code type} appears anywhere in {@code t}'s cause chain (the JDK wraps cancel aborts). */
    private static boolean hasCauseInChain(Throwable t, Class<? extends Throwable> type) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (type.isInstance(c)) {
                return true;
            }
        }
        return false;
    }
}
