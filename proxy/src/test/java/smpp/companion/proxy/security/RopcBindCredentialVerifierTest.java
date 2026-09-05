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
 * (fixture-cert TLS — the same trust story as the shared provider stand-in; no container, no
 * network beyond loopback). The adapter is constructed exactly as the wiring constructs it:
 * {@code new RopcBindCredentialVerifier(new IdpSslContextFactory(properties))} — real trust-store
 * load, the token endpoint derived from the provider-url realm base (Story 3.4 T9, 2026-08-29 —
 * no discovery wire call at construction), real shared client.
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
 * ALLOWING key-set handler at the realm's key-set path (the retired discovery doc used to
 * advertise it; the handler itself is what stays load-bearing) — zero hits proves no fetch path
 * exists.
 *
 * <p><b>No startup provider call (Story 3.4 T9, 2026-08-29).</b> The startup discovery probe is
 * REMOVED: the adapter is constructed exactly as the wiring constructs it,
 * {@code new RopcBindCredentialVerifier(new IdpSslContextFactory(properties))} — real trust-store
 * load, the token endpoint DERIVED from the {@code provider-url} realm base (every fixture URL
 * below carries the realm segment so the derived endpoint lands on the served {@code TOKEN_PATH}),
 * real shared client, ZERO wire calls at construction. The fresh T9 pins: the derivation unit pin
 * (incl. trailing-slash), the never-hit startup-probe pin (the stand-in's provider-metadata
 * context records zero hits through the real TLS link), and the starred operator-WARN pin (the
 * retired startup-refusal/DAG-warning posture's loud successor on the connection-error and
 * non-mapped-non-200 arms).
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

    private static final String REALM_SEGMENT = "/realms/smpp-companions";
    private static final String REALM_PATH = REALM_SEGMENT + "/protocol/openid-connect";
    private static final String TOKEN_PATH = REALM_PATH + "/token";
    private static final String JWKS_PATH = REALM_PATH + "/certs";
    private static final String INTROSPECTION_PATH = REALM_PATH + "/token/introspect";

    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    // ── AC2: the token-endpoint status rows (the refined production table) ─────────────────────

    @Test
    @DisplayName("bare 401 (unparseable body) → DenyInvalid — RFC 6749 §5.2 positive auth-layer rejection")
    void bare401YieldsDenyInvalid(@TempDir Path dir, CapturedOutput out) throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 401, "not-json-at-all");
        });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a bare 401 IS the provider's positive invalid-credential signal (AC2)")
                    .isInstanceOf(Verdict.DenyInvalid.class);
            assertThat(out.getAll())
                    .as("a MAPPED arm stays WARN-free — the operator banner belongs to the failure arms "
                            + "alone (arm selectivity, chunk-B review 2026-09-01)")
                    .doesNotContain("OIDC TOKEN CALL FAILED")
                    .doesNotContain("the token endpoint returned HTTP");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("400 invalid_grant (bad USER credentials) → DenyInvalid")
    void badUser400InvalidGrantYieldsDenyInvalid(@TempDir Path dir, CapturedOutput out) throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 400, "{\"error\":\"invalid_grant\",\"error_description\":\"Invalid user credentials\"}");
        });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("400 + parsed error=invalid_grant is a positive invalid-credential signal (finding #6)")
                    .isInstanceOf(Verdict.DenyInvalid.class);
            assertThat(out.getAll())
                    .as("a MAPPED arm stays WARN-free — the operator banner belongs to the failure arms "
                            + "alone (arm selectivity, chunk-B review 2026-09-01)")
                    .doesNotContain("OIDC TOKEN CALL FAILED")
                    .doesNotContain("the token endpoint returned HTTP");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("400 invalid_client → DenyInvalid (some providers send 400, not 401, for a bad client)")
    void badClient400InvalidClientYieldsDenyInvalid(@TempDir Path dir, CapturedOutput out) throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 400, "{\"error\":\"invalid_client\"}");
        });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("400 + parsed error=invalid_client is a positive invalid-credential signal")
                    .isInstanceOf(Verdict.DenyInvalid.class);
            assertThat(out.getAll())
                    .as("a MAPPED arm stays WARN-free — the operator banner belongs to the failure arms "
                            + "alone (arm selectivity, chunk-B review 2026-09-01)")
                    .doesNotContain("OIDC TOKEN CALL FAILED")
                    .doesNotContain("the token endpoint returned HTTP");
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
        });
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
        });
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
        });
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
        });
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
        });
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
        // response. The key-set endpoint (the retired discovery doc used to advertise it; the
        // handler registration is what stays load-bearing) is registered
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

    @Test
    @DisplayName("the structural gate's segment-count BOUNDARIES: 2- and 4-segment tokens deny fail-closed "
            + "(D6) — only EXACTLY three segments Allows (D7)")
    void segmentCountBoundariesDenyFailClosed(@TempDir Path dir) throws Exception {
        // Chunk-B review 2026-09-01: the D6/D7 rows drove only 0-segment and 3-segment shapes, so a
        // neutered gate (segments < 3 / >= 3 / "more than one dot") stayed green — a 4-segment
        // (JWE-shaped) token would have ALLOWED. Both boundaries bite now, in both tiers (the slice's
        // twin row: RopcSliceFailClosedTest.segmentCountBoundariesDenyFailClosed).
        HttpsServer fourSegment = standInIdP(ex -> {
            drain(ex);
            respond(ex, 200, tokenBody("a.b.c.d"));
        });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, fourSegment))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a 4-segment (JWE-shaped) token is not a three-segment JWS — D6 fail-closed")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            fourSegment.stop(0);
        }
        HttpsServer twoSegment = standInIdP(ex -> {
            drain(ex);
            respond(ex, 200, tokenBody("a.b"));
        });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, twoSegment))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a 2-segment token is not a three-segment JWS — D6 fail-closed")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            twoSegment.stop(0);
        }
    }

    // ── AC4 (amended by Story 3.4 T1/D6, 2026-08-27): JWT-only adjudication — no second wire arm ──

    @Test
    @DisplayName("200 + OPAQUE token → DenyIndeterminate + WARN naming the JWT-only policy, NO wire round 2 (D6)")
    void opaqueTokenDeniesFailClosedWithoutAWireRound2(@TempDir Path dir, CapturedOutput out) throws Exception {
        AtomicInteger introHits = new AtomicInteger();
        // The retired arm's endpoint stays REGISTERED with an ALLOWING handler (200 + active:true —
        // the row that once ALLOWed; the retired discovery doc used to advertise the path, the
        // registration itself is what stays load-bearing): any hit would flip
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
        // Chunk-B review 2026-09-01: the retired 7662 variant asserted introHits == 1 ("the timed-out
        // exchange WAS the introspection round"); without an observable here, a PRE-SEND failure (e.g.
        // a broken deadline clamp aborting before sendAsync) would pass for a mid-exchange timeout.
        AtomicInteger wireHits = new AtomicInteger();
        HttpsServer server = standInIdP(ex -> {
            wireHits.incrementAndGet();   // the exchange reached the wire — entry IS the proof
            try {
                drain(ex);
                hold.await();
                respond(ex, 200, "{}");
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } catch (IOException ioe) {
                // best-effort late write after release — not a verdict signal
            }
        });
        try (RopcBindCredentialVerifier adapter =
                adapter(properties(dir, server, Duration.ofMillis(250), 4))) {
            try {
                assertThat(awaitVerdict(verify(adapter)))
                        .as("HttpTimeoutException → fail-closed indeterminate (AC2 timeout row)")
                        .isInstanceOf(Verdict.DenyIndeterminate.class);
                assertThat(wireHits.get())
                        .as("the timed-out exchange REACHED the wire (chunk-B review 2026-09-01): the "
                                + "deny is a mid-exchange timeout, not a pre-send failure misread as one")
                        .isEqualTo(1);
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
        // T9 (2026-08-29): the endpoint is DERIVED from the provider-url, so a dead-port REALM BASE
        // is the whole fixture — no stand-in server at all (the former variant pointed a discovery
        // document's token_endpoint here; with the probe gone there is no document to serve).
        try (RopcBindCredentialVerifier adapter = adapter(reverseBProperties(idpStore(dir),
                secret(dir), deadRealmBase(), Duration.ofSeconds(1), 4))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("network error → fail-closed indeterminate (AC2)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        }
    }

    // ── T9 (2026-08-29): no startup provider call — derivation + never-hit probe + operator WARN ──

    @Test
    @DisplayName("T9 derivation: token endpoint = provider-url + protocol/openid-connect/token "
            + "(trailing slash normalizes through the config layer)")
    void tokenEndpointDerivesFromTheProviderUrlRealmBase() {
        // The realm base → the pinned-Keycloak realm token path, byte-identical to the live
        // fixture layout the post-T8 slice injects directly (KeycloakFixture.TOKEN_ENDPOINT).
        assertThat(RopcBindCredentialVerifier.deriveTokenEndpoint(URI.create(KeycloakFixture.REALM_BASE)))
                .as("the derivation must land exactly on the fixture container's token endpoint")
                .isEqualTo(KeycloakFixture.TOKEN_ENDPOINT);
        assertThat(RopcBindCredentialVerifier.deriveTokenEndpoint(
                URI.create("https://idp.example.com/realms/smpp-companions")))
                .isEqualTo(URI.create(
                        "https://idp.example.com/realms/smpp-companions/protocol/openid-connect/token"));
        // The trailing-slash behavior re-pointed from the retired discovery row: the Oidc compact
        // ctor strips exactly ONE trailing '/', so the bound record derives the SAME endpoint — and
        // the static itself is slash-tolerant (a base that bypassed the ctor resolves identically:
        // URI.resolve appends after the last '/').
        ProxyCompanionProperties.Oidc bound = new ProxyCompanionProperties.Oidc(
                URI.create("https://idp.example.com/realms/smpp-companions/"),
                "smpp-client-confidential", "/run/secrets/oidc-client-secret",
                new ProxyCompanionProperties.TrustStore("/run/secrets/idp-truststore.p12", "changeit"),
                Duration.ofSeconds(4), 8);
        assertThat(bound.providerUrl().toString())
                .as("the config layer still strips exactly one trailing slash")
                .doesNotEndWith("/");
        assertThat(RopcBindCredentialVerifier.deriveTokenEndpoint(bound.providerUrl()))
                .isEqualTo(URI.create(
                        "https://idp.example.com/realms/smpp-companions/protocol/openid-connect/token"));
        assertThat(RopcBindCredentialVerifier.deriveTokenEndpoint(
                URI.create("https://idp.example.com/realms/smpp-companions/")))
                .as("the raw static is slash-tolerant too (the join never doubles a slash)")
                .isEqualTo(URI.create(
                        "https://idp.example.com/realms/smpp-companions/protocol/openid-connect/token"));
    }

    @Test
    @DisplayName("T9 never-hit pin: NO provider-metadata fetch at construction or first bind — the "
            + "one wire call lands on the DERIVED endpoint through the real TLS link")
    void noStartupProviderCallEverFetchesTheMetadataDocument(@TempDir Path dir) throws Exception {
        // The shared stand-in still serves its provider-metadata context (deliberately re-purposed,
        // not deleted — Story 3.4 T9) behind a hit counter. The provider-url is the stand-in's BASE
        // — deliberately WITHOUT the realm segment, so a re-introduced startup GET of the old
        // probe's exact URL (<issuer>/.well-known/openid-configuration) lands on the counted
        // context and this row goes RED. The derived token endpoint (<base>/protocol/openid-connect/
        // token) is UNREGISTERED on the stand-in: its 404 → the fail-closed verdict below proves,
        // through the real TLS link, that the one call the adapter makes lands on the derived URI —
        // a call to the metadata path instead would have moved the hit counter and failed the
        // assertions around it.
        int hitsBefore = OidcDiscoveryStandIn.discoveryHits();
        try (RopcBindCredentialVerifier adapter = adapter(reverseBProperties(idpStore(dir),
                secret(dir), OidcDiscoveryStandIn.url(), Duration.ofSeconds(4), 8))) {
            assertThat(OidcDiscoveryStandIn.discoveryHits())
                    .as("constructing the adapter must make NO provider wire call (the probe is gone)")
                    .isEqualTo(hitsBefore);
            assertThat(awaitVerdict(verify(adapter)))
                    .as("the 404 off the derived (unregistered) path denies fail-closed (AC2)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat(OidcDiscoveryStandIn.discoveryHits())
                    .as("a full adjudication must not fetch the provider-metadata document either")
                    .isEqualTo(hitsBefore);
        }
    }

    @Test
    @DisplayName("test-infra smoke (positive control): the never-hit pin's hit counter actually counts — "
            + "two real GETs of the metadata context move discoveryHits() by exactly two")
    void discoveryHitCounterSmoke() throws Exception {
        // Chunk-B review 2026-09-01, the CapturingRelayObserverTest idiom: the fake's observable is
        // proof-tested itself. The never-hit pin asserts before/after EQUALITY, so a stand-in refactor
        // that breaks the counting would disarm it silently — this row is the counter's positive
        // control. (The pin is order-independent: only its DELTAS are load-bearing, so a non-zero
        // JVM-wide counter from this row does not disturb it.)
        int before = OidcDiscoveryStandIn.discoveryHits();
        HttpClient client = KeycloakFixture.newHttpClient();
        for (int i = 0; i < 2; i++) {
            HttpResponse<String> response = client.send(
                    HttpRequest.newBuilder(
                                    URI.create(OidcDiscoveryStandIn.url() + "/.well-known/openid-configuration"))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).as("the stand-in serves the metadata context over TLS").isEqualTo(200);
        }
        assertThat(OidcDiscoveryStandIn.discoveryHits())
                .as("the counter counts — two GETs, two hits (the never-hit pin's observable)")
                .isEqualTo(before + 2);
    }

    @Test
    @DisplayName("T9 operator WARN: connection-error + non-mapped-non-200 arms log the starred banner "
            + "naming the derived endpoint and provider-url (the retired startup posture's successor)")
    void providerFailureArmsLogTheStarredOperatorWarning(@TempDir Path dir, CapturedOutput out)
            throws Exception {
        // Arm 1 — connection error (the typo'd/dead provider-url case the retired startup refusal
        // used to catch at boot). The retired DAG row's log-capture idiom re-homes HERE (T9).
        try (RopcBindCredentialVerifier adapter = adapter(reverseBProperties(idpStore(dir),
                secret(dir), deadRealmBase(), Duration.ofSeconds(1), 4))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("the connection-error arm denies fail-closed via the UNCHANGED AC2 mapping")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        }
        assertThat(out.getAll())
                .as("the starred operator WARN names the failure, the derived endpoint, the "
                        + "provider-url, and the DAG remediation")
                .contains("OIDC TOKEN CALL FAILED")
                .contains("token endpoint: https://localhost:")
                .contains(REALM_SEGMENT + "/protocol/openid-connect/token")
                .contains("provider-url:  https://localhost:")
                .contains("Direct Access Grants");
        // Arm 2 — non-mapped non-200 (the DAG-off flagship: 400 unauthorized_client is Keycloak's
        // answer for a Direct-Access-Grants-disabled client; 401/400-invalid_* stay WARN-free, pinned
        // by the mapped rows' banner-absence asserts — chunk-B review 2026-09-01).
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 400, "{\"error\":\"unauthorized_client\"}");
        });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            assertThat(awaitVerdict(verify(adapter)))
                    .as("400 unauthorized_client stays DenyIndeterminate (AC2 unchanged — log-only)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat(out.getAll())
                    .as("the non-mapped-non-200 arm names the status AND the parsed OAuth error code in "
                            + "the WARN — unauthorized_client IS the DAG-off datum (chunk-A patch, "
                            + "pinned by chunk-B review 2026-09-01)")
                    .contains("the token endpoint returned HTTP 400")
                    .contains("unauthorized_client");
        } finally {
            server.stop(0);
        }
    }

    // ── T5 (Story 4.1 checkpoint 24, 2026-09-03): operator-warning flood bounding ─────────────

    @Test
    @DisplayName("T5 flood bound: a dead provider under N binds logs the starred banner ONCE + one "
            + "one-liner WARN per bind (the 2026-09-01 review's per-bind-flooding row)")
    void deadProviderFloodLogsBannerOnceThenOneLinerPerBind(@TempDir Path dir, CapturedOutput out)
            throws Exception {
        // The flood row: the provider-url points at a probed-free port — every bind denies
        // fail-closed on the connection-error arm, the exact condition a dead or typo'd provider
        // creates. Five binds must produce ONE ~14-line banner (the condition is one: the
        // transport failure class) and one one-liner per LATER bind — per-bind visibility
        // survives the bound, only the banner stops repeating.
        try (RopcBindCredentialVerifier adapter = adapter(reverseBProperties(idpStore(dir),
                secret(dir), deadRealmBase(), Duration.ofSeconds(1), 4))) {
            for (int i = 0; i < 5; i++) {
                assertThat(awaitVerdict(verify(adapter)))
                        .as("every bind denies fail-closed via the UNCHANGED AC2 mapping")
                        .isInstanceOf(Verdict.DenyIndeterminate.class);
            }
        }
        String logged = out.getAll();
        assertThat(occurrences(logged, "OIDC TOKEN CALL FAILED"))
                .as("the starred banner fires exactly once per condition — a dead provider is ONE "
                        + "condition however many binds it denies")
                .isEqualTo(1);
        assertThat(occurrences(logged, "OIDC token call failed again"))
                .as("every LATER bind gets exactly one one-liner WARN (binds 2-5)")
                .isEqualTo(4);
        assertThat(occurrences(logged, "token call failed at the transport layer"))
                .as("the per-occurrence detail covers ALL five binds — the banner's own detail "
                        + "line plus four one-liners")
                .isEqualTo(5);
    }

    @Test
    @DisplayName("T5 flood bound: the non-mapped-status arm — banner once per condition, one-liner "
            + "per repeat; a SECOND condition earns its own banner (no cross-condition silencing)")
    void statusArmFloodIsBoundedPerCondition(@TempDir Path dir, CapturedOutput out) throws Exception {
        // Rotation: three 400 unauthorized_client responses (the DAG-off flagship — ONE
        // condition), then one 404 (a second condition). The bound is per-condition: the banner
        // may not repeat WITHIN a condition, but a NEW failure mode must not be silenced by an
        // old one either — an operator who fixes the dead provider and hits DAG-off next still
        // gets the full remediation banner for the new arm.
        AtomicInteger rotation = new AtomicInteger();
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            if (rotation.getAndIncrement() < 3) {
                respond(ex, 400, "{\"error\":\"unauthorized_client\"}");
            } else {
                respond(ex, 404, "{\"error\":\"misc\"}");
            }
        });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            for (int i = 0; i < 4; i++) {
                assertThat(awaitVerdict(verify(adapter)))
                        .as("both conditions deny fail-closed via the UNCHANGED AC2 mapping")
                        .isInstanceOf(Verdict.DenyIndeterminate.class);
            }
        } finally {
            server.stop(0);
        }
        String logged = out.getAll();
        assertThat(occurrences(logged, "OIDC TOKEN CALL FAILED"))
                .as("one banner per condition: 400-unauthorized_client and 404 are two conditions")
                .isEqualTo(2);
        assertThat(occurrences(logged, "OIDC token call failed again"))
                .as("only the 400 condition repeats (binds 2-3); the 404's single occurrence is "
                        + "its own banner")
                .isEqualTo(2);
        assertThat(occurrences(logged, "the token endpoint returned HTTP 404"))
                .as("the second condition's detail rides its own banner, once")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("T5 flood bound (step-04 review, finding #6): one STATUS is one condition — the same "
            + "400 with two DIFFERENT provider-echoed error strings still earns exactly 1 banner + 1 "
            + "one-liner (the error string rides the detail line, never the condition key)")
    void sameStatusWithDistinctErrorStringsStaysOneCondition(@TempDir Path dir, CapturedOutput out)
            throws Exception {
        // The unbounded-growth vector the old status+error key admitted: a provider echoing
        // DISTINCT error strings on the same status would re-fire the ~14-line banner per bind and
        // grow operatorWarnedConditions without bound. Keying on the status alone keeps one
        // condition per status; each occurrence's detail still names ITS error string.
        AtomicInteger rotation = new AtomicInteger();
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 400, rotation.getAndIncrement() == 0
                    ? "{\"error\":\"unauthorized_client\"}"
                    : "{\"error\":\"expired_token\"}");
        });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            for (int i = 0; i < 2; i++) {
                assertThat(awaitVerdict(verify(adapter)))
                        .as("both occurrences deny fail-closed via the UNCHANGED AC2 mapping")
                        .isInstanceOf(Verdict.DenyIndeterminate.class);
            }
        } finally {
            server.stop(0);
        }
        String logged = out.getAll();
        assertThat(occurrences(logged, "OIDC TOKEN CALL FAILED"))
                .as("the STATUS is the condition — a distinct error echo must not re-fire the banner")
                .isEqualTo(1);
        assertThat(occurrences(logged, "OIDC token call failed again"))
                .as("the second occurrence gets the one-liner")
                .isEqualTo(1);
        assertThat(logged)
                .as("each occurrence's detail still names its own error string (per-bind visibility)")
                .contains("unauthorized_client")
                .contains("expired_token");
    }

    @Test
    @DisplayName("T5: the opaque-token WARN is aligned to the banner pattern — full policy warning "
            + "ONCE (now with provider context), one-liner per repeat")
    void opaqueTokenWarningIsBoundedAndContextualized(@TempDir Path dir, CapturedOutput out)
            throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 200, tokenBody("opaque-secret-token"));
        });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            for (int i = 0; i < 3; i++) {
                assertThat(awaitVerdict(verify(adapter)))
                        .as("an opaque token denies fail-closed on every bind (D6)")
                        .isInstanceOf(Verdict.DenyIndeterminate.class);
            }
        } finally {
            server.stop(0);
        }
        String logged = out.getAll();
        assertThat(occurrences(logged, "configure the client/realm to issue JWT access tokens"))
                .as("the full policy + remediation warning fires ONCE (the opaque arm's own bound)")
                .isEqualTo(1);
        assertThat(occurrences(logged, "opaque) access token again"))
                .as("the two later binds get the one-liner, not a full-policy repeat")
                .isEqualTo(2);
        assertThat(occurrences(logged, "non-JWT (opaque) access token"))
                .as("every occurrence names the token shape (full warning + two one-liners)")
                .isEqualTo(3);
        // The 2026-09-01 review's multi-cell context gap: both the full warning and the
        // one-liner must identify WHICH provider issued the opaque token.
        assertThat(logged)
                .contains("token endpoint: https://localhost:")
                .contains(REALM_SEGMENT + "/protocol/openid-connect/token")
                .contains("provider-url: https://localhost:");
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
        });
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
        });
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
        });
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
        });
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
    @DisplayName("deny window: a post-deny verify() denies fail-closed with NO wire call (F2, 4.2 review)")
    void denyWindowVerifyDeniesWithoutWireCall(@TempDir Path dir) throws Exception {
        CountDownLatch secondToken = new CountDownLatch(1);
        AtomicInteger tokenHits = new AtomicInteger();
        HttpsServer server = standInIdP(ex -> {
            if (tokenHits.incrementAndGet() > 1) {
                secondToken.countDown();   // any request after the warm-up IS the leak
            }
            drain(ex);
            respond(ex, 401, "{}");
        });
        try (RopcBindCredentialVerifier adapter = adapter(properties(dir, server))) {
            // WARM the shared client first (one completed exchange, pooled keep-alive) so the quiet
            // window below observes the ADVERSARIAL case: a live connection the leak could ride.
            awaitVerdict(verify(adapter));
            assertThat(tokenHits.get()).as("the warm-up exchange reached the IdP").isOne();

            adapter.deny();   // the deny window opens: pool down, client STILL open until release()
            assertThat(awaitVerdict(verify(adapter)))
                    .as("a deny-window verify settles DenyIndeterminate (AD-11)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            // F2's deny-window arm, as a QUIET WINDOW: the post-deny verify settles with NO wire
            // call — nothing else reaches the IdP for the rest of the row. Bite disclosure (4.2
            // review mutation pass): a NEUTERED guard is NOT caught here — its fired-then-cancelled
            // exchange is aborted before transmission (empirically, even over a warm connection),
            // so the guard's no-wire-call property has no black-box-observable behavioral delta;
            // this row pins the settle shape and the guarded world's silence, not RED-on-neuter.
            assertThat(secondToken.await(500, TimeUnit.MILLISECONDS))
                    .as("a deny-window bind must not transmit the ROPC form (F2 ordering)")
                    .isFalse();
            assertThat(tokenHits.get()).as("still exactly the warm-up exchange").isOne();
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("unpaired release() self-denies (the 4.2 review pairing guard): never awaits a LIVE pool")
    void unpairedReleaseSelfDeniesAndNeverAwaitsALivePool(@TempDir Path dir) throws Exception {
        HttpsServer server = standInIdP(ex -> {
            drain(ex);
            respond(ex, 401, "{}");
        });
        RopcBindCredentialVerifier adapter = adapter(properties(dir, server, Duration.ofMillis(500), 8));
        try {
            long start = System.nanoTime();
            adapter.release();   // deliberately NO prior deny() — the pairing guard must supply it
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            // Neutered (no self-deny): the await burns the full budget + 1s = 1.5s on the LIVE pool;
            // with the guard the deny shuts the (empty) pool down and the await joins instantly.
            assertThat(elapsedMs)
                    .as("an unpaired release must not wait out the drain budget on a live pool")
                    .isLessThan(1_000L);
            assertThat(awaitVerdict(verify(adapter)))
                    .as("the self-deny left the adapter fail-closed")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
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
        });
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
        });
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
        });
        // Secret file WITH the conventional trailing newline — the trimmed value, not the raw file
        // content, must reach the wire (the '&' pins the boundary: a %0A would sit before it).
        Path store = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        Path secret = Files.writeString(dir.resolve("oidc-client-secret"), "smpp-confidential-secret\n");
        try (RopcBindCredentialVerifier adapter = adapter(reverseBProperties(store, secret, realmBase(server),
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
        });
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
        });
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
        // T9: no stand-in server — construction makes NO provider wire call anymore, so a dead-port
        // realm base is a perfectly valid provider-url for this row.
        Path store = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        Path secret = Files.writeString(dir.resolve("oidc-client-secret"), "smpp-confidential-secret");
        String realmBase = deadRealmBase();

        // maxInFlight < 1 — direct construction bypasses the @Min(1) annotation; without this guard
        // Semaphore(0) is valid and EVERY bind silently denies (fail-closed but broken).
        assertThatThrownBy(() -> adapter(reverseBProperties(store, secret, realmBase,
                Duration.ofSeconds(4), 0)))
                .as("the typed admission-capacity guard (AD-28(4))")
                .isInstanceOf(IllegalArgumentException.class);

        // Missing client-secret file — AD-18: read at bean init, fail-closed refuse. The assertion
        // pins the NOT-READABLE arm specifically (not just the shared refusal substrings) so the
        // two guard arms cannot mask each other under mutation.
        assertThatThrownBy(() -> adapter(reverseBProperties(store, dir.resolve("missing"), realmBase,
                Duration.ofSeconds(4), 8)))
                .as("a missing client-secret file refuses startup")
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("client-secret-path")
                .hasMessageContaining("does not exist or is not readable")
                .hasMessageContaining("refusing to start");

        // Blank/whitespace secret file — an empty credential is a misconfiguration, not a secret.
        Path blank = Files.writeString(dir.resolve("blank-secret"), " \n");
        assertThatThrownBy(() -> adapter(reverseBProperties(store, blank, realmBase,
                Duration.ofSeconds(4), 8)))
                .as("a blank client-secret file refuses startup")
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("client-secret-path")
                .hasMessageContaining("empty")
                .hasMessageContaining("refusing to start");
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

    /** The adapter exactly as the wiring constructs it: real factory, derived token endpoint (T9). */
    private static RopcBindCredentialVerifier adapter(ProxyCompanionProperties properties) {
        return new RopcBindCredentialVerifier(new IdpSslContextFactory(properties));
    }

    private static ProxyCompanionProperties properties(Path dir, HttpsServer server) throws IOException {
        return properties(dir, server, Duration.ofSeconds(4), 8);
    }

    private static ProxyCompanionProperties properties(Path dir, HttpsServer server, Duration timeout,
            int maxInFlight) throws IOException {
        return reverseBProperties(idpStore(dir), secret(dir), realmBase(server), timeout, maxInFlight);
    }

    private static Path idpStore(Path dir) throws IOException {
        return RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
    }

    private static Path secret(Path dir) throws IOException {
        return Files.writeString(dir.resolve("oidc-client-secret"), "smpp-confidential-secret");
    }

    /** A probed-free-port realm base — the unreachable-provider-url fixture (T9). */
    private static String deadRealmBase() {
        return "https://localhost:" + RelayTestFixtures.freePort() + REALM_SEGMENT;
    }

    /**
     * The provider-url these fixtures use: the stand-in's base + the realm segment — since T9 the
     * DERIVED token endpoint ({@code realmBase + protocol/openid-connect/token}) must land exactly
     * on the served {@code TOKEN_PATH}.
     */
    private static String realmBase(HttpsServer server) {
        return base(server) + REALM_SEGMENT;
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
                                timeout, maxInFlight)), null),
                null);
    }

    /**
     * An ad-hoc stand-in IdP serving the realm's TOKEN path (the path the DERIVED token endpoint
     * lands on when {@code provider-url} carries the realm segment — Story 3.4 T9, 2026-08-29). The
     * former discovery context is gone with the probe: nothing fetches it, and the never-hit
     * startup-probe pin lives on the SHARED stand-in ({@code OidcDiscoveryStandIn.discoveryHits()}).
     * The optional {@code keySetHandler} and {@code introHandler} serve the two RETIRED realm
     * paths — {@code /certs} (removed with local JWT verification, Story 3.4 T2) and
     * {@code /token/introspect} (removed with the opaque-token arm, Story 3.4 T1) — their
     * registration stays load-bearing for the never-hit pins (a reachable, ALLOWING endpoint that
     * must record zero hits). The CALLER owns {@code stop(0)} — always in a {@code finally}.
     */
    private static HttpsServer standInIdP(HttpHandler tokenHandler) throws IOException {
        return standInIdP(tokenHandler, null, null);
    }

    private static HttpsServer standInIdP(HttpHandler tokenHandler, @Nullable HttpHandler keySetHandler,
            @Nullable HttpHandler introHandler) throws IOException {
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
                });
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

    /** Non-overlapping substring count — the T5 bounding rows' observable (banner vs one-liner). */
    private static int occurrences(String haystack, String needle) {
        int count = 0;
        int at = 0;
        while ((at = haystack.indexOf(needle, at)) != -1) {
            count++;
            at += needle.length();
        }
        return count;
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
        return new RopcBindCredentialVerifier(tlsFactory, recording);
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
