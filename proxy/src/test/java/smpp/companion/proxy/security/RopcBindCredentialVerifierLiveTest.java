package smpp.companion.proxy.security;

import com.nimbusds.jose.util.JSONObjectUtils;
import io.netty.channel.DefaultChannelId;
import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.testsupport.OidcDiscoveryStandIn;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

/**
 * Story 3.2 T9 (AC9) — the <b>production</b> adapter driven through the real AD-12 port against
 * the pinned Keycloak &ge;26.7.0 fixture, in the amended <b>3-path</b> shape (the RFC 8705 mTLS
 * path was removed pre-release, 2026-08-19 — {@code client_secret} is the sole provider client
 * auth; {@link RopcSliceLiveTest} path 3 keeps the historical ratification): (1) JWT happy path
 * &rarr; {@code Allow} — fully live: startup discovery &rarr; trust-only TLS &rarr; ROPC &rarr;
 * live JWKS fetch &rarr; local Nimbus defense-in-depth; (2) RFC 7662 introspection interop —
 * round&nbsp;2 against the <b>live</b> introspection endpoint; (3) bad credentials &rarr;
 * {@code DenyInvalid} both ways the fixture exhibits them (400 {@code invalid_grant}, 401
 * {@code invalid_client}).
 *
 * <p>Each test constructs the adapter exactly as the T7 wiring does
 * ({@code new RopcBindCredentialVerifier(new IdpSslContextFactory(props),
 * new OidcStartupDiscovery(props, factory))}) — the container is
 * {@link TrustOnlyKeycloakContainer}, the fixture variant whose server-auth-only TLS matches the
 * production link (the 2.1 {@code KeycloakContainer} demands peer certs, which a trust-only
 * client cannot present).
 *
 * <p><b>Path 2 honest scope (structural, recorded rather than worked around):</b> an
 * introspection <i>Allow</i> cannot be driven through the production adapter against a live
 * Keycloak — Keycloak's token endpoint only ever issues JWTs, the adapter dispatches a
 * three-segment token to local {@code verifyJwt} (AC3/AC4's structural dispatch), and Keycloak's
 * introspection answers {@code active:true} only for a real, valid token: the Allow row is
 * therefore unreachable without faking one side or the other. The test-tier {@link RopcSlice}
 * forced introspection by a config flag (its path 2 ratified the client-side wire shape live);
 * the production adapter has — and should have — no such flag. Coverage of the Allow row stays
 * where it already lives: the T5 unit suite (10 tests, in-process stand-ins incl. the
 * never-cached flip), plus this class's <b>live interop row</b>: round&nbsp;1 through a stand-in
 * discovery/token endpoint issuing an opaque token, round&nbsp;2 fired by the production adapter
 * at the <b>real</b> Keycloak RFC 7662 endpoint with real {@code client_secret} Basic auth —
 * with a direct same-shape control call proving KC answers {@code 200 + active:false} for
 * exactly that token, so the asserted {@code DenyIndeterminate} is the truthful
 * {@code active:false} mapping, not a 401/5xx.
 *
 * <p>Docker-gated ({@code @Testcontainers(disabledWithoutDocker = true)}): runs and bites
 * whenever Docker is present, skips cleanly without it; {@link RopcSliceLiveTest} and the other
 * {@code RopcSlice*} suites stay green unchanged (the reference slice keeps its own container).
 */
@Tag("integration")
@Tag("security")
@Tag("p1")
@Testcontainers(disabledWithoutDocker = true)
@DisplayName("AD-12 production RopcBindCredentialVerifier — live Keycloak ≥26.7.0 (3-path, amended)")
class RopcBindCredentialVerifierLiveTest {

    /** The pinned fixture in the production trust-only TLS posture (see its class javadoc). */
    @Container
    static final TrustOnlyKeycloakContainer KEYCLOAK = new TrustOnlyKeycloakContainer();

    /** The {@link RequestContext} handle the adapter re-binds on its pool thread (AD-5). */
    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    /** The direct-control client: same trust-only posture the adapter's link uses. */
    private static final HttpClient CONTROL_HTTP = HttpClient.newBuilder()
            .sslContext(TrustOnlyKeycloakContainer.trustOnlySslContext())
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";
    private static final String REALM_PATH = "/realms/smpp-companions/protocol/openid-connect";
    private static final String TOKEN_PATH = REALM_PATH + "/token";

    /** The live realm's RFC 7662 endpoint — REALM_BASE already carries the realm path. */
    private static final String LIVE_INTROSPECTION =
            TrustOnlyKeycloakContainer.REALM_BASE + "/protocol/openid-connect/token/introspect";

    /**
     * The opaque round-1 token of the introspection interop path — dot-free on purpose (a
     * non-three-segment token is what dispatches to the RFC 7662 arm) and exactly the value the
     * direct control introspects, so the control's {@code active:false} answer is known to be
     * for the token the adapter sends.
     */
    private static final String OPAQUE_TOKEN = "kc-live-introspection-interop-opaque-probe";

    /** Written per test: the correct secret, or the wrong one for the 401 row. */
    @TempDir
    static Path DIR;

    @Test
    @DisplayName("path 1 — valid ROPC → 200 + JWT → cached-JWKS defense-in-depth → Allow (fully live)")
    void path1_jwtHappyPathYieldsAllow() throws Exception {
        ProxyCompanionProperties properties = properties("smpp-confidential-secret");
        try (RopcBindCredentialVerifier adapter = adapter(properties)) {
            awaitCachePopulated(adapter);   // the live JWKS initial refresh, before the bind
            Verdict verdict = awaitVerdict(
                    verify(adapter, cred(KeycloakFixture.TEST_USER, KeycloakFixture.TEST_PASS)));
            assertThat(verdict).isEqualTo(new Verdict.Allow());
        }
    }

    @Test
    @DisplayName("path 2 — live RFC 7662 interop: adapter round 2 at real KC → truthful active:false → DenyIndeterminate")
    void path2_introspectionLiveInteropYieldsDenyIndeterminateOnRealActiveFalse() throws Exception {
        StandInIdP standIn = standInOpaqueIdP();
        try {
            // Control FIRST (a fail-here beats a misleading pass below): KC's introspection endpoint,
            // the same Basic client auth the adapter sends, the same opaque token → 200 + active:false.
            assertKcIntrospectionAnswersActiveFalse(OPAQUE_TOKEN);

            ProxyCompanionProperties properties = properties(standIn.base(), "smpp-confidential-secret");
            try (RopcBindCredentialVerifier adapter = adapter(properties)) {
                Verdict verdict = awaitVerdict(
                        verify(adapter, cred(KeycloakFixture.TEST_USER, KeycloakFixture.TEST_PASS)));
                assertThat(verdict).isInstanceOf(Verdict.DenyIndeterminate.class);
                assertThat(standIn.tokenHits()).hasValue(1);   // round 1 went through the stand-in
            }
        } finally {
            standIn.server().stop(0);   // exception-safe teardown — a stranded server hangs the JVM
        }
    }

    @Test
    @DisplayName("path 3a — invalid user password → 400 invalid_grant → DenyInvalid (fixture finding #6)")
    void path3a_invalidUserPasswordYieldsDenyInvalid() throws Exception {
        ProxyCompanionProperties properties = properties("smpp-confidential-secret");
        try (RopcBindCredentialVerifier adapter = adapter(properties)) {
            Verdict verdict = awaitVerdict(verify(adapter, cred(KeycloakFixture.TEST_USER, "WRONGPW")));
            assertThat(verdict).isInstanceOf(Verdict.DenyInvalid.class);
        }
    }

    @Test
    @DisplayName("path 3b — invalid client secret → 401 invalid_client → DenyInvalid (fixture finding #6)")
    void path3b_invalidClientSecretYieldsDenyInvalid() throws Exception {
        ProxyCompanionProperties properties = properties("WRONG-SECRET");
        try (RopcBindCredentialVerifier adapter = adapter(properties)) {
            Verdict verdict = awaitVerdict(
                    verify(adapter, cred(KeycloakFixture.TEST_USER, KeycloakFixture.TEST_PASS)));
            assertThat(verdict).isInstanceOf(Verdict.DenyInvalid.class);
        }
    }

    // ── helpers ────────────────────────────────────────────────────────────────────────────────

    /** The adapter exactly as the T7 wiring constructs it: real factory + real discovery over TLS. */
    private static RopcBindCredentialVerifier adapter(ProxyCompanionProperties properties) {
        IdpSslContextFactory tlsFactory = new IdpSslContextFactory(properties);
        return new RopcBindCredentialVerifier(tlsFactory, new OidcStartupDiscovery(properties, tlsFactory));
    }

    /** The live-KC variant: provider-url is the container's fixed realm base. */
    private static ProxyCompanionProperties properties(String clientSecret) throws IOException {
        return properties(TrustOnlyKeycloakContainer.REALM_BASE, clientSecret);
    }

    /**
     * A reverse&times;B properties record pointing at {@code providerUrl} with client A's fixture
     * credentials: the fixture CA trust store (AD-13 anchor), a real secret file carrying
     * {@code clientSecret}, and the yml-template oidc budgets. Same shape as the unit suite's
     * direct-construction fixture — one home there, mirrored here for the live provider URL.
     */
    private static ProxyCompanionProperties properties(String providerUrl, String clientSecret)
            throws IOException {
        Path store = RelayTestFixtures.idpTrustStoreFixture(DIR.resolve("idp-truststore.p12"));
        Path secret = Files.writeString(DIR.resolve("oidc-client-secret"), clientSecret);
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
                                URI.create(providerUrl), KeycloakFixture.CLIENT_A_ID, secret.toString(),
                                new ProxyCompanionProperties.TrustStore(store.toString(),
                                        RelayTestFixtures.IDP_STORE_PASSWORD),
                                Duration.ofSeconds(4), 8, Duration.ofMinutes(5))), null));
    }

    /** Verifies via the port, binding the context in a scope (models real relay usage). */
    private static VerdictRequest verify(RopcBindCredentialVerifier adapter, BindCredential credential) {
        RequestContext rc = new RequestContext(
                credential.systemId(), DefaultChannelId.newInstance(), Instant.now().plusSeconds(15));
        return ScopedValue.where(CTX, rc).call(() -> adapter.verify(credential, CTX));
    }

    private static BindCredential cred(String user, String pass) {
        return new BindCredential(new SystemId(new AsciiString(user)), new Password(new AsciiString(pass)));
    }

    private static Verdict awaitVerdict(VerdictRequest request) throws Exception {
        return request.future().get(20, TimeUnit.SECONDS);
    }

    /** Polls the adapter's initial live JWKS refresh (every 10ms up to 10s — Docker-leg slack). */
    private static void awaitCachePopulated(RopcBindCredentialVerifier adapter) {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (System.nanoTime() < deadline) {
            if (adapter.jwksCache().current() != null) {
                return;
            }
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted awaiting the live JWKS refresh", e);
            }
        }
        throw new IllegalStateException("the adapter's initial JWKS refresh did not land within 10s");
    }

    /**
     * The direct control of path 2: introspect {@code token} at the LIVE Keycloak endpoint with
     * client A's Basic auth (the same header the adapter assembles from the secret file) and
     * assert {@code 200 + active:false} — KC accepted the client and truthfully reports the
     * opaque token as inactive, which is what turns the adapter's verdict into the
     * {@code active:false} row (a 401/5xx would deny identically; the control distinguishes).
     */
    private static void assertKcIntrospectionAnswersActiveFalse(String token) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(LIVE_INTROSPECTION))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                        (KeycloakFixture.CLIENT_A_ID + ":" + KeycloakFixture.CLIENT_A_SECRET)
                                .getBytes(StandardCharsets.US_ASCII)))
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString("token=" + token))
                .build();
        HttpResponse<String> response =
                CONTROL_HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode())
                .as("live KC introspection accepts client A's Basic auth (401 would mean otherwise)")
                .isEqualTo(200);
        assertThat(JSONObjectUtils.getBoolean(JSONObjectUtils.parse(response.body()), "active"))
                .as("live KC truthfully reports the opaque probe token inactive")
                .isFalse();
    }

    /**
     * The path-2 stand-in: serves the discovery document (issuer = its own base — the AC7
     * equality check — with the introspection endpoint pointing at the LIVE Keycloak) and a
     * token endpoint that issues {@link #OPAQUE_TOKEN}. The adapter's round 2 therefore lands on
     * the real provider while round 1 is stand-in-served (the only leg KC cannot provide — see
     * the class javadoc). Daemon executor: {@code stop(0)} does not stop an explicit executor,
     * so the threads must not be able to hold the JVM open.
     */
    private static StandInIdP standInOpaqueIdP() throws IOException {
        HttpsServer server = HttpsServer.create(
                new InetSocketAddress("localhost", RelayTestFixtures.freePort()), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(OidcDiscoveryStandIn.fixtureServerSslContext()));
        server.setExecutor(Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "t9-stand-in-idp");
            t.setDaemon(true);
            return t;
        }));
        String base = "https://localhost:" + server.getAddress().getPort();
        AtomicInteger tokenHits = new AtomicInteger();
        server.createContext(DISCOVERY_PATH, exchange -> {
            byte[] document = ("{\"issuer\": \"" + base + "\", \"token_endpoint\": \"" + base + TOKEN_PATH
                    + "\", \"introspection_endpoint\": \"" + LIVE_INTROSPECTION
                    + "\", \"jwks_uri\": \"" + base + REALM_PATH + "/certs"
                    + "\", \"grant_types_supported\": [\"password\"]}")
                    .getBytes(StandardCharsets.UTF_8);
            respondJson(exchange, 200, document);
        });
        server.createContext(TOKEN_PATH, exchange -> {
            tokenHits.incrementAndGet();
            exchange.getRequestBody().readAllBytes();   // drain the ROPC form
            respondJson(exchange, 200, ("{\"access_token\": \"" + OPAQUE_TOKEN + "\", \"token_type\": \"Bearer\"}")
                    .getBytes(StandardCharsets.UTF_8));
        });
        server.start();
        return new StandInIdP(server, base, tokenHits);
    }

    private static void respondJson(com.sun.net.httpserver.HttpExchange exchange, int status, byte[] body)
            throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    /** The path-2 stand-in handles: the server (caller owns {@code stop(0)} in a finally), its
     *  base URL, and the round-1 hit counter. */
    private record StandInIdP(HttpsServer server, String base, AtomicInteger tokenHits) { }
}
