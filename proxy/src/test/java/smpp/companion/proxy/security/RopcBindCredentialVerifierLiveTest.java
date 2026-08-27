package smpp.companion.proxy.security;

import io.netty.channel.DefaultChannelId;
import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

/**
 * Story 3.2 T9 (AC9) — the <b>production</b> adapter driven through the real AD-12 port against
 * the pinned Keycloak &ge;26.7.0 fixture, in the amended <b>2-path</b> shape (the RFC 8705 mTLS
 * path was removed pre-release, 2026-08-19 — {@code client_secret} is the sole provider client
 * auth, {@link RopcSliceLiveTest} path 3 keeps the historical ratification; the RFC 7662
 * introspection interop leg was removed by Story 3.4 T1, 2026-08-27 — JWT-only adjudication,
 * the unit suite's D6 pin owns the non-JWT deny): (1) JWT happy path &rarr; {@code Allow} —
 * fully live: startup discovery &rarr; trust-only TLS &rarr; ROPC &rarr; live JWKS fetch &rarr;
 * local Nimbus defense-in-depth; (2) bad credentials &rarr; {@code DenyInvalid} both ways the
 * fixture exhibits them (400 {@code invalid_grant}, 401 {@code invalid_client}).
 *
 * <p>Each test constructs the adapter exactly as the T7 wiring does
 * ({@code new RopcBindCredentialVerifier(new IdpSslContextFactory(props),
 * new OidcStartupDiscovery(props, factory))}) — the container is
 * {@link TrustOnlyKeycloakContainer}, the fixture variant whose server-auth-only TLS matches the
 * production link (the 2.1 {@code KeycloakContainer} demands peer certs, which a trust-only
 * client cannot present).
 *
 * <p>Docker-gated ({@code @Testcontainers(disabledWithoutDocker = true)}): runs and bites
 * whenever Docker is present, skips cleanly without it; {@link RopcSliceLiveTest} and the other
 * {@code RopcSlice*} suites stay green unchanged (the reference slice keeps its own container).
 */
@Tag("integration")
@Tag("security")
@Tag("p1")
@Testcontainers(disabledWithoutDocker = true)
@DisplayName("AD-12 production RopcBindCredentialVerifier — live Keycloak ≥26.7.0 (2-path, amended)")
class RopcBindCredentialVerifierLiveTest {

    /** The pinned fixture in the production trust-only TLS posture (see its class javadoc). */
    @Container
    static final TrustOnlyKeycloakContainer KEYCLOAK = new TrustOnlyKeycloakContainer();

    /** The {@link RequestContext} handle the adapter re-binds on its pool thread (AD-5). */
    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

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
}
