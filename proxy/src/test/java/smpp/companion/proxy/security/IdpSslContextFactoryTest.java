package smpp.companion.proxy.security;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.jspecify.annotations.Nullable;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Story 3.2 T2 (AC7) — the IdP client {@code SSLContext} factory at the unit level (direct
 * construction, no Spring). Every REVERSE cell's {@code oidc} node drives a JDK-only SSLContext from
 * the dedicated IdP trust store at the full AD-13 depth &mdash; the 5-state PKIX load the T1
 * amendment-2 validator deliberately deferred here (a bad store refuses startup at bean init,
 * fail-closed) &mdash; and the AD-34 intersection of {@code companion.tls.*} with THIS context's
 * supported suites/protocols refuses on empty (decision D2's discharge for the IdP context; the
 * bind-time validator only checks the JDK-default context). Forward cells carry no oidc node (AD-12
 * amended 2026-08-18 &mdash; the reverse role adjudicates): the factory must stay INACTIVE there,
 * never refusing a forward boot. The RFC 8705 client-keystore arm is gone (removed pre-release
 * 2026-08-19) &mdash; {@code client_secret} is the sole provider client auth, so the factory builds a
 * trust-only context (client auth rides the ROPC form, T3).
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
class IdpSslContextFactoryTest {

    /**
     * The application.yml AD-34 pin (CompanionTlsBindingTest pins these exact values from a real
     * boot); restated because direct construction bypasses yml.
     */
    private static final List<String> TLS12 = List.of(
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    private static final List<String> TLS13 = List.of(
            "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256");

    // --- active cells ----------------------------------------------------------------------

    @Test
    @DisplayName("reverse×B: the fixture-CA IdP trust store builds an active context + AD-34-intersected parameters")
    void reverseBCellBuildsActiveContextFromFixtureCaStore(@TempDir Path dir) {
        Path idpStore = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        IdpSslContextFactory factory = new IdpSslContextFactory(
                reverseB(idpStore, RelayTestFixtures.IDP_STORE_PASSWORD, "https://localhost:8443/realms/x"));

        assertThat(factory.active()).as("a reverse cell must build the IdP SSLContext at bean init").isTrue();
        assertThat(factory.resolvedOidc()).isNotNull();
        assertThat(factory.resolvedOidc().keyPrefix())
                .as("the resolved key prefix names the branch the refusal messages cite")
                .isEqualTo("companion.reverse.mode-b");
        assertThat(factory.sslContext()).isNotNull();
        // The effective suites are the AD-34 intersection: on the pinned JDK 25 every configured
        // suite is supported by the context, so the intersection is the full configured set (a JDK
        // dropping one of these suites must refuse loudly here, not silently narrow the link).
        assertThat(factory.sslParameters().getCipherSuites())
                .containsExactlyInAnyOrder(
                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                        "TLS_AES_256_GCM_SHA384",
                        "TLS_AES_128_GCM_SHA256",
                        "TLS_CHACHA20_POLY1305_SHA256");
        assertThat(factory.sslParameters().getProtocols())
                .as("the effective protocols are the configured ones that this context supports")
                .containsExactly("TLSv1.3", "TLSv1.2");
    }

    @Test
    @DisplayName("reverse×A also builds the IdP context (every reverse cell adjudicates — AD-12 amended)")
    void reverseACellAlsoBuildsActiveContext(@TempDir Path dir) {
        Path idpStore = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        IdpSslContextFactory factory = new IdpSslContextFactory(reverseA(idpStore));
        assertThat(factory.active()).as("reverse×A carries the oidc node — the factory must be active").isTrue();
        assertThat(factory.resolvedOidc().keyPrefix()).isEqualTo("companion.reverse.mode-a");
    }

    @Test
    @DisplayName("reverse×C also builds the IdP context (every reverse cell adjudicates — AD-12 amended)")
    void reverseCCellAlsoBuildsActiveContext(@TempDir Path dir) {
        Path idpStore = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        IdpSslContextFactory factory = new IdpSslContextFactory(reverseC(idpStore));
        assertThat(factory.active()).as("reverse×C carries the oidc node — the factory must be active").isTrue();
        assertThat(factory.resolvedOidc().keyPrefix()).isEqualTo("companion.reverse.mode-c");
    }

    @Test
    @DisplayName("forward×A carries no oidc node — the factory stays inactive and never refuses a forward boot")
    void forwardCellLeavesFactoryInactive() {
        IdpSslContextFactory factory = new IdpSslContextFactory(forwardA());
        assertThat(factory.active()).as("forward cells carry no oidc node (AD-12 amended 2026-08-18)").isFalse();
        assertThat(factory.resolvedOidc()).isNull();
        assertThatThrownBy(factory::sslContext)
                .as("the accessors must fail fast on an inactive cell, not return null")
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(factory::sslParameters).isInstanceOf(IllegalStateException.class);
    }

    // --- IdP trust-store 5-state (AD-13: never cacerts; the T1-amendment-2 deferred load) --

    @Test
    @DisplayName("AD-13: a wrong trust-store password refuses startup (the exact bad value bound)")
    void wrongTrustStorePasswordRefusesStartup(@TempDir Path dir) {
        Path idpStore = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        assertThatThrownBy(() -> new IdpSslContextFactory(
                reverseB(idpStore, "definitely-the-wrong-password", "https://localhost:8443/realms/x")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("oidc.trust-store")
                .hasMessageContaining("not a valid trust store")
                .hasMessageContaining("SEC-050")
                .hasMessageContaining("refusing to start");
    }

    @Test
    @DisplayName("AD-13: a non-keystore file at the trust-store path refuses startup")
    void garbageTrustStoreFileRefusesStartup(@TempDir Path dir) throws Exception {
        Path garbage = dir.resolve("garbage.p12");
        Files.write(garbage, "this is not a keystore".getBytes(StandardCharsets.UTF_8));
        assertThatThrownBy(() -> new IdpSslContextFactory(
                reverseB(garbage, RelayTestFixtures.IDP_STORE_PASSWORD, "https://localhost:8443/realms/x")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not a valid trust store")
                .hasMessageContaining("SEC-050");
    }

    @Test
    @DisplayName("AD-13: a zero-trustedCertEntry store refuses startup (an anchor-less store would trust nothing, fail-closed)")
    void zeroTrustedCertEntryStoreRefusesStartup(@TempDir Path dir) throws Exception {
        Path empty = zeroEntryStore(dir.resolve("empty.p12"));
        assertThatThrownBy(() -> new IdpSslContextFactory(
                reverseB(empty, RelayTestFixtures.IDP_STORE_PASSWORD, "https://localhost:8443/realms/x")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("zero trustedCertEntry")
                .hasMessageContaining("AD-13");
    }

    @Test
    @DisplayName("SEC-050: a missing trust-store file refuses startup (defense-in-depth for direct construction)")
    void missingTrustStoreFileRefusesStartup(@TempDir Path dir) {
        Path absent = dir.resolve("absent.p12");
        assertThatThrownBy(() -> new IdpSslContextFactory(
                reverseB(absent, RelayTestFixtures.IDP_STORE_PASSWORD, "https://localhost:8443/realms/x")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("does not exist")
                .hasMessageContaining("SEC-050");
    }

    @Test
    @DisplayName("SEC-050: a zero-byte trust-store file refuses startup")
    void emptyTrustStoreFileRefusesStartup(@TempDir Path dir) throws Exception {
        Path empty = Files.createFile(dir.resolve("empty.p12"));
        assertThatThrownBy(() -> new IdpSslContextFactory(
                reverseB(empty, RelayTestFixtures.IDP_STORE_PASSWORD, "https://localhost:8443/realms/x")))
                .isInstanceOf(IllegalStateException.class)
                // Arm-specific (a Story 3.2 T10 mutation-pass finding): the bare "empty" substring is
                // satisfied by the FILENAME (empty.p12) inside the shared load-catch message, so a
                // neutered zero-byte guard stayed green via the wrong arm — the shared-substring
                // masking trap, rediscovered by the consolidated pass.
                .hasMessageContaining("is empty (zero bytes)")
                .hasMessageContaining("SEC-050");
    }

    // --- AD-34 intersection (decision D2 discharge FOR THE IdP CONTEXT) --------------------

    @Test
    @DisplayName("AD-34: cipher suites with an empty intersection vs THIS context's supported suites refuse startup")
    void emptyCipherIntersectionRefusesStartup(@TempDir Path dir) {
        Path idpStore = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        ProxyCompanionProperties bogusSuites = properties(
                List.of("TLSv1.3", "TLSv1.2"), List.of("TLS_FAKE_BOGUS_SUITE"), List.of("TLS_FAKE_BOGUS13"),
                new ProxyCompanionProperties.Reverse(null, new ProxyCompanionProperties.ReverseModeB(
                        new ProxyCompanionProperties.Smsc("smsc.example", 2775), true,
                        oidc(idpStore, RelayTestFixtures.IDP_STORE_PASSWORD, "https://localhost:8443/realms/x")),
                        null));
        assertThatThrownBy(() -> new IdpSslContextFactory(bogusSuites))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("intersection")
                .hasMessageContaining("AD-34");
    }

    @Test
    @DisplayName("AD-34: protocols with an empty intersection vs THIS context's supported protocols refuse startup")
    void emptyProtocolIntersectionRefusesStartup(@TempDir Path dir) {
        Path idpStore = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        ProxyCompanionProperties bogusProtocols = properties(
                List.of("TLSv9.99"), TLS12, TLS13,
                new ProxyCompanionProperties.Reverse(null, new ProxyCompanionProperties.ReverseModeB(
                        new ProxyCompanionProperties.Smsc("smsc.example", 2775), true,
                        oidc(idpStore, RelayTestFixtures.IDP_STORE_PASSWORD, "https://localhost:8443/realms/x")),
                        null));
        assertThatThrownBy(() -> new IdpSslContextFactory(bogusProtocols))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("protocol")
                .hasMessageContaining("AD-34");
    }

    // --- fixtures ----------------------------------------------------------------------------

    /** A reverse×B properties record with the given IdP trust store + full AD-34 TLS lists. */
    private static ProxyCompanionProperties reverseB(Path idpStore, String idpStorePassword, String providerUrl) {
        return properties(List.of("TLSv1.3", "TLSv1.2"), TLS12, TLS13,
                new ProxyCompanionProperties.Reverse(null, new ProxyCompanionProperties.ReverseModeB(
                        new ProxyCompanionProperties.Smsc("smsc.example", 2775), true,
                        oidc(idpStore, idpStorePassword, providerUrl)), null));
    }

    private static ProxyCompanionProperties reverseA(Path idpStore) {
        return properties(List.of("TLSv1.3", "TLSv1.2"), TLS12, TLS13,
                new ProxyCompanionProperties.Reverse(new ProxyCompanionProperties.ReverseModeA(
                        new ProxyCompanionProperties.Smsc("smsc.example", 2775),
                        new ProxyCompanionProperties.ServerCert("/run/secrets/reverse-server.crt", "/run/secrets/reverse-server.key"),
                        oidc(idpStore, RelayTestFixtures.IDP_STORE_PASSWORD, "https://localhost:8443/realms/x")),
                        null, null));
    }

    private static ProxyCompanionProperties reverseC(Path idpStore) {
        return properties(List.of("TLSv1.3", "TLSv1.2"), TLS12, TLS13,
                new ProxyCompanionProperties.Reverse(null, null, new ProxyCompanionProperties.ReverseModeC(
                        new ProxyCompanionProperties.Smsc("smsc.example", 2775),
                        new ProxyCompanionProperties.ServerCert("/run/secrets/reverse-server.crt", "/run/secrets/reverse-server.key"),
                        new ProxyCompanionProperties.TrustStore("/run/secrets/truststore.p12", "changeit"),
                        oidc(idpStore, RelayTestFixtures.IDP_STORE_PASSWORD, "https://localhost:8443/realms/x"))));
    }

    private static ProxyCompanionProperties forwardA() {
        ProxyCompanionProperties.Forward forward = new ProxyCompanionProperties.Forward(
                new ProxyCompanionProperties.ForwardModeA(
                        new ProxyCompanionProperties.TrustStore("/run/secrets/truststore.p12", "changeit"),
                        List.of(new ProxyCompanionProperties.RoutingEntry("carrierOne", "reverse.internal", 2776, null))),
                null, null);
        return properties(List.of("TLSv1.3", "TLSv1.2"), TLS12, TLS13, forward, null);
    }

    /** Forward/reverse asymmetric: exactly one branch is non-null (AD-17 single-branch by construction). */
    private static ProxyCompanionProperties properties(List<String> protocols, List<String> tls12, List<String> tls13,
                                                       ProxyCompanionProperties.@Nullable Forward forward,
                                                       ProxyCompanionProperties.@Nullable Reverse reverse) {
        return new ProxyCompanionProperties(
                new ProxyCompanionProperties.Bind(2775, "127.0.0.1", RelayTestFixtures.DEFAULT_ADJUDICATION_DEADLINE),
                new ProxyCompanionProperties.Memory(1, 1, 1.0, ProxyCompanionProperties.Memory.BudgetCheck.FAIL),
                new ProxyCompanionProperties.Tls(protocols, tls12, tls13),
                forward,
                reverse,
                null,
                new ProxyCompanionProperties.Shutdown(RelayTestFixtures.DEFAULT_DRAIN_TIMEOUT));
    }

    private static ProxyCompanionProperties properties(List<String> protocols, List<String> tls12, List<String> tls13,
                                                       ProxyCompanionProperties.@Nullable Reverse reverse) {
        return properties(protocols, tls12, tls13, null, reverse);
    }

    /** The oidc node (yml-template budget defaults) over the given IdP trust store. */
    private static ProxyCompanionProperties.Oidc oidc(Path idpStore, String password, String providerUrl) {
        return new ProxyCompanionProperties.Oidc(
                java.net.URI.create(providerUrl), "smpp-client-confidential", "/run/secrets/oidc-client-secret",
                new ProxyCompanionProperties.TrustStore(idpStore.toString(), password),
                Duration.ofSeconds(4), 64);
    }

    /** A valid PKCS12 with ZERO entries — the SEC-050 zero-{@code trustedCertEntry} state. */
    private static Path zeroEntryStore(Path file) throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, RelayTestFixtures.IDP_STORE_PASSWORD.toCharArray());
        try (OutputStream out = Files.newOutputStream(file)) {
            ks.store(out, RelayTestFixtures.IDP_STORE_PASSWORD.toCharArray());
        }
        return file;
    }
}
