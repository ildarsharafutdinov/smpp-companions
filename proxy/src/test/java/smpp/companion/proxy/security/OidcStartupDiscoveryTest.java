package smpp.companion.proxy.security;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.function.UnaryOperator;
import java.util.ArrayList;
import java.util.List;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;

import smpp.companion.proxy.ProxyCompanionApplication;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.testsupport.OidcDiscoveryStandIn;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * Story 3.2 T2 (AC7) — the hard-required startup OIDC discovery probe. Every REVERSE cell's adapter
 * link discovers {@code <provider-url>/.well-known/openid-configuration} ONCE at bean init over the
 * real IdP TLS context (the fixture-CA trust store handshakes with the shared T1 stand-in — its
 * server cert chains to that CA); any failure REFUSES startup (fail-closed: a misconfigured
 * provider URL is the common case, and a provider outage blocks binds either way per A-2 — the
 * refusal surfaces as the standard Spring startup failure, proven here by a full-app boot). The
 * discovered {@code issuer} must equal {@code provider-url} (the fixture's deterministic-issuer
 * property); a provider that does not advertise the {@code password} grant gets the LOUD DAG
 * warning and defers to runtime (Keycloak disables Direct Access Grants per client since 26.2).
 * Forward cells carry no oidc node (AD-12 amended 2026-08-18) — the probe stays inactive.
 *
 * <p>Failure-matrix servers are ad-hoc {@link HttpsServer}s reusing the stand-in's fixture-cert
 * context ({@link OidcDiscoveryStandIn#fixtureServerSslContext()}) — test-tier only (SEC-090).
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@ExtendWith(OutputCaptureExtension.class)
class OidcStartupDiscoveryTest {

    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";

    // --- happy path -------------------------------------------------------------------------

    @Test
    @DisplayName("reverse×B: discovery against the T1 stand-in yields the metadata (issuer echoes provider-url)")
    void discoversStandInMetadata(@TempDir Path dir) {
        String standIn = OidcDiscoveryStandIn.url();
        OidcStartupDiscovery discovery = discovery(reverseBProperties(idpStore(dir), standIn));

        assertThat(discovery.active()).as("a reverse cell must run the discovery probe at bean init").isTrue();
        OidcStartupDiscovery.OidcProviderMetadata metadata = discovery.metadata();
        assertThat(metadata.issuer())
                .as("the discovered issuer must be the configured provider-url (AC7 issuer check)")
                .isEqualTo(standIn);
        String realm = standIn + "/realms/smpp-companions/protocol/openid-connect";
        assertThat(metadata.tokenEndpoint()).isEqualTo(URI.create(realm + "/token"));
        assertThat(metadata.introspectionEndpoint()).isEqualTo(URI.create(realm + "/token/introspect"));
        assertThat(metadata.jwksUri()).isEqualTo(URI.create(realm + "/certs"));
    }

    @Test
    @DisplayName("forward×A carries no oidc node — the probe stays inactive and never refuses a forward boot")
    void forwardCellLeavesDiscoveryInactive() {
        OidcStartupDiscovery discovery = discovery(forwardAProperties());
        assertThat(discovery.active()).isFalse();
        assertThatThrownBy(discovery::metadata)
                .as("the accessor must fail fast on an inactive cell, not return null")
                .isInstanceOf(IllegalStateException.class);
    }

    // --- fail-closed refusal matrix (every outcome refuses startup, AD-11/AD-12) ------------

    @Test
    @DisplayName("a discovered issuer != provider-url refuses startup (the deterministic-issuer check)")
    void issuerMismatchRefusesStartup(@TempDir Path dir) throws IOException {
        HttpsServer server = adHocDiscoveryServer(200, base -> discoveryDoc("https://elsewhere.example/realms/x",
                "\"authorization_code\", \"client_credentials\""));
        try {
            String providerUrl = base(server);
            assertThatThrownBy(() -> discovery(reverseBProperties(idpStore(dir), providerUrl)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("issuer")
                    .hasMessageContaining("refusing to start")
                    .hasMessageContaining("AD-12")
                    .hasMessageContaining(providerUrl);
        } finally {
            server.stop(0);   // exception-safe cleanup — a stranded in-process server hangs the test JVM
        }
    }

    @Test
    @DisplayName("a non-200 discovery response refuses startup (provider outage => fail-closed, A-2)")
    void non200DiscoveryRefusesStartup(@TempDir Path dir) throws IOException {
        HttpsServer server = adHocDiscoveryServer(503, base -> "service unavailable");
        try {
            assertThatThrownBy(() -> discovery(reverseBProperties(idpStore(dir), base(server))))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("503")
                    .hasMessageContaining("refusing to start")
                    .hasMessageContaining("AD-12");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("a malformed discovery body refuses startup")
    void malformedDiscoveryBodyRefusesStartup(@TempDir Path dir) throws IOException {
        HttpsServer server = adHocDiscoveryServer(200, base -> "{this is not json");
        try {
            assertThatThrownBy(() -> discovery(reverseBProperties(idpStore(dir), base(server))))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("refusing to start")
                    .hasMessageContaining("AD-12");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("a discovery document omitting token_endpoint refuses startup (incomplete provider metadata)")
    void missingEndpointFieldRefusesStartup(@TempDir Path dir) throws IOException {
        // Field-completeness is checked BEFORE the issuer equality (both refusals are legitimate;
        // this document isolates the missing-field arm by keeping the other fields well-formed).
        HttpsServer server = adHocDiscoveryServer(200,
                base -> "{\"issuer\": \"placeholder\", \"introspection_endpoint\": \"https://x/introspect\","
                        + " \"jwks_uri\": \"https://x/certs\"}");
        try {
            assertThatThrownBy(() -> discovery(reverseBProperties(idpStore(dir), base(server))))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("token_endpoint")
                    .hasMessageContaining("refusing to start");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("an unreachable provider refuses startup (dead port, valid TLS config)")
    void unreachableProviderRefusesStartup(@TempDir Path dir) {
        int deadPort = RelayTestFixtures.freePort();   // probed, never bound -> connection refused
        assertThatThrownBy(() -> discovery(
                reverseBProperties(idpStore(dir), "https://localhost:" + deadPort + "/realms/x")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("refusing to start")
                .hasMessageContaining("AD-12");
    }

    @Test
    @DisplayName("a trailing-slash provider-url is normalized by the config layer and still discovers")
    void trailingSlashProviderUrlNormalizesAndDiscovers(@TempDir Path dir) {
        // The 2026-08-19 FIXME pass moved the trailing-'/' strip out of the discovery build into
        // the Oidc record's compact ctor (the config layer) — this pins the move end-to-end: the
        // normalized issuer still equals the stand-in's slash-free base URL, so discovery succeeds.
        OidcStartupDiscovery discovery =
                discovery(reverseBProperties(idpStore(dir), OidcDiscoveryStandIn.url() + "/"));
        assertThat(discovery.active()).isTrue();
        assertThat(discovery.metadata().issuer()).isEqualTo(OidcDiscoveryStandIn.url());
    }

    // --- DAG warning (loud, deferred to runtime) ---------------------------------------------

    @Test
    @DisplayName("grant_types_supported without password: loud DAG warning, discovery still succeeds")
    void dagMissingPasswordGrantWarnsButDiscovers(@TempDir Path dir, CapturedOutput out) throws IOException {
        HttpsServer server = adHocDiscoveryServer(200,
                base -> discoveryDoc(base, "\"client_credentials\", \"authorization_code\""));
        try {
            String providerUrl = base(server);
            OidcStartupDiscovery discovery = discovery(reverseBProperties(idpStore(dir), providerUrl));
            assertThat(discovery.active())
                    .as("a DAG-less provider is a runtime denial posture, not a startup refusal").isTrue();
            assertThat(discovery.metadata().issuer()).isEqualTo(providerUrl);
            assertThat(out.getAll())
                    .as("the missing password grant must produce the loud DAG warning (Keycloak 26.2+ default)")
                    .contains("Direct Access Grants")
                    .contains("password");
        } finally {
            server.stop(0);
        }
    }

    // --- full-app proof: the refusal is the standard Spring startup failure -------------------

    @Test
    @DisplayName("a discovery refusal fails a FULL app boot (standard Spring startup failure, non-zero exit)")
    void discoveryRefusalSurfacesAsSpringStartupFailure(@TempDir Path dir) throws IOException {
        int deadPort = RelayTestFixtures.freePort();   // probed, never bound -> connection refused
        // RED-on-neuter exception-safety: if the probe was neutered the context STARTS — close it so
        // the unexpectedly-started context cannot outlive the assertion failure.
        Throwable thrown = catchThrowable(() -> {
            ConfigurableApplicationContext ctx = new SpringApplicationBuilder(ProxyCompanionApplication.class)
                    .web(WebApplicationType.NONE)
                    .run(reverseBArgs(dir, "https://localhost:" + deadPort + "/realms/x"));
            ctx.close();
        });
        assertThat(thrown).as("a dead provider must refuse the boot (fail-closed, A-2)").isNotNull();
        assertThat(chainMessages(thrown))
                .as("the startup failure must carry the AD-12 discovery refusal")
                .anyMatch(msg -> msg.contains("refusing to start") && msg.contains("AD-12"));
    }

    // --- fixtures ------------------------------------------------------------------------------

    /** Factory + probe over the SAME properties (the wiring Spring does by constructor injection). */
    private static OidcStartupDiscovery discovery(ProxyCompanionProperties properties) {
        return new OidcStartupDiscovery(properties, new IdpSslContextFactory(properties));
    }

    private static Path idpStore(Path dir) {
        return RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
    }

    /** A minimal valid discovery document with the Keycloak realm endpoint layout. */
    private static String discoveryDoc(String issuer, String grants) {
        return """
                {"issuer": "%s", "token_endpoint": "%s/token", "introspection_endpoint": "%s/token/introspect",
                 "jwks_uri": "%s/certs", "grant_types_supported": [%s]}"""
                .formatted(issuer, realmOf(issuer), realmOf(issuer), realmOf(issuer), grants);
    }

    private static String realmOf(String base) {
        return base + "/realms/smpp-companions/protocol/openid-connect";
    }

    /**
     * An ad-hoc HTTPS server at the discovery path serving {@code status} + the body computed from
     * the server's own base URL (so a well-formed document can echo its issuer, what the AC7
     * equality check demands) with the fixture-cert TLS context (same trust story as the shared
     * stand-in). The CALLER owns {@code stop(0)} — always in a {@code finally} (a stranded
     * in-process server hangs the JVM).
     */
    private static HttpsServer adHocDiscoveryServer(int status, UnaryOperator<String> bodyForBase)
            throws IOException {
        HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(OidcDiscoveryStandIn.fixtureServerSslContext()));
        server.createContext(DISCOVERY_PATH, exchange -> {
            byte[] bytes = bodyForBase.apply(base(server)).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
        return server;
    }

    private static String base(HttpsServer server) {
        return "https://localhost:" + server.getAddress().getPort();
    }

    /** A reverse×B properties record (full AD-34 TLS lists, yml-template oidc budgets). */
    private static ProxyCompanionProperties reverseBProperties(Path idpStore, String providerUrl) {
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
                                URI.create(providerUrl), "smpp-client-confidential", "/run/secrets/oidc-client-secret",
                                new ProxyCompanionProperties.TrustStore(idpStore.toString(),
                                        RelayTestFixtures.IDP_STORE_PASSWORD),
                                Duration.ofSeconds(4), 64, Duration.ofMinutes(5))), null));
    }

    /** A forward×A properties record — no oidc node anywhere (AD-12 amended 2026-08-18). */
    private static ProxyCompanionProperties forwardAProperties() {
        return new ProxyCompanionProperties(
                new ProxyCompanionProperties.Bind(2775, RelayTestFixtures.DEFAULT_ADJUDICATION_DEADLINE),
                new ProxyCompanionProperties.Memory(1, 1, 1.0, ProxyCompanionProperties.Memory.BudgetCheck.FAIL),
                new ProxyCompanionProperties.Tls(List.of("TLSv1.3", "TLSv1.2"),
                        List.of("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"), List.of("TLS_AES_256_GCM_SHA384")),
                new ProxyCompanionProperties.Forward(new ProxyCompanionProperties.ForwardModeA(
                        new ProxyCompanionProperties.ServerCert("/run/secrets/server.crt", "/run/secrets/server.key"),
                        List.of(new ProxyCompanionProperties.RoutingEntry("carrierOne", "reverse.internal", 2776, null))),
                        null),
                null);
    }

    /**
     * Full-boot {@code --key=value} args for a reverse×B cell against the given provider URL
     * (minimal AD-30 budget + a free bind port, the DirectMemoryBudgetStartupCheckTest pattern, so
     * the ONLY startup failure possible here is the discovery probe).
     */
    private static String[] reverseBArgs(Path dir, String providerUrl) throws IOException {
        Path secret = Files.createFile(dir.resolve("oidc-client-secret"));
        Path idpStore = idpStore(dir);
        return new String[] {
                "--companion.reverse.mode-b.smsc.host=smsc.example",
                "--companion.reverse.mode-b.smsc.port=2775",
                "--companion.reverse.mode-b.acknowledged=true",
                "--companion.reverse.mode-b.oidc.provider-url=" + providerUrl,
                "--companion.reverse.mode-b.oidc.client-id=smpp-client-confidential",
                "--companion.reverse.mode-b.oidc.client-secret-path=" + secret,
                "--companion.reverse.mode-b.oidc.trust-store.path=" + idpStore,
                "--companion.reverse.mode-b.oidc.trust-store.password=" + RelayTestFixtures.IDP_STORE_PASSWORD,
                "--companion.reverse.mode-b.oidc.timeout=4s",
                "--companion.reverse.mode-b.oidc.max-in-flight=64",
                "--companion.reverse.mode-b.oidc.jwks-cache-ttl=5m",
                "--companion.memory.max-inbound-depth=1",
                "--companion.memory.concurrent-pairs=1",
                "--companion.memory.safety-factor=1.0",
                "--companion.bind.port=" + RelayTestFixtures.freePort()};
    }

    /** Collects messages across a Throwable's cause chain (Spring wraps startup failures deeply). */
    private static List<String> chainMessages(Throwable t) {
        List<String> messages = new ArrayList<>();
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c.getMessage() != null) {
                messages.add(c.getMessage());
            }
        }
        return messages;
    }
}
