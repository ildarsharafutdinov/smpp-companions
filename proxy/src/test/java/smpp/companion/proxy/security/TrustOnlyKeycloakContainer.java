package smpp.companion.proxy.security;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.AbstractWaitStrategy;
import org.testcontainers.containers.wait.strategy.WaitStrategyTarget;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Map;

/**
 * Story 3.2 T9 (AC9) — the pinned Keycloak &ge;26.7.0 fixture in the <b>production provider-link
 * posture</b>: server-auth-only TLS. The 2.1 {@link KeycloakContainer} (kept as-is, the ratified
 * contract fixture) runs {@code KC_HTTPS_CLIENT_AUTH=required} because its {@code client-x509}
 * path demands the peer cert at the TLS layer — but the production {@link RopcBindCredentialVerifier}
 * link is <b>trust-only</b> (the RFC 8705 keystore arm was removed pre-release, 2026-08-19: the
 * ROPC {@code client_secret} is the sole provider client auth, so {@link IdpSslContextFactory}
 * builds the context with no key managers). A trust-only client cannot complete a handshake
 * against a {@code required} server, so the production live suite needs this variant:
 * {@code KC_HTTPS_CLIENT_AUTH=none}, everything else the verified fixture recipe verbatim.
 *
 * <p>Two container facts were docker-probe-verified live (2026-08-21, throwaway
 * {@code quay.io/keycloak/keycloak:26.7.0}, removed after):
 * <ol>
 * <li>a trust-only client (fixture CA anchor, no client cert) handshakes and gets the discovery
 *     document from a {@code KC_HTTPS_CLIENT_AUTH=none} server — the posture this container exists
 *     to provide;</li>
 * <li>KC 26 hostname v2 <b>rejects</b> {@code KC_HOSTNAME=localhost:8444} ("Provided hostname is
 *     neither a plain hostname nor a valid URL") — the full-URL form is what works, and it must
 *     be the <b>server root</b> ({@code https://localhost:8444}): pointing it at the realm base
 *     doubles the path, and the realm then advertises
 *     {@code …/realms/smpp-companions/realms/smpp-companions} as its issuer, which the adapter's
 *     {@code issuer == provider-url} equality refuses (observed live). Root form &rarr;
 *     deterministic issuer {@code https://localhost:8444/realms/<realm>}.</li>
 * </ol>
 *
 * <p>The HTTPS port is bound <b>fixed</b> to {@code localhost:8444} — deliberately NOT the
 * fixture's {@code :8443}, so this container never contends with the 2.1 container (or any
 * standing manual one) and the two live suites stay independent. Readiness is "OIDC discovery
 * served over <b>trust-only</b> HTTPS" — the probe proves the production TLS posture itself is
 * live before any test runs, not just that the realm is up. The strategy keeps the 2.1 shape:
 * Testcontainers 2.x does not wrap the no-arg {@code waitUntilReady()} in a timeout, so the
 * deadline is set on the strategy and honored by the loop directly.
 */
final class TrustOnlyKeycloakContainer extends GenericContainer<TrustOnlyKeycloakContainer> {

    private static final String IMAGE = "quay.io/keycloak/keycloak:26.7.0";
    private static final int CONTAINER_HTTPS_PORT = 8443;
    private static final String REALM = "smpp-companions";

    /** The fixed host bind — see the class javadoc for why it is not the fixture's :8443. */
    static final int HOST_PORT = 8444;

    /**
     * The realm base the production adapter uses as {@code provider-url}; identical in shape to
     * {@link KeycloakFixture#REALM_BASE} but on this container's port, and it doubles as the
     * {@code KC_HOSTNAME} value (full-URL form — see the class javadoc).
     */
    static final String REALM_BASE = "https://localhost:" + HOST_PORT + "/realms/" + REALM;

    TrustOnlyKeycloakContainer() {
        super(DockerImageName.parse(IMAGE));
        withCommand("start", "--import-realm", "--hostname-strict=false");
        withEnv("KEYCLOAK_ADMIN", "admin");
        withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin");
        withEnv("KC_HTTP_ENABLED", "false");          // HTTPS only (AD-12: provider endpoints over TLS)
        withEnv("KC_HTTPS_PORT", Integer.toString(CONTAINER_HTTPS_PORT));
        // Full-URL hostname = the SERVER ROOT (KC appends /realms/<realm> itself — pointing it at
        // the realm base doubles the path and the issuer). Probe-verified: root URL → deterministic
        // issuer https://localhost:8444/realms/<realm> == REALM_BASE for the imported realm.
        withEnv("KC_HOSTNAME", "https://localhost:" + HOST_PORT);
        withEnv("KC_HTTPS_CERTIFICATE_FILE", "/opt/keycloak/conf/server.pem");
        withEnv("KC_HTTPS_CERTIFICATE_KEY_FILE", "/opt/keycloak/conf/server-key.pem");
        withEnv("KC_HTTPS_CLIENT_AUTH", "none");      // the production trust-only posture (amendment 5)
        withEnv("KC_TRUSTSTORE_PATHS", "/opt/keycloak/conf/keycloak-truststore.pem");

        // Same mounts as the 2.1 fixture: copy (not bind) is fine for a throwaway start-time-read
        // container; 0400 on the key mirrors the original :ro perms.
        withCopyFileToContainer(
                MountableFile.forClasspathResource("keycloak/certs/server.pem"),
                "/opt/keycloak/conf/server.pem");
        withCopyFileToContainer(
                MountableFile.forClasspathResource("keycloak/certs/server-key.pem", 0400),
                "/opt/keycloak/conf/server-key.pem");
        withCopyFileToContainer(
                MountableFile.forClasspathResource("keycloak/certs/keycloak-truststore.pem"),
                "/opt/keycloak/conf/keycloak-truststore.pem");
        withCopyFileToContainer(
                MountableFile.forClasspathResource("keycloak/realm-smpp-companions.json"),
                "/opt/keycloak/data/import/realm-smpp-companions.json");

        withExposedPorts(CONTAINER_HTTPS_PORT);
        setPortBindings(java.util.List.of(HOST_PORT + ":" + CONTAINER_HTTPS_PORT));
        waitingFor(new TrustOnlyDiscoveryWaitStrategy().withStartupTimeout(Duration.ofMinutes(4)));
    }

    /**
     * A trust-only {@link SSLContext} over the fixture CA anchor ({@code truststore.p12}, the
     * minimal single-CA store — AD-13) — exactly the posture {@link IdpSslContextFactory} builds
     * for the provider link (no key managers, JDK-default PKIX trust). Package-private: the
     * readiness probe and the live suite's direct control calls share it.
     */
    static SSLContext trustOnlySslContext() {
        try {
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(loadStore("/keycloak/certs/truststore.p12"));
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustManagerFactory.getTrustManagers(), null);
            return context;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("could not build the trust-only fixture SSLContext", e);
        }
    }

    private static KeyStore loadStore(String resource) throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = TrustOnlyKeycloakContainer.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("fixture resource missing on classpath: " + resource);
            }
            store.load(in, KeycloakFixture.STORE_PASSWORD.toCharArray());
        }
        return store;
    }

    /**
     * Readiness = the OIDC discovery doc served over <b>trust-only</b> HTTPS (200 + a present
     * {@code issuer}) — proving both that the realm is imported and that the server really accepts
     * a no-client-cert handshake (a mis-set {@code KC_HTTPS_CLIENT_AUTH} fails HERE, at startup,
     * instead of surfacing as a confusing adapter-construction refusal inside a test). Records the
     * last status/error so a permanent config failure is distinguishable from a cold start.
     */
    private static final class TrustOnlyDiscoveryWaitStrategy extends AbstractWaitStrategy {

        private int lastStatus = -1;
        private String lastError = null;

        @Override
        protected void waitUntilReady() {
            WaitStrategyTarget target = waitStrategyTarget;
            HttpClient http = HttpClient.newBuilder()
                    .sslContext(trustOnlySslContext())
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();
            long deadlineNanos = System.nanoTime() + startupTimeout.toNanos();
            while (System.nanoTime() < deadlineNanos) {
                if (probe(http, discoveryUri(target))) {
                    return;
                }
                try {
                    Thread.sleep(2000L);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("trust-only readiness probe interrupted", ie);
                }
            }
            throw new IllegalStateException("Keycloak discovery not ready (trust-only TLS) within "
                    + startupTimeout + " — last status: " + (lastStatus < 0 ? "(no response)" : lastStatus)
                    + " — last error: " + (lastError != null ? lastError : "(none)"));
        }

        private URI discoveryUri(WaitStrategyTarget target) {
            return URI.create(REALM_BASE + "/.well-known/openid-configuration");
        }

        private boolean probe(HttpClient http, URI disco) {
            HttpResponse<String> r;
            try {
                r = http.send(HttpRequest.newBuilder(disco)
                        .timeout(Duration.ofSeconds(5)).GET().build(), HttpResponse.BodyHandlers.ofString());
                lastStatus = r.statusCode();
                lastError = null;
            } catch (Exception e) {
                lastStatus = -1;   // connection/TLS failure — e.g. a required-client-auth regression lands here
                lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
                return false;
            }
            if (r.statusCode() != 200) {
                return false;   // persistent 404 = realm name/path typo (config error, not slow start)
            }
            try {
                Map<String, Object> m = JSONObjectUtils.parse(r.body());
                return m.get("issuer") != null;   // realm imported + serving OIDC discovery
            } catch (Exception e) {
                lastError = "200-but-" + e.getClass().getSimpleName() + ": " + e.getMessage();
                return false;
            }
        }
    }
}
