package smpp.companion.proxy.security;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.AbstractWaitStrategy;
import org.testcontainers.containers.wait.strategy.WaitStrategyTarget;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Story 2.1 — the Keycloak &ge;26.7.0 fixture as a <b>Testcontainers-managed</b> container (replaces the
 * former external {@code docker-compose.yml}). Replicates the verified compose config verbatim: pinned
 * {@code quay.io/keycloak/keycloak:26.7.0}, the HTTPS server cert, {@code KC_HTTPS_CLIENT_AUTH=required}
 * (so the {@code client-x509} authenticator sees the peer cert — path 3), the mTLS truststore, and the realm
 * import. The HTTPS port is bound <b>fixed</b> to {@code localhost:8443} (parity with the original compose's
 * {@code "8443:8443"}) — so the slice uses the {@link KeycloakFixture} {@code :8443} coordinates directly;
 * there is no dynamic discovery.
 *
 * <p>Readiness is "OIDC discovery served over mTLS HTTPS" — the authoritative signal that the realm is
 * imported and serving. The built-in {@code Wait.forHttps} cannot be used: {@code KC_HTTPS_CLIENT_AUTH=required}
 * rejects any handshake without a client cert, and {@code forHttps} can only customize trust, not present a
 * client identity. The custom strategy reuses {@link KeycloakFixture#newSslContext()} (trusts the fixture CA
 * <b>and</b> presents the client cert). It self-enforces the startup deadline: in Testcontainers 2.x
 * {@code AbstractWaitStrategy} does <b>not</b> wrap the no-arg {@code waitUntilReady()} in a timeout, and the
 * container's startup timeout is not propagated to the strategy — so the timeout is set on the strategy and
 * the loop honors it directly (default 60s flakes on KC26 cold-start + realm import).
 */
final class KeycloakContainer extends GenericContainer<KeycloakContainer> {

    private static final String IMAGE = "quay.io/keycloak/keycloak:26.7.0";
    private static final int HTTPS_PORT = 8443;
    private static final String REALM = "smpp-companions";

    KeycloakContainer() {
        super(DockerImageName.parse(IMAGE));
        withCommand("start", "--import-realm", "--hostname-strict=false");
        withEnv("KEYCLOAK_ADMIN", "admin");
        withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin");
        withEnv("KC_HTTP_ENABLED", "false");          // HTTPS only (AD-12: provider endpoints over TLS, never HTTP)
        withEnv("KC_HTTPS_PORT", Integer.toString(HTTPS_PORT));
        withEnv("KC_HOSTNAME", "localhost");
        withEnv("KC_HTTPS_CERTIFICATE_FILE", "/opt/keycloak/conf/server.pem");
        withEnv("KC_HTTPS_CERTIFICATE_KEY_FILE", "/opt/keycloak/conf/server-key.pem");
        withEnv("KC_HTTPS_CLIENT_AUTH", "required");  // NEED: surfaces the peer cert to client-x509 (path 3)
        withEnv("KC_TRUSTSTORE_PATHS", "/opt/keycloak/conf/keycloak-truststore.pem");

        // Mounted read-once-at-start files. forClasspathResource takes a LEADING-SLASH-FREE classpath path
        // (unlike KeycloakFixture's getResourceAsStream("/keycloak/…") leading-slash convention). Copy (not
        // bind) is fine for a throwaway start-time-read container; 0400 on the key mirrors the compose :ro perms.
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

        withExposedPorts(HTTPS_PORT);
        // Fixed host bind (parity with the original compose "8443:8443") → the slice uses KeycloakFixture's
        // :8443 coordinates directly. setPortBindings takes the docker-compose-style "hostPort:containerPort".
        setPortBindings(List.of(HTTPS_PORT + ":" + HTTPS_PORT));
        waitingFor(new DiscoveryWaitStrategy().withStartupTimeout(Duration.ofMinutes(4)));
    }

    /**
     * Readiness = the OIDC discovery doc served over mTLS HTTPS (HTTP 200 + a present {@code issuer} field).
     * Polls every 2s until ready or the startup deadline elapses. {@link #waitStrategyTarget} is set by
     * {@code AbstractWaitStrategy} before it delegates to this no-arg override (Testcontainers 2.x shape).
     * The probe records the last HTTP status / last error so a permanent config failure (e.g. a missing
     * realm → persistent 404, or a wrong truststore → SSLHandshakeException) is distinguishable from a cold
     * start in the timeout message (a swallowed exception can only DELAY success, never fake it).
     */
    private static final class DiscoveryWaitStrategy extends AbstractWaitStrategy {

        private int lastStatus = -1;
        private String lastError = null;

        @Override
        protected void waitUntilReady() {
            WaitStrategyTarget target = waitStrategyTarget;
            HttpClient http = HttpClient.newBuilder()
                    .sslContext(KeycloakFixture.newSslContext())
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
                    throw new IllegalStateException("Keycloak readiness probe interrupted", ie);
                }
            }
            throw new IllegalStateException("Keycloak discovery not ready within " + startupTimeout
                    + " — last probe: " + discoveryUri(target)
                    + " — last status: " + (lastStatus < 0 ? "(no response)" : lastStatus)
                    + " — last error: " + (lastError != null ? lastError : "(none)"));
        }

        private URI discoveryUri(WaitStrategyTarget target) {
            return URI.create("https://" + target.getHost() + ":" + target.getMappedPort(HTTPS_PORT)
                    + "/realms/" + REALM + "/.well-known/openid-configuration");
        }

        private boolean probe(HttpClient http, URI disco) {
            HttpResponse<String> r;
            try {
                r = http.send(HttpRequest.newBuilder(disco)
                        .timeout(Duration.ofSeconds(5)).GET().build(), HttpResponse.BodyHandlers.ofString());
                lastStatus = r.statusCode();
                lastError = null;
            } catch (Exception e) {
                lastStatus = -1;   // connection/TLS/timeout failure — no HTTP response (cert mismatch = here)
                lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
                return false;   // not ready yet (TLS not up / realm still importing) — keep polling
            }
            if (r.statusCode() != 200) {
                return false;   // e.g. persistent 404 = realm name/path typo (config error, not slow start)
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
