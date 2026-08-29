package smpp.companion.proxy.security;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

/**
 * Story 2.1 Task 2 — the real Keycloak &ge;26.7.0 fixture contract the test-tier ROPC slice
 * ({@link RopcSlice}) ratifies the AD-12 {@code proxy/security/} port against. Owns the immutable
 * fixture coordinates (the realm token endpoint, the confidential client id/secret, the test user) and the
 * TLS {@link SSLContext} the slice presents on every IdP call — the transport trust anchor of the amended
 * contract (Story 3.4 T8, 2026-08-29: the client cert is presented on <b>every</b> call as transport
 * identity; OAuth-level client auth is {@code client_secret} ONLY — the RFC 8705 cert-auth arm, the
 * introspection endpoint, and the key-set endpoint died with the slice's 2.1-era interop arms).
 *
 * <p>All material is test-only self-signed PKI under {@code proxy/src/test/resources/keycloak/certs/}
 * (regenerate with {@code generate.sh}); the credentials below are NOT production secrets. The trust anchor
 * is the minimal single-CA {@code truststore.p12} — AD-13: <b>never JDK {@code cacerts}</b>.
 *
 * <p>The {@link KeycloakContainer} binds the realm HTTPS port <b>fixed</b> to {@code localhost:8443} (parity
 * with the original compose), so the {@code :8443} coordinates below are the addresses the slice uses. See
 * {@code proxy/src/test/resources/keycloak/README.md} for how the fixture is stood up (Testcontainers) and the
 * real-fixture findings baked into Task 2 / AC8.
 */
final class KeycloakFixture {

    /** The realm base the pinned {@code keycloak:26.7.0} container serves on {@code localhost:8443} (fixed bind). */
    static final String REALM_BASE = "https://localhost:8443/realms/smpp-companions";
    static final URI TOKEN_ENDPOINT = URI.create(REALM_BASE + "/protocol/openid-connect/token");

    /** Client A — confidential, DAG enabled, {@code client_secret}. The amended contract's sole client (paths 1 + 4). */
    static final String CLIENT_A_ID = "smpp-client-confidential";
    static final String CLIENT_A_SECRET = "smpp-confidential-secret";

    /** The full-profile ROPC user (KC 26 User Profile requires email/firstName/lastName — finding #4). */
    static final String TEST_USER = "testuser";
    static final String TEST_PASS = "testpass";

    /** PKCS12 store password for both {@code truststore.p12} and {@code client-keystore.p12}. */
    static final String STORE_PASSWORD = "smpp-test";

    private KeycloakFixture() {
    }

    /**
     * The TLS-capable {@link SSLContext}: trusts the fixture CA (server cert) <b>and</b> presents the client
     * cert (the fixture container demands it on every handshake). Built once; the {@link HttpClient} shares it
     * across every IdP call — transport identity only; the OAuth-level cert-auth use died with Story 3.4 T8
     * (2026-08-29).
     */
    static SSLContext newSslContext() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(loadStore("/keycloak/certs/truststore.p12"));

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(loadStore("/keycloak/certs/client-keystore.p12"), STORE_PASSWORD.toCharArray());

            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return ctx;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("could not build the fixture mTLS SSLContext (certs missing?)", e);
        }
    }

    /** An {@link HttpClient} that trusts the fixture and presents the client cert on every call (AD-12/AD-29). */
    static HttpClient newHttpClient() {
        return HttpClient.newBuilder()
                .sslContext(newSslContext())
                .connectTimeout(java.time.Duration.ofSeconds(5))
                .build();
    }

    private static KeyStore loadStore(String resource) throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = KeycloakFixture.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("fixture resource missing on classpath: " + resource);
            }
            store.load(in, STORE_PASSWORD.toCharArray());
        }
        return store;
    }
}
