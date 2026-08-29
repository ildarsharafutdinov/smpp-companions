package smpp.companion.proxy.testsupport;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Story 3.2 T1 — the shared in-process HTTPS provider stand-in (AC7's test-support leg). A
 * lazy-shared {@link HttpsServer} on a free loopback port, TLS-terminated with the Keycloak
 * fixture's own server cert/key ({@code keycloak/certs/server.pem} + {@code server-key.pem},
 * CN=localhost, SAN localhost/127.0.0.1, signed by the fixture CA).
 *
 * <p><b>Why it exists (re-purposed 2026-08-29, Story 3.4 T9):</b> the startup discovery probe —
 * this stand-in's original consumer — is REMOVED whole (the token endpoint is DERIVED from
 * {@code provider-url}; no provider wire call happens at boot). The stand-in survives deliberately:
 * (1) {@link #url()} remains the default reverse-cell {@code provider-url}
 * ({@code TestCompanionConfigs.oidcKeys()} and the full-context boots) — a valid https+hostful
 * value that keeps every bootable reverse config provider-shaped with no Docker/Keycloak; (2) the
 * provider-metadata context below stays registered behind a hit counter as the NEVER-HIT
 * startup-probe pin (re-introducing a startup GET turns {@code RopcBindCredentialVerifierTest}'s
 * pin RED); (3) {@link #fixtureServerSslContext()} stays load-bearing for every ad-hoc test HTTPS
 * server that needs the fixture trust story. The PKCS#8 PEM key parses via the JDK
 * {@link KeyFactory} (no BouncyCastle, no {@code sun.security..} reach — AD-36).
 *
 * <p>Test-tier only (SEC-090: {@code com.sun.net.httpserver} + {@code javax.net.ssl} JDK-context
 * use are test-tier concerns; {@code HttpsParameters} never appears in main). One shared instance
 * per JVM, started on first {@link #url()} call and stopped by a shutdown hook.
 */
public final class OidcDiscoveryStandIn {

    /**
     * The OIDC provider-metadata path. Since Story 3.4 T9 (2026-08-29) nothing in {@code src/main}
     * fetches it — the context below exists purely as the NEVER-HIT startup-probe pin (its hits
     * are counted; see {@link #discoveryHits()}).
     */
    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";

    /**
     * In-memory key-entry password for the server keystore. Protects nothing (the store is never
     * persisted); it only satisfies the PKCS12 key-entry API.
     */
    private static final char[] KEY_PASSWORD = "stand-in".toCharArray();

    /** Hits on the provider-metadata context — the never-hit startup-probe pin's observable (T9). */
    private static final java.util.concurrent.atomic.AtomicInteger DISCOVERY_HITS =
            new java.util.concurrent.atomic.AtomicInteger();

    private static volatile String baseUrl;

    private OidcDiscoveryStandIn() {}

    /**
     * The stand-in's base URL ({@code https://localhost:<free-port>}) — use it verbatim as
     * {@code companion.reverse.mode-*.oidc.provider-url}; the served document's {@code issuer} is
     * this exact string. Starts the shared server on first call.
     */
    public static String url() {
        String url = baseUrl;
        if (url == null) {
            synchronized (OidcDiscoveryStandIn.class) {
                url = baseUrl;
                if (url == null) {
                    url = start();
                    baseUrl = url;
                }
            }
        }
        return url;
    }

    /**
     * Hits recorded on the provider-metadata context since JVM start — the observable of the
     * never-hit startup-probe pin (Story 3.4 T9, 2026-08-29): with the probe removed, NOTHING in
     * {@code src/main} may fetch this path, at construction or at first bind.
     */
    public static int discoveryHits() {
        return DISCOVERY_HITS.get();
    }

    private static String start() {
        try {
            HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
            server.setHttpsConfigurator(new HttpsConfigurator(serverSslContext()));
            String base = "https://localhost:" + server.getAddress().getPort();
            server.createContext(DISCOVERY_PATH, discoveryHandler(base));
            server.start();
            Runtime.getRuntime().addShutdownHook(
                    new Thread(() -> server.stop(0), "oidc-discovery-stand-in-stop"));
            return base;
        } catch (IOException e) {
            throw new IllegalStateException("could not start the OIDC discovery stand-in", e);
        }
    }

    private static HttpHandler discoveryHandler(String base) {
        return exchange -> {
            DISCOVERY_HITS.incrementAndGet();   // the never-hit pin's counter (T9)
            byte[] body = discoveryDocument(base).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        };
    }

    /**
     * Minimal but shape-faithful discovery doc; endpoints mirror the Keycloak realm layout. The
     * 3.2-era {@code introspection_endpoint} field was removed with the RFC 7662 arm (Story 3.4
     * T1, 2026-08-27) and the {@code jwks_uri} field with local JWT verification (Story 3.4 T2,
     * same day) — every boot through this stand-in now also proves a document omitting both
     * retired fields is ACCEPTED (the requirement is issuer + token endpoint only).
     */
    private static String discoveryDocument(String base) {
        String realm = base + "/realms/smpp-companions/protocol/openid-connect";
        return """
                {
                  "issuer": "%s",
                  "token_endpoint": "%s/token",
                  "grant_types_supported": ["password", "authorization_code", "client_credentials", "refresh_token"]
                }
                """.formatted(base, realm);
    }

    /**
     * The fixture-cert server-side TLS context, shared with ad-hoc test HTTPS servers that need the
     * same trust story as the shared stand-in (their certs chain to the fixture CA the reverse-cell
     * configs anchor) — Story 3.2 T2's discovery failure-matrix servers.
     */
    public static SSLContext fixtureServerSslContext() {
        try {
            return serverSslContext();
        } catch (IOException e) {
            throw new IllegalStateException("could not build the fixture server SSLContext", e);
        }
    }

    /** Server-side TLS context from the fixture's PEM cert + PKCS#8 key; no client auth. */
    private static SSLContext serverSslContext() throws IOException {
        try {
            PrivateKey key = readPrivateKey("/keycloak/certs/server-key.pem");
            X509Certificate cert = readCertificate("/keycloak/certs/server.pem");
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            store.setKeyEntry("stand-in-server", key, KEY_PASSWORD, new X509Certificate[] {cert});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(store, KEY_PASSWORD);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("could not build the stand-in server SSLContext (fixture certs?)", e);
        }
    }

    private static PrivateKey readPrivateKey(String resource) throws IOException, GeneralSecurityException {
        String pem = readResource(resource);
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der;
        try {
            der = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            // a corrupt / non-base64 fixture key must not escape as a bare IAE with no context
            throw new IllegalStateException("fixture server key is not raw-base64 PKCS#8: " + resource, e);
        }
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static X509Certificate readCertificate(String resource) throws IOException, GeneralSecurityException {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(readResource(resource).getBytes(StandardCharsets.UTF_8)));
    }

    private static String readResource(String resource) throws IOException {
        try (InputStream in = OidcDiscoveryStandIn.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("fixture resource missing on classpath: " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
