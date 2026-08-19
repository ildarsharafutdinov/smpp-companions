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
 * Story 3.2 T1 — the shared in-process HTTPS OIDC discovery stand-in (AC7's test-support leg). A
 * lazy-shared {@link HttpsServer} on a free loopback port, TLS-terminated with the Keycloak
 * fixture's own server cert/key ({@code keycloak/certs/server.pem} + {@code server-key.pem},
 * CN=localhost, SAN localhost/127.0.0.1, signed by the fixture CA), serving a minimal discovery
 * document whose {@code issuer} ECHOES ITS OWN BASE URL — the exact property the T2 startup
 * discovery check requires ({@code discovered issuer == provider-url}).
 *
 * <p><b>Why it exists:</b> from T2 the REVERSE cells' adapter bean performs a hard-required
 * discovery probe at boot (a refusal surfaces as the standard Spring startup failure; re-targeted
 * by the AD-12 amendment of 2026-08-18 — every reverse cell adjudicates, forward cells carry no
 * oidc node). The reverse-cell configs default {@code provider-url} here —
 * {@code TestCompanionConfigs.oidcKeys()} (the {@code reverseA()/reverseB()/reverseC()} bases) and
 * the two reverse mode-b full-context boots ({@code RelayServerLifecycleTest},
 * {@code DirectMemoryBudgetStartupCheckTest}) — so a bootable reverse cell needs no Docker/Keycloak
 * and no test is weakened or skipped; live Keycloak tests override with the fixture URL. The PKCS#8
 * PEM key parses via the JDK {@link KeyFactory} (no BouncyCastle, no {@code sun.security..} reach
 * — AD-36).
 *
 * <p>Test-tier only (SEC-090: {@code com.sun.net.httpserver} + {@code javax.net.ssl} JDK-context
 * use are test-tier concerns; {@code HttpsParameters} never appears in main). One shared instance
 * per JVM, started on first {@link #url()} call and stopped by a shutdown hook.
 */
public final class OidcDiscoveryStandIn {

    /** OIDC discovery is always {@code <issuer>/.well-known/openid-configuration}. */
    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";

    /**
     * In-memory key-entry password for the server keystore. Protects nothing (the store is never
     * persisted); it only satisfies the PKCS12 key-entry API.
     */
    private static final char[] KEY_PASSWORD = "stand-in".toCharArray();

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
            byte[] body = discoveryDocument(base).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        };
    }

    /** Minimal but shape-faithful discovery doc; endpoints mirror the Keycloak realm layout. */
    private static String discoveryDocument(String base) {
        String realm = base + "/realms/smpp-companions/protocol/openid-connect";
        return """
                {
                  "issuer": "%s",
                  "token_endpoint": "%s/token",
                  "introspection_endpoint": "%s/token/introspect",
                  "jwks_uri": "%s/certs",
                  "grant_types_supported": ["password", "authorization_code", "client_credentials", "refresh_token"]
                }
                """.formatted(base, realm, realm, realm);
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
