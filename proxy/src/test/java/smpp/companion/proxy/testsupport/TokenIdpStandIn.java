package smpp.companion.proxy.testsupport;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

/**
 * Story 4.3 T2 (ledger fold) — the shared stand-in TOKEN-endpoint IdP of the AD-22 shutdown-walk
 * suites: an ad-hoc in-process TLS {@link HttpsServer} on the {@link OidcDiscoveryStandIn} trust
 * story whose token handler PARKS on a latch before answering, so a bind's token exchange is
 * genuinely IN-FLIGHT when the walk (or a lifecycle stop) fires. Formerly triplicated as the
 * private {@code parkedTokenIdp} / {@code allowIdp} fixtures of {@code AdjudicationLifecycleTest},
 * {@code ProxyCompanionLifecycleTest} and {@code GracefulShutdownRacesTest}; one home before the
 * 4.3 gate/body rows add a fourth consumer.
 *
 * <p>Since Story 3.4 T9 (2026-08-29) the token endpoint is DERIVED from the provider-url realm
 * base, so these servers serve only the realm's token path — the former discovery context is gone
 * with the startup probe (the never-hit pin lives on the shared {@code OidcDiscoveryStandIn}).
 * Daemon executors throughout (the JDK server's default dispatcher is a single thread — a parked
 * handler must not starve other handlers or strand the JVM). Test-tier only (SEC-090:
 * {@code com.sun.net.httpserver} never appears in {@code src/main}).
 */
public final class TokenIdpStandIn {

    /**
     * The host-side name a CONTAINER resolves to the test host (Testcontainers' host-access
     * extra-host entry; {@code GenericContainer#INTERNAL_HOST_HOSTNAME}). The Docker E2E cells dial
     * their host-side satellites — this stand-in family and the loopback {@code MockSmsc} — through
     * it (Story 5.2 T3).
     */
    public static final String DOCKER_GATEWAY_HOST = "host.testcontainers.internal";

    /** The pinned-Keycloak realm token path every stand-in IdP here serves (the T3 fixture idiom). */
    public static final String TOKEN_PATH = "/realms/smpp-companions/protocol/openid-connect/token";

    private TokenIdpStandIn() {}

    /**
     * The provider-url these fixtures use over the given stand-in server: base + the realm segment
     * (T9 — the DERIVED token endpoint lands exactly on {@link #TOKEN_PATH}).
     */
    public static String realmBase(HttpsServer server) {
        return "https://localhost:" + server.getAddress().getPort() + "/realms/smpp-companions";
    }

    /**
     * A stand-in IdP whose TOKEN handler PARKS on a latch — the bind is in-flight until the test
     * releases it (or the lifecycle's drain / the walk's deny path interrupts it) — and then
     * answers 401 (the deny-window rows of the lifecycle and coordinator suites). Daemon executor
     * (the JDK server's default dispatcher is a single thread — a parked handler must not starve
     * other handlers or strand the JVM).
     */
    public static HttpsServer parkedTokenIdp(CountDownLatch tokenReceived, CountDownLatch hold, String threadName)
            throws IOException {
        return tokenEndpointIdp(tokenReceived, hold, true, 10, 401, "{}", 4, threadName,
                OidcDiscoveryStandIn.fixtureServerSslContext(), "localhost");
    }

    /**
     * A stand-in IdP whose TOKEN handler answers a VALID 200 + three-segment-JWS
     * {@code access_token} — a genuine {@code Allow}. The PARKED variant ({@code park = true}, the
     * race rows) holds that response on a latch — the bind is in-flight until the test releases it
     * (or the walk's deny forces the exchange's own abort), and the late write onto the dead
     * exchange is the race's deterministic half. The IMMEDIATE variant ({@code park = false}, the
     * coupled-pairs row) answers without parking, so the exchange yields {@code Allow} and the
     * bind COUPLES to the mock SMSC. Daemon executor (a parked handler must not strand the JVM).
     */
    public static HttpsServer allowIdp(CountDownLatch tokenReceived, CountDownLatch hold, boolean park,
            String threadName) throws IOException {
        return tokenEndpointIdp(tokenReceived, hold, park, 15, 200,
                "{\"access_token\":\"aa.bb.cc\",\"token_type\":\"Bearer\"}", 6, threadName,
                OidcDiscoveryStandIn.fixtureServerSslContext(), "localhost");
    }

    /**
     * The DOCKER-REACHABLE variant of the IMMEDIATE-allow stand-in (Story 5.2 T3): same handler
     * behavior, but the server presents the fixture CA's {@code docker-host} cert (SAN
     * {@value #DOCKER_GATEWAY_HOST}) and the realm base advertises that name, so a CONTAINERized
     * reverse cell (whose provider-url must name the HOST, not localhost) passes full TLS hostname
     * verification against the same {@code truststore.p12} anchor every other fixture uses. The
     * binding itself stays on the host loopback — Testcontainers' host-access portal forwards
     * {@code host.testcontainers.internal:<port>} to the test host's loopback, so {@link
     * MockSmsc}-style loopback satellites stay untouched (spec Design Notes: "parameterize or
     * re-point rather than weakening TLS verification").
     */
    public static HttpsServer dockerHostAllowIdp(CountDownLatch tokenReceived, CountDownLatch hold,
            boolean park, String threadName) throws IOException {
        return tokenEndpointIdp(tokenReceived, hold, park, 15, 200,
                "{\"access_token\":\"aa.bb.cc\",\"token_type\":\"Bearer\"}", 6, threadName,
                OidcDiscoveryStandIn.serverSslContext(
                        "/keycloak/certs/docker-host.pem", "/keycloak/certs/docker-host-key.pem"),
                "127.0.0.1");
    }

    /** The provider-url base a CONTAINERized cell must dial for this stand-in family (the host). */
    public static String dockerHostRealmBase(HttpsServer server) {
        return "https://" + DOCKER_GATEWAY_HOST + ":" + server.getAddress().getPort()
                + "/realms/smpp-companions";
    }

    /** The shared body: TLS stand-in server, daemon pool, the realm token context (park, then answer). */
    private static HttpsServer tokenEndpointIdp(
            CountDownLatch tokenReceived, CountDownLatch hold, boolean park, int parkSeconds,
            int status, String body, int poolSize, String threadName,
            SSLContext serverSslContext, String bindHost) throws IOException {
        HttpsServer server = HttpsServer.create(new InetSocketAddress(bindHost, 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverSslContext));
        server.setExecutor(Executors.newFixedThreadPool(poolSize, r -> {
            Thread t = new Thread(r, threadName);
            t.setDaemon(true);
            return t;
        }));
        server.createContext(TOKEN_PATH, ex -> {
            tokenReceived.countDown();
            drain(ex);
            try {
                if (park) {
                    hold.await(parkSeconds, TimeUnit.SECONDS);   // park: the adjudication is in-flight
                }
                respond(ex, status, body);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException e) {
                // best-effort late write on the torn connection — not a verdict signal
            }
        });
        server.start();
        return server;
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
}
