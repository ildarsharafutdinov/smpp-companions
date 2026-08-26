package smpp.companion.proxy.security;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import io.netty.channel.DefaultChannelId;
import io.netty.util.AsciiString;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import smpp.companion.proxy.bootstrap.ProxyCompanionLifecycle;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.relay.netty.RelayServerLifecycle;
import smpp.companion.proxy.testsupport.OidcDiscoveryStandIn;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AC1 (Story 3.2 T7) — {@link AdjudicationLifecycle}: the AD-22 phase discipline (strictly below
 * the relay acceptor's stop phase, so the acceptor closes first), the running-flag / callback /
 * idempotence contract (the {@code RelayServerLifecycle} house pattern), and the load-bearing stop
 * body — a stop during an in-flight adjudication DENIES it: {@code stop()} is synchronous with the
 * drain, so the in-flight future is SETTLED fail-closed the moment {@code stop()} returns, and
 * every post-stop verify settles fail-closed too (use-after-close).
 *
 * <p>The deny-in-flight case drives the REAL adapter over a parked in-process TLS stand-in IdP (the
 * {@code RopcBindCredentialVerifierTest} pattern, compact): the bind's token exchange is parked on
 * a latch with a 4s per-request budget &mdash; far longer than the test window &mdash; so the ONLY
 * thing that can settle it inside the window is the lifecycle's drain (interrupt &rarr; STS join
 * throws &rarr; fail-closed settle; the request timeout is the 4s backstop).
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AC1 — AdjudicationLifecycle: AD-22 phase + idempotent stop + deny-in-flight drain")
class AdjudicationLifecycleTest {

    private static final String TOKEN_PATH = "/realms/smpp-companions/protocol/openid-connect/token";
    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    @Test
    @DisplayName("phase: the app-level slot, strictly BELOW the relay acceptor (AD-22 — acceptor stops first)")
    void phaseSitsBelowTheRelayAcceptor() {
        AdjudicationLifecycle lifecycle = new AdjudicationLifecycle(new AlwaysAllowBindCredentialVerifier());
        assertThat(lifecycle.getPhase()).isEqualTo(ProxyCompanionLifecycle.APP_PHASE);
        assertThat(lifecycle.getPhase())
                .as("the adjudicator must stop AFTER the acceptor (AD-22 step order)")
                .isLessThan(RelayServerLifecycle.RELAY_ACCEPTOR_PHASE);
    }

    @Test
    @DisplayName("running flag flips on start/stop; stop(Runnable) invokes the callback; stop is idempotent")
    void runningFlagCallbackAndIdempotenceFollowTheHousePattern() {
        AdjudicationLifecycle lifecycle = new AdjudicationLifecycle(new AlwaysAllowBindCredentialVerifier());
        assertThat(lifecycle.isRunning()).as("never started").isFalse();

        lifecycle.start();
        assertThat(lifecycle.isRunning()).isTrue();

        AtomicBoolean callbackRan = new AtomicBoolean(false);
        lifecycle.stop(() -> callbackRan.set(true));
        assertThat(callbackRan).as("stop(Runnable) MUST invoke the callback (releases the shutdown latch)").isTrue();
        assertThat(lifecycle.isRunning()).as("stop() flips the flag").isFalse();

        lifecycle.stop();   // idempotent second stop: a no-op, never a throw
        assertThat(lifecycle.isRunning()).isFalse();
    }

    @Test
    @DisplayName("stop() DENIES an in-flight adjudication: settled DenyIndeterminate when stop() returns (AD-22)")
    void stopDeniesInFlightAdjudications(@TempDir Path dir) throws Exception {
        CountDownLatch tokenReceived = new CountDownLatch(1);
        CountDownLatch hold = new CountDownLatch(1);
        HttpsServer server = parkedTokenIdp(tokenReceived, hold);
        try {
            ProxyCompanionProperties props = reverseBProperties(dir, base(server), Duration.ofSeconds(4));
            IdpSslContextFactory tlsFactory = new IdpSslContextFactory(props);
            RopcBindCredentialVerifier adapter =
                    new RopcBindCredentialVerifier(tlsFactory, new OidcStartupDiscovery(props, tlsFactory));
            AdjudicationLifecycle lifecycle = new AdjudicationLifecycle(adapter);
            lifecycle.start();

            VerdictRequest inFlight = ScopedValue.where(CTX, rc()).call(() -> adapter.verify(credential(), CTX));
            assertTrue(tokenReceived.await(5, TimeUnit.SECONDS),
                    "the adjudication must be in-flight (parked at the token endpoint) when stop() fires");

            lifecycle.stop();

            // stop() is SYNCHRONOUS with the drain (shutdownNow + bounded awaitTermination): the
            // in-flight future is settled the moment stop() returns — the 4s request budget is the
            // backstop, so only the drain can have settled it inside this window.
            assertThat(inFlight.future().isDone())
                    .as("deny-in-flight: the adjudication must be settled when stop() returns (AD-22)")
                    .isTrue();
            assertThat(inFlight.future().getNow(null))
                    .as("a shutdown-denied adjudication is fail-closed (AD-11)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);

            // Post-stop verifies settle fail-closed (the adapter is closed — use-after-close).
            assertThat(ScopedValue.where(CTX, rc()).call(() -> adapter.verify(credential(), CTX)).future().getNow(null))
                    .as("every post-stop verify settles fail-closed")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            hold.countDown();   // exception-safe: never strand the parked stand-in handler
            server.stop(0);
        }
    }

    // ── fixtures ────────────────────────────────────────────────────────────────────────────

    private static BindCredential credential() {
        return new BindCredential(new SystemId(new AsciiString("testuser")), new Password(new AsciiString("testpass")));
    }

    /**
     * A stand-in IdP whose discovery document echoes its own base URL (the AC7 equality check) and
     * whose token handler PARKS on a latch — the bind is in-flight until the test releases it (or
     * the lifecycle's drain interrupts it). Daemon executor (the JDK server's default dispatcher is
     * a single thread — a parked handler must not starve discovery or strand the JVM).
     */
    private static HttpsServer parkedTokenIdp(CountDownLatch tokenReceived, CountDownLatch hold) throws IOException {
        HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(OidcDiscoveryStandIn.fixtureServerSslContext()));
        server.setExecutor(Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "lifecycle-idp");
            t.setDaemon(true);
            return t;
        }));
        server.createContext("/.well-known/openid-configuration", (HttpHandler) ex -> {
            String realm = base(server) + "/realms/smpp-companions/protocol/openid-connect";
            byte[] document = ("{\"issuer\": \"" + base(server) + "\", \"token_endpoint\": \"" + realm
                    + "/token\", \"introspection_endpoint\": \"" + realm + "/token/introspect\", \"jwks_uri\": \""
                    + realm + "/certs\", \"grant_types_supported\": [\"password\"]}")
                    .getBytes(StandardCharsets.UTF_8);
            respond(ex, 200, document);
        });
        server.createContext(TOKEN_PATH, ex -> {
            tokenReceived.countDown();
            drain(ex);
            try {
                hold.await(10, TimeUnit.SECONDS);   // park: the adjudication is in-flight at stop() time
                respond(ex, 401, "{}");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException e) {
                // best-effort late write on the torn connection — not a verdict signal
            }
        });
        server.start();
        return server;
    }

    /** A reverse×B properties record over the given provider URL (the T3 direct-construction shape). */
    private static ProxyCompanionProperties reverseBProperties(Path dir, String providerUrl, Duration timeout)
            throws IOException {
        Path store = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        Path secret = Files.writeString(dir.resolve("oidc-client-secret"), "smpp-confidential-secret");
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
                                URI.create(providerUrl), "smpp-client-confidential", secret.toString(),
                                new ProxyCompanionProperties.TrustStore(store.toString(),
                                        RelayTestFixtures.IDP_STORE_PASSWORD),
                                timeout, 8, Duration.ofMinutes(5))), null));
    }

    /** The deadline must outlive the test window — the per-REQUEST budget (oidc.timeout) is the real bound. */
    private static RequestContext rc() {
        return new RequestContext(new SystemId(new AsciiString("testuser")),
                DefaultChannelId.newInstance(), Instant.now().plusSeconds(30));
    }

    private static String base(HttpsServer server) {
        return "https://localhost:" + server.getAddress().getPort();
    }

    private static void respond(HttpExchange exchange, int status, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        respond(exchange, status, body.getBytes(StandardCharsets.UTF_8));
    }

    private static void drain(HttpExchange exchange) throws IOException {
        exchange.getRequestBody().readAllBytes();
    }
}
