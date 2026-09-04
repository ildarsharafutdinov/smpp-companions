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
import smpp.companion.proxy.observability.MetricsEndpointLifecycle;
import smpp.companion.proxy.relay.netty.RelayServerLifecycle;
import smpp.companion.proxy.testsupport.OidcDiscoveryStandIn;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AC1 (Story 3.2 T7; phase pin re-authored by Story 4.2 T1) — {@link AdjudicationLifecycle}: the
 * AD-22 phase discipline (the deny window strictly between the relay acceptor's stop phase and the
 * metrics endpoint's scrape-late window — the acceptor closes first, the final scrape still sees
 * the deny), the running-flag / callback / idempotence contract (the {@code RelayServerLifecycle}
 * house pattern), and the load-bearing stop body — a stop during an in-flight adjudication DENIES
 * it: {@code stop()} is synchronous with the drain, so the in-flight future is SETTLED fail-closed
 * the moment {@code stop()} returns, and every post-stop verify settles fail-closed too
 * (use-after-close). The 4.2 T1 deny/release SPLIT is pinned alongside: {@code deny()} alone
 * settles the in-flight adjudication fail-closed (bounded, not synchronous — the await lives in
 * the release half), and {@code release()} / the fused {@code close()} re-firing after the split
 * sequence are no-ops (the destroy-method backstop contract).
 *
 * <p>The deny-in-flight cases drive the REAL adapter over a parked in-process TLS stand-in IdP (the
 * {@code RopcBindCredentialVerifierTest} pattern, compact): the bind's token exchange is parked on
 * a latch, so the ONLY thing that can settle it inside the window is the deny path — the parked
 * exchange aborts at its OWN per-request budget (the forked {@code CompletableFuture} join ignores
 * the deny interrupt; the pin settles fail-closed with the abort), and the fused {@code stop()} is
 * SYNCHRONOUS with that settle because release()'s {@code awaitTermination} joins it.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AC1 — AdjudicationLifecycle: AD-22 phase + idempotent stop + deny-in-flight drain")
class AdjudicationLifecycleTest {

    private static final String TOKEN_PATH = "/realms/smpp-companions/protocol/openid-connect/token";
    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    @Test
    @DisplayName("phase: the deny window, strictly between the acceptor (stops first) and the metrics scrape-late window")
    void phaseSitsStrictlyBetweenAcceptorAndMetricsScrapeWindow() {
        AdjudicationLifecycle lifecycle = new AdjudicationLifecycle(new AlwaysAllowBindCredentialVerifier());
        assertThat(lifecycle.getPhase()).isEqualTo(AdjudicationLifecycle.ADJUDICATION_PHASE);
        assertThat(lifecycle.getPhase())
                .as("the adjudicator must stop AFTER the acceptor (AD-22 step order — no new binds before the deny)")
                .isLessThan(RelayServerLifecycle.RELAY_ACCEPTOR_PHASE);
        assertThat(lifecycle.getPhase())
                .as("the deny must run while the metrics scrape-late window is still live "
                        + "(the operator's final scrape sees the denied binds)")
                .isGreaterThan(MetricsEndpointLifecycle.METRICS_ENDPOINT_PHASE);
        assertThat(lifecycle.getPhase())
                .as("the deny window sits strictly between the acceptor and the app phases (the 5-step spine)")
                .isGreaterThan(ProxyCompanionLifecycle.APP_PHASE);
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
            ProxyCompanionProperties props = reverseBProperties(dir, realmBase(server), Duration.ofSeconds(4));
            IdpSslContextFactory tlsFactory = new IdpSslContextFactory(props);
            RopcBindCredentialVerifier adapter = new RopcBindCredentialVerifier(tlsFactory);
            AdjudicationLifecycle lifecycle = new AdjudicationLifecycle(adapter);
            lifecycle.start();

            VerdictRequest inFlight = ScopedValue.where(CTX, rc()).call(() -> adapter.verify(credential(), CTX));
            assertTrue(tokenReceived.await(5, TimeUnit.SECONDS),
                    "the adjudication must be in-flight (parked at the token endpoint) when stop() fires");

            lifecycle.stop();

            // stop() runs the adapter's FUSED close() — deny (shutdownNow) then release (the
            // bounded awaitTermination) — so it is SYNCHRONOUS with the settle: the parked
            // exchange aborts at its own 4s per-request budget, the pin settles fail-closed with
            // that abort, and release()'s await JOINS it before stop() returns (the pin can never
            // still be pending here — the 5s await budget outlasts the 4s abort).
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

    @Test
    @DisplayName("deny/release split (4.2 T1): deny alone settles fail-closed; release + close re-fires are no-ops")
    void denyReleaseSplitSettlesFailClosedAndReFiresAsNoOps(@TempDir Path dir) throws Exception {
        CountDownLatch tokenReceived = new CountDownLatch(1);
        CountDownLatch hold = new CountDownLatch(1);
        HttpsServer server = parkedTokenIdp(tokenReceived, hold);
        try {
            // SHORT per-request budget for this row: the settle lands when the parked exchange
            // aborts at its OWN budget (the forked join ignores the deny interrupt — the fused
            // row's 4s duration proves the timing), so a 500ms budget keeps deny()-alone fast.
            ProxyCompanionProperties props = reverseBProperties(dir, realmBase(server), Duration.ofMillis(500));
            IdpSslContextFactory tlsFactory = new IdpSslContextFactory(props);
            RopcBindCredentialVerifier adapter = new RopcBindCredentialVerifier(tlsFactory);

            VerdictRequest inFlight = ScopedValue.where(CTX, rc()).call(() -> adapter.verify(credential(), CTX));
            assertTrue(tokenReceived.await(5, TimeUnit.SECONDS),
                    "the adjudication must be in-flight (parked at the token endpoint) when deny() fires");

            adapter.deny();   // AD-22 step 2 ALONE — no await, no client close

            // deny() carries no await (the await is release()'s, so the coordinator can sequence
            // work between the halves), so the settle is asserted BOUNDED here, not synchronous —
            // the synchronous pin lives on the fused lifecycle stop above. The bound is the
            // exchange's own abort (4x the 500ms budget).
            assertThat(inFlight.future().get(2, TimeUnit.SECONDS))
                    .as("deny() alone must settle the in-flight adjudication fail-closed (Story 3.2 AC5)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            // No new adjudications after the deny: the pool rejects the task and verify() settles
            // fail-closed synchronously (the use-after-close catch — the client is still OPEN here,
            // the pool is what denies).
            assertThat(ScopedValue.where(CTX, rc()).call(() -> adapter.verify(credential(), CTX)).future().getNow(null))
                    .as("every post-deny verify settles fail-closed")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);

            adapter.release();   // AD-22 steps 4/5: bounded await + shared client close + zeroize
            adapter.release();   // idempotent second release — a no-op, never a hang or double-free
            adapter.close();     // the destroy-method backstop re-firing after the halves ran — a no-op

            assertThat(ScopedValue.where(CTX, rc()).call(() -> adapter.verify(credential(), CTX)).future().getNow(null))
                    .as("use-after-close stays fail-closed through the whole split sequence")
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
     * A stand-in IdP whose TOKEN handler PARKS on a latch — the bind is in-flight until the test
     * releases it (or the lifecycle's drain interrupts it). Since Story 3.4 T9 (2026-08-29) the
     * token endpoint is DERIVED from the provider-url realm base, so this server serves only the
     * realm's token path — the former discovery context is gone with the startup probe. Daemon
     * executor (the JDK server's default dispatcher is a single thread — a parked handler must not
     * starve other handlers or strand the JVM).
     */
    private static HttpsServer parkedTokenIdp(CountDownLatch tokenReceived, CountDownLatch hold) throws IOException {
        HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(OidcDiscoveryStandIn.fixtureServerSslContext()));
        server.setExecutor(Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "lifecycle-idp");
            t.setDaemon(true);
            return t;
        }));
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
                                timeout, 8)), null),
                null);
    }

    /** The deadline must outlive the test window — the per-REQUEST budget (oidc.timeout) is the real bound. */
    private static RequestContext rc() {
        return new RequestContext(new SystemId(new AsciiString("testuser")),
                DefaultChannelId.newInstance(), Instant.now().plusSeconds(30));
    }

    private static String base(HttpsServer server) {
        return "https://localhost:" + server.getAddress().getPort();
    }

    /** The provider-url these fixtures use: base + the realm segment (T9 — the derived endpoint lands on TOKEN_PATH). */
    private static String realmBase(HttpsServer server) {
        return base(server) + "/realms/smpp-companions";
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
