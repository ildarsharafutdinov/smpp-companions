package smpp.companion.proxy.observability;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.DefaultChannelId;
import io.netty.util.AsciiString;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.security.BindCredential;
import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.security.IdpSslContextFactory;
import smpp.companion.proxy.security.Password;
import smpp.companion.proxy.security.RequestContext;
import smpp.companion.proxy.security.RopcBindCredentialVerifier;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.security.VerdictRequest;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 4.1 T3 (checkpoint 22): both resource gauges present and sane. The direct-memory gauge
 * reads the SHARED allocator's live {@code usedDirectMemory()} and reaches the scrape surface; the
 * active-VT gauge exists only where the ROPC pool exists (reverse cells), is 0 at rest, counts an
 * in-flight adjudication, and returns to 0 when it settles.
 *
 * <p><b>The black-hole provider:</b> a {@link ServerSocket} bound and listening but never
 * accepting/replying — the adapter's HTTPS token call completes its TCP connect (the kernel
 * backlog takes it), sends the ClientHello, and then blocks until the 2s per-call budget elapses,
 * giving the in-flight window a DETERMINISTIC lower bound. The verdict is the fail-closed
 * {@code DenyIndeterminate} (AC2's timeout arm — the starred operator WARN in the output is that
 * arm working, not noise). The gauge's {@code ==1} assertion is deterministic because the adapter
 * counts the adjudication at SUBMIT (before {@code execute} returns, before {@code verify()}
 * returns); the {@code ==0}-again assertion polls because the pool task's verdict completes a
 * hair's breadth before its {@code finally} decrement.
 */
@Tag("unit")
@Tag("observability")
@Tag("p1")
@DisplayName("ResourceMetrics — direct-memory + active-VT gauges")
class ResourceMetricsTest {

    /** The verifier-driving context handle (the relay binds its own; tests own theirs). */
    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    @Test
    @DisplayName("direct-memory gauge present and sane; no VT gauge where no ROPC pool exists")
    void directMemoryGaugePresentAndSaneWithoutPool() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        new ApplicationContextRunner()
                .withBean(PrometheusMeterRegistry.class, () -> registry)
                .withBean(PooledByteBufAllocator.class, () -> PooledByteBufAllocator.DEFAULT)
                .withBean(ResourceMetrics.class)
                .run(ctx -> {
                    assertThat(registry.get(ResourceMetrics.DIRECT_MEMORY_GAUGE).gauge().value())
                            .as("the gauge reads the shared allocator's live usage — the authoritative "
                                    + "runtime number (AD-21/AD-30)")
                            .isEqualTo(PooledByteBufAllocator.DEFAULT.metric().usedDirectMemory())
                            .isGreaterThanOrEqualTo(0.0);
                    assertThat(registry.scrape())
                            .as("the gauge reaches the scrape surface (bytes base unit)")
                            .contains("relay_direct_memory_used_bytes");
                    assertThat(registry.find(ResourceMetrics.ACTIVE_ADJUDICATIONS_GAUGE).gauge())
                            .as("no ROPC verifier bean (a forward cell / a slice) — no VT gauge; "
                                    + "the absence is truthful, not a gap")
                            .isNull();
                });
    }

    @Test
    @Timeout(30)
    @DisplayName("active-VT gauge: 0 at rest, 1 while an adjudication is in flight, 0 after it settles")
    void activeVtGaugeTracksInFlightAdjudications(@TempDir Path dir) throws Exception {
        // The black-hole provider: bound to the literal loopback so the URL below cannot drift to ::1
        // (a refused-connect would settle the adjudication instantly and race the ==1 assertion).
        try (ServerSocket blackHole = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            RopcBindCredentialVerifier adapter = new RopcBindCredentialVerifier(
                    new IdpSslContextFactory(reverseBProperties(dir, blackHole.getLocalPort())));
            try {
                PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
                new ApplicationContextRunner()
                        .withBean(PrometheusMeterRegistry.class, () -> registry)
                        .withBean(PooledByteBufAllocator.class, () -> PooledByteBufAllocator.DEFAULT)
                        .withBean(BindCredentialVerifier.class, () -> adapter)
                        .withBean(ResourceMetrics.class)
                        .run(ctx -> {
                            assertThat(registry.get(ResourceMetrics.ACTIVE_ADJUDICATIONS_GAUGE).gauge().value())
                                    .as("the VT gauge is present (the verifier IS the ROPC adapter) "
                                            + "and 0 at rest")
                                    .isZero();

                            BindCredential cred = new BindCredential(
                                    new SystemId(new AsciiString("testuser")),
                                    new Password(new AsciiString("testpass")));
                            VerdictRequest request = ScopedValue.where(CTX, new RequestContext(
                                    cred.systemId(), DefaultChannelId.newInstance(),
                                    Instant.now().plusSeconds(15)))
                                    .call(() -> adapter.verify(cred, CTX));

                            assertThat(registry.get(ResourceMetrics.ACTIVE_ADJUDICATIONS_GAUGE).gauge().value())
                                    .as("counted from SUBMIT — deterministic the moment verify() returns "
                                            + "(the black-holed exchange cannot settle inside the 2s budget)")
                                    .isEqualTo(1.0);

                            Verdict verdict = awaitVerdict(request);
                            assertThat(verdict)
                                    .as("the black-holed provider denies fail-closed (AC2 timeout arm)")
                                    .isEqualTo(new Verdict.DenyIndeterminate());
                            awaitTrue("the gauge returns to 0 after the adjudication settles",
                                    () -> registry.get(ResourceMetrics.ACTIVE_ADJUDICATIONS_GAUGE)
                                            .gauge().value() == 0.0);
                            assertThat(registry.scrape())
                                    .as("the VT gauge reaches the scrape surface")
                                    .contains("ropc_adjudications_active");
                        });
            } finally {
                adapter.close(); // idempotent (also the runner's inferred destroy) — releases the VT pool + client
            }
        }
    }

    // --- fixtures ---------------------------------------------------------------------------

    private static Verdict awaitVerdict(VerdictRequest request) {
        try {
            return request.future().get(15, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new AssertionError("the adjudication did not settle within the budget", e);
        }
    }

    /** Polls a condition on a 10s deadline (the RopcBindCredentialVerifierTest awaitCondition idiom). */
    private static void awaitTrue(String what, BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError(what + " — timed out");
            }
            Thread.sleep(10);
        }
    }

    /**
     * A reverse&times;B properties record whose derived token endpoint is the BLACK-HOLED loopback
     * port (https, so the exchange stops in the TLS handshake) with a 2s per-call budget — the
     * RopcBindCredentialVerifierTest fixture shape (real fixture trust store, real secret file,
     * full AD-34 TLS lists, explicit budget keys: runner-style constructions load no yml).
     */
    private static ProxyCompanionProperties reverseBProperties(Path dir, int providerPort) throws IOException {
        Path secret = Files.writeString(dir.resolve("oidc-client-secret"), "stand-in-client-secret\n");
        Path idpStore = RelayTestFixtures.idpTrustStoreFixture(dir.resolve("idp-truststore.p12"));
        return new ProxyCompanionProperties(
                new ProxyCompanionProperties.Bind(2775, "127.0.0.1", Duration.ofSeconds(4)),
                new ProxyCompanionProperties.Memory(1, 1, 1.0,
                        ProxyCompanionProperties.Memory.BudgetCheck.FAIL),
                new ProxyCompanionProperties.Tls(
                        RelayTestFixtures.TLS_PROTOCOLS, RelayTestFixtures.TLS12_SUITES,
                        RelayTestFixtures.TLS13_SUITES),
                null,
                new ProxyCompanionProperties.Reverse(null,
                        new ProxyCompanionProperties.ReverseModeB(
                                new ProxyCompanionProperties.Smsc("smsc.example", 2775), true,
                                new ProxyCompanionProperties.Oidc(
                                        URI.create("https://127.0.0.1:" + providerPort + "/realms/test"),
                                        "smpp-client-confidential", secret.toString(),
                                        new ProxyCompanionProperties.TrustStore(idpStore.toString(),
                                                RelayTestFixtures.IDP_STORE_PASSWORD),
                                        Duration.ofSeconds(2), 4)),
                        null),
                null,
                new ProxyCompanionProperties.Shutdown(RelayTestFixtures.DEFAULT_DRAIN_TIMEOUT));
    }
}
