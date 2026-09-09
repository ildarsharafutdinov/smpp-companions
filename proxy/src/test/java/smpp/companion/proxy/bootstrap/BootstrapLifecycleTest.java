package smpp.companion.proxy.bootstrap;

import java.io.IOException;
import java.nio.file.Path;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import io.netty.channel.EventLoopGroup;

import smpp.companion.proxy.ProxyCompanionApplication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC8: Spring Boot boots a NON-web context and shuts down cleanly within the graceful-shutdown
 * timeout. "SIGTERM-equivalent" = closing the context ({@code ContextClosedEvent} ->
 * {@code SmartLifecycle.stop}), which is exactly what the JVM shutdown hook does on SIGTERM.
 * Since Story 4.2 T3 the close drives the REAL AD-22 coordinator body
 * ({@code ProxyCompanionLifecycle}'s 5-step walk; since 4.3 T5 step 3 carries the drain body —
 * the EMPTY-registry no-op on this idle boot); the MEANINGFUL shutdown upper bound (well
 * under the 30s phase ceiling) landed with Story 4.2 T4 — the walk's race-level rows live in
 * {@code GracefulShutdownRacesTest}.
 *
 * <p>Story 1.3 lockstep: the boot now supplies a complete valid forward+A config (mode + the
 * cell-required secret paths + routing + OIDC) so the AD-17 matrix validator passes and the test
 * keeps exercising lifecycle, not the new required fields.
 */
@Tag("integration")
@Tag("deploy")
@Tag("p2")
class BootstrapLifecycleTest {

    /**
     * Minimal AD-30 budget (Story 2.2 T5b: the self-check is unconditional — this forward-A boot carries
     * it too). Passed as run() args — HIGHEST precedence — so they beat application.yml's realistic
     * memory defaults (64 × 1024 × 1.5 ≈ 6 GiB), which exceed the test JVM's direct-memory ceiling.
     */
    private static final String[] MINIMAL_MEMORY = {
            "--companion.memory.max-inbound-depth=1",
            "--companion.memory.concurrent-pairs=1",
            "--companion.memory.safety-factor=1.0",
            // Story 3.3: the forward cell now BINDS its trusted-leg listener — a free ephemeral port
            // (beats yml's shipped 2775); the F13 cap IS concurrent-pairs=1 above (one number).
            "--companion.bind.port=" + smpp.companion.proxy.testsupport.RelayTestFixtures.freePort(),
            // Story 4.1 T2: these yml-loading boots otherwise bind yml's shipped metrics 9090 — a free
            // ephemeral port keeps them deterministic against a locally-running Prometheus (run-args
            // outrank yml; .properties() does not).
            "--companion.metrics.port=" + smpp.companion.proxy.testsupport.RelayTestFixtures.freePort()};

    @Test
    void bootsAsNonWebContextAndStartsLifecycle(@TempDir Path dir) throws IOException {
        try (ConfigurableApplicationContext ctx = builder(dir).run(MINIMAL_MEMORY)) {
            assertThat(ctx.isActive()).isTrue();
            // No embedded web server (AD-16): the context is a plain AnnotationConfigApplicationContext.
            assertThat(ctx.getClass().getSimpleName()).doesNotContain("WebServer");
            // The SmartLifecycle stub was started.
            assertThat(ctx.getBean(ProxyCompanionLifecycle.class).isRunning()).isTrue();
        }
    }

    @Test
    void contextCloseStopsLifecycleWithinGracefulTimeout(@TempDir Path dir) throws IOException {
        ConfigurableApplicationContext ctx = builder(dir).run(MINIMAL_MEMORY);
        ProxyCompanionLifecycle lifecycle = ctx.getBean(ProxyCompanionLifecycle.class);
        EventLoopGroup group = ctx.getBean(EventLoopGroup.class);
        assertThat(lifecycle.isRunning()).isTrue();

        long start = System.nanoTime();
        ctx.close(); // SIGTERM-equivalent (ContextClosedEvent -> SmartLifecycle.stop)
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        assertThat(lifecycle.isRunning()).isFalse(); // stop() ran (the flag flips only there)
        // The walk's final step at FULL-APP close: the shared loop is provably down once close()
        // returns (the coordinator's awaited quiesce; the group bean's destroyMethod backstop is
        // a no-op re-fire behind it — an unawaited or missing quiesce goes RED here).
        assertThat(group.isTerminated())
                .as("the coordinator's quiesce ran and was awaited before close() returned")
                .isTrue();
        // The MEANINGFUL upper bound (Story 4.2 T4; rationale re-signed by Story 4.3 T6 for the
        // drain deadline): an idle forward-cell walk is the flag + three no-op adapter steps + the
        // 100ms-quiet quiesce — the 4.3 drain body's EMPTY-REGISTRY short-circuit is what keeps it
        // that way (the snapshot read returns before any deadline arithmetic, so the armed 10s
        // drain-timeout is never slept on this boot). The deadline-aware margin for a NON-idle
        // close: drain-timeout (10s yml default) + release's await (oidc.timeout + 1s over the
        // documented [2s, 5s] operator window) + the 2s quiesce cap = 18s at the defaults, still
        // inside the 30s per-phase ceiling — and a peer that never half-closes is force-closed AT
        // the deadline (OBS-020), so nothing can push the walk past that sum. 5s stays the idle
        // bound: headroom for CI variance over the ~0.1s reality while still catching every gross
        // regression (a wedged step eating most of the phase window, a drain that unconditionally
        // sleeps its window, a re-added blocking seam).
        assertThat(elapsedMs)
                .as("the full-app SIGTERM-equivalent close completes well under the 30s phase ceiling")
                .isLessThan(5_000L);
    }

    /**
     * A forward+A boot ([B] topology, Story 3.3): the common keys come from application.yml (except
     * the memory/port overrides passed as run() args — see MINIMAL_MEMORY); the forward.mode-a branch
     * supplies the cell-required DIAL material — the committed SMPP-leg trust store (REAL material:
     * the full boot constructs SmppLegTlsFactory, which loads it eagerly). NO oidc keys — the forward
     * role is a trusted-side relay (AD-12 amended 2026-08-18); the reverse role adjudicates.
     */
    private static SpringApplicationBuilder builder(Path dir) throws IOException {
        var legs = smpp.companion.proxy.testsupport.RelayTestFixtures.smppTlsLegs(dir);
        String storePassword = smpp.companion.proxy.testsupport.RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD;
        return new SpringApplicationBuilder(ProxyCompanionApplication.class)
                .web(WebApplicationType.NONE)
                .properties(
                        "companion.forward.mode-a.trust-store.path=" + legs.trustStore(),
                        "companion.forward.mode-a.trust-store.password=" + storePassword,
                        "companion.forward.mode-a.routing[0].system-id=carrierOne",
                        "companion.forward.mode-a.routing[0].host=reverse.internal",
                        "companion.forward.mode-a.routing[0].port=2776");
    }
}
