package smpp.companion.proxy.bootstrap;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import com.sun.net.httpserver.HttpsServer;

import io.netty.channel.DefaultChannelId;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.util.AsciiString;
import io.netty.util.concurrent.DefaultThreadFactory;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.observability.MetricsEndpointLifecycle;
import smpp.companion.proxy.relay.netty.RelayServerLifecycle;
import smpp.companion.proxy.security.AdjudicationLifecycle;
import smpp.companion.proxy.security.AlwaysAllowBindCredentialVerifier;
import smpp.companion.proxy.security.BindCredential;
import smpp.companion.proxy.security.IdpSslContextFactory;
import smpp.companion.proxy.security.Password;
import smpp.companion.proxy.security.RequestContext;
import smpp.companion.proxy.security.RopcBindCredentialVerifier;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.security.VerdictRequest;
import smpp.companion.proxy.testsupport.RelayTestFixtures;
import smpp.companion.proxy.testsupport.TokenIdpStandIn;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Story 4.2 T3 — {@link ProxyCompanionLifecycle} is the AD-22 <b>shutdown coordinator</b>: the
 * app-phase bean whose {@code stop()} walks the 5-step spine's remaining steps — deny &rarr; the
 * (still-empty, 4.3) drain seam &rarr; release-await &rarr; the shared loop's quiesce with an
 * EXPLICIT short quiet period (the {@code MetricsEndpointLifecycle} 100ms/2s pattern, never
 * Netty's 2s default). Pinned here: the phase discipline (the coordinator stops LAST — below the
 * acceptor, the deny window, and the metrics scrape-late window, so the walk begins with the port
 * closed, the adjudications denied and the final scrape done), the walk's end state (by the time
 * {@code stop()} returns: the in-flight adjudication settled fail-closed — release's bounded await
 * JOINED the deny's unwind — the pool denying every new verify, and the loop provably quiesced),
 * the idempotence contract (a second {@code stop()} is a no-op; the bean-destroy backstops — the
 * group bean's {@code shutdownGracefully} and the adapter's fused {@code close()} — re-fire
 * harmlessly), and the source-level shape of the walk itself (the deny &rarr; seam &rarr; release
 * &rarr; quiesce order + the explicit quiesce args).
 *
 * <p>The real-adapter rows drive the ROPC adapter over a parked in-process TLS stand-in IdP (the
 * {@code AdjudicationLifecycleTest} pattern, compact): the bind's token exchange parks on a latch,
 * so the ONLY thing that can settle it inside the window is the walk's deny path, and the walk's
 * release half provably JOINS that settle — synchronous with {@code stop()}'s return. Class-level
 * {@link Timeout} turns a hung walk into a test FAILURE, never a stalled JVM.
 */
@Tag("unit")
@Tag("bootstrap")
@Tag("p1")
@Timeout(value = 30, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
@DisplayName("Story 4.2 T3 — ProxyCompanionLifecycle: the AD-22 coordinator skeleton")
class ProxyCompanionLifecycleTest {

    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    @Test
    @DisplayName("phase: the coordinator stops LAST (below the acceptor, the deny window and the metrics "
            + "scrape-late window); house pattern: flag, callback, idempotence")
    void phaseSitsBelowEveryOtherLifecycleAndFollowsTheHousePattern() {
        EventLoopGroup group = newGroup();
        ProxyCompanionLifecycle coordinator =
                new ProxyCompanionLifecycle(new AlwaysAllowBindCredentialVerifier(), group);
        try {
            assertThat(coordinator.getPhase()).isEqualTo(ProxyCompanionLifecycle.APP_PHASE);
            // The walk runs LAST: everything above has already stopped when it begins — the final
            // scrape (the operator saw the denied binds' counters), the deny window (the in-flight
            // adjudications are settling), the acceptor (no new binds; the loop kept live for the
            // deny continuations). A re-phased coordinator that stops before any of them goes RED.
            assertThat(ProxyCompanionLifecycle.APP_PHASE)
                    .as("the coordinator stops after the metrics scrape-late window")
                    .isLessThan(MetricsEndpointLifecycle.METRICS_ENDPOINT_PHASE);
            assertThat(ProxyCompanionLifecycle.APP_PHASE)
                    .as("the coordinator stops after the deny window (its release-await joins what "
                            + "the deny started)")
                    .isLessThan(AdjudicationLifecycle.ADJUDICATION_PHASE);
            assertThat(ProxyCompanionLifecycle.APP_PHASE)
                    .as("the coordinator stops after the acceptor (no new binds; the loop survives "
                            + "into the walk)")
                    .isLessThan(RelayServerLifecycle.RELAY_ACCEPTOR_PHASE);

            assertThat(coordinator.isRunning()).as("never started").isFalse();
            coordinator.start();
            assertThat(coordinator.isRunning()).isTrue();

            AtomicBoolean callbackRan = new AtomicBoolean(false);
            coordinator.stop(() -> callbackRan.set(true));
            assertThat(callbackRan)
                    .as("stop(Runnable) MUST invoke the callback (releases the shutdown latch)")
                    .isTrue();
            assertThat(coordinator.isRunning()).as("stop() flips the flag").isFalse();

            coordinator.stop();   // idempotent second stop: a no-op, never a throw
            assertThat(coordinator.isRunning()).isFalse();
            // Neuter-guard: the walk really ran, not just the flag — the quiesce was AWAITED, so
            // the loop is provably down at stop() return (direct construction: the group bean's
            // destroyMethod backstop is NOT in play here; an emptied stop() body goes RED).
            assertThat(group.isShutdown())
                    .as("the coordinator's final step quiesced the shared loop (awaited)")
                    .isTrue();
        } finally {
            group.shutdownGracefully().syncUninterruptibly();   // exception-safe: never strand the scratch loop
        }
    }

    @Test
    @DisplayName("the walk: deny → (empty drain seam) → release-await → quiesce — the settle is "
            + "SYNCHRONOUS with stop()'s return, and the loop is down")
    void theWalkDeniesReleasesAndQuiescesSynchronouslyWithStop(@TempDir Path dir) throws Exception {
        CountDownLatch tokenReceived = new CountDownLatch(1);
        CountDownLatch hold = new CountDownLatch(1);
        HttpsServer server = TokenIdpStandIn.parkedTokenIdp(tokenReceived, hold, "coordinator-idp");
        EventLoopGroup group = newGroup();
        try {
            // SHORT per-request budget (the AdjudicationLifecycleTest split-row timing): the parked
            // exchange aborts at its OWN budget, and the walk's release await (budget + 1s) JOINS
            // that abort — so stop() returns with everything settled, quickly.
            ProxyCompanionProperties props = RelayTestFixtures.reverseBProperties(
                    dir, TokenIdpStandIn.realmBase(server), Duration.ofMillis(500));
            IdpSslContextFactory tlsFactory = new IdpSslContextFactory(props);
            RopcBindCredentialVerifier adapter = new RopcBindCredentialVerifier(tlsFactory);
            ProxyCompanionLifecycle coordinator = new ProxyCompanionLifecycle(adapter, group);
            coordinator.start();

            VerdictRequest inFlight = ScopedValue.where(CTX, rc()).call(() -> adapter.verify(credential(), CTX));
            assertTrue(tokenReceived.await(5, TimeUnit.SECONDS),
                    "the adjudication must be in-flight (parked at the token endpoint) when the walk begins");

            coordinator.stop();

            // Release's bounded awaitTermination JOINS the deny's unwind (the synchronous-settle
            // invariant the fused lifecycle stop carried until 4.2 T3 re-homed it here): the
            // in-flight adjudication is settled fail-closed the moment stop() returns.
            assertThat(inFlight.future().isDone())
                    .as("the walk's release-await joins the settle — done at stop() return")
                    .isTrue();
            assertThat(inFlight.future().getNow(null))
                    .as("a shutdown-denied adjudication is fail-closed (AD-11)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            // The deny fired (the pool is down): every post-walk verify settles fail-closed
            // SYNCHRONOUSLY — the use-after-close arm, no wire call, no wait.
            assertThat(ScopedValue.where(CTX, rc()).call(() -> adapter.verify(credential(), CTX)).future().getNow(null))
                    .as("every post-walk verify settles fail-closed")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            // The final step: the quiesce ran AND was awaited — the loop threads are gone at
            // stop() return (an unawaited or missing quiesce goes RED here).
            assertThat(group.isTerminated())
                    .as("the walk's final step quiesced the shared loop (awaited — threads gone)")
                    .isTrue();
        } finally {
            hold.countDown();   // exception-safe: never strand the parked stand-in handler
            server.stop(0);
            group.shutdownGracefully().syncUninterruptibly();   // exception-safe (assertions can throw)
        }
    }

    @Test
    @DisplayName("idempotence: a second stop() is a no-op, and the destroy backstops (the group's "
            + "shutdownGracefully, the adapter's fused close()) re-fire harmlessly")
    void doubleStopAndTheDestroyBackstopsAreNoOps(@TempDir Path dir) throws Exception {
        // Real adapter, idle (no parked exchange — the provider-url is never dialed: no wire call at
        // construction, and every verify below hits the rejected/closed pool, never the network).
        ProxyCompanionProperties props = RelayTestFixtures.reverseBProperties(
                dir, "https://idle.invalid/realms/smpp-companions", Duration.ofSeconds(1));
        IdpSslContextFactory tlsFactory = new IdpSslContextFactory(props);
        RopcBindCredentialVerifier adapter = new RopcBindCredentialVerifier(tlsFactory);
        EventLoopGroup group = newGroup();
        try {
            ProxyCompanionLifecycle coordinator = new ProxyCompanionLifecycle(adapter, group);
            coordinator.start();
            coordinator.stop();   // the walk (idle: the pool joins instantly, the quiesce is ~100ms)

            coordinator.stop();   // second stop: a no-op — never a throw, never a re-walk
            // The group bean's destroyMethod backstop re-firing after the coordinator — Netty's
            // quiesce is idempotent: the re-fire COMPLETES immediately (nothing left to do).
            group.shutdownGracefully().syncUninterruptibly();
            adapter.close();      // the adapter bean's inferred fused close() backstop re-firing

            assertThat(coordinator.isRunning()).isFalse();
            assertThat(group.isTerminated())
                    .as("still down after every backstop re-fire — no re-walk, no double-free")
                    .isTrue();
            assertThat(ScopedValue.where(CTX, rc()).call(() -> adapter.verify(credential(), CTX)).future().getNow(null))
                    .as("use-after-close stays fail-closed through every backstop re-fire")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            group.shutdownGracefully().syncUninterruptibly();   // exception-safe (assertions can throw)
        }
    }

    @Test
    @DisplayName("idle forward-cell walk: every adapter step a no-op over the stand-in verifier; "
            + "fast exit well under the 30s phase ceiling")
    void idleWalkOverTheStandInVerifierExitsFast() {
        EventLoopGroup group = newGroup();
        ProxyCompanionLifecycle coordinator =
                new ProxyCompanionLifecycle(new AlwaysAllowBindCredentialVerifier(), group);
        try {
            coordinator.start();
            long start = System.nanoTime();
            coordinator.stop();
            long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
            // The walk is the flag + three no-op steps + a 100ms-quiet quiesce: this bound sits
            // between that reality and the 2s-default quiet period this bean refuses (an idle walk
            // under Netty's defaults floors at ~2s and goes RED here), and is nowhere near the 30s
            // per-phase ceiling (application.yml). The meaningful full-boot bound is 4.2 T4's row.
            assertThat(elapsedMs)
                    .as("the idle walk completes fast (no drain body yet — 4.3)")
                    .isLessThan(1_500L);
            assertThat(group.isTerminated()).as("the quiesce was awaited").isTrue();
        } finally {
            group.shutdownGracefully().syncUninterruptibly();   // exception-safe (assertions can throw)
        }
    }

    @Test
    @DisplayName("source pin: the walk's order (deny → drain seam → release → quiesce) and the "
            + "EXPLICIT quiesce args (never Netty's 2s default)")
    void theWalkOrderAndExplicitQuiesceAreSourcePinned() throws IOException {
        // The MetricsEndpointTest scan idiom (test CWD = the proxy module; `clean build` covers the
        // incremental UP-TO-DATE trap for source scans).
        Path src = Path.of("src/main/java/smpp/companion/proxy/bootstrap/ProxyCompanionLifecycle.java");
        assertThat(Files.exists(src)).as("coordinator source present (test CWD = proxy module)").isTrue();
        String code = Files.readString(src);
        // The explicit-args quiesce (the MetricsEndpointLifecycle pattern — the deferred-work
        // "≥2s per close" cost died with this bean): named constants, never the no-args default.
        assertThat(code).as("the quiet period is the explicit short constant")
                .contains("SHUTDOWN_QUIET_PERIOD_MS = 100");
        assertThat(code).as("the quiesce cap is the explicit 2s constant")
                .contains("SHUTDOWN_TIMEOUT_MS = 2_000");
        assertThat(code).as("the quiesce call passes the explicit args")
                .contains("shutdownGracefully(SHUTDOWN_QUIET_PERIOD_MS, SHUTDOWN_TIMEOUT_MS");
        assertThat(code).as("never Netty's 2s-default no-args quiesce").doesNotContain("shutdownGracefully()");
        // The walk ORDER (the 5-step spine's steps 2-5, in stop() body order): deny < the (empty)
        // drain seam < release < quiesce. A re-ordered or dropped step goes RED here.
        int deny = code.indexOf("adapter.deny()");
        int drain = code.indexOf("drainRelayedConnections();");
        int release = code.indexOf("adapter.release()");
        int quiesce = code.indexOf("shutdownGracefully(SHUTDOWN_QUIET_PERIOD_MS");
        assertThat(deny).as("step 2 (deny) present").isGreaterThanOrEqualTo(0);
        assertThat(drain).as("step 3 (the empty drain seam) is walked, after the deny").isGreaterThan(deny);
        assertThat(release).as("step 4 (release-await) lands after the seam").isGreaterThan(drain);
        assertThat(quiesce).as("step 5 (the quiesce) is the last step").isGreaterThan(release);
    }

    // ── fixtures (the stand-in IdP and the reverse×B record live in testsupport — 4.3 T2) ─────

    private static BindCredential credential() {
        return new BindCredential(new SystemId(new AsciiString("testuser")), new Password(new AsciiString("testpass")));
    }

    /** The deadline must outlive the test window — the per-REQUEST budget (oidc.timeout) is the real bound. */
    private static RequestContext rc() {
        return new RequestContext(new SystemId(new AsciiString("testuser")),
                DefaultChannelId.newInstance(), Instant.now().plusSeconds(30));
    }

    /** Mirrors the RelayNettyConfig bean: the Netty 4.2 NIO idiom (NOT the deprecated NioEventLoopGroup). */
    private static EventLoopGroup newGroup() {
        return new MultiThreadIoEventLoopGroup(
                // daemon: a wedged walk past the timeout must not outlive the failure (hang the JVM).
                1, new DefaultThreadFactory("coordinator-test", true), NioIoHandler.newFactory());
    }
}
