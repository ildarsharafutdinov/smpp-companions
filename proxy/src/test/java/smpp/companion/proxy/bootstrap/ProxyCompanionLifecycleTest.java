package smpp.companion.proxy.bootstrap;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import com.sun.net.httpserver.HttpsServer;

import io.netty.channel.Channel;
import io.netty.channel.DefaultChannelId;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.nio.NioIoHandler;
import io.netty.util.AsciiString;
import io.netty.util.AttributeKey;
import io.netty.util.concurrent.DefaultThreadFactory;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import org.slf4j.LoggerFactory;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.observability.CloseReason;
import smpp.companion.proxy.observability.MetricsEndpointLifecycle;
import smpp.companion.proxy.relay.ConnectionRegistry;
import smpp.companion.proxy.relay.CoupledRelayHandler;
import smpp.companion.proxy.relay.RelayStateManager;
import smpp.companion.proxy.relay.netty.RelayServerLifecycle;
import smpp.companion.proxy.security.AdjudicationLifecycle;
import smpp.companion.proxy.security.AlwaysAllowBindCredentialVerifier;
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
import smpp.companion.proxy.testsupport.TokenIdpStandIn;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Story 4.2 T3 — {@link ProxyCompanionLifecycle} is the AD-22 <b>shutdown coordinator</b>: the
 * app-phase bean whose {@code stop()} walks the 5-step spine's remaining steps — deny &rarr; the
 * drain body (Story 4.3 T5: snapshot &rarr; poll {@code size()==0} to the Clock deadline &rarr;
 * force-close the remainder) &rarr; release-await &rarr; the shared loop's quiesce with an
 * EXPLICIT short quiet period (the {@code MetricsEndpointLifecycle} 100ms/2s pattern, never
 * Netty's 2s default). Pinned here: the phase discipline (the coordinator stops LAST — below the
 * acceptor, the deny window, and the metrics scrape-late window, so the walk begins with the port
 * closed, the adjudications denied and the final scrape done), the walk's end state (by the time
 * {@code stop()} returns: the in-flight adjudication settled fail-closed — release's bounded await
 * JOINED the deny's unwind — the pool denying every new verify, and the loop provably quiesced),
 * the idempotence contract (a second {@code stop()} is a no-op; the bean-destroy backstops — the
 * group bean's {@code shutdownGracefully} and the adapter's fused {@code close()} — re-fire
 * harmlessly), and the source-level shape of the walk itself (the deny &rarr; drain &rarr; release
 * &rarr; quiesce order + the explicit quiesce args).
 *
 * <p><b>Story 4.3 T5 — the drain body's coordinator-level rows:</b> the empty registry's instant
 * no-op (the deadline is never slept), the deadline force-close over a real
 * {@code ConnectionRegistry}/{@code RelayStateManager} populated with embedded channels (a MUTABLE
 * {@link Clock} advances past the budget — the OBS-020 knob, never a wall-clock wait; the channels
 * are the recording surface: force-closed legs, {@code SHUTDOWN_DRAIN} stashed on each, registry
 * empty), and the ONE bounded WARN naming the count. Story 4.3 T6 adds the 4.2 ledger's
 * <b>throw-path behavioral pin</b> (a throwing drain step &rarr; release skipped, the
 * finally-quiesce still terminates the group); the six-event walk-order behavioral pin, RELAY-022
 * sequence integrity, and the observer-level OBS-020 proof are the races rows
 * ({@code GracefulShutdownRacesTest}).
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
@DisplayName("Story 4.2 T3 + 4.3 T5 — ProxyCompanionLifecycle: the AD-22 coordinator walk and its drain body")
class ProxyCompanionLifecycleTest {

    private static final ScopedValue<RequestContext> CTX = ScopedValue.newInstance();

    @Test
    @DisplayName("phase: the coordinator stops LAST (below the acceptor, the deny window and the metrics "
            + "scrape-late window); house pattern: flag, callback, idempotence")
    void phaseSitsBelowEveryOtherLifecycleAndFollowsTheHousePattern() {
        EventLoopGroup group = newGroup();
        ProxyCompanionLifecycle coordinator = idleCoordinator(new AlwaysAllowBindCredentialVerifier(), group);
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
            ProxyCompanionLifecycle coordinator = idleCoordinator(adapter, group);
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
            ProxyCompanionLifecycle coordinator = idleCoordinator(adapter, group);
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
        ProxyCompanionLifecycle coordinator = idleCoordinator(new AlwaysAllowBindCredentialVerifier(), group);
        try {
            coordinator.start();
            long start = System.nanoTime();
            coordinator.stop();
            long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
            // The walk is the flag + three no-op steps + a 100ms-quiet quiesce: this bound sits
            // between that reality and the 2s-default quiet period this bean refuses (an idle walk
            // under Netty's defaults floors at ~2s and goes RED here), and is nowhere near the 30s
            // per-phase ceiling (application.yml). The drain body's empty-registry no-op keeps this
            // true with a REALISTIC 10s deadline armed (the dedicated no-op row below pins that).
            // The meaningful full-boot bound is 4.2 T4's row.
            assertThat(elapsedMs)
                    .as("the idle walk completes fast (the drain body's empty-registry no-op)")
                    .isLessThan(1_500L);
            assertThat(group.isTerminated()).as("the quiesce was awaited").isTrue();
        } finally {
            group.shutdownGracefully().syncUninterruptibly();   // exception-safe (assertions can throw)
        }
    }

    @Test
    @DisplayName("source pin: the walk's order (deny → drain → release → quiesce) and the "
            + "EXPLICIT quiesce args (never Netty's 2s default)")
    void theWalkOrderAndExplicitQuiesceAreSourcePinned() throws IOException {
        // The MetricsEndpointTest scan idiom (test CWD = the proxy module; `clean build` covers the
        // incremental UP-TO-DATE trap for source scans). BELT ONLY since Story 4.3 T6: the order
        // and the throw-path are pinned BEHAVIORALLY — the OBS-016 six-event chain and the
        // throw-path quiesce rows (this suite + GracefulShutdownRacesTest).
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
        // The walk ORDER (the 5-step spine's steps 2-5, in stop() body order): deny < the drain
        // step < release < quiesce. A re-ordered or dropped step goes RED here.
        int deny = code.indexOf("adapter.deny()");
        int drain = code.indexOf("drainRelayedConnections();");
        int release = code.indexOf("adapter.release()");
        int quiesce = code.indexOf("shutdownGracefully(SHUTDOWN_QUIET_PERIOD_MS");
        assertThat(deny).as("step 2 (deny) present").isGreaterThanOrEqualTo(0);
        assertThat(drain).as("step 3 (the drain) is walked, after the deny").isGreaterThan(deny);
        assertThat(release).as("step 4 (release-await) lands after the drain").isGreaterThan(drain);
        assertThat(quiesce).as("step 5 (the quiesce) is the last step").isGreaterThan(release);
    }

    // ── Story 4.3 T5: the drain body's coordinator-level rows ─────────────────────────────────

    @Test
    @DisplayName("drain: an empty registry is an INSTANT no-op — the deadline is never slept")
    void drainOverAnEmptyRegistryIsAnInstantNoOp() {
        EventLoopGroup group = newGroup();
        ConnectionRegistry registry = new ConnectionRegistry();   // EMPTY — nothing to drain
        ProxyCompanionLifecycle coordinator = new ProxyCompanionLifecycle(
                new AlwaysAllowBindCredentialVerifier(), group, registry,
                new RelayStateManager(registry),
                new ProxyCompanionProperties.Shutdown(RelayTestFixtures.DEFAULT_DRAIN_TIMEOUT), Clock.systemUTC());
        try {
            coordinator.start();
            long start = System.nanoTime();
            coordinator.stop();
            long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
            // The empty-snapshot short-circuit: with a REALISTIC 10s deadline armed, a drain that
            // unconditionally sleeps the window (or polls before checking emptiness) floors at 10s
            // and goes RED here; the honest no-op is the flag + three no-op steps + the 100ms-quiet
            // quiesce (the idle-row bound).
            assertThat(elapsedMs)
                    .as("the empty-registry drain is an instant no-op, never a deadline sleep")
                    .isLessThan(1_500L);
            assertThat(registry.size()).as("still empty — the drain mutated nothing").isZero();
        } finally {
            group.shutdownGracefully().syncUninterruptibly();   // exception-safe (assertions can throw)
        }
    }

    @Test
    @DisplayName("drain: at the Clock deadline the remainder is force-closed — SHUTDOWN_DRAIN stashed "
            + "on every leg, registry empty, walk completes (OBS-020's coordinator half)")
    void drainForceClosesTheRemainderAtTheClockDeadline() throws Exception {
        ConnectionRegistry registry = new ConnectionRegistry();
        RelayStateManager manager = new RelayStateManager(registry);
        // Two live pairs that NEVER drain on their own (the OBS-020 premise: peers that never
        // half-close): one fully coupled (both legs) and one still in the optimistic-entry window
        // (egress never attached — RELAY-006's shape must force-close too).
        EmbeddedChannel ingress = channel();
        EmbeddedChannel egress = channel();
        EmbeddedChannel ingressPending = channel();
        manager.register(ingress, systemId("legacyA"));
        manager.attachEgress(ingress.id(), egress);
        manager.register(ingressPending, systemId("legacyB"));
        MutableClock clock = new MutableClock();
        EventLoopGroup group = newGroup();
        ProxyCompanionLifecycle coordinator = new ProxyCompanionLifecycle(
                new AlwaysAllowBindCredentialVerifier(), group, registry, manager,
                new ProxyCompanionProperties.Shutdown(Duration.ofSeconds(5)), clock);
        try {
            coordinator.start();
            stopAdvancingTheClock(coordinator, clock);

            // The force-close took effect through the manager (the recording surface: the channels):
            // every leg of every remaining pair is closed and carries the SHUTDOWN_DRAIN stash, the
            // registry is empty, and the walk completed through the quiesce.
            assertThat(registry.size()).as("the deadline force-close emptied the registry").isZero();
            assertThat(ingress.isOpen()).as("the coupled pair's ingress leg was force-closed").isFalse();
            assertThat(egress.isOpen()).as("the coupled pair's egress leg was force-closed").isFalse();
            assertThat(ingressPending.isOpen()).as("the pending-egress pair was force-closed").isFalse();
            assertThat(reasonStashedOn(ingress)).isEqualTo(CloseReason.SHUTDOWN_DRAIN);
            assertThat(reasonStashedOn(egress)).isEqualTo(CloseReason.SHUTDOWN_DRAIN);
            assertThat(reasonStashedOn(ingressPending)).isEqualTo(CloseReason.SHUTDOWN_DRAIN);
            assertThat(group.isTerminated()).as("the walk completed through the quiesce").isTrue();
        } finally {
            group.shutdownGracefully().syncUninterruptibly();   // exception-safe (assertions can throw)
        }
    }

    @Test
    @DisplayName("drain WARN shape: the deadline force-close logs ONE bounded WARN naming the count")
    void theDeadlineForceCloseWarnsOnceNamingTheCount() throws Exception {
        Logger logger = (Logger) LoggerFactory.getLogger(ProxyCompanionLifecycle.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        EventLoopGroup group = newGroup();
        try {
            ConnectionRegistry registry = new ConnectionRegistry();
            RelayStateManager manager = new RelayStateManager(registry);
            for (int i = 0; i < 3; i++) {   // THREE stuck pairs — the WARN must name the bulk count
                manager.register(channel(), systemId("legacy" + i));
            }
            MutableClock clock = new MutableClock();
            ProxyCompanionLifecycle coordinator = new ProxyCompanionLifecycle(
                    new AlwaysAllowBindCredentialVerifier(), group, registry, manager,
                    new ProxyCompanionProperties.Shutdown(Duration.ofSeconds(5)), clock);
            coordinator.start();
            stopAdvancingTheClock(coordinator, clock);

            List<ILoggingEvent> warns = appender.list.stream()
                    .filter(event -> event.getLevel() == Level.WARN).toList();
            assertThat(warns).as("exactly ONE bounded WARN for the whole bulk force-close").hasSize(1);
            assertThat(warns.get(0).getFormattedMessage())
                    .as("the WARN names the force-closed count and the SHUTDOWN_DRAIN close")
                    .contains("force-closed 3 live pair(s)")
                    .contains("SHUTDOWN_DRAIN");
        } finally {
            // Exception-safe: detach BEFORE the group release — a failed assertion must not leak the
            // appender into the next row's capture.
            logger.detachAppender(appender);
            appender.stop();
            group.shutdownGracefully().syncUninterruptibly();
        }
    }

    @Test
    @DisplayName("throw-path (4.2 ledger fold): a throwing drain step skips release but NEVER strands "
            + "the shared loop — the finally-quiesce still terminates the group")
    void aThrowingDrainStepSkipsReleaseAndStillQuiescesTheLoop(@TempDir Path dir) throws Exception {
        CountDownLatch tokenReceived = new CountDownLatch(1);
        CountDownLatch hold = new CountDownLatch(1);
        HttpsServer server = TokenIdpStandIn.parkedTokenIdp(tokenReceived, hold, "throw-path-idp");
        EventLoopGroup group = newGroup();
        try {
            // A LONG per-request budget (the AdjudicationLifecycleTest idiom): the pin's
            // "still pending at stop() return" assertion below races the exchange's OWN self-abort
            // budget — 3s makes an early settle unreachable inside the row's ~200ms window.
            ProxyCompanionProperties props = RelayTestFixtures.reverseBProperties(
                    dir, TokenIdpStandIn.realmBase(server), Duration.ofSeconds(3));
            IdpSslContextFactory tlsFactory = new IdpSslContextFactory(props);
            RopcBindCredentialVerifier adapter = new RopcBindCredentialVerifier(tlsFactory);
            // The walk's step-3 blow-up, injected through the coordinator's own seam: a live pair in
            // the registry (the drain's non-empty arm) + a clock whose first read — the drain body's
            // deadline computation — throws. (The spec's "a throwing manager" presumed a stubbable
            // manager; RelayStateManager is final, and the Clock is the coordinator's one injectable
            // dependency INSIDE the drain body — same behavioral pin: a throwing step 3.)
            ConnectionRegistry registry = new ConnectionRegistry();
            RelayStateManager manager = new RelayStateManager(registry);
            manager.register(channel(), systemId("legacyA"));
            RuntimeException drainBlewUp = new RuntimeException("the drain step blew up");
            ProxyCompanionLifecycle coordinator = new ProxyCompanionLifecycle(
                    adapter, group, registry, manager,
                    new ProxyCompanionProperties.Shutdown(Duration.ofSeconds(5)),
                    new ThrowingClock(drainBlewUp));
            coordinator.start();

            // An in-flight adjudication over the REAL adapter: release's bounded awaitTermination is
            // the ONLY step that joins its settle (the synchronous-settle row above) — so "the pin is
            // still pending at stop() return" IS the observable for "release never ran".
            VerdictRequest inFlight = ScopedValue.where(CTX, rc()).call(() -> adapter.verify(credential(), CTX));
            assertTrue(tokenReceived.await(5, TimeUnit.SECONDS),
                    "the adjudication must be in-flight (parked at the token endpoint) when the walk begins");

            assertThatThrownBy(coordinator::stop)
                    .as("the drain step's failure propagates out of stop() (never swallowed)")
                    .isSameAs(drainBlewUp);

            // RELEASE SKIPPED: its await never ran, so the parked pin is still PENDING at stop()
            // return — the healthy walk joins it (the synchronous-settle row); a re-shaped stop()
            // that swallowed the throw and carried on would settle it and go RED here.
            assertThat(inFlight.future().isDone())
                    .as("release skipped — the drain's throw short-circuited step 4 (the pin still pending)")
                    .isFalse();
            // The finally-quiesce STILL ran and was AWAITED: the walk's one non-negotiable tail —
            // a throwing step must never strand the shared loop's non-daemon threads.
            assertThat(group.isTerminated())
                    .as("the finally-quiesce terminated the group despite the throwing drain step")
                    .isTrue();
            // And the throw aborted the drain BEFORE the force-close: the pair is still registered
            // (force-close-never-ran is also the drain-started proof — the throw was step 3's).
            assertThat(registry.size())
                    .as("the force-close never ran (the drain threw at its first clock read)")
                    .isEqualTo(1);
            // The deny step DID run before the drain blew up: every post-walk verify settles
            // fail-closed SYNCHRONOUSLY (the use-after-close arm, no wire call, no wait).
            assertThat(ScopedValue.where(CTX, rc()).call(() -> adapter.verify(credential(), CTX)).future().getNow(null))
                    .as("the deny step ran before the throwing drain — post-walk verifies fail closed")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
        } finally {
            hold.countDown();   // exception-safe: never strand the parked stand-in handler
            server.stop(0);
            group.shutdownGracefully().syncUninterruptibly();   // no-op re-fire if the quiesce ran
        }
    }

    // ── T5 fixtures: the mutable clock, the embedded drain pairs, the stopper ─────────────────

    /**
     * The 4.2-row construction re-signed for the widened ctor (Story 4.3 T5): an EMPTY registry over
     * the stand-in/real adapter — those rows never hold live pairs, so the drain is the no-op and
     * the realistic 10s deadline is inert.
     */
    private static ProxyCompanionLifecycle idleCoordinator(BindCredentialVerifier verifier, EventLoopGroup group) {
        ConnectionRegistry registry = new ConnectionRegistry();
        return new ProxyCompanionLifecycle(verifier, group, registry, new RelayStateManager(registry),
                new ProxyCompanionProperties.Shutdown(RelayTestFixtures.DEFAULT_DRAIN_TIMEOUT),
                Clock.systemUTC());
    }

    /**
     * Runs {@code stop()} on a helper thread while advancing the mutable clock every 25ms until the
     * walk completes: whenever the drain computes its deadline, the NEXT advance (a 6s jump over a
     * 5s budget) pushes the clock past it — the deterministic OBS-020 knob, never a wall-clock wait
     * for the budget. Bounded at 10s: a walk that never resolves at an advanced clock fails HERE.
     * The stopper is a DAEMON (the mutation-pass discipline): a neutered deadline check can strand
     * it mid-drain without hanging the test JVM past the failure.
     */
    private static void stopAdvancingTheClock(ProxyCompanionLifecycle coordinator, MutableClock clock)
            throws InterruptedException {
        Thread stopper = new Thread(coordinator::stop, "drain-deadline-stopper");
        stopper.setDaemon(true);
        stopper.start();
        long bail = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (stopper.isAlive() && System.nanoTime() < bail) {
            clock.advance(Duration.ofSeconds(6));
            TimeUnit.MILLISECONDS.sleep(25);
        }
        assertThat(stopper.isAlive())
                .as("the drain resolved at the advanced clock — never a wall-clock wait for the budget")
                .isFalse();
        stopper.join(TimeUnit.SECONDS.toMillis(1));
    }

    /**
     * A frozen-by-default, externally advancing {@link Clock} (the OBS-020 injectable-deadline knob):
     * reads return the last advanced instant, so a test threads the deadline from OUTSIDE the walk —
     * the drain's {@code isBefore(deadline)} flips only when the test says so.
     */
    private static final class MutableClock extends Clock {

        private volatile Instant now = Instant.EPOCH;

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /**
     * The throw-path injection (Story 4.3 T6, the 4.2 ledger fold): every {@link #instant()} read
     * throws the caller's failure — the drain body's FIRST clock read (its deadline computation)
     * blows step 3 open. The coordinator's one injectable dependency inside the drain body
     * ({@code RelayStateManager} is final — not stubbable; the clock is the sanctioned seam).
     */
    private static final class ThrowingClock extends Clock {

        private final RuntimeException failure;

        ThrowingClock(RuntimeException failure) {
            this.failure = failure;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            throw failure;
        }
    }

    /**
     * The {@link CoupledRelayHandler#CLOSE_REASON} stash a teardown path left for the
     * {@code channelInactive} site — re-resolved by name (the global {@link AttributeKey} registry
     * hands back the SAME key the relay's protected field holds).
     */
    private static final AttributeKey<CloseReason> CLOSE_REASON =
            AttributeKey.valueOf(CoupledRelayHandler.class, "closeReason");

    private static CloseReason reasonStashedOn(Channel channel) {
        return channel.attr(CLOSE_REASON).get();
    }

    /** A unique-id embedded channel (the ConnectionRegistryTest idiom — no singleton-id key collision). */
    private static EmbeddedChannel channel() {
        return new EmbeddedChannel(DefaultChannelId.newInstance());
    }

    private static SystemId systemId(String value) {
        return new SystemId(new AsciiString(value));
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
