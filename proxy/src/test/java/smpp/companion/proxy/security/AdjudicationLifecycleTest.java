package smpp.companion.proxy.security;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

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
import smpp.companion.proxy.testsupport.RelayTestFixtures;
import smpp.companion.proxy.testsupport.TokenIdpStandIn;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AC1 (Story 3.2 T7; phase pin re-authored by Story 4.2 T1) — {@link AdjudicationLifecycle}: the
 * AD-22 phase discipline (the deny window strictly between the relay acceptor's stop phase and the
 * metrics endpoint's scrape-late window — the acceptor closes first, the final scrape still sees
 * the deny), the running-flag / callback / idempotence contract (the {@code RelayServerLifecycle}
 * house pattern), and the load-bearing stop body — a stop during an in-flight adjudication DENIES
 * it: {@code stop()} runs the adapter's deny ALONE (4.2 T3 — release-await is the app-phase
 * coordinator's), so the DENY is synchronous with {@code stop()} (the pool is down before it
 * returns; every post-stop verify settles fail-closed with no wait — use-after-close) while the
 * in-flight settle lands BOUNDED, at the exchange's own per-request abort, never awaited here.
 * The 4.2 T1 deny/release SPLIT is pinned alongside: {@code deny()} alone
 * settles the in-flight adjudication fail-closed (bounded, not synchronous — the await lives in
 * the release half), and {@code release()} / the fused {@code close()} re-firing after the split
 * sequence are no-ops (the destroy-method backstop contract).
 *
 * <p>The deny-in-flight cases drive the REAL adapter over a parked in-process TLS stand-in IdP (the
 * {@code RopcBindCredentialVerifierTest} pattern, compact): the bind's token exchange is parked on
 * a latch, so the ONLY thing that can settle it inside the window is the deny path — the parked
 * exchange aborts at its OWN per-request budget (the forked {@code CompletableFuture} join ignores
 * the deny interrupt; the pin settles fail-closed with the abort); the lifecycle stop() denies
 * WITHOUT awaiting (the await is the coordinator's release half, 4.2 T3).
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AC1 — AdjudicationLifecycle: AD-22 phase + idempotent stop + deny-in-flight drain")
class AdjudicationLifecycleTest {

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
    @DisplayName("stop() DENIES in-flight adjudications synchronously (deny-only, 4.2 T3); the settle lands bounded fail-closed")
    void stopDeniesInFlightAdjudications(@TempDir Path dir) throws Exception {
        CountDownLatch tokenReceived = new CountDownLatch(1);
        CountDownLatch hold = new CountDownLatch(1);
        HttpsServer server = TokenIdpStandIn.parkedTokenIdp(tokenReceived, hold, "lifecycle-idp");
        try {
            // 6s budget (4.2 review, up from 4s): the isDone()==false pin below races the exchange's
            // OWN self-abort budget — a loaded runner stalling the test thread past the budget would
            // settle the pin early and false-fail the no-await boolean. 6s makes that stall window
            // unreachable while the get(10s) backstop still bounds the row.
            ProxyCompanionProperties props = RelayTestFixtures.reverseBProperties(
                    dir, TokenIdpStandIn.realmBase(server), Duration.ofSeconds(6));
            IdpSslContextFactory tlsFactory = new IdpSslContextFactory(props);
            RopcBindCredentialVerifier adapter = new RopcBindCredentialVerifier(tlsFactory);
            AdjudicationLifecycle lifecycle = new AdjudicationLifecycle(adapter);
            lifecycle.start();

            VerdictRequest inFlight = ScopedValue.where(CTX, rc()).call(() -> adapter.verify(credential(), CTX));
            assertTrue(tokenReceived.await(5, TimeUnit.SECONDS),
                    "the adjudication must be in-flight (parked at the token endpoint) when stop() fires");

            lifecycle.stop();

            // stop() runs the adapter's deny ALONE (4.2 T3 — the release half moved to the
            // app-phase coordinator, sequenced behind the empty drain seam): shutdownNow fired
            // INSIDE stop(), but NO await ran here — so the in-flight settle is still PENDING the
            // instant stop() returns. The boolean pin that the fused await left this stop: a fused
            // close() would have blocked on the parked task's ~6s abort before returning.
            assertThat(inFlight.future().isDone())
                    .as("the lifecycle stop carries no await (4.2 T3) — the settle is still pending "
                            + "at stop() return")
                    .isFalse();
            // The deny DID fire synchronously: the pool is down, so a post-stop verify is rejected
            // and settles fail-closed SYNCHRONOUSLY (no wire call, no wait — use-after-close).
            assertThat(ScopedValue.where(CTX, rc()).call(() -> adapter.verify(credential(), CTX)).future().getNow(null))
                    .as("stop() denies synchronously: every post-stop verify settles fail-closed")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            // ...and the parked exchange aborts at its OWN 6s per-request budget (the forked join
            // ignores the deny interrupt), settling the pin fail-closed — bounded, never awaited
            // by the stop (the await that JOINS it is the coordinator's release step).
            assertThat(inFlight.future().get(10, TimeUnit.SECONDS))
                    .as("a shutdown-denied adjudication settles fail-closed at its own abort budget (AD-11)")
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
        HttpsServer server = TokenIdpStandIn.parkedTokenIdp(tokenReceived, hold, "lifecycle-idp");
        try {
            // SHORT per-request budget for this row: the settle lands when the parked exchange
            // aborts at its OWN budget (the forked join ignores the deny interrupt — the fused
            // row's 4s duration proves the timing), so a 500ms budget keeps deny()-alone fast.
            ProxyCompanionProperties props = RelayTestFixtures.reverseBProperties(
                    dir, TokenIdpStandIn.realmBase(server), Duration.ofMillis(500));
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

    // ── fixtures (the stand-in IdP and the reverse×B record live in testsupport — 4.3 T2) ─────

    private static BindCredential credential() {
        return new BindCredential(new SystemId(new AsciiString("testuser")), new Password(new AsciiString("testpass")));
    }

    /** The deadline must outlive the test window — the per-REQUEST budget (oidc.timeout) is the real bound. */
    private static RequestContext rc() {
        return new RequestContext(new SystemId(new AsciiString("testuser")),
                DefaultChannelId.newInstance(), Instant.now().plusSeconds(30));
    }
}
