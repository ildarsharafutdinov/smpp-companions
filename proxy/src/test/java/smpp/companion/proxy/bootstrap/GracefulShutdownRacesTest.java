package smpp.companion.proxy.bootstrap;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import com.sun.net.httpserver.HttpsServer;

import io.netty.buffer.PooledByteBufAllocator;
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

import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.observability.CapturingRelayObserver;
import smpp.companion.proxy.observability.CloseReason;
import smpp.companion.proxy.observability.Direction;
import smpp.companion.proxy.relay.MockSmsc;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayServerLifecycle;
import smpp.companion.proxy.security.AdjudicationLifecycle;
import smpp.companion.proxy.security.BindCredential;
import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.security.IdpSslContextFactory;
import smpp.companion.proxy.security.RequestContext;
import smpp.companion.proxy.security.RopcBindCredentialVerifier;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.security.VerdictRequest;
import smpp.companion.proxy.testsupport.RelayTestFixtures;
import smpp.companion.proxy.testsupport.TokenIdpStandIn;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Story 4.2 T4 — the AD-22 walk under RACE, over the REAL stack: a legacy loopback socket through
 * the REAL acceptor and ingress pipeline, the REAL ROPC adapter parked mid-exchange at an in-process
 * TLS stand-in IdP, and the REAL Spring stop order — all five beans ({@code RelayServerLifecycle},
 * {@code AdjudicationLifecycle}, {@code ProxyCompanionLifecycle}, the group bean's
 * {@code destroyMethod="shutdownGracefully"} backstop, the adapter bean's fused {@code close()}
 * backstop) registered in an {@link AnnotationConfigApplicationContext}, whose {@code close()} IS
 * the SIGTERM-equivalent (ContextClosedEvent &rarr; DefaultLifecycleProcessor &rarr;
 * {@code SmartLifecycle.stop} in DESCENDING phase — exactly what the JVM shutdown hook drives; the
 * phase constants, not this test's hand, sequence the walk).
 *
 * <p>The catalog rows landed here:
 * <ul>
 * <li><b>RELAY-023 / OBS-019 — the Allow racing the deny.</b> The bind's token exchange parks at the
 * stand-in's token endpoint (the latch-held adjudication); the walk fires; the pinned outcome:
 * the client receives its non-ROK {@code bind_resp} (the AD-33 {@code ESME_RBINDFAIL} collapse)
 * BEFORE the close, the couple flag never flips ({@code onBindAccept} never fires; the mock SMSC
 * never sees a session — it ANSWERS ROK, so a transient couple cannot hide), the registry empties,
 * the password zeroizes (the caller-owned wipe at the settle), and the verdict settles
 * {@code DenyIndeterminate}. <b>The race's deterministic half:</b> the armed Allow — a VALID 200 +
 * three-segment JWS — completes only AFTER the walk, onto the dead exchange, and resolves NOTHING
 * (the pin completes exactly once, fail-closed first; AD-11). The other half — the 200 landing in
 * the sub-window between the {@code shutdownNow()} and the exchange's own abort — is not
 * deterministically stageable against this story's mechanics (the parked join ignores the deny
 * interrupt by design, and 4.2 carries no new-adjudication gate); landing a verdict in that window
 * is exactly what 4.3's mutation fence + gate will own. Pinned here is what 4.2 owns: the deny on
 * the LIVE loop, the fail-closed settle, and the once-only pin.</li>
 * <li><b>The matrix row "SIGTERM, coupled pairs mid-splice" + AC3's coupled arm.</b> The
 * IMMEDIATE-answer IdP variant lets the bind genuinely COUPLE (token Allow &rarr; egress dial
 * &rarr; the mock's ROK — the only row family in this suite where the couple flag DOES flip); the walk
 * then fires mid-splice and pins the drain body's contract (Story 4.3 T5): neither peer
 * half-closes, so the drain polls the registry to the rig's SHORT drain deadline and
 * force-closes the pair there ({@code SHUTDOWN_DRAIN} stashed on both legs) — both legs die,
 * the registry empties, and the walk still exits inside the meaningful window (the 5s idiom,
 * well under the 30s ceiling). Story 4.3 T6 adds the two proofs that row named as T6's: the
 * RELAY-022 sequenced-splice row (N coupled pairs mid-splice — every accepted PDU lands
 * byte-exact with its sequence number intact, never dropped, duplicated, or truncated by the
 * force-close) and the OBS-020 observer row (the force-close's {@code SHUTDOWN_DRAIN} named on
 * BOTH legs through the {@code CapturingRelayObserver} seam, zero half-flushed bytes on the
 * client leg).</li>
 * <li><b>OBS-021 — zero orphaned adjudication VTs.</b> The catalog's literal "ThreadMXBean
 * snapshot" is unimplementable as written: JEP 444 excludes virtual threads from
 * {@code Thread.getAllStackTraces()}/{@code ThreadMXBean.getAllThreadIds()} (verified empirically
 * on this JDK; the repo's own observability tier documented the same — "the pool counts itself",
 * {@code ResourceMetrics}). The row keeps its intent via the sanctioned VT-visible seam — the
 * adapter's {@code activeAdjudications()} count (incremented at submit, decremented in each pool
 * task's {@code finally}, rejection-compensated: an adjudication VT that survived the walk would
 * hold it &gt; 0) — plus the joined-walk bound: release's {@code awaitTermination} only returns
 * promptly if the pool drained, so a walk that finished well inside the await budget proves no VT
 * outlived it.</li>
 * <li><b>The OBS-016 six-event ordering chain</b> (Story 4.3 T6 — the 4.2 ordering-prefix pin
 * EXTENDED, not re-authored): acceptor-stopped &le; adjudications-denied &le; drain-started &le;
 * drain-completed &le; vt-drained &le; exit. The walk's step gaps (acceptor &rarr; deny &rarr;
 * drain entry) are MILLISECONDS — far under the 5ms poll-cadence jitter the 4.2 row absorbed with
 * seconds-wide budgets — so the first three events are stamped CAUSALLY on the close thread
 * itself: two {@link PhaseStamp} listener beans slotted strictly between the production phases
 * (Spring stops phases strictly descending and awaits each before the next, so an 875-phase
 * stamp can only be taken after the acceptor's stop completed and a 375-phase stamp only after
 * the deny returned), plus the drain's FIRST clock read ({@link DrainStartClock} — the rig
 * constructs the coordinator directly, the deadline's injectable time source is the seam).
 * "Adjudications-denied" is thereby the DENY STEP's completion — the settle of the parked
 * exchange is its bounded async tail (the forked join ignores the interrupt; release's await
 * joins it at step 4), which mechanically lands INSIDE the drain window, after drain-started —
 * pinning the settle there instead would false-RED the spine's own design. The last three events
 * keep the 4.2 polled-probe discipline (monotonic predicates, stamps can only run LATE):
 * drain-completed = the registry reaching zero (the deadline force-close), vt-drained = the VT
 * pool count reaching zero, exit = the shared loop terminated behind the 100ms-quiet quiesce.
 * The row arms the SHORT drain deadline so the force-close lands ~300ms in — a &ge;300ms margin
 * for every arrow the pollers CAN separate. The one pair they cannot: drain-completed and
 * vt-drained are µs-adjacent causal twins BY THE DRAIN'S OWN MECHANICS (the force-close's
 * teardown hygiene {@code cancelHttp()}s the parked exchange inside the same loop iteration that
 * removed its entry — the pin completes on the walk thread and the pool task's finally lands
 * microseconds behind; and from the other side a self-settle empties the registry, so the pool
 * can never outlive the registry by more than that finally) — asserted as one window against
 * drain-started and exit, never against each other, the 4.2 prefix row's own discipline. The 4.2
 * arrows survive transitively: the settle (the pool-count flip) is strictly after the acceptor
 * stamp and strictly before the loop's death.</li>
 * </ul>
 *
 * <p>Timing idiom (the T3 rows): a SHORT {@code oidc.timeout} budget — the parked exchange aborts
 * at its OWN per-request budget (the forked join ignores the deny interrupt), so the walk is
 * deny(&asymp;0) &rarr; abort(500ms) &rarr; settle+continuation &rarr; release-join &rarr; quiesce
 * (100ms quiet) — never Netty's 2s default, always inside the 30s per-phase ceiling.
 * Class-level {@link Timeout} on a separate thread: sockets + a parked stand-in can hang — a stuck
 * walk must FAIL a test, never stall the suite.
 */
@Tag("integration")
@Tag("bootstrap")
@Tag("p1")
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
@DisplayName("Story 4.2 T4 — AD-22 walk races: deny-on-live-loop, VT hygiene, ordering prefix")
@SuppressWarnings("FutureReturnValueIgnored") // reason: the recorder's whenComplete listener is
// fire-and-forget observation — its downstream future is deliberately unobserved (the settle is
// read via the SAME pin future the assertions hold), and the listener itself can never throw.
class GracefulShutdownRacesTest {

    /** The bind_resp wire contract, pinned as LITERALS (the RelayA1SmokeTest discipline). */
    private static final int BIND_TRANSCEIVER = 0x00000009;
    private static final int BIND_TRANSCEIVER_RESP = 0x80000009;

    /** ESME_RBINDFAIL 0x0000000D — the AD-33 generic bind-failure collapse (SMPP 3.4 §5.1.3). */
    private static final int ESME_RBINDFAIL = 0x0000000D;

    /**
     * The SHORT per-request budget (the T3 split-row timing): the parked exchange aborts at its OWN
     * budget — 500ms — and release's await (budget + 1s = 1.5s) JOINS that abort, keeping every walk
     * in this suite fast and its joined-vs-timed-out separation wide (~700ms vs ≥1.6s).
     */
    private static final Duration OIDC_TIMEOUT = Duration.ofMillis(500);

    /**
     * The rig's drain-deadline rule (Story 4.3 T5): the deny rows' parked exchanges settle at their
     * OWN oidc budget and only then (via the continuation's teardown) empty the registry — so the
     * drain must OUTLIVE that settle (oidc + 2s) or the deadline force-close would beat the deny
     * {@code bind_resp} write. This mirrors production's operator contract (drain-timeout 10s vs the
     * documented [2s, 5s] oidc window), just scaled to the rig's budgets.
     */
    private static final Duration COUPLED_DRAIN_DEADLINE = Duration.ofMillis(300);

    @Test
    @DisplayName("RELAY-023/OBS-019: the Allow racing the deny resolves fail-closed — non-ROK bind_resp "
            + "on the live loop, couple never flips, password zeroized; the late armed Allow resolves nothing")
    void allowRacingDenyResolvesFailClosedAndTheClientHoldsTheBindRespError(@TempDir Path dir) throws Exception {
        Rig rig = rig(dir, 1);
        try (Socket legacy = rig.connectLegacy()) {
            writePdu(legacy, bindRequest(7, "legacy1", "pw123456"));
            assertTrue(rig.awaitTokens(),
                    "the adjudication must be in-flight (parked at the token endpoint) when SIGTERM fires");

            rig.ctx.close(); // SIGTERM-equivalent: Spring stops phase 1000 -> 750 -> 0, then the destroy backstops

            // OBS-019: the fail-closed bind_resp reached the client BEFORE the close — the deny's
            // continuation executed on the STILL-LIVE loop (the stranding residue is unreachable).
            assertDenyBindResp(readPdu(legacy), 7);
            assertAtEof(legacy); // "bind_resp error, then close" — the CLOSE listener ran after the write

            // RELAY-023: the couple flag never flipped. The mock ANSWERS ROK, so a couple attempt
            // would surface here: no accept trigger, no SMSC session, no registry entry.
            assertThat(rig.harness.observer().bindAccepts())
                    .as("the latch-held Allow never coupled (no onBindAccept)")
                    .isEmpty();
            assertThat(rig.smsc.sessions())
                    .as("no egress pair ever dialed the SMSC (the couple never began)")
                    .isEmpty();
            assertThat(rig.harness.registry().size())
                    .as("the registry emptied — the deny teardown removed the pair")
                    .isZero();

            // The settle: fail-closed (AD-11) — the deny's forced abort, not a provider verdict.
            assertThat(rig.recorder.requests.get(0).future().getNow(null))
                    .as("a shutdown-denied adjudication settles DenyIndeterminate (AD-11)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            // OBS-019: the password zeroized — the caller-owned wipe at the settle (the SAME backing
            // array the relay handed the verifier; the recording delegate captured it).
            assertThat(zeroized(rig.recorder.credentials.get(0).password().value()))
                    .as("the bind password zeroized on the shutdown-deny path")
                    .isTrue();

            // THE RACE, its deterministic half: the armed Allow — a VALID 200 + three-segment JWS —
            // completes only now, onto the dead exchange (release's http.close() already tore it).
            // The pin completes exactly once, fail-closed first: the Allow resolves NOTHING.
            rig.hold.countDown();
            assertStillAtEof(legacy);
            assertThat(rig.recorder.requests.get(0).future().getNow(null))
                    .as("the late Allow cannot flip the settled pin (completes exactly once — AD-11)")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);
            assertThat(rig.harness.observer().bindAccepts())
                    .as("the couple flag still never flipped after the late Allow")
                    .isEmpty();
            assertThat(rig.smsc.sessions()).as("still no SMSC session").isEmpty();
        } finally {
            rig.close(); // idempotent: releases the parked stand-in handlers, stops everything still up
        }
    }

    @Test
    @DisplayName("matrix 'SIGTERM, coupled pairs mid-splice' + AC3's coupled arm: the drain body "
            + "(4.3 T5) force-closes the still-live pair at the rig's short drain deadline and the "
            + "walk exits inside the window")
    void coupledPairsMidSpliceDrainForceClosesAtTheDeadlineAndExitInsideTheWindow(@TempDir Path dir) throws Exception {
        // The IMMEDIATE-answer IdP variant: the exchange yields Allow, the egress dials, the mock
        // answers ROK — a genuinely COUPLED pair mid-splice when SIGTERM fires.
        Rig rig = rig(dir, 1, false);
        try (Socket legacy = rig.connectLegacy()) {
            byte[] bind = bindRequest(11, "legacy1", "pw123456");
            writePdu(legacy, bind);
            assertRokBindResp(readPdu(legacy), 11); // the full chain: token Allow -> dial -> SMSC ROK

            // The couple REALLY established (the contrast to every other row in this suite): the
            // mock session carries the verbatim bind (AD-14), the pair is live, the flag flipped.
            MockSmsc.Session session = rig.smsc.awaitSession(0);
            assertThat(session.bindFrame())
                    .as("AD-14: the original bind reached the SMSC byte-exact")
                    .isEqualTo(bind);
            assertThat(rig.harness.registry().size())
                    .as("the coupled pair is live mid-splice")
                    .isEqualTo(1);
            assertThat(rig.harness.observer().bindAccepts())
                    .as("the couple flag flipped exactly once")
                    .hasSize(1);

            long start = System.nanoTime();
            rig.ctx.close(); // SIGTERM-equivalent, mid-splice — the drain body owns the live pair now
            long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

            // The drain contract (4.3 T5, coordinator level): neither peer half-closes, so the drain
            // polls to the rig's SHORT deadline (300ms) and force-closes the pair there — both legs
            // closed (SHUTDOWN_DRAIN stashed; never a mid-write truncation: the legs close cleanly
            // while the loop is still live), the registry emptied — and the walk still exits fast:
            // a 300ms drain + an idle-pool deny + an instantly-joined release + the 100ms-quiet
            // quiesce, the Bootstrap 5s idiom, well under the 30s per-phase ceiling.
            assertThat(elapsedMs)
                    .as("the mid-splice walk exits inside the window (the short rig drain deadline "
                            + "force-closed the pair)")
                    .isLessThan(5_000L);
            assertAtEof(legacy); // the ingress leg died at the drain force-close
            awaitTrue("the SMSC session closed by the drain force-close", session::closed); // the egress leg with it
            assertThat(rig.harness.registry().size())
                    .as("the pair is gone from the registry")
                    .isZero();
            assertThat(rig.group.isTerminated())
                    .as("the loop is down — the walk completed")
                    .isTrue();
        } finally {
            rig.close();
        }
    }

    @Test
    @DisplayName("OBS-021: zero orphaned adjudication VTs after the walk — the VT-gauge count cannot "
            + "leak and every parked continuation delivered its deny")
    void zeroOrphanedAdjudicationVtsAfterTheWalk(@TempDir Path dir) throws Exception {
        Rig rig = rig(dir, 3);
        List<Socket> clients = new ArrayList<>();
        try {
            for (int i = 0; i < 3; i++) {
                Socket legacy = rig.connectLegacy();
                clients.add(legacy);
                writePdu(legacy, bindRequest(100 + i, "legacy1", "pw123456"));
            }
            assertTrue(rig.awaitTokens(), "all three adjudications must be in-flight when SIGTERM fires");
            // Sanity (the probe must be ABLE to see them): the pool counts 3 in-flight adjudications.
            assertThat(rig.adapter.activeAdjudications())
                    .as("precondition: three live adjudication VTs (the VT-gauge seam)")
                    .isEqualTo(3);

            long start = System.nanoTime();
            rig.ctx.close(); // the walk: shutdownNow interrupts all three; each aborts at its own budget
            long walkMs = (System.nanoTime() - start) / 1_000_000L;

            // Every cancelled continuation executed on the live loop: each client holds its deny.
            for (int i = 0; i < 3; i++) {
                assertDenyBindResp(readPdu(clients.get(i)), 100 + i);
                assertAtEof(clients.get(i));
            }
            // Zero orphaned adjudication VTs: the count decrements only in each pool task's finally —
            // a surviving VT would hold it > 0 (ThreadMXBean cannot see VTs; JEP 444 — see class doc).
            assertThat(rig.adapter.activeAdjudications())
                    .as("post-walk: zero adjudication VTs survive (OBS-021)")
                    .isZero();
            assertThat(rig.harness.observer().bindAccepts()).isEmpty();
            assertThat(rig.harness.registry().size()).isZero();
            // The joined-walk bound: release's awaitTermination(budget+1s) returned PROMPTLY (the
            // pool drained) — a surviving VT would floor the walk at the full await + the warn.
            assertThat(walkMs)
                    .as("the walk finished inside the release-await budget (the pool provably joined)")
                    .isLessThan(OIDC_TIMEOUT.plusSeconds(1).toMillis());
        } finally {
            clients.forEach(socket -> {
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // teardown best-effort — the walk's own close is what the test asserts
                }
            });
            rig.close();
        }
    }

    @Test
    @DisplayName("OBS-016 six-event chain: acceptor-stopped ≤ adjudications-denied ≤ drain-started ≤ "
            + "drain-completed ≤ vt-drained ≤ exit — causal phase stamps + polled effect stamps, one timeline")
    void theWalksSixEventOrderingChainAcceptorDeniedDrainReleasedExit(@TempDir Path dir) throws Exception {
        // The 4.2 ordering-prefix row EXTENDED to the OBS-016 six-event probe (the frozen block's
        // "extends, not re-authored" — its arrows all survive below, transitively). Budgets: the 3s
        // oidc idiom (4.2 review: the parked exchange self-aborts at its OWN budget, so 500ms would
        // race the watcher arming and the acceptor stop — a pre-close settle would break t3 ≤ t5)
        // PLUS the SHORT drain deadline: the force-close lands ~300ms in, giving the t3 → effect
        // arrows a ≥300ms mechanical margin over the 5ms poll cadence. The deny rows keep oidc + 2s
        // so the force-close cannot beat the deny bind_resp write; THIS row does not read the
        // client's bind_resp (the force-close closes the parked pair's ingress before its
        // continuation could write it — the bind_resp contract is the RELAY-023 row's).
        DrainStartClock clock = new DrainStartClock();
        PhaseStamp acceptorStopped = new PhaseStamp((RelayServerLifecycle.RELAY_ACCEPTOR_PHASE
                + AdjudicationLifecycle.ADJUDICATION_PHASE) / 2);   // 875: strictly acceptor → deny
        PhaseStamp adjudicationsDenied = new PhaseStamp((AdjudicationLifecycle.ADJUDICATION_PHASE
                + ProxyCompanionLifecycle.APP_PHASE) / 2);   // 375: strictly deny → coordinator
        Rig rig = rig(dir, 1, true, Duration.ofSeconds(3), COUPLED_DRAIN_DEADLINE,
                clock, acceptorStopped, adjudicationsDenied);
        ExecutorService watchers = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "shutdown-race-watcher");
            t.setDaemon(true);
            return t;
        });
        try (Socket legacy = rig.connectLegacy()) {
            writePdu(legacy, bindRequest(9, "legacy1", "pw123456"));
            assertTrue(rig.awaitTokens(), "the adjudication must be in-flight when SIGTERM fires");

            // The three EFFECT probes, armed BEFORE the walk (the 4.2 discipline): each stamps the
            // FIRST time its monotonic predicate holds, so a stamp can only run LATE, never early —
            // the asserted chain is conservative. All three predicates are FALSE at arming (the
            // parked pair's optimistic entry holds the registry at 1, its adjudication the pool at 1).
            Future<Long> drainCompleted = watchers.submit(() -> pollStamp(
                    "the registry emptied (the drain force-closed the parked pair at the deadline)",
                    () -> rig.harness.registry().size() == 0));
            Future<Long> vtDrained = watchers.submit(() -> pollStamp(
                    "the adjudication VT pool drained (the force-close's cancelHttp settled the parked exchange)",
                    () -> rig.adapter.activeAdjudications() == 0));
            Future<Long> exitStamp = watchers.submit(() -> pollStamp("the shared relay loop terminated",
                    rig.group::isTerminated));

            rig.ctx.close(); // SIGTERM-equivalent — the phases, not this hand, order the walk

            // The causal close-thread prefix (NO poll jitter): Spring stops phases strictly
            // descending and awaits each phase's stop before the next begins, so the 875 stamp is
            // taken only after the acceptor's stop completed, the 375 stamp only after the deny
            // step returned, and the drain's first clock read (drain-started) only inside the
            // coordinator's stop that follows them all. "Adjudications-denied" is thereby the DENY
            // STEP's completion — the parked exchange's settle is its bounded async tail (joined by
            // release's await at step 4), mechanically INSIDE the drain window by design.
            long t1 = acceptorStopped.stampOrThrow("the acceptor phase completed");
            long t2 = adjudicationsDenied.stampOrThrow("the deny phase completed");
            long t3 = clock.drainStartedOrThrow();
            long t4 = drainCompleted.get(20, TimeUnit.SECONDS);
            long t5 = vtDrained.get(20, TimeUnit.SECONDS);
            long t6 = exitStamp.get(20, TimeUnit.SECONDS);

            // The six-event chain (OBS-016). The prefix is causal (same thread, Spring's phase
            // sequencing) — ≤, exact. The effect arrows carry ≥300ms mechanical margins over the
            // 5ms poll cadence — strict <. The ONE window: drain-completed and vt-drained are
            // µs-adjacent CAUSAL TWINS by the drain's own mechanics — the force-close's teardown
            // hygiene cancelHttp()s the parked exchange's pending verdict INSIDE the same loop
            // iteration that removed its registry entry, so the pin completes on the walk thread
            // and the pool task's finally lands microseconds behind the registry flip (and the
            // alternative ordering — the exchange's own settle emptying the registry — is the same
            // twin pair from the other side: a settle tears down its pair, so the pool can never
            // outlive the registry by more than the finally's µs). They are asserted as one window
            // against t3 and t6, never against each other — the 4.2 prefix row's discipline for
            // exactly this mechanical reason.
            assertThat(t1).as("step 1 -> step 2: the acceptor stopped before the deny phase ran")
                    .isLessThanOrEqualTo(t2);
            assertThat(t2).as("step 2 -> step 3: the deny step completed before the drain began")
                    .isLessThanOrEqualTo(t3);
            assertThat(t3).as("step 3: the drain began before it completed (the deadline force-close)")
                    .isLessThan(t4);
            assertThat(t3).as("step 3: the drain began before the VT pool drained (the twin window's "
                    + "other side)")
                    .isLessThan(t5);
            assertThat(t4).as("the drain-completed/vt-drained twin window closed before the exit "
                    + "(release's await joined the settled pool, then the 100ms-quiet quiesce)")
                    .isLessThan(t6);
            assertThat(t5).as("the VT pool drained before the loop's death (release's await joins it)")
                    .isLessThan(t6);
            // The 4.2 prefix arrows, transitively re-stated (the settle is the pool-count flip the
            // vt-drained probe observed): the acceptor strictly precedes the fail-closed settle...
            assertThat(t1).as("4.2 prefix: the acceptor stopped before the in-flight settle landed")
                    .isLessThan(t5);
            // ...and the settle's verdict is the fail-closed deny, not a provider verdict.
            assertThat(rig.recorder.settleVerdicts.get(0))
                    .as("the settle the pool-drain probe observed is the fail-closed deny")
                    .isInstanceOf(Verdict.DenyIndeterminate.class);

            // The end state the walk owes, and the client-visible outcome (the parked pair was
            // force-closed at the deadline — before its continuation could write the deny
            // bind_resp — so this row pins EOF, not the bind_resp; that contract is the
            // RELAY-023 row's, whose deadline outlives the settle).
            assertThat(rig.group.isTerminated()).as("the walk awaited the loop's death").isTrue();
            assertThat(rig.adapter.activeAdjudications()).isZero();
            assertThat(rig.harness.registry().size()).isZero();
            assertAtEof(legacy);
            // The acceptor REALLY closed (the 4.2 t1 probe, kept as an end-state check — the
            // ordering above no longer needs its poll jitter).
            awaitTrue("the acceptor port freed", () -> portFree(rig.relayPort));
        } finally {
            watchers.shutdownNow();
            rig.close();
        }
    }

    @Test
    @DisplayName("RELAY-022: N coupled pairs mid-splice drain clean — every accepted PDU lands "
            + "byte-exact with its sequence number intact (no drop, no dup, no truncation at the "
            + "force-close), the registry reaches zero, the walk exits inside the window")
    void relay022CoupledPairsMidSpliceDrainWithSequenceIntegrity(@TempDir Path dir) throws Exception {
        Rig rig = rig(dir, 2, false);   // IMMEDIATE-answer IdP: both binds genuinely couple
        try (Socket legacyA = rig.connectLegacy(); Socket legacyB = rig.connectLegacy()) {
            byte[] bindA = bindRequest(21, "legacy1", "pw123456");
            byte[] bindB = bindRequest(22, "legacy1", "pw123456");
            writePdu(legacyA, bindA);
            writePdu(legacyB, bindB);
            assertRokBindResp(readPdu(legacyA), 21);   // the full chain per pair: token Allow -> dial -> SMSC ROK
            assertRokBindResp(readPdu(legacyB), 22);
            assertThat(rig.harness.registry().size())
                    .as("both coupled pairs are live mid-splice")
                    .isEqualTo(2);

            // Match each legacy client to ITS SMSC session by the bind frame it carried (the
            // egress accept order is a race — the RelayA1SmokeTest idiom).
            MockSmsc.Session sessionA = sessionBoundWith(rig, bindA);
            MockSmsc.Session sessionB = sessionBoundWith(rig, bindB);

            // The sequenced splice: three submit_sm per client, distinct sequence numbers, one
            // coalesced write per leg (the framers must preserve the boundaries both ways).
            List<byte[]> spliceA = List.of(submitSm(3101), submitSm(3102), submitSm(3103));
            List<byte[]> spliceB = List.of(submitSm(3201), submitSm(3202), submitSm(3203));
            writeRaw(legacyA, concat(spliceA));
            writeRaw(legacyB, concat(spliceB));
            assertThat(sessionA.awaitPdus(3))
                    .as("pair A's splice landed complete before SIGTERM — no drop, no dup, byte-exact")
                    .containsExactlyElementsOf(spliceA);
            assertThat(sessionB.awaitPdus(3))
                    .as("pair B's splice landed complete before SIGTERM — no drop, no dup, byte-exact")
                    .containsExactlyElementsOf(spliceB);

            // MID-SPLICE: one further PDU per client races the walk — written immediately before
            // ctx.close(), unawaited. Whatever the relay ACCEPTED it relayed whole; whatever it
            // never read never entered the relay (the force-close cannot lose an accepted PDU).
            byte[] tailA = submitSm(3104);
            byte[] tailB = submitSm(3204);
            writeRaw(legacyA, tailA);
            writeRaw(legacyB, tailB);

            long start = System.nanoTime();
            rig.ctx.close(); // SIGTERM-equivalent, mid-splice — the drain body owns both pairs now
            long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

            // The bounded exit (OBS-020's coordinator half): neither peer half-closes, so both
            // pairs force-close at the rig's SHORT deadline and the walk still finishes fast.
            assertThat(elapsedMs)
                    .as("the mid-splice walk over two pairs exits inside the window")
                    .isLessThan(5_000L);
            // Drain integrity, per pair: the SMSC-side stream is the exact sequenced splice plus
            // OPTIONALLY the racing tail — a prefix of what was written, every frame byte-exact
            // (a truncated or corrupted write surfaces as a frame that is not the sent bytes; a
            // dropped completed PDU surfaces as a hole the sequence ledger exposes).
            assertDrainedSequence(sessionA.received(), spliceA, tailA, "pair A");
            assertDrainedSequence(sessionB.received(), spliceB, tailB, "pair B");
            // The registry emptied and both legs of both pairs died.
            assertThat(rig.harness.registry().size())
                    .as("RELAY-022: the registry reached zero")
                    .isZero();
            assertThat(rig.group.isTerminated())
                    .as("the loop is down — the walk completed")
                    .isTrue();
        } finally {
            rig.close();
        }
    }

    @Test
    @DisplayName("OBS-020 races row: a peer that never FINs is force-closed at the SHORT drain "
            + "deadline — SHUTDOWN_DRAIN observed on BOTH legs through the observer seam, zero "
            + "half-flushed bytes on the client leg, exit bounded")
    void obs020PeerThatNeverHalfClosesIsForceClosedAsShutdownDrainObserved(@TempDir Path dir) throws Exception {
        Rig rig = rig(dir, 1, false);   // the IMMEDIATE-answer IdP — a genuinely coupled pair
        try (Socket legacy = rig.connectLegacy()) {
            byte[] bind = bindRequest(31, "legacy1", "pw123456");
            writePdu(legacy, bind);
            assertRokBindResp(readPdu(legacy), 31);
            MockSmsc.Session session = rig.smsc.awaitSession(0);

            // Mid-splice traffic through the pair (both directions have carried frames when the
            // walk fires — the force-close closes a BUSY splice, not an idle socket).
            byte[] submit = submitSm(3301);
            writeRaw(legacy, submit);
            assertThat(session.awaitPdus(1))
                    .as("the splice PDU crossed the pair byte-exact before SIGTERM")
                    .containsExactly(submit);

            long start = System.nanoTime();
            rig.ctx.close(); // SIGTERM-equivalent — neither peer will ever half-close
            long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

            assertThat(elapsedMs)
                    .as("the peer that never FINs cannot hang the exit — force-closed AT the deadline")
                    .isLessThan(5_000L);

            // The observer seam: BOTH legs' closes name the drain — exactly two onConnectionClosed
            // fires (exactly-once per channel), one per direction, both SHUTDOWN_DRAIN, never the
            // OTHER catch-all (the stash the force-close left for the channelInactive site).
            awaitTrue("both legs fired their exactly-once onConnectionClosed",
                    () -> rig.harness.observer().connectionCloses().size() >= 2);
            assertThat(rig.harness.observer().connectionCloses())
                    .as("OBS-020: the deadline force-close is named SHUTDOWN_DRAIN on both legs")
                    .containsExactlyInAnyOrder(
                            new CapturingRelayObserver.ConnectionClose(Direction.INGRESS, CloseReason.SHUTDOWN_DRAIN),
                            new CapturingRelayObserver.ConnectionClose(Direction.EGRESS, CloseReason.SHUTDOWN_DRAIN));

            // NO HALF-FLUSHED FRAME on the client leg: everything the relay ever wrote toward the
            // client was read whole (the ROK bind_resp above); the force-close must leave ZERO
            // residue — a truncated mid-write PDU would surface as stray bytes before the EOF.
            assertThat(bytesUntilEof(legacy))
                    .as("the force-close left no partial frame on the client leg")
                    .isZero();
            awaitTrue("the SMSC session closed by the drain force-close", session::closed);
            assertThat(rig.harness.registry().size())
                    .as("the force-closed pair is gone from the registry")
                    .isZero();
            assertThat(rig.group.isTerminated())
                    .as("the loop is down — the walk completed")
                    .isTrue();
        } finally {
            rig.close();
        }
    }

    // ── the rig: the real stack wired into a real Spring stop order ───────────────────────────

    /** Everything one row needs; {@link #close()} is idempotent and exception-safe. */
    private record Rig(
            MockSmsc smsc,
            HttpsServer idp,
            CountDownLatch tokenReceived,
            CountDownLatch hold,
            EventLoopGroup group,
            RopcBindCredentialVerifier adapter,
            RecordingVerifier recorder,
            RelayTestFixtures.RelayHarness harness,
            RelayServerLifecycle relay,
            AdjudicationLifecycle adjudication,
            ProxyCompanionLifecycle coordinator,
            AnnotationConfigApplicationContext ctx,
            int relayPort) {

        /** A legacy loopback client on the real acceptor (the RelayA1SmokeTest idiom). */
        Socket connectLegacy() throws IOException {
            Socket socket = new Socket(InetAddress.getLoopbackAddress(), relayPort);
            socket.setSoTimeout(4_000);
            return socket;
        }

        /** Waits until the stand-in IdP has parked every expected token exchange. */
        boolean awaitTokens() throws InterruptedException {
            // the shared latch was sized at rig build: each parked exchange counts it down once
            return tokenReceived.await(5, TimeUnit.SECONDS);
        }

        /** Best-effort, idempotent teardown — never strands the port, the IdP, the mock, or the loop. */
        void close() {
            hold.countDown(); // release any parked stand-in handlers
            try {
                idp.stop(0);
            } catch (Exception ignored) {
                // already stopped
            }
            try {
                smsc.close();
            } catch (Exception ignored) {
                // already closed
            }
            try {
                ctx.close(); // idempotent (the walk's normal path already closed it)
            } catch (Exception ignored) {
                // a failed refresh/close must not mask the test's own assertion
            }
            group.shutdownGracefully().syncUninterruptibly(); // re-fire: a no-op after the walk
        }
    }

    /**
     * The race rows' rig: the PARKED-allow stand-in IdP (the latch-held adjudication).
     * See {@link #rig(Path, int, boolean)}.
     */
    private static Rig rig(Path dir, int tokenCount) throws IOException {
        return rig(dir, tokenCount, true, OIDC_TIMEOUT);
    }

    private static Rig rig(Path dir, int tokenCount, boolean park) throws IOException {
        return park ? rig(dir, tokenCount, park, OIDC_TIMEOUT)
                : rig(dir, tokenCount, park, OIDC_TIMEOUT, COUPLED_DRAIN_DEADLINE);
    }

    /**
     * The deny-row default: the drain deadline outlives the parked exchanges' own settle (see
     * {@link #COUPLED_DRAIN_DEADLINE}) — oidc + 2s.
     */
    private static Rig rig(Path dir, int tokenCount, boolean park, Duration oidcTimeout) throws IOException {
        return rig(dir, tokenCount, park, oidcTimeout, oidcTimeout.plusSeconds(2));
    }

    /**
     * Builds the whole rig: the mock SMSC (it ANSWERS ROK — a couple attempt cannot hide), the
     * stand-in IdP (PARKED for the race rows, IMMEDIATE for the coupled-pairs rows), the shared
     * loop, the REAL adapter, the real ingress wiring behind a {@link RecordingVerifier} (the
     * relay-facing half — production wires ONE verifier bean; the recorder is a pass-through that
     * only captures the credential and the settle, the OBS-019 tooling), and the three lifecycles
     * + the two destroy backstops as Spring beans so {@code ctx.close()} walks the REAL phase
     * order. Story 4.3 T6: the coordinator's {@link Clock} is caller-injectable (the drain-started
     * probe — a {@link DrainStartClock} stamps the drain body's first deadline read) and extra
     * {@link SmartLifecycle} listener beans (the OBS-016 {@link PhaseStamp}s) slot between the
     * production phases.
     */
    private static Rig rig(Path dir, int tokenCount, boolean park, Duration oidcTimeout,
            Duration drainDeadline) throws IOException {
        return rig(dir, tokenCount, park, oidcTimeout, drainDeadline, Clock.systemUTC());
    }

    private static Rig rig(Path dir, int tokenCount, boolean park, Duration oidcTimeout,
            Duration drainDeadline, Clock clock, SmartLifecycle... extraLifecycles) throws IOException {
        MockSmsc smsc = MockSmsc.start();
        CountDownLatch tokenReceived = new CountDownLatch(tokenCount);
        CountDownLatch hold = new CountDownLatch(1);
        HttpsServer idp = TokenIdpStandIn.allowIdp(tokenReceived, hold, park, "shutdown-race-idp");
        EventLoopGroup group = new MultiThreadIoEventLoopGroup(
                // daemon: a test that times out wedged inside the uninterruptible walk never runs its
                // finally — a non-daemon loop thread would then outlive the failure and hang the JVM.
                1, new DefaultThreadFactory("shutdown-race-relay", true), NioIoHandler.newFactory());
        AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext();
        try {
            // concurrent-pairs 8 (>= the row's binds): the F13 acceptor cap shares this number. The
            // drain deadline: oidc + 2s for the deny rows (the parked exchanges must settle and
            // empty the registry BEFORE any force-close), the SHORT 300ms knob for the coupled rows
            // (their pairs never drain — the force-close is the point there).
            ProxyCompanionProperties properties = RelayTestFixtures.reverseBProperties(
                    dir, TokenIdpStandIn.realmBase(idp), RelayTestFixtures.freePort(), 8,
                    "127.0.0.1", smsc.port(), oidcTimeout, drainDeadline);
            IdpSslContextFactory tlsFactory = new IdpSslContextFactory(properties);
            RopcBindCredentialVerifier adapter = new RopcBindCredentialVerifier(tlsFactory);
            RecordingVerifier recorder = new RecordingVerifier(adapter);
            RelayTestFixtures.RelayHarness harness = RelayTestFixtures.relayHarness(properties, recorder);
            RelayServerLifecycle relay = new RelayServerLifecycle(properties, group,
                    new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT),
                    harness.ingressInitializer(), harness.gate());
            AdjudicationLifecycle adjudication = new AdjudicationLifecycle(adapter);
            // Story 4.3 T5 re-sign: the coordinator's drain reads the SAME registry/manager the
            // initializers wired (the harness's shared beans — the wiring Spring guarantees by
            // component scan) and polls the properties' drain deadline on the caller's clock
            // (system time everywhere except the six-event row's DrainStartClock).
            ProxyCompanionLifecycle coordinator = new ProxyCompanionLifecycle(adapter, group,
                    harness.registry(), harness.manager(), properties.shutdown(), clock);

            // The production bean set the stop order needs — the group bean's destroyMethod backstop
            // (RelayNettyConfig) and the adapter bean's fused close() backstop included, so a full
            // close() exercises their re-fire-as-no-op contract too.
            ctx.registerBean(EventLoopGroup.class, () -> group,
                    bd -> ((AbstractBeanDefinition) bd).setDestroyMethodName("shutdownGracefully"));
            ctx.registerBean(RopcBindCredentialVerifier.class, () -> adapter,
                    bd -> ((AbstractBeanDefinition) bd).setDestroyMethodName("close"));
            ctx.registerBean(RelayServerLifecycle.class, () -> relay);
            ctx.registerBean(AdjudicationLifecycle.class, () -> adjudication);
            ctx.registerBean(ProxyCompanionLifecycle.class, () -> coordinator);
            for (SmartLifecycle extra : extraLifecycles) {
                // The OBS-016 PhaseStamp listeners — named beans (several may share the interface),
                // registered in whatever phase slots the row chose between the production phases.
                ctx.registerBean("walk-phase-stamp-" + extra.getPhase(), SmartLifecycle.class, () -> extra);
            }
            ctx.refresh(); // starts ascending (coordinator 0, deny window 750, acceptor 1000 — the port binds)

            assertThat(relay.isRunning()).as("precondition: the real acceptor is up").isTrue();
            return new Rig(smsc, idp, tokenReceived, hold, group, adapter, recorder, harness,
                    relay, adjudication, coordinator, ctx, properties.bind().port());
        } catch (RuntimeException | Error e) {
            // A rig that fails to build must not strand what it already created (4.2 review): the
            // caller's try/finally never engages when the rig never returns — release it HERE.
            hold.countDown();
            try {
                ctx.close();   // safe unrefreshed (a no-op); walks the stop order if refresh half-ran
            } catch (Exception ignored) {
                // teardown best-effort — the build failure is the signal
            }
            try {
                idp.stop(0);
            } catch (Exception ignored) {
                // already stopped
            }
            try {
                smsc.close();
            } catch (Exception ignored) {
                // already closed
            }
            group.shutdownGracefully().syncUninterruptibly();
            throw e;
        }
    }

    /**
     * The relay-facing verifier: a pass-through over the REAL adapter that records the credential
     * (the OBS-019 password-zeroize probe — the SAME backing array the relay's settle wipe zeroes)
     * and the verdict request (stamping the settle BEFORE the relay registers its own continuation,
     * so the ordering probe sees the settle no later than the relay does). The LIFECYCLES keep the
     * raw adapter — {@code AdjudicationLifecycle}'s deny and the coordinator's halves must fire on
     * the real pool (their {@code instanceof RopcBindCredentialVerifier} key).
     */
    private static final class RecordingVerifier implements BindCredentialVerifier {

        private final RopcBindCredentialVerifier delegate;

        /** Every credential the relay adjudicated, in arrival order (the zeroize probe reads these). */
        final List<BindCredential> credentials = new CopyOnWriteArrayList<>();

        /** Every verdict request returned to the relay, in arrival order. */
        final List<VerdictRequest> requests = new CopyOnWriteArrayList<>();

        /** NanoTime of each settle, stamped by a listener registered before the relay's own. */
        final List<Long> settleStamps = new CopyOnWriteArrayList<>();

        /** What each settle carried (the verdict, or the exceptional future's error). */
        final List<Object> settleVerdicts = new CopyOnWriteArrayList<>();

        RecordingVerifier(RopcBindCredentialVerifier delegate) {
            this.delegate = delegate;
        }

        @Override
        public VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx) {
            credentials.add(cred);
            VerdictRequest request = delegate.verify(cred, ctx);
            requests.add(request);
            request.future().whenComplete((verdict, error) -> {
                settleStamps.add(System.nanoTime());
                settleVerdicts.add(error != null ? error : verdict);
            });
            return request;
        }
    }

    // ── probes, stamps, and hand-authored wire bytes (the RelayA1SmokeTest idiom) ────────────

    /**
     * Bounded poll for a monotonic predicate (the {@code MockSmsc.pollUntil} idiom — that helper
     * is package-private to {@code relay/}, so this suite carries its own): awaits {@code probe},
     * failing after 5s rather than hanging.
     */
    private static void awaitTrue(String what, BooleanSupplier probe) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!probe.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("never observed: " + what);
            }
            try {
                Thread.sleep(5);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("interrupted while awaiting: " + what, e);
            }
        }
    }

    /** Polls {@code probe} every 5ms until it holds; returns the stamp (fails, never hangs). */
    private static long pollStamp(String what, BooleanSupplier probe) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        while (!probe.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("the walk watcher never observed: " + what);
            }
            try {
                Thread.sleep(5);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("interrupted while watching: " + what, e);
            }
        }
        return System.nanoTime();
    }

    /**
     * {@code true} iff the port can be (re)bound by a LISTENER — the acceptor REALLY closed it
     * (Netty 4.2 completes the close future ~ms before the OS releases the listen socket, which
     * the poller rides out; a genuinely-held port never binds). SO_REUSEADDR on the probe (set
     * before bind): a TIME_WAIT left by a connection the port legitimately served must not fail
     * the probe, while an actual LISTENER (what the pin is about) still refuses.
     */
    private static boolean portFree(int port) {
        try (ServerSocket ignored = RelayTestFixtures.rebindableProbe(port)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    // ── the OBS-016 six-event probes: the causal close-thread stamps (4.3 T6) ─────────────────

    /**
     * The drain-started stamp (OBS-016 event 3): a pass-through {@link Clock} that records the
     * nanoTime of its FIRST {@link #instant()} read — the drain body's deadline computation, the
     * first thing it does once the snapshot read found the registry non-empty (the empty-arm no-op
     * never touches the clock, so an unstamped clock also proves the no-op). The read runs ON the
     * close thread inside the coordinator's {@code stop()}, so the stamp carries no poll jitter —
     * the spec's "a decorated registry stamping the first snapshot", realized on the deadline's
     * injectable time source instead ({@code ConnectionRegistry} is final; the clock is the
     * coordinator's own injectable seam and stamps one call later, the same instant for ordering).
     */
    private static final class DrainStartClock extends Clock {

        private final Clock delegate = Clock.systemUTC();
        private final AtomicLong firstReadNanos = new AtomicLong(Long.MIN_VALUE);

        @Override
        public ZoneId getZone() {
            return delegate.getZone();
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            firstReadNanos.compareAndSet(Long.MIN_VALUE, System.nanoTime());
            return delegate.instant();   // real time — the deadline arithmetic stays wall-clock true
        }

        long drainStartedOrThrow() {
            long stamp = firstReadNanos.get();
            assertThat(stamp)
                    .as("the drain body opened its deadline window (its first clock read ran)")
                    .isNotEqualTo(Long.MIN_VALUE);
            return stamp;
        }
    }

    /**
     * One causal phase stamp (the OBS-016 "capturing lifecycle listener"): a trivial
     * {@link SmartLifecycle} whose {@code stop()} records one nanoTime. Spring stops phases
     * strictly descending and awaits each phase's stop before the next begins, so a bean slotted
     * strictly between two production phases stamps, ON THE CLOSE THREAD, provably after the
     * earlier phase completed and before the later one began — the millisecond step gaps of the
     * walk (acceptor &rarr; deny &rarr; drain) made causal, where the 4.2 polled probes could only
     * be as fine as their 5ms cadence.
     */
    private static final class PhaseStamp implements SmartLifecycle {

        private final int phase;
        private volatile boolean running;
        private final AtomicLong stamp = new AtomicLong(Long.MIN_VALUE);

        PhaseStamp(int phase) {
            this.phase = phase;
        }

        @Override
        public void start() {
            running = true;
        }

        @Override
        public void stop() {
            running = false;
            stamp.compareAndSet(Long.MIN_VALUE, System.nanoTime());
        }

        @Override
        public boolean isRunning() {
            return running;
        }

        @Override
        public int getPhase() {
            return phase;
        }

        long stampOrThrow(String what) {
            long value = stamp.get();
            assertThat(value)
                    .as("the walk completed the phase this listener stamps (%s)", what)
                    .isNotEqualTo(Long.MIN_VALUE);
            return value;
        }
    }

    // ── splice helpers (RELAY-022 / OBS-020 — the RelayA1SmokeTest idioms, this suite's copies) ──

    /** A hand-authored opaque {@code submit_sm} (raw bytes — independent of the codec under test). */
    private static byte[] submitSm(int sequence) {
        byte[] body = ascii("SUBMIT-" + sequence);
        return assemble(0x00000004, 0, sequence, body.length, out -> out.put(body));
    }

    /** Writes raw bytes (several coalesced PDUs) — the framer under test owns the boundaries. */
    private static void writeRaw(Socket socket, byte[] bytes) throws IOException {
        socket.getOutputStream().write(bytes);
        socket.getOutputStream().flush();
    }

    private static byte[] concat(List<byte[]> pdus) {
        int total = 0;
        for (byte[] pdu : pdus) {
            total += pdu.length;
        }
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] pdu : pdus) {
            System.arraycopy(pdu, 0, out, pos, pdu.length);
            pos += pdu.length;
        }
        return out;
    }

    /** The {@code sequence_number} header field (offset 12) of a framed PDU — the integrity ledger key. */
    private static int sequenceOf(byte[] pdu) {
        return ByteBuffer.wrap(pdu).getInt(12);
    }

    /** The SMSC session whose bind frame is byte-exactly {@code bind} (the accept order is a race). */
    private static MockSmsc.Session sessionBoundWith(Rig rig, byte[] bind) {
        rig.smsc.awaitSession(1);   // bounded-wait until BOTH egress sessions exist, then match by content
        return rig.smsc.sessions().stream()
                .filter(session -> Arrays.equals(session.bindFrame(), bind))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no SMSC session carried the expected bind frame"));
    }

    /**
     * RELAY-022's per-pair integrity ledger: the drained stream must be the awaited splice,
     * byte-exact and in sequence order, plus OPTIONALLY the PDU that raced the walk (accepted whole
     * or never accepted — a force-close can lose neither a completed relay nor a frame's tail).
     */
    private static void assertDrainedSequence(List<byte[]> drained, List<byte[]> splice, byte[] racingTail,
            String which) {
        assertThat(drained.size())
                .as("%s: the drained stream is the splice, at most plus the racing tail PDU", which)
                .isBetween(splice.size(), splice.size() + 1);
        List<byte[]> expected = new ArrayList<>(splice);
        if (drained.size() == splice.size() + 1) {
            expected.add(racingTail);
        }
        assertThat(drained)
                .as("%s: no drop, no duplicate, no corruption — every drained frame byte-exact", which)
                .containsExactlyElementsOf(expected);
        // The sequence ledger, stated on the parsed field (byte-equality implies it; parsing names it):
        assertThat(drained.stream().mapToInt(GracefulShutdownRacesTest::sequenceOf).toArray())
                .as("%s: the drained sequence_numbers are intact and in order", which)
                .containsExactly(expected.stream().mapToInt(GracefulShutdownRacesTest::sequenceOf).toArray());
    }

    /**
     * Bytes still readable before EOF — zero when the relay wrote nothing partial: every complete
     * PDU toward the client was read whole beforehand, so a truncated mid-write frame would surface
     * exactly here (the OBS-020 "no half-flushed frame" probe, client leg).
     */
    private static int bytesUntilEof(Socket socket) throws IOException {
        socket.setSoTimeout(2_000);
        InputStream in = socket.getInputStream();
        int total = 0;
        int read;
        while ((read = in.read()) >= 0) {
            total += read;
        }
        return total;
    }

    /** {@code true} iff every value octet of the (shared-backing) password {@link AsciiString} is zero. */
    private static boolean zeroized(AsciiString value) {
        byte[] array = value.array();
        for (int i = value.arrayOffset(); i < value.arrayOffset() + value.length(); i++) {
            if (array[i] != 0) {
                return false;
            }
        }
        return true;
    }

    /** A hand-authored {@code bind_transceiver} (raw bytes — independent of the codec under test). */
    private static byte[] bindRequest(int sequence, String systemId, String password) {
        byte[] id = ascii(systemId);
        byte[] pw = ascii(password);
        byte[] type = ascii("SMPP");
        byte[] range = ascii("");
        int body = (id.length + 1) + (pw.length + 1) + (type.length + 1) + 3 + (range.length + 1);
        return assemble(BIND_TRANSCEIVER, 0, sequence, body, out -> {
            out.put(id).put((byte) 0);
            out.put(pw).put((byte) 0);
            out.put(type).put((byte) 0);
            out.put((byte) 0x34).put((byte) 0).put((byte) 0);
            out.put(range).put((byte) 0);
        });
    }

    private interface BodyWriter {
        void writeTo(ByteBuffer out);
    }

    private static byte[] assemble(int commandId, int commandStatus, int sequence, int bodyLen,
            BodyWriter writer) {
        ByteBuffer out = ByteBuffer.allocate(16 + bodyLen);
        out.putInt(16 + bodyLen).putInt(commandId).putInt(commandStatus).putInt(sequence);
        writer.writeTo(out);
        return out.array();
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    // ── raw-socket PDU I/O + the pinned deny contract (literals, independent of production) ───

    private static void writePdu(Socket socket, byte[] pdu) throws IOException {
        socket.getOutputStream().write(pdu);
        socket.getOutputStream().flush();
    }

    /** Reads exactly ONE framed PDU (16-octet header, then {@code command_length - 16} body octets). */
    private static byte[] readPdu(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        byte[] header = in.readNBytes(16);
        if (header.length < 16) {
            throw new EOFException("peer closed mid-header (expected a complete framed PDU)");
        }
        int commandLength = ByteBuffer.wrap(header).getInt(0);
        // Sanity bounds (4.2 review): < 16 is unframed; > 64KB cannot be a bind_resp this suite
        // reads — a garbage frame from the relay under test must FAIL THE READ, never steer a
        // copyOf into a ~2GB allocation that OOMs the test JVM instead of failing the test.
        if (commandLength < 16 || commandLength > 65_536) {
            throw new IOException("nonsense command_length " + commandLength + " on the wire");
        }
        byte[] pdu = java.util.Arrays.copyOf(header, commandLength);
        int body = in.readNBytes(pdu, 16, commandLength - 16);
        if (body < commandLength - 16) {
            throw new EOFException("peer closed mid-body (partial frame reached the wire!)");
        }
        return pdu;
    }

    /** The pinned ROK contract (the RelayA1SmokeTest literals) — the couple's premise at this leg. */
    private static void assertRokBindResp(byte[] resp, int expectedSequence) {
        ByteBuffer header = ByteBuffer.wrap(resp);
        int commandLength = header.getInt(0);
        int commandId = header.getInt(4);
        int commandStatus = header.getInt(8);
        int sequence = header.getInt(12);
        assertThat(commandLength).as("the resp's command_length covers the whole PDU").isEqualTo(resp.length);
        assertThat(commandId).as("bind_transceiver answered by bind_transceiver_resp")
                .isEqualTo(BIND_TRANSCEIVER_RESP);
        assertThat(commandStatus).as("ESME_ROK — the SMSC's verbatim answer reached the client (the couple)")
                .isZero();
        assertThat(sequence).as("the resp answers the request's sequence_number").isEqualTo(expectedSequence);
    }

    /** The pinned AD-33 deny contract, asserted on LITERALS (independent of the production constants). */
    private static void assertDenyBindResp(byte[] resp, int expectedSequence) {
        ByteBuffer header = ByteBuffer.wrap(resp);
        int commandLength = header.getInt(0);
        int commandId = header.getInt(4);
        int commandStatus = header.getInt(8);
        int sequence = header.getInt(12);
        assertThat(commandLength).as("the deny is the ONE header-only 16-octet PDU the relay builds")
                .isEqualTo(16).isEqualTo(resp.length);
        assertThat(commandId).as("bind_transceiver answered by bind_transceiver_resp")
                .isEqualTo(BIND_TRANSCEIVER_RESP);
        assertThat(commandStatus).as("non-ROK: ESME_RBINDFAIL — the AD-33 generic fail-closed deny")
                .isEqualTo(ESME_RBINDFAIL);
        assertThat(sequence).as("the deny answers the request's sequence_number").isEqualTo(expectedSequence);
    }

    /** The relay closed AFTER writing the deny ("bind_resp error, then close"). */
    private static void assertAtEof(Socket socket) throws IOException {
        socket.setSoTimeout(2_000);
        assertThat(socket.getInputStream().read())
                .as("the relay closed the leg after the deny write (never before it)")
                .isEqualTo(-1);
    }

    /** Nothing further EVER arrives on the closed leg (the late Allow reached no one). */
    private static void assertStillAtEof(Socket socket) throws IOException {
        assertAtEof(socket);
    }
}
