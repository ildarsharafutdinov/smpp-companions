package smpp.companion.proxy.relay;

import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Timeout.ThreadMode;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelOption;
import io.netty.channel.ConnectTimeoutException;
import io.netty.channel.DefaultChannelId;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;
import io.netty.util.concurrent.ScheduledFuture;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrame;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.observability.CapturingRelayObserver;
import smpp.companion.proxy.observability.CloseReason;
import smpp.companion.proxy.observability.Direction;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.relay.netty.RelayEgressInitializer;
import smpp.companion.proxy.tls.SmppLegTlsFactory;
import smpp.companion.proxy.security.BindCredential;
import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.security.RequestContext;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.security.VerdictRequest;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 2.2 Task 7 / AC2 &mdash; the {@code BindInterceptor} bind-handshake contract: verifier gating
 * (AD-12/AD-15), the AD-33 denial collapse, the AD-14 verbatim original-frame forward, the AD-25
 * forwarder split ({@code BindInterceptor} forwards {@code bind_*_resp}), caller-owned zeroize, and
 * RELAY-004's deterministic retry-bind rejection.
 *
 * <p>Every test drives a REAL pipeline ({@code SmppFrameDecoder → SmppCodec → BindInterceptor} on an
 * {@link EmbeddedChannel} with a unique {@link DefaultChannelId} — the T4 singleton-id trap) and writes
 * hand-authored wire PDUs (independent of the codec under test, mirroring {@code SmppCodecTest}'s
 * builders). The per-bind egress connect goes through the {@link BindInterceptor.EgressConnector} seam:
 * RELAY-006's sanctioned "injected failing ChannelFuture", which also lets these tests pin the T6
 * egress-bootstrap wiring the T6 review deferred to T7 (group = the ingress event loop, the
 * {@code RelayEgressInitializer} handler, the shared substrate options). Real-socket end-to-end is T9.
 *
 * <p><b>Q2 ratification pin (AD-33):</b> the deny-collapse {@code command_status} is asserted as the
 * LITERAL {@code 0x0000000D} ({@code ESME_RBINDFAIL}, SMPP 3.4 §5.1.3 "Bind Failed" — verified against
 * {@code docs/SMPP_v3_4_Issue1_2.pdf}), NOT via a production constant, so changing the constant cannot
 * silently re-point the wire contract.
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
@SuppressWarnings("FutureReturnValueIgnored") // reason: EmbeddedChannel.close()/writeInbound in tests are
// synchronous fire-and-forget — the assertions observe the channel's outbound queue and lifecycle state,
// never the close/write futures themselves.
@Timeout(value = 10, threadMode = ThreadMode.SEPARATE_THREAD) // owner FIXME "prove non-blocking call":
// the relay must never block on the verdict. SEPARATE_THREAD is load-bearing — the default SAME_THREAD
// can only observe a timeout AFTER the method returns, so a hanging writeInbound would hang forever;
// on a separate thread JUnit INTERRUPTS the test on expiry, converting an interruptible block (a join
// on future(), a latched/sleeping verify — the realistic blocking-verifier regression) into a failure.
class BindInterceptorTest {

    /** AD-33 Q2 — the ratified generic bind-failure code, pinned independently of the production constant. */
    private static final int ESME_RBINDFAIL = 0x0000000D;

    private static final int HEADER = 16;

    /** {@code RelayTestFixtures.modeBProperties}' egress target — the single configured reverse.mode-b SMSC. */
    private static final String SMSC_HOST = "smsc.example";
    private static final int SMSC_PORT = 2775;

    private ConnectionRegistry registry;
    /** The Story 3.4 T6 state manager over the registry — the interceptor's transitions route through it. */
    private RelayStateManager manager;
    /** Story 4.3 T4: unarmed by default — this suite's rows predate the gate; {@code NewAdjudicationGateTest} arms it. */
    private NewAdjudicationGate gate;
    private CapturingRelayObserver observer;
    private LatchedBindCredentialVerifier verifier;
    private FakeEgressConnector connector;
    /** Story 4.4 T3 (F14): the captured deadline tasks — the rows fire them manually, no wall clock. */
    private CapturingChannelTimer timer;
    private RelayEgressInitializer egressInitializer;
    private EmbeddedChannel ingress;
    private EmbeddedChannel egress;
    private final List<ByteBuf> toRelease = new ArrayList<>();

    @BeforeEach
    void freshIngress() {
        if (ingress != null) {
            ingress.finishAndReleaseAll(); // a manually-recycled channel (denySynthMatchesEachBindType) must not leak
        }
        registry = new ConnectionRegistry();
        manager = new RelayStateManager(registry);
        gate = new NewAdjudicationGate();
        observer = new CapturingRelayObserver();
        verifier = new LatchedBindCredentialVerifier();
        connector = new FakeEgressConnector();
        timer = new CapturingChannelTimer();
        egressInitializer = new RelayEgressInitializer(manager, observer); // T8: constructor-carrying (shared beans)
        ProxyCompanionProperties properties = RelayTestFixtures.modeBProperties(RelayTestFixtures.freePort(), 1);
        RelayChannelOptions channelOptions = new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT);
        // Story 3.3: the role-split graph — the routing table + per-cell TLS factory resolve from the
        // SAME properties (mode-b: no routing, no TLS — the reverse arm's plaintext dial).
        BindInterceptor interceptor = new BindInterceptor(
                verifier, manager, observer, properties, egressInitializer, channelOptions,
                new RoutingTable(properties), new SmppLegTlsFactory(properties, Runnable::run), gate, connector,
                timer);
        // The REAL production ingress pipeline (AC4): framer → codec → BindInterceptor →
        // RelayIngressHandler — T8 added the last entry; both legs carry one per-channel relay
        // handler (RelayIngressHandler/RelayEgressHandler, the Story 3.4 T5 split) sharing these beans.
        ingress = new EmbeddedChannel(
                DefaultChannelId.newInstance(), new SmppFrameDecoder(), new SmppCodec(), interceptor,
                new RelayIngressHandler(manager, observer));
    }

    @AfterEach
    void drainAndRelease() {
        if (ingress != null) {
            ingress.finishAndReleaseAll();
        }
        if (egress != null) {
            egress.finishAndReleaseAll();
        }
        toRelease.forEach(b -> {
            if (b.refCnt() > 0) {
                b.release();
            }
        });
        toRelease.clear();
    }

    // ---------- RELAY-004: retry-bind while adjudication is in-flight ----------

    @Test
    @DisplayName("RELAY-004: a retry bind while the first adjudication is in-flight is deterministically "
            + "rejected — generic deny for the RETRY's sequence, cancelHttp, no second pair, registry intact")
    void retriedBindWhileAdjudicationInFlightIsRejectedDeterministically() {
        // First bind parked mid-adjudication (the latch is held).
        ByteBuf first = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 1, "legacy1", "pw123456"));
        ingress.writeInbound(first);
        assertThat(registry.size()).as("exactly one entry for the in-flight bind").isEqualTo(1);
        assertThat(verifier.capturedCredentials).as("the first bind was adjudicated").hasSize(1);
        assertThat(connector.targets).as("no egress before the verdict").isEmpty();

        // The retry bind (same channel, same system_id) arrives while the first is unresolved.
        ByteBuf retry = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 2, "legacy1", "pw123456"));
        ingress.writeInbound(retry);

        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("the retry bind is answered with the AD-33 generic deny, not enqueued").isNotNull();
        assertThat(deny.getInt(8)).isEqualTo(ESME_RBINDFAIL);
        assertThat(deny.getInt(12)).as("the deny answers the RETRY's sequence_number").isEqualTo(2);
        assertThat(ingress.isOpen()).as("the misbehaving connection is torn down").isFalse();
        assertThat(verifier.cancelHttpCalls).as("the in-flight adjudication is cancelled (AD-32)").hasValue(1);
        assertThat(connector.targets).as("no second egress pair was ever created").isEmpty();
        assertThat(observer.bindRejects())
                .as("the retry-guard reject is not a Verdict — no onBindReject (AD-27)")
                .isEmpty();
        assertThat(observer.connectionCloses())
                .as("Story 4.1 T4 hoist: the retry-guard deny close carries BIND_REJECTED, not OTHER")
                .containsExactly(new CapturingRelayObserver.ConnectionClose(
                        Direction.INGRESS, CloseReason.BIND_REJECTED));
        assertThat(retry.refCnt()).as("the retry bind's original frame is released (never forwarded)").isZero();
        assertThat(registry.size()).as("no registry corruption — the single entry was torn down").isZero();

        // The late first verdict lands AFTER teardown: the continuation must no-op. runPendingTasks pumps
        // the embedded loop's queue — the ingress is closed, so the eventLoop().execute hop QUEUED the
        // continuation (a real loop always drains its queue; the embedded one has no thread to do it).
        verifier.completeAllow();
        ingress.runPendingTasks();
        assertThat(connector.targets).as("the late Allow after teardown opens NO egress (AD-25 re-check)").isEmpty();
        assertThat(ingress.<ByteBuf>readOutbound()).as("the late verdict emits nothing on the wire").isNull();
        assertThat(first.refCnt()).as("the abandoned first bind's frame is released by the no-op path").isZero();
    }

    // ---------- F1 (Story 4.4 T2): client-sent bind_resp — the ingress direction violation ----------

    @Test
    @DisplayName("F1 (Story 4.4 T2): a client-sent bind_resp as the FIRST PDU (no bind ever sent) bare-closes "
            + "with NO response PDU — no registry entry exists, so close only")
    void clientBindRespBeforeAnyBindBareClosesWithNoResponse() {
        // A FORGED ROK (status 0x00000000) is the worst case: nothing may treat it as an answer.
        ByteBuf forged = inbound(
                bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 9, 0x00000000, "legacy1", new byte[0]));
        ingress.writeInbound(forged);

        assertThat(ingress.<ByteBuf>readOutbound())
                .as("F1: NO response PDU — the bare close is the whole wire effect (AD-32 uniform close)")
                .isNull();
        assertThat(ingress.isOpen()).as("the offending connection is closed").isFalse();
        assertThat(registry.size()).as("no registry entry ever existed").isZero();
        assertThat(verifier.capturedCredentials).as("no adjudication ever started").isEmpty();
        assertThat(verifier.cancelHttpCalls).as("nothing to cancel — no entry, no adjudication").hasValue(0);
        assertThat(connector.targets).as("no egress was ever opened").isEmpty();
        assertThat(observer.bindRejects()).as("no Verdict exists — no onBindReject (AD-27)").isEmpty();
        assertThat(observer.bindAccepts()).as("a client-sent bind_resp never couples").isEmpty();
        assertThat(observer.framedPdus()).as("nothing is relayed from a violation").isEmpty();
        assertThat(observer.connectionCloses())
                .as("the bare close is observed with the uniform pre-couple reason, exactly once")
                .containsExactly(new CapturingRelayObserver.ConnectionClose(
                        Direction.INGRESS, CloseReason.PRE_COUPLE_NON_BIND_PDU));
        assertThat(forged.refCnt()).as("the stray bind_resp's frame is released, not leaked").isZero();
    }

    @Test
    @DisplayName("F1 (Story 4.4 T2): a client-sent bind_resp MID-ADJUDICATION bare-closes with NO response PDU "
            + "and NO forwarding — beginTeardown cancels + zeroizes, the entry is gone, no onBindReject, and "
            + "the late Allow no-ops (AD-25 re-check)")
    void clientBindRespMidAdjudicationBareClosesCancelsAndZeroizes() {
        // Park the bind mid-adjudication (the latch is held) so the pre-couple window is wide open.
        ByteBuf bind = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 1, "legacy1", "pw123456"));
        ingress.writeInbound(bind);
        assertThat(registry.size()).as("precondition: the bind is parked mid-adjudication").isEqualTo(1);
        assertThat(verifier.capturedCredentials).as("precondition: the bind was adjudicated").hasSize(1);

        ByteBuf forged = inbound(
                bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 2, 0x00000000, "legacy1", new byte[0]));
        ingress.writeInbound(forged);

        assertThat(ingress.<ByteBuf>readOutbound())
                .as("F1: NO response PDU and NO forwarding — a forwarded pre-flip ROK would couple the "
                        + "pair without SMSC consent (the forged-ROK window stays sealed)")
                .isNull();
        assertThat(ingress.isOpen()).as("the offending connection is closed").isFalse();
        assertThat(connector.targets).as("no egress was ever opened").isEmpty();
        assertThat(registry.size()).as("the entry is gone — beginTeardown removed it BEFORE close (AC3)").isZero();
        assertThat(verifier.cancelHttpCalls).as("the in-flight adjudication is cancelled inside beginTeardown").hasValue(1);
        assertThat(CoupledPairHarness.zeroized(verifier.capturedCredentials.get(0).password().value()))
                .as("the pending password is zeroized inside the same teardown").isTrue();
        assertThat(observer.bindRejects()).as("a bare close is not a Verdict — no onBindReject (AD-27)").isEmpty();
        assertThat(observer.bindAccepts()).as("the forged ROK never couples the pair").isEmpty();
        assertThat(observer.connectionCloses())
                .as("the bare close is observed with the uniform pre-couple reason, exactly once")
                .containsExactly(new CapturingRelayObserver.ConnectionClose(
                        Direction.INGRESS, CloseReason.PRE_COUPLE_NON_BIND_PDU));
        assertThat(forged.refCnt()).as("the stray bind_resp's frame is released exactly once").isZero();

        // The late Allow lands AFTER the bare-close: the continuation's AD-25 re-check no-ops — no
        // couple, no wire write — and releases the abandoned first bind's frame (runPendingTasks pumps
        // the embedded loop's queue; the ingress is closed so the eventLoop().execute hop queued it).
        verifier.completeAllow();
        ingress.runPendingTasks();
        assertThat(connector.targets).as("the late Allow after the bare-close opens NO egress (AD-25 re-check)").isEmpty();
        assertThat(ingress.<ByteBuf>readOutbound()).as("the late verdict emits nothing on the wire").isNull();
        assertThat(bind.refCnt()).as("the abandoned first bind's frame is released by the no-op path").isZero();
    }

    // ---------- F14 (Story 4.4 T3): the adjudication-deadline arm ----------

    @Test
    @DisplayName("F14 (Story 4.4 T3): a never-settling verifier is denied AT the deadline — the generic "
            + "non-ROK bind_resp, entry released, cancelHttp + zeroize, no onBindReject; the timer is "
            + "armed at the CONFIGURED adjudication-deadline millis")
    void neverSettlingVerifierIsDeniedAtTheConfiguredDeadline() {
        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 1, "legacy1", "pw123456"));
        ingress.writeInbound(frame);
        assertThat(registry.size()).as("precondition: the bind is parked mid-adjudication").isEqualTo(1);
        // Story 4.4 T4 re-index: channelActive (EmbeddedChannel construction) arms the idle watchdog
        // FIRST (task 0, the 30s window), so the adjudication-deadline timer is now the SECOND capture.
        assertThat(timer.tasks).as("both arms are live: the idle watchdog (channelActive) + the deadline (adjudicate)")
                .hasSize(2);
        assertThat(timer.delays.get(1))
                .as("the deadline timer is armed at the CONFIGURED adjudication-deadline millis (F14)")
                .isEqualTo(RelayTestFixtures.DEFAULT_ADJUDICATION_DEADLINE.toMillis());

        timer.tasks.get(1).run(); // fire the captured deadline task — the deterministic seam, no wall clock

        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("the deadline deny answers the parked bind on the wire (never pinned past it)").isNotNull();
        assertThat(deny.readableBytes()).as("header-only synth — the ONE place the relay builds a PDU").isEqualTo(HEADER);
        assertThat(deny.getInt(4)).isEqualTo(SmppCommandIds.BIND_TRANSCEIVER_RESP);
        assertThat(deny.getInt(8)).as("the AD-33 generic collapse — the SAME code as a verifier deny").isEqualTo(ESME_RBINDFAIL);
        assertThat(deny.getInt(12)).as("the deny correlates the still-pending bind's sequence").isEqualTo(1);
        assertThat(ingress.isOpen()).as("deny → then close").isFalse();
        assertThat(registry.size()).as("the pinned entry is released at the deadline (F14 core)").isZero();
        assertThat(verifier.cancelHttpCalls)
                .as("beginTeardown's hygiene aborted the dead exchange (PERF-032, SEC-009 relay arm)")
                .hasValue(1);
        assertThat(CoupledPairHarness.zeroized(verifier.capturedCredentials.get(0).password().value()))
                .as("the pending password is zeroized inside the same teardown").isTrue();
        assertThat(observer.bindRejects())
                .as("a timer deny fabricates no Verdict — NEVER onBindReject (AD-27 observer contract)")
                .isEmpty();
        assertThat(observer.connectionCloses())
                .as("the deadline deny's close carries BIND_REJECTED, exactly once")
                .containsExactly(new CapturingRelayObserver.ConnectionClose(
                        Direction.INGRESS, CloseReason.BIND_REJECTED));

        // The settle that follows in production (the cancelHttp'd pin completing) lands on the torn-down
        // pair: the AD-25 re-check no-ops — no couple, no further wire write — and releases the abandoned
        // frame (runPendingTasks pumps the embedded loop's queued hop).
        verifier.completeAllow();
        ingress.runPendingTasks();
        // Story 8.1 T5: the deadline exchange IS a completed adjudication once its pin settles (the
        // production adapter settles inside cancelHttp; the latched stand-in settles at completeAllow) —
        // the settle funnel records EXACTLY ONE strictly-positive latency even on the torn-down pair
        // (the runbook's "a deadline deny records" promise, pinned on the deterministic seam).
        assertThat(observer.bindAdjudications())
                .as("the deadline exchange recorded EXACTLY ONE adjudication at the settle")
                .hasSize(1);
        assertThat(observer.bindAdjudications().get(0).toNanos())
                .as("the recorded latency spans arm → deadline fire → settle — strictly positive")
                .isPositive();
        assertThat(connector.targets).as("the late Allow opens NO egress — never a late couple").isEmpty();
        assertThat(observer.bindAccepts()).isEmpty();
        assertThat(ingress.<ByteBuf>readOutbound()).as("nothing follows the deadline deny on the wire").isNull();
        assertThat(frame.refCnt()).as("the abandoned bind's frame is released by the no-op continuation").isZero();
    }

    @Test
    @DisplayName("F14 (Story 4.4 T3): a late ALLOW after the deadline fired is a pure no-op — the AD-25 "
            + "re-check carries it: frame released, no couple, exactly one wire write (the deny)")
    void lateAllowAfterTheDeadlineFiredIsANoOpThatNeverCouples() {
        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 2, "legacy1", "pw123456"));
        ingress.writeInbound(frame);
        assertThat(timer.tasks).as("precondition: the deadline timer is armed (after the T4 watchdog)")
                .hasSize(2);

        timer.tasks.get(1).run(); // the deadline elapses first (task 0 is the idle watchdog — 4.4 T4)
        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("the deadline deny is the wire answer").isNotNull();
        assertThat(deny.getInt(8)).isEqualTo(ESME_RBINDFAIL);

        verifier.completeAllow(); // ... THEN the verifier settles Allow (the race's late arm)
        ingress.runPendingTasks(); // pump the queued continuation hop so the no-op actually runs

        assertThat(connector.targets).as("the late Allow after the deadline deny opens NO egress").isEmpty();
        assertThat(observer.bindAccepts()).as("the couple flag never flips after a deadline deny").isEmpty();
        assertThat(observer.bindRejects()).as("the late Allow is not a NEW deny either — a pure no-op").isEmpty();
        assertThat(frame.refCnt()).as("the abandoned frame is released by the no-op continuation").isZero();
        assertThat(ingress.<ByteBuf>readOutbound())
                .as("exactly ONE wire write — the deny; the late settle adds nothing")
                .isNull();
    }

    @Test
    @DisplayName("F14 (Story 4.4 T3): client-close-then-timer — the channelInactive teardown already ran, "
            + "the stale fire no-ops: single teardown, single cancelHttp, timer cancelled at teardown")
    void clientCloseThenTimerFireIsASingleTeardown() {
        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 4, "legacy1", "pw123456"));
        ingress.writeInbound(frame);
        assertThat(registry.size()).isEqualTo(1);
        assertThat(timer.tasks).hasSize(2); // the T4 idle watchdog (0) + the F14 deadline (1)

        ingress.close(); // the legacy client vanished mid-adjudication — the AD-32 teardown runs NOW

        assertThat(verifier.cancelHttpCalls).as("precondition: the channelInactive teardown cancelled the exchange").hasValue(1);
        assertThat(CoupledPairHarness.zeroized(verifier.capturedCredentials.get(0).password().value()))
                .as("precondition: the pending password zeroized once")
                .isTrue();
        assertThat(timer.futures.get(0).isCancelled())
                .as("the teardown arm cancelled the idle watchdog too (4.4 T4 — the socket it would close is gone)")
                .isTrue();
        assertThat(timer.futures.get(1).isCancelled())
                .as("the teardown arm cancelled the pending deadline timer (hygiene — no stale armed task)")
                .isTrue();

        timer.tasks.get(1).run(); // the stale fire (a missed cancellation would land here too)

        assertThat(observer.connectionCloses())
                .as("exactly ONE close — the stale fire adds no second teardown")
                .hasSize(1);
        assertThat(verifier.cancelHttpCalls).as("no double cancelHttp (RELAY-005 idempotence)").hasValue(1);
        assertThat(CoupledPairHarness.zeroized(verifier.capturedCredentials.get(0).password().value()))
                .as("no double-zeroize harm (idempotent wipe)")
                .isTrue();
        assertThat(registry.size()).as("still zero — nothing resurrected").isZero();
        assertThat(ingress.<ByteBuf>readOutbound()).as("the stale fire writes nothing").isNull();
    }

    // ---------- F13 residue (Story 4.4 T4): the pre-couple idle watchdog ----------

    @Test
    @DisplayName("T4 arm: the pre-couple idle watchdog is armed AT channelActive at the CONFIGURED "
            + "idle-window millis — the FIRST capture, before any bind exists")
    void idleWatchdogArmsAtChannelActiveAtTheConfiguredWindow() {
        // A NON-default window (7s, not the 30s yml default): the pin cannot mistake a hardcoded
        // constant for the configured value (the derivation-pin rule of the T1 deadline row).
        ProxyCompanionProperties properties = RelayTestFixtures.modeBProperties(
                RelayTestFixtures.freePort(), 1, RelayTestFixtures.DEFAULT_ADJUDICATION_DEADLINE,
                java.time.Duration.ofSeconds(7));
        CapturingChannelTimer customTimer = new CapturingChannelTimer(); // the @BeforeEach timer already has its own capture
        BindInterceptor interceptor = new BindInterceptor(
                verifier, manager, observer, properties, egressInitializer,
                new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT),
                new RoutingTable(properties), new SmppLegTlsFactory(properties, Runnable::run), gate, connector,
                customTimer);
        EmbeddedChannel idle = new EmbeddedChannel(
                DefaultChannelId.newInstance(), new SmppFrameDecoder(), new SmppCodec(), interceptor,
                new RelayIngressHandler(manager, observer));
        try {
            // channelActive fires at EmbeddedChannel construction — the watchdog is captured with
            // NOTHING else having happened on the channel: no bind, no adjudication, no registry entry.
            assertThat(customTimer.tasks).as("armed at channelActive, before any bind").hasSize(1);
            assertThat(customTimer.delays.get(0))
                    .as("armed at the CONFIGURED companion.bind.pre-couple-idle-timeout millis (T4)")
                    .isEqualTo(7_000L);
        } finally {
            idle.finishAndReleaseAll();
        }
    }

    @Test
    @DisplayName("F13 residue (Story 4.4 T4): an accepted socket that never binds is bare-closed by the idle "
            + "watchdog — no response PDU, no registry entry ever, no verifier contact (close only)")
    void idleWatchdogBareClosesTheNeverBindingSocket() {
        assertThat(timer.tasks).as("precondition: the watchdog is armed at channelActive").hasSize(1);

        timer.tasks.get(0).run(); // the idle window elapses with ZERO PDUs from the client

        assertThat(ingress.<ByteBuf>readOutbound())
                .as("NO response PDU — the bare close is the whole wire effect (nothing was ever sent to answer)")
                .isNull();
        assertThat(ingress.isOpen()).as("the never-binding socket is closed").isFalse();
        assertThat(registry.size()).as("no registry entry ever existed").isZero();
        assertThat(verifier.capturedCredentials).as("no adjudication ever started").isEmpty();
        assertThat(connector.targets).as("no egress was ever opened").isEmpty();
        assertThat(observer.bindRejects()).as("no Verdict exists — no onBindReject (AD-27)").isEmpty();
        assertThat(observer.connectionCloses())
                .as("the close is observed with the uniform pre-couple reason, exactly once — the cap "
                        + "slot's release rides exactly this closeFuture")
                .containsExactly(new CapturingRelayObserver.ConnectionClose(
                        Direction.INGRESS, CloseReason.PRE_COUPLE_NON_BIND_PDU));
    }

    @Test
    @DisplayName("F13 residue (Story 4.4 T4): the idle watchdog firing MID-ADJUDICATION bare-closes with NO "
            + "response PDU — beginTeardown cancels + zeroizes, the entry is gone, no onBindReject, and "
            + "the late Allow no-ops (AD-25 re-check)")
    void idleWatchdogMidAdjudicationBareClosesCancelsAndZeroizes() {
        ByteBuf bind = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 3, "legacy1", "pw123456"));
        ingress.writeInbound(bind);
        assertThat(registry.size()).as("precondition: the bind is parked mid-adjudication").isEqualTo(1);
        assertThat(timer.tasks).hasSize(2); // the idle watchdog (0) + the F14 deadline (1)

        timer.tasks.get(0).run(); // the idle window elapses while the verifier future hangs

        assertThat(ingress.<ByteBuf>readOutbound())
                .as("NO response PDU — the watchdog is a bare close, never a deny synth")
                .isNull();
        assertThat(ingress.isOpen()).as("the idled-out connection is closed").isFalse();
        assertThat(registry.size()).as("the entry is gone — beginTeardown removed it BEFORE close (AC3)").isZero();
        assertThat(verifier.cancelHttpCalls).as("the in-flight adjudication is cancelled inside beginTeardown").hasValue(1);
        assertThat(CoupledPairHarness.zeroized(verifier.capturedCredentials.get(0).password().value()))
                .as("the pending password is zeroized inside the same teardown").isTrue();
        assertThat(observer.bindRejects()).as("a bare close is not a Verdict — no onBindReject (AD-27)").isEmpty();
        assertThat(observer.connectionCloses())
                .as("the bare close is observed with the uniform pre-couple reason, exactly once")
                .containsExactly(new CapturingRelayObserver.ConnectionClose(
                        Direction.INGRESS, CloseReason.PRE_COUPLE_NON_BIND_PDU));
        assertThat(timer.futures.get(1).isCancelled())
                .as("the watchdog's fire cancelled the still-armed F14 deadline timer (the pair is closing NOW)")
                .isTrue();

        // The late Allow lands AFTER the bare-close: the continuation's AD-25 re-check no-ops — no
        // couple, no wire write — and releases the abandoned bind's frame (the queued-hop pump).
        verifier.completeAllow();
        ingress.runPendingTasks();
        assertThat(connector.targets).as("the late Allow after the idle close opens NO egress (AD-25 re-check)").isEmpty();
        assertThat(ingress.<ByteBuf>readOutbound()).as("the late verdict emits nothing on the wire").isNull();
        assertThat(bind.refCnt()).as("the abandoned bind's frame is released by the no-op path").isZero();
    }

    @Test
    @DisplayName("F13 residue (Story 4.4 T4): the watchdog also bounds the SILENT-SMSC await after the "
            + "forward — bare-close both legs, no deny, no couple (the R32 sub-window RELAY-021 does not cover)")
    void idleWatchdogBoundsTheSilentSmscAwaitAfterTheForward() {
        coupledEgress(); // Allow settled, egress attached, bind forwarded — and the SMSC never answers
        assertThat(registry.size()).as("precondition: the pair is awaiting bind_resp").isEqualTo(1);
        assertThat(timer.futures.get(0).isCancelled())
                .as("the watchdog SURVIVES the verdict settle — the egress dial + the SMSC await are still pre-couple")
                .isFalse();

        timer.tasks.get(0).run(); // the idle window elapses with the bind unanswered

        assertThat(ingress.<ByteBuf>readOutbound())
                .as("NO deny for the legacy client to retry on — the watchdog is a bare close")
                .isNull();
        assertThat(ingress.isOpen()).as("the ingress leg is closed").isFalse();
        assertThat(egress.isOpen()).as("the silent egress leg is closed too").isFalse();
        assertThat(registry.size()).as("the pair leaves the registry").isZero();
        assertThat(observer.bindAccepts()).as("nothing coupled — the SMSC never consented").isEmpty();
        assertThat(observer.bindRejects()).as("no Verdict — no onBindReject (AD-27)").isEmpty();
        assertThat(observer.connectionCloses())
                .as("the INGRESS close carries the uniform pre-couple reason (the egress leg's own close "
                        + "fires unstashed — the pre-couple OTHER default, the F1-arm shape)")
                .contains(
                        new CapturingRelayObserver.ConnectionClose(Direction.INGRESS, CloseReason.PRE_COUPLE_NON_BIND_PDU),
                        new CapturingRelayObserver.ConnectionClose(Direction.EGRESS, CloseReason.OTHER));
    }

    @Test
    @DisplayName("PERF-2 negative (Story 4.4 T4): a COUPLED pair idling indefinitely is NEVER reaped — the "
            + "watchdog was cancelled at the couple and a stale fire no-ops")
    void coupledIdlePairIsNeverReapedByTheIdleWatchdog() {
        coupledEgress();
        egress.writeInbound(inbound(
                bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0x00000000, "SMSC01", new byte[0])));
        assertThat(observer.bindAccepts()).as("precondition: the pair coupled on the SMSC's ROK").hasSize(1);
        ByteBuf rokAtLegacy = ingress.readOutbound();
        assertThat(rokAtLegacy).as("precondition: the ROK reached the legacy client").isNotNull();
        rokAtLegacy.release(); // readOutbound hands the reader ownership (the T7 trap)
        assertThat(timer.futures.get(0).isCancelled())
                .as("the watchdog was CANCELLED at the couple (the egress answer arm) — connect→couple "
                        + "is the ONLY window it bounds")
                .isTrue();

        timer.tasks.get(0).run(); // a stale fire (the missed-cancellation convergence arm)

        assertThat(ingress.isOpen()).as("PERF-2: the idle COUPLED pair stays up — never reaped").isTrue();
        assertThat(egress.isOpen()).as("... on both legs").isTrue();
        assertThat(registry.size()).as("the coupled pair keeps its registry entry").isEqualTo(1);
        assertThat(ingress.<ByteBuf>readOutbound()).as("the stale fire writes nothing").isNull();
        assertThat(observer.connectionCloses()).as("no close observed — the couple won the race").isEmpty();
    }

    // ---------- AD-33: verifier denial collapse ----------

    @Test
    @DisplayName("AD-33: a verifier Deny collapses to ONE generic bind-failure code (ESME_RBINDFAIL 0x0D) — "
            + "header-only, matching the request's bind type + sequence, then close; onBindReject fires once; "
            + "the password is zeroized")
    void verifierDenyCollapsesToTheSingleGenericBindFailureCode() {
        verifier.completeDeny(new Verdict.DenyInvalid());
        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 42, "legacy1", "pw123456"));
        ingress.writeInbound(frame);

        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("the denial is answered on the wire (walkthrough §5: bind_resp error, then close)").isNotNull();
        assertThat(deny.readableBytes()).as("header-only synth — the ONE place the relay builds a PDU").isEqualTo(HEADER);
        assertThat(deny.getInt(0)).isEqualTo(HEADER);
        assertThat(deny.getInt(4)).isEqualTo(SmppCommandIds.BIND_TRANSCEIVER_RESP);
        assertThat(deny.getInt(8)).as("Q2: the AD-33 generic code is ESME_RBINDFAIL 0x0000000D (§5.1.3)").isEqualTo(ESME_RBINDFAIL);
        assertThat(deny.getInt(12)).as("sequence_number correlates the denied request").isEqualTo(42);
        assertThat(ingress.isOpen()).as("deny → then close").isFalse();
        assertThat(registry.size()).as("the optimistically-registered entry is removed").isZero();
        assertThat(observer.bindRejects()).as("onBindReject fires for the Verdict deny (AD-27)")
                .singleElement()
                .satisfies(reject -> {
                    assertThat(reject.systemId()).isEqualTo(new SystemId(new AsciiString("legacy1")));
                    assertThat(reject.verdict()).isEqualTo(new Verdict.DenyInvalid());
                });
        assertThat(frame.refCnt()).as("the denied bind's original frame is released (never forwarded)").isZero();
        assertThat(observer.connectionCloses())
                .as("Story 4.1 T4 hoist: the deny-path close carries BIND_REJECTED, not the OTHER default")
                .containsExactly(new CapturingRelayObserver.ConnectionClose(
                        Direction.INGRESS, CloseReason.BIND_REJECTED));
        assertThat(CoupledPairHarness.zeroized(verifier.capturedCredentials.get(0).password().value()))
                .as("caller-owned zeroize on the Deny path").isTrue();
    }

    @Test
    @DisplayName("AD-33: the deny synth matches each bind type — bind_receiver→bind_receiver_resp, "
            + "bind_transmitter→bind_transmitter_resp")
    void denySynthMatchesEachBindType() {
        verifier.completeDeny(new Verdict.DenyIndeterminate());
        ingress.writeInbound(inbound(bindRequest(SmppCommandIds.BIND_RECEIVER, 7, "legacy1", "pw123456")));
        assertThat(ingress.<ByteBuf>readOutbound().getInt(4)).isEqualTo(SmppCommandIds.BIND_RECEIVER_RESP);

        // A fresh channel for the second type (the first channel closed on its deny).
        freshIngress();
        verifier.completeDeny(new Verdict.DenyIndeterminate());
        ingress.writeInbound(inbound(bindRequest(SmppCommandIds.BIND_TRANSMITTER, 8, "legacy1", "pw123456")));
        assertThat(ingress.<ByteBuf>readOutbound().getInt(4)).isEqualTo(SmppCommandIds.BIND_TRANSMITTER_RESP);
    }

    // ---------- AD-33: egress-establishment-fail collapse (the indistinguishability arm) ----------

    @Test
    @DisplayName("AD-33: egress-establishment failure collapses to the SAME generic code — no onBindReject, "
            + "so a prober cannot distinguish verifier-reject from unreachable-SMSC")
    void egressEstablishmentFailureCollapsesToTheSameGenericCode() {
        verifier.completeAllow();
        egress = new EmbeddedChannel();
        connector.result = egress.newFailedFuture(new ConnectException("connection refused"));
        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 9, "legacy1", "pw123456"));
        ingress.writeInbound(frame);

        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("no SMSC response PDU exists — the proxy synthesizes the AD-33 deny").isNotNull();
        assertThat(deny.readableBytes()).isEqualTo(HEADER);
        assertThat(deny.getInt(4)).isEqualTo(SmppCommandIds.BIND_TRANSCEIVER_RESP);
        assertThat(deny.getInt(8)).as("the SAME generic code as the verifier-deny arm (the collapse)").isEqualTo(ESME_RBINDFAIL);
        assertThat(deny.getInt(12)).isEqualTo(9);
        assertThat(observer.bindRejects())
                .as("NOT a Verdict — egress-fail never reaches onBindReject (AD-27)")
                .isEmpty();
        assertThat(ingress.isOpen()).isFalse();
        assertThat(registry.size()).isZero();
        assertThat(observer.connectionCloses())
                .as("Story 4.1 T4 hoist: the connect-fail close carries EGRESS_CONNECT_FAILED — the "
                        + "taxonomy value's namesake arm (no egress leg exists to close)")
                .containsExactly(new CapturingRelayObserver.ConnectionClose(
                        Direction.INGRESS, CloseReason.EGRESS_CONNECT_FAILED));
        assertThat(frame.refCnt()).as("the never-forwarded original frame is released").isZero();
    }

    @Test
    @DisplayName("F10 (Story 4.4 T1): a blackholed SMSC target fails the dial at the deadline-derived "
            + "CONNECT_TIMEOUT_MILLIS — the SAME collapse arm as a refused connect")
    void blackholedEgressFailsAtTheDerivedConnectBoundAndCollapses() {
        verifier.completeAllow();
        egress = new EmbeddedChannel();
        // The connect-timeout shape Netty fails the dial future with once CONNECT_TIMEOUT_MILLIS
        // elapses against a SYN-dropping target — the blackhole variant of the refused-connect row
        // above (RELAY-020b's unit half; the bound itself is pinned in RelayChannelOptionsTest).
        connector.result = egress.newFailedFuture(
                new ConnectTimeoutException("connection timed out: " + SMSC_HOST + '/' + SMSC_PORT));
        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 21, "legacy1", "pw123456"));
        ingress.writeInbound(frame);

        // The dial the interceptor assembled carried the DERIVED bound — the fixture's 4s adjudication
        // deadline → 4000ms, NOT Netty's ~30s default (the F10 landing: the legacy client's answer is
        // bounded by the deadline, deadline + ε at worst).
        Bootstrap bootstrap = connector.bootstraps.get(0);
        assertThat(bootstrap.config().options().get(ChannelOption.CONNECT_TIMEOUT_MILLIS))
                .as("the egress dial is bounded at the adjudication-deadline millis (F10)")
                .isEqualTo((int) RelayTestFixtures.DEFAULT_ADJUDICATION_DEADLINE.toMillis());

        // The existing connect-fail arm runs unchanged: AD-33 deny, no onBindReject, teardown, release.
        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("the timeout-shaped connect failure answers with the AD-33 deny").isNotNull();
        assertThat(deny.getInt(8)).isEqualTo(ESME_RBINDFAIL);
        assertThat(deny.getInt(12)).as("correlates the still-pending bind").isEqualTo(21);
        assertThat(observer.bindRejects())
                .as("NOT a Verdict — a timed-out dial never reaches onBindReject (AD-27)")
                .isEmpty();
        assertThat(ingress.isOpen()).as("deny → then close").isFalse();
        assertThat(registry.size()).as("the pair is cleaned from the registry").isZero();
        assertThat(observer.connectionCloses())
                .as("Story 4.1 T4 hoist: the timeout-shaped connect-fail close carries "
                        + "EGRESS_CONNECT_FAILED — indistinguishable from a refused dial by design")
                .containsExactly(new CapturingRelayObserver.ConnectionClose(
                        Direction.INGRESS, CloseReason.EGRESS_CONNECT_FAILED));
        assertThat(frame.refCnt()).as("the never-forwarded original frame is released").isZero();
    }

    // ---------- AD-14: the Allow path forwards the ORIGINAL frame to the single configured egress ----------

    @Test
    @DisplayName("AD-14/AC2: Allow → egress to the single configured reverse.mode-b.smsc; the ORIGINAL bind "
            + "bytes are forwarded verbatim and released; the T6 egress-bootstrap wiring is pinned")
    void allowForwardsTheOriginalFrameVerbatimToTheConfiguredEgress() {
        verifier.completeAllow();
        egress = new EmbeddedChannel(egressInitializer);
        connector.result = egress.newSucceededFuture();
        byte[] bind = bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 7, "legacy1", "pw123456");
        ByteBuf frame = inbound(bind);
        ingress.writeInbound(frame);

        assertThat(connector.targets)
                .as("EVERY bind routes to the single configured egress — no system_id allow-list (AC2)")
                .containsExactly(SMSC_HOST + ":" + SMSC_PORT);
        ByteBuf forwarded = egress.readOutbound();
        assertThat(forwarded).as("the bind was forwarded to the SMSC").isNotNull();
        assertThat(bytesOf(forwarded)).as("AD-14 identity-preserved — byte-exact original frame").isEqualTo(bind);
        // readOutbound() hands the reader ownership — release it, THEN the shared-underlying refCnt
        // reaching zero proves the interceptor's side of the ownership transfer is clean.
        forwarded.release();
        assertThat(frame.refCnt()).as("ownership transferred to the egress write — released").isZero();

        // The T6-deferred wiring pin: the egress Bootstrap carries the shared substrate.
        Bootstrap bootstrap = connector.bootstraps.get(0);
        assertThat(bootstrap.config().group())
                .as("HexDumpProxy same-loop coupling: the egress rides the ingress event loop (AD-2)")
                .isSameAs(ingress.eventLoop());
        assertThat(bootstrap.config().handler())
                .as("the egress pipeline is the T6 RelayEgressInitializer (codec prefix + T8 slot)")
                .isSameAs(egressInitializer);
        Map<ChannelOption<?>, Object> options = bootstrap.config().options();
        assertThat(options.get(ChannelOption.ALLOCATOR))
                .as("AD-21: the ONE shared pooled allocator")
                .isSameAs(PooledByteBufAllocator.DEFAULT);
        assertThat(options.get(ChannelOption.AUTO_READ))
                .as("AD-2: demand-driven read on the egress leg too").isEqualTo(false);
        WriteBufferWaterMark mark = (WriteBufferWaterMark) options.get(ChannelOption.WRITE_BUFFER_WATER_MARK);
        assertThat(mark).as("AD-30: the egress watermark is set").isNotNull();
        assertThat(mark.low()).as("AD-30 low = one max frame").isEqualTo(SmppFrame.MAX_COMMAND_LENGTH);
        assertThat(mark.high())
                .as("AD-30 high = depth frames (depth 1 → equal marks; WriteBufferWaterMark has no equals — assert accessors, the T6 trap)")
                .isEqualTo(SmppFrame.MAX_COMMAND_LENGTH);

        assertThat(registry.size()).isEqualTo(1);
        assertThat(registry.entryFor(egress)).as("the egress leg is attached to the pair").isNotNull();
        assertThat(observer.bindAccepts())
                .as("onBindAccept fires at the AD-25 couple (T8), NOT at the verdict — silent here")
                .isEmpty();
        assertThat(CoupledPairHarness.zeroized(verifier.capturedCredentials.get(0).password().value()))
                .as("caller-owned zeroize on the ALLOW path too (the continuation's settle wipe — Story 3.4 "
                        + "T6 moved it into the state manager; no teardown wipe covers this arm)")
                .isTrue();
        // T7 owner-FIXME round: the CONFIGURED budget (companion.bind.adjudication-deadline, 4s via
        // RelayTestFixtures.DEFAULT_ADJUDICATION_DEADLINE) flows end-to-end into RequestContext.deadline
        // — the verifier reads it out of the ScopedValue the relay bound around verify().
        long remainingMs = java.time.Duration
                .between(java.time.Instant.now(), verifier.capturedDeadlines.get(0)).toMillis();
        assertThat(remainingMs)
                .as("RequestContext.deadline == now + the configured 4s budget (±100ms test latency)")
                .isBetween(3_000L, 4_100L);
    }

    // ---------- AD-25 forwarder split + RELAY-002c: SMSC bind_resp forwarded VERBATIM ----------

    @Test
    @DisplayName("RELAY-002c: an SMSC-originated NON-ROK bind_resp is forwarded VERBATIM (system_id + TLV "
            + "tail intact) — NOT collapsed to the generic deny")
    void smscNonRokBindRespIsForwardedVerbatimNotCollapsed() {
        coupledEgress();
        byte[] smscResp = bindResponse(
                SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0x00000008, "SMSC01", new byte[] {0x01, 0x02, 0x00, 0x01, 0x07});
        egress.writeInbound(inbound(smscResp));

        ByteBuf toLegacy = ingress.readOutbound();
        assertThat(toLegacy).as("the SMSC's bind result reaches the legacy client (AD-25 forwarder split)").isNotNull();
        assertThat(bytesOf(toLegacy))
                .as("VERBATIM — the SMSC's own status, system_id AND unparsed TLV tail, not a 16-byte synth")
                .isEqualTo(smscResp);
        // T8 landed: the non-ROK teardown is RelayEgressHandler's arm (AC3: no couple; forward FIRST, then tear
        // down both legs). This suite's egress leg carries the real T8 relay handler via the shared initializer.
        assertThat(ingress.<ByteBuf>readOutbound()).as("nothing follows the verbatim answer").isNull();
        assertThat(ingress.isOpen()).as("non-ROK → tear down (AC3)").isFalse();
        assertThat(egress.isOpen()).isFalse();
        assertThat(registry.size()).as("the failed pair leaves the registry").isZero();
        assertThat(observer.connectionCloses())
                .as("observed with the non-ROK reason on both legs (T8's stashes)")
                .containsExactlyInAnyOrder(
                        new CapturingRelayObserver.ConnectionClose(Direction.EGRESS, CloseReason.BIND_FAILED_NON_ROK),
                        new CapturingRelayObserver.ConnectionClose(Direction.INGRESS, CloseReason.BIND_FAILED_NON_ROK));
    }

    @Test
    @DisplayName("the ROK bind_resp is forwarded verbatim too (the couple itself is T8's single couple unit)")
    void smscRokBindRespIsForwardedVerbatim() {
        coupledEgress();
        byte[] smscResp = bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0x00000000, "SMSC01", new byte[0]);
        egress.writeInbound(inbound(smscResp));

        ByteBuf toLegacy = ingress.readOutbound();
        assertThat(toLegacy).isNotNull();
        assertThat(bytesOf(toLegacy)).isEqualTo(smscResp);
    }

    // ---------- AD-33: SMSC death pre-bind_resp (RST/unbind/half-close — no response PDU) ----------

    @Test
    @DisplayName("AD-33: the SMSC dying BEFORE any bind_resp (egress close) collapses to the same generic "
            + "deny — the legacy socket never hangs")
    void egressDeathBeforeBindRespCollapsesToTheGenericCode() {
        coupledEgress();
        egress.close();

        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("no SMSC response PDU will ever arrive — the proxy synthesizes the deny").isNotNull();
        assertThat(deny.getInt(8)).isEqualTo(ESME_RBINDFAIL);
        assertThat(deny.getInt(12)).as("correlates the still-pending bind").isEqualTo(5);
        assertThat(ingress.isOpen()).isFalse();
        assertThat(registry.size()).isZero();
        assertThat(observer.bindRejects()).as("not a Verdict — no onBindReject").isEmpty();
        assertThat(observer.connectionCloses())
                .as("Story 4.1 T4 hoist: the pre-answer SMSC death is an egress-establishment "
                        + "failure — the INGRESS deny-close carries EGRESS_CONNECT_FAILED (the egress "
                        + "leg's own close fired first, unstashed: the pre-couple OTHER default)")
                .contains(
                        new CapturingRelayObserver.ConnectionClose(Direction.INGRESS, CloseReason.EGRESS_CONNECT_FAILED),
                        new CapturingRelayObserver.ConnectionClose(Direction.EGRESS, CloseReason.OTHER));
    }

    // ---------- teardown window: the legacy client vanishing mid-adjudication ----------

    @Test
    @DisplayName("ingress vanishing mid-adjudication tears down, cancels the ROPC, zeroizes — and the late "
            + "verdict no-ops (AD-25 re-check)")
    void ingressVanishingMidAdjudicationTearsDownCancelsAndZeroizes() {
        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 3, "legacy1", "pw123456"));
        ingress.writeInbound(frame);
        assertThat(registry.size()).isEqualTo(1);

        ingress.close();

        assertThat(verifier.cancelHttpCalls).as("the in-flight adjudication is cancelled (AD-32 teardown)").hasValue(1);
        assertThat(CoupledPairHarness.zeroized(verifier.capturedCredentials.get(0).password().value()))
                .as("the wipe does not wait for a cancelled adjudication").isTrue();
        assertThat(registry.size()).isZero();

        verifier.completeAllow();
        ingress.runPendingTasks(); // the closed ingress queued the continuation — pump the embedded loop
        assertThat(connector.targets).as("the late Allow after teardown opens NO egress").isEmpty();
        assertThat(frame.refCnt()).isZero();
    }

    // ---------- AD-11: verifier failure is fail-closed, not fail-open ----------

    @Test
    @DisplayName("a verifier EXCEPTION (exceptional future or a synchronous throw) denies fail-closed with "
            + "the same generic code — no onBindReject (not a Verdict), zeroized")
    void verifierFailureFailsClosedWithTheSameGenericDeny() {
        // (a) An exceptional future: the continuation's error arm — deny, no observer trigger.
        verifier.completeExceptionally();
        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 11, "legacy1", "pw123456"));
        ingress.writeInbound(frame);
        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("fail-closed: an indeterminate adjudication DENIES (AD-11)").isNotNull();
        assertThat(deny.getInt(8)).isEqualTo(ESME_RBINDFAIL);
        assertThat(deny.getInt(12)).isEqualTo(11);
        assertThat(observer.bindRejects()).as("an exception is not a returned Verdict — no onBindReject (AD-27)").isEmpty();
        assertThat(observer.connectionCloses())
                .as("Story 4.1 T4 hoist: the fail-closed exception arm's close carries BIND_REJECTED")
                .containsExactly(new CapturingRelayObserver.ConnectionClose(
                        Direction.INGRESS, CloseReason.BIND_REJECTED));
        assertThat(ingress.isOpen()).isFalse();
        assertThat(CoupledPairHarness.zeroized(verifier.capturedCredentials.get(0).password().value())).isTrue();
        assertThat(frame.refCnt()).isZero();

        // (b) A synchronous throw out of verify(): the adjudicate catch arm — same collapse.
        freshIngress();
        ProxyCompanionProperties properties = RelayTestFixtures.modeBProperties(RelayTestFixtures.freePort(), 1);
        BindInterceptor throwing = new BindInterceptor(
                new BindCredentialVerifier() {
                    @Override
                    public VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx) {
                        throw new IllegalStateException("verifier exploded");
                    }
                },
                manager, observer, properties, egressInitializer,
                new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT),
                new RoutingTable(properties), new SmppLegTlsFactory(properties, Runnable::run), gate, connector,
                timer);
        // Swap the interceptor into a fresh pipeline (the @BeforeEach channel already has one).
        EmbeddedChannel throwingIngress = new EmbeddedChannel(
                DefaultChannelId.newInstance(), new SmppFrameDecoder(), new SmppCodec(), throwing,
                new RelayIngressHandler(manager, observer));
        try {
            throwingIngress.writeInbound(inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 12, "legacy1", "pw123456")));
            ByteBuf deny2 = throwingIngress.readOutbound();
            assertThat(deny2).as("a synchronous verifier blow-up also denies fail-closed").isNotNull();
            assertThat(deny2.getInt(8)).isEqualTo(ESME_RBINDFAIL);
            assertThat(deny2.getInt(12)).isEqualTo(12);
            assertThat(throwingIngress.isOpen()).isFalse();
            assertThat(observer.connectionCloses())
                    .as("Story 4.1 T4 hoist: the synchronous-throw arm ALSO closes BIND_REJECTED "
                            + "(freshIngress() above reset the observer — this is arm (b)'s own close)")
                    .containsExactly(new CapturingRelayObserver.ConnectionClose(
                            Direction.INGRESS, CloseReason.BIND_REJECTED));
            assertThat(registry.size()).isZero();
        } finally {
            throwingIngress.finishAndReleaseAll();
        }
    }

    @Test
    @DisplayName("a null-returning verify() (port-contract violation) denies fail-closed AND releases the "
            + "original frame — no NPE escape, no pooled-buffer leak (review F12)")
    void nullReturningVerifierFailsClosedAndReleasesTheFrame() {
        BindCredential[] seen = new BindCredential[1];
        ProxyCompanionProperties properties = RelayTestFixtures.modeBProperties(RelayTestFixtures.freePort(), 1);
        BindInterceptor nulling = new BindInterceptor(
                new BindCredentialVerifier() {
                    @Override
                    public VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx) {
                        seen[0] = cred;
                        return null; // violates the port's never-null contract (BindCredentialVerifier)
                    }
                },
                manager, observer, properties, egressInitializer,
                new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT),
                new RoutingTable(properties), new SmppLegTlsFactory(properties, Runnable::run), gate, connector,
                timer);
        EmbeddedChannel nullingIngress = new EmbeddedChannel(
                DefaultChannelId.newInstance(), new SmppFrameDecoder(), new SmppCodec(), nulling,
                new RelayIngressHandler(manager, observer));
        try {
            ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 13, "legacy1", "pw123456"));
            nullingIngress.writeInbound(frame);
            ByteBuf deny = nullingIngress.readOutbound();
            assertThat(deny).as("fail-closed: a null VerdictRequest DENIES like a verifier blow-up (AD-11)").isNotNull();
            assertThat(deny.getInt(8)).isEqualTo(ESME_RBINDFAIL);
            assertThat(deny.getInt(12)).isEqualTo(13);
            assertThat(observer.bindRejects()).as("null is not a returned Verdict — no onBindReject (AD-27)").isEmpty();
            assertThat(observer.connectionCloses())
                    .as("Story 4.1 T4 hoist: the null-verdict arm's close carries BIND_REJECTED")
                    .containsExactly(new CapturingRelayObserver.ConnectionClose(
                            Direction.INGRESS, CloseReason.BIND_REJECTED));
            assertThat(nullingIngress.isOpen()).isFalse();
            assertThat(registry.size()).isZero();
            assertThat(CoupledPairHarness.zeroized(seen[0].password().value()))
                    .as("the never-adjudicated secret is zeroized exactly once (this arm's explicit wipe)").isTrue();
            assertThat(frame.refCnt()).as("the original frame is released — no pooled-buffer leak").isZero();
        } finally {
            nullingIngress.finishAndReleaseAll();
        }
    }

    // ---------- fixtures ----------

    /** Completes the Allow path with a fake (Embedded) egress leg carrying the REAL T6 egress pipeline. */
    private void coupledEgress() {
        verifier.completeAllow();
        egress = new EmbeddedChannel(egressInitializer);
        connector.result = egress.newSucceededFuture();
        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 5, "legacy1", "pw123456"));
        ingress.writeInbound(frame);
        assertThat(egress.<ByteBuf>readOutbound()).as("precondition: the bind reached the SMSC").isNotNull();
    }

    /**
     * The injected egress connect (RELAY-006's "injected failing ChannelFuture"): records the assembled
     * {@link Bootstrap} (+ target) and returns the test-chosen {@link ChannelFuture}.
     */
    static final class FakeEgressConnector implements BindInterceptor.EgressConnector {
        final List<Bootstrap> bootstraps = new CopyOnWriteArrayList<>();
        final List<String> targets = new CopyOnWriteArrayList<>();
        volatile ChannelFuture result;

        @Override
        public ChannelFuture connect(Bootstrap bootstrap, String host, int port) {
            bootstraps.add(bootstrap);
            targets.add(host + ":" + port);
            return result;
        }
    }

    /**
     * Story 4.4 T3's deterministic timer seam (F14): captures every scheduled deadline task (delay +
     * body + handle) for the rows to FIRE MANUALLY — no real wall-clock waits. The returned handle is a
     * REAL cancellable scheduled task on the embedded loop (a no-op due at the captured delay — never
     * reached in a test's lifetime), so the production cancel path has a genuine future to cancel and
     * the rows can pin the cancellation.
     */
    static final class CapturingChannelTimer implements BindInterceptor.ChannelTimer {
        final List<Long> delays = new CopyOnWriteArrayList<>();
        final List<Runnable> tasks = new CopyOnWriteArrayList<>();
        final List<ScheduledFuture<?>> futures = new CopyOnWriteArrayList<>();

        @Override
        public ScheduledFuture<?> schedule(Channel channel, long delayMillis, Runnable task) {
            delays.add(delayMillis);
            tasks.add(task);
            ScheduledFuture<?> handle = channel.eventLoop().schedule(() -> { }, delayMillis, TimeUnit.MILLISECONDS);
            futures.add(handle);
            return handle;
        }
    }

    // ---------- hand-authored PDU builders (raw bytes — independent of the codec; mirrors SmppCodecTest) ----------

    private static byte[] bindRequest(int commandId, int sequence, String systemId, String password) {
        byte[] id = ascii(systemId);
        byte[] pw = ascii(password);
        byte[] type = ascii("SMPP");
        byte[] range = ascii("");
        int body = (id.length + 1) + (pw.length + 1) + (type.length + 1) + 3 + (range.length + 1);
        return assemble(commandId, 0, sequence, body, out -> {
            out.put(id).put((byte) 0);
            out.put(pw).put((byte) 0);
            out.put(type).put((byte) 0);
            out.put((byte) 0x34).put((byte) 0).put((byte) 0);
            out.put(range).put((byte) 0);
        });
    }

    private static byte[] bindResponse(int commandId, int sequence, int commandStatus, String systemId, byte[] tlvTail) {
        byte[] id = ascii(systemId);
        int body = (id.length + 1) + tlvTail.length;
        return assemble(commandId, commandStatus, sequence, body, out -> {
            out.put(id).put((byte) 0);
            out.put(tlvTail);
        });
    }

    private interface BodyWriter {
        void writeTo(java.nio.ByteBuffer out);
    }

    private static byte[] assemble(int commandId, int commandStatus, int sequence, int bodyLen, BodyWriter writer) {
        java.nio.ByteBuffer out = java.nio.ByteBuffer.allocate(HEADER + bodyLen);
        out.putInt(HEADER + bodyLen).putInt(commandId).putInt(commandStatus).putInt(sequence);
        writer.writeTo(out);
        return out.array();
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private ByteBuf inbound(byte[] pdu) {
        ByteBuf buf = Unpooled.wrappedBuffer(pdu);
        toRelease.add(buf); // backstop release; the normal path releases via the pipeline
        return buf;
    }

    private static byte[] bytesOf(ByteBuf buf) {
        byte[] out = new byte[buf.readableBytes()];
        buf.getBytes(buf.readerIndex(), out);
        return out;
    }
}
