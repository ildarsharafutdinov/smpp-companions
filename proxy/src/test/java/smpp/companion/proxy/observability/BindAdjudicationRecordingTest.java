package smpp.companion.proxy.observability;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Timeout.ThreadMode;
import org.junit.jupiter.api.io.TempDir;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.relay.BindInterceptor;
import smpp.companion.proxy.relay.ConnectionRegistry;
import smpp.companion.proxy.relay.NewAdjudicationGate;
import smpp.companion.proxy.relay.RelayIngressHandler;
import smpp.companion.proxy.relay.RelayStateManager;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayEgressInitializer;
import smpp.companion.proxy.security.BindCredential;
import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.security.RequestContext;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.security.VerdictRequest;
import smpp.companion.proxy.tls.SmppLegTlsFactory;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 8.1 T3 (2026-09-19) &mdash; the bind-adjudication-latency histogram's FIRE-SITE contract:
 * {@link RelayObserver#onBindAdjudication(Duration)} records <b>exactly once per completed
 * adjudication</b> at the settle funnel ({@code BindInterceptor.onVerdict} &mdash; {@code
 * recordAdjudicationLatency}), for EVERY settled verifier future alike ({@code Allow}, both
 * {@code Deny*} permits, an exceptional future, and a teardown/cancel-aborted exchange whose pin
 * settles), and NEVER for the never-armed arms (synchronous verifier blow-up, null {@code
 * VerdictRequest}) or the non-verdict denials (routing miss, the new-adjudication gate) &mdash; the
 * seam javadoc's pinned contract, the I/O matrix's "Bind adjudicated" row.
 *
 * <p>Same wiring discipline as {@code ThrowingObserverHardeningTest} (the observability-package
 * mirror of the relay harness): the REAL production pipeline ({@code framer -> codec ->
 * BindInterceptor -> RelayIngressHandler}) through the PUBLIC constructor, so every row reaches the
 * settle funnel exactly as production does. The deny rows never dial; the Allow row points the
 * cell's SMSC at an unbound loopback port so the egress dial fails fast &mdash; proving the record
 * is spent at the SETTLE (before the dial), and the dial's own {@code EGRESS_CONNECT_FAILED} deny
 * does not double-record (it is not a verdict).
 *
 * <p>RED-on-neuter: record twice (or from the deny path) and the exactly-once counts fail; move the
 * fire to the verifier hand-off or drop the settle fire and the class/never-arm rows fail; record
 * from {@code denyAndTeardown} and the never-armed rows below catch it.
 */
@Tag("unit")
@Tag("relay")
@Tag("observability")
@Tag("p1")
@Timeout(value = 10, threadMode = ThreadMode.SEPARATE_THREAD) // a hung handler chain must FAIL a test,
// not hang the suite (the BindInterceptorTest pattern).
class BindAdjudicationRecordingTest extends ObservabilityPairHarness {

    /** AD-33 Q2 — the ratified generic bind-failure code, pinned independently of the production constant. */
    private static final int ESME_RBINDFAIL = 0x0000000D;

    private ConnectionRegistry registry;
    private RelayStateManager manager;
    private ProxyCompanionProperties properties;
    private RoutingTable routingTable;
    private SmppLegTlsFactory tlsFactory;
    private RelayChannelOptions channelOptions;
    private NewAdjudicationGate gate;

    @BeforeEach
    void sharedBeans() {
        registry = new ConnectionRegistry();
        manager = new RelayStateManager(registry);
        properties = RelayTestFixtures.modeBProperties(RelayTestFixtures.freePort(), 1);
        routingTable = new RoutingTable(properties);
        tlsFactory = new SmppLegTlsFactory(properties, Runnable::run);
        channelOptions = new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT);
        gate = new NewAdjudicationGate();
    }

    @Test
    @DisplayName("every verifier DENY settle records EXACTLY ONE adjudication — DenyInvalid and "
            + "DenyIndeterminate, one per leg — and the deny is still synthesized")
    void denySettlesEachRecordExactlyOnce() {
        SettleableVerifier verifier = new SettleableVerifier();
        CapturingRelayObserver observer = new CapturingRelayObserver();

        // (a) The settle arrives AFTER the bind (the async future): one record once it lands.
        EmbeddedChannel deniedLate = adjudicatingChannel(verifier, observer);
        ByteBuf frameA = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 21, "legacy1", "pw123456"));
        deniedLate.writeInbound(frameA);
        assertThat(observer.bindAdjudications())
                .as("pending adjudication records NOTHING before the future settles")
                .isEmpty();
        verifier.settle(new Verdict.DenyInvalid());
        deniedLate.runPendingTasks(); // pump the embedded loop's queued continuation, if any

        // (b) A second adjudication on its own leg (the per-channel interceptor state re-arms):
        // settled with the OTHER Deny permit — one more record, nothing shared with (a).
        EmbeddedChannel deniedEager = adjudicatingChannel(verifier, observer);
        ByteBuf frameB = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 22, "legacy1", "pw123456"));
        deniedEager.writeInbound(frameB);
        verifier.settle(new Verdict.DenyIndeterminate());
        deniedEager.runPendingTasks();

        assertThat(observer.bindAdjudications())
                .as("one record per completed adjudication — two settles, two records, no more")
                .hasSize(2);
        assertThat(observer.bindAdjudications())
                .allSatisfy(latency -> assertThat(latency.toNanos())
                        .as("each latency is a real monotonic delta — the settle provably spans the "
                                + "arm plus the intervening test work, so strictly positive (a "
                                + "constant-zero carry at the fire site must fail here)")
                        .isPositive());
        for (EmbeddedChannel leg : List.of(deniedLate, deniedEager)) {
            ByteBuf deny = leg.readOutbound();
            assertThat(deny).as("the verdict path runs on regardless — the deny is synthesized").isNotNull();
            assertThat(deny.getInt(8)).isEqualTo(ESME_RBINDFAIL);
            assertThat(deny.getInt(12)).isEqualTo(leg == deniedLate ? 21 : 22);
            deny.release(); // readOutbound hands the reader ownership (the T7 trap)
            assertThat(leg.isOpen()).as("deny → then close").isFalse();
        }
        assertThat(frameA.refCnt()).as("the original frames are released").isZero();
        assertThat(frameB.refCnt()).isZero();
        assertThat(registry.size()).as("both pairs left the registry").isZero();
        assertThat(observer.bindRejects())
                .as("both denies also fired the (uninstrumented here) reject trigger — the settle "
                        + "recording is additive, never a replacement")
                .hasSize(2);
    }

    @Test
    @DisplayName("an EXCEPTIONAL settle (broken adapter) still records exactly one adjudication — "
            + "every settled future alike")
    void exceptionalSettleRecordsExactlyOnce() {
        SettleableVerifier verifier = new SettleableVerifier();
        CapturingRelayObserver observer = new CapturingRelayObserver();
        EmbeddedChannel ingress = adjudicatingChannel(verifier, observer);

        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 23, "legacy1", "pw123456"));
        ingress.writeInbound(frame);
        verifier.settleExceptionally(new IllegalStateException("adapter broke"));
        ingress.runPendingTasks();

        assertThat(observer.bindAdjudications())
                .as("the exceptional future settled — one record, the same funnel")
                .hasSize(1);
        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("fail-closed deny still synthesized (AD-11)").isNotNull();
        assertThat(deny.getInt(8)).isEqualTo(ESME_RBINDFAIL);
        deny.release();
        assertThat(observer.bindRejects())
                .as("an exception is not a returned Verdict — no onBindReject (AD-27)")
                .isEmpty();
        assertThat(frame.refCnt()).isZero();
        assertThat(ingress.isOpen()).isFalse();
    }

    @Test
    @DisplayName("an ALLOW settle records exactly once BEFORE the egress dial — and the dial's own "
            + "EGRESS_CONNECT_FAILED deny does NOT double-record (not a verdict)")
    void allowSettleRecordsOnceAndTheFailedDialDoesNotDoubleRecord() {
        // The cell's SMSC target is an UNBOUND loopback port: the egress dial fails fast, the
        // EGRESS_CONNECT_FAILED deny answers — the record is spent at the settle either way.
        ProxyCompanionProperties deadSmsc = RelayTestFixtures.modeBProperties(
                RelayTestFixtures.freePort(), 1, "127.0.0.1", RelayTestFixtures.freePort());
        SettleableVerifier verifier = new SettleableVerifier();
        CapturingRelayObserver observer = new CapturingRelayObserver();
        EmbeddedChannel ingress = channel(new SmppFrameDecoder(), new SmppCodec(),
                new BindInterceptor(verifier, manager, observer, deadSmsc,
                        new RelayEgressInitializer(manager, observer),
                        new RelayChannelOptions(deadSmsc, PooledByteBufAllocator.DEFAULT),
                        new RoutingTable(deadSmsc), new SmppLegTlsFactory(deadSmsc, Runnable::run), gate),
                new RelayIngressHandler(manager, observer));

        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 24, "legacy1", "pw123456"));
        ingress.writeInbound(frame);
        verifier.settle(new Verdict.Allow());
        ingress.runPendingTasks();
        // The failed dial's deny may land synchronously or one pump later on the embedded loop.
        ingress.runPendingTasks();

        assertThat(observer.bindAdjudications())
                .as("the Allow settle records EXACTLY once — and the connect-fail deny (a "
                        + "non-verdict denial) never records")
                .hasSize(1);
        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("the unreachable SMSC collapses to the same generic deny (AD-33)").isNotNull();
        assertThat(deny.getInt(8)).isEqualTo(ESME_RBINDFAIL);
        assertThat(deny.getInt(12)).isEqualTo(24);
        deny.release();
        assertThat(observer.bindRejects())
                .as("no returned Deny verdict ever existed — no onBindReject")
                .isEmpty();
        assertThat(frame.refCnt()).isZero();
        assertThat(ingress.isOpen()).isFalse();
        assertThat(registry.size()).isZero();
    }

    @Test
    @DisplayName("a CANCEL-ABORTED settle (teardown's cancelHttp settles the pin DenyIndeterminate) "
            + "still records once — the record precedes the race-free re-check")
    void cancelAbortedSettleStillRecordsOnce() {
        SettleableVerifier verifier = new SettleableVerifier();
        CapturingRelayObserver observer = new CapturingRelayObserver();
        EmbeddedChannel ingress = adjudicatingChannel(verifier, observer);

        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 25, "legacy1", "pw123456"));
        ingress.writeInbound(frame);
        ingress.close(); // the legacy client vanished mid-adjudication: teardown → cancelHttp → the pin settles
        ingress.runPendingTasks();

        assertThat(observer.bindAdjudications())
                .as("the cancel-aborted exchange IS a completed adjudication — one record, counted "
                        + "before the AD-25 re-check no-ops the rest")
                .hasSize(1);
        ByteBuf noDeny = ingress.readOutbound();
        assertThat(noDeny)
                .as("nobody left to answer — no deny is synthesized on a torn-down connection")
                .isNull();
        assertThat(verifier.cancelHttpCalls.get())
                .as("the teardown really did cancel the in-flight adjudication (the arm under test)")
                .isEqualTo(1);
        assertThat(frame.refCnt()).isZero();
        assertThat(registry.size()).isZero();
    }

    @Test
    @DisplayName("NEVER-armed arms record NOTHING: synchronous verifier blow-up, null VerdictRequest, "
            + "the armed gate, a forward routing miss — each still denies on the wire")
    void neverAdjudicatedArmsRecordNothing(@TempDir Path dir) throws IOException {
        CapturingRelayObserver observer = new CapturingRelayObserver();

        // (a) A verifier that blows up synchronously: denied before a future existed — never armed.
        EmbeddedChannel blown = adjudicatingChannel((cred, ctx) -> {
            throw new IllegalStateException("verifier exploded");
        }, observer);
        ByteBuf frameA = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 31, "legacy1", "pw123456"));
        blown.writeInbound(frameA);
        ByteBuf denyA = blown.readOutbound();
        assertThat(denyA).as("(a) fail-closed deny on the wire").isNotNull();
        denyA.release(); // readOutbound hands the reader ownership (the T7 trap)

        // (b) A null VerdictRequest (port-contract violation): same never-armed shape.
        EmbeddedChannel nulled = adjudicatingChannel((cred, ctx) -> null, observer);
        ByteBuf frameB = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 32, "legacy1", "pw123456"));
        nulled.writeInbound(frameB);
        ByteBuf denyB = nulled.readOutbound();
        assertThat(denyB).as("(b) fail-closed deny on the wire").isNotNull();
        denyB.release(); // readOutbound hands the reader ownership (the T7 trap)

        // (c) The armed new-adjudication gate (acceptor stopped): denied before the verifier, no entry.
        SettleableVerifier gated = new SettleableVerifier();
        gate.arm();
        EmbeddedChannel gatedChannel = adjudicatingChannel(gated, observer);
        ByteBuf frameC = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 33, "legacy1", "pw123456"));
        gatedChannel.writeInbound(frameC);
        ByteBuf denyC = gatedChannel.readOutbound();
        assertThat(denyC).as("(c) fail-closed deny on the wire").isNotNull();
        denyC.release(); // readOutbound hands the reader ownership (the T7 trap)
        assertThat(gated.verifyCalls.get()).as("(c) the verifier is never contacted").isZero();

        // (d) A forward-cell routing miss (system_id not in the table): denied pre-adjudication.
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        ProxyCompanionProperties forward = RelayTestFixtures.forwardAProperties(
                RelayTestFixtures.freePort(), 1, legs, "reverse.internal", 2776);
        SettleableVerifier routed = new SettleableVerifier();
        EmbeddedChannel missed = channel(new SmppFrameDecoder(), new SmppCodec(),
                new BindInterceptor(routed, manager, observer, forward,
                        new RelayEgressInitializer(manager, observer),
                        new RelayChannelOptions(forward, PooledByteBufAllocator.DEFAULT),
                        new RoutingTable(forward), new SmppLegTlsFactory(forward, Runnable::run),
                        new NewAdjudicationGate()),
                new RelayIngressHandler(manager, observer));
        ByteBuf frameD = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 34, "gamma", "pw123456"));
        missed.writeInbound(frameD);
        ByteBuf missDeny = missed.readOutbound();
        assertThat(missDeny).as("(d) the AD-33 deny answers the unrouted bind").isNotNull();
        assertThat(missDeny.getInt(8)).isEqualTo(ESME_RBINDFAIL);
        missDeny.release();
        assertThat(routed.verifyCalls.get()).as("(d) the verifier is never contacted").isZero();

        assertThat(observer.bindAdjudications())
                .as("NONE of the never-armed/non-verdict arms ever recorded — the histogram counts "
                        + "completed adjudications only")
                .isEmpty();
        assertThat(observer.bindRejects())
                .as("none of these is a returned Verdict — no onBindReject either (AD-27)")
                .isEmpty();
        for (EmbeddedChannel leg : List.of(blown, nulled, gatedChannel, missed)) {
            assertThat(leg.isOpen()).as("every arm denied → closed").isFalse();
        }
        assertThat(frameA.refCnt()).as("every original frame is released").isZero();
        assertThat(frameB.refCnt()).isZero();
        assertThat(frameC.refCnt()).isZero();
        assertThat(frameD.refCnt()).isZero();
        assertThat(registry.size()).as("no pair survives any arm").isZero();
    }

    // --- fixtures ---------------------------------------------------------------------------

    /**
     * The settle-controllable verifier ({@code ObservabilityPairHarness.denyingVerifier} upgraded):
     * each {@code verify} hands back a NEW pending future the test settles via {@link #settle} /
     * {@link #settleExceptionally}; {@code cancelHttp} settles the pin {@code DenyIndeterminate}
     * (the production adapter's no-op-if-done pin-settle contract the settle javadoc cites). Counts
     * {@code verify} calls (the never-armed rows assert zero) and {@code cancelHttp} calls.
     */
    private static final class SettleableVerifier implements BindCredentialVerifier {
        final AtomicInteger verifyCalls = new AtomicInteger();
        final AtomicInteger cancelHttpCalls = new AtomicInteger();
        private final List<CompletableFuture<Verdict>> pending = new CopyOnWriteArrayList<>();

        @Override
        public VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx) {
            verifyCalls.incrementAndGet();
            CompletableFuture<Verdict> future = new CompletableFuture<>();
            pending.add(future);
            return new VerdictRequest() {
                @Override
                public CompletableFuture<Verdict> future() {
                    return future;
                }

                @Override
                public void cancelHttp() {
                    cancelHttpCalls.incrementAndGet();
                    future.complete(new Verdict.DenyIndeterminate()); // the pin-settle contract
                }
            };
        }

        /** Settles the OLDEST still-pending adjudication with the given verdict. */
        void settle(Verdict verdict) {
            pending.stream().filter(f -> !f.isDone()).findFirst()
                    .orElseThrow(() -> new IllegalStateException("no pending adjudication to settle"))
                    .complete(verdict);
        }

        /** Settles the OLDEST still-pending adjudication exceptionally. */
        void settleExceptionally(Throwable cause) {
            pending.stream().filter(f -> !f.isDone()).findFirst()
                    .orElseThrow(() -> new IllegalStateException("no pending adjudication to settle"))
                    .completeExceptionally(cause);
        }
    }

    /** An ingress pipeline over the REAL production wiring (the public-constructor idiom). */
    private EmbeddedChannel adjudicatingChannel(BindCredentialVerifier verifier, CapturingRelayObserver observer) {
        return channel(new SmppFrameDecoder(), new SmppCodec(),
                new BindInterceptor(verifier, manager, observer, properties,
                        new RelayEgressInitializer(manager, observer), channelOptions, routingTable, tlsFactory,
                        gate),
                new RelayIngressHandler(manager, observer));
    }
}
