package smpp.companion.proxy.relay;

import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

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
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelOption;
import io.netty.channel.DefaultChannelId;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;

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
    private CapturingRelayObserver observer;
    private LatchedBindCredentialVerifier verifier;
    private FakeEgressConnector connector;
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
        observer = new CapturingRelayObserver();
        verifier = new LatchedBindCredentialVerifier();
        connector = new FakeEgressConnector();
        egressInitializer = new RelayEgressInitializer(manager, observer); // T8: constructor-carrying (shared beans)
        ProxyCompanionProperties properties = RelayTestFixtures.modeBProperties(RelayTestFixtures.freePort(), 1);
        RelayChannelOptions channelOptions = new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT);
        // Story 3.3: the role-split graph — the routing table + per-cell TLS factory resolve from the
        // SAME properties (mode-b: no routing, no TLS — the reverse arm's plaintext dial).
        BindInterceptor interceptor = new BindInterceptor(
                verifier, manager, observer, properties, egressInitializer, channelOptions,
                new RoutingTable(properties), new SmppLegTlsFactory(properties, Runnable::run), connector);
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
                new RoutingTable(properties), new SmppLegTlsFactory(properties, Runnable::run), connector);
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
                new RoutingTable(properties), new SmppLegTlsFactory(properties, Runnable::run), connector);
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
