package smpp.companion.proxy.relay;

import java.io.IOException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Timeout.ThreadMode;

import io.netty.buffer.ByteBuf;
import io.netty.channel.DefaultChannelId;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.observability.CapturingRelayObserver;
import smpp.companion.proxy.observability.CloseReason;
import smpp.companion.proxy.observability.Direction;
import smpp.companion.proxy.security.SystemId;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 2.2 Task 8 / AC3+AC5+AC6 (the ingress half of the Story 3.4 T5 split of
 * {@code RelayHandlerTest}) &mdash; the {@code RelayIngressHandler} contract: the AD-32 case-3
 * bare-close through the {@code RelayStateManager} DIRECTLY (Story 3.4 T6: the pre-T6
 * {@code BindInterceptor} delegation died with the absorption — the pending-adjudication
 * {@code cancelHttp} + zeroize hygiene is manager-side now), the structural no-bind-arm fact (a stray
 * decoded {@code bind_resp} on this leg fails CLOSED — never couples, never a
 * {@code ClassCastException}), and the base-owned planes driven from this leg (the post-couple
 * half-close propagation RELAY-008, the write/close micro-race RELAY-009, the RST observation
 * RELAY-010, the exactly-once close AC5). The shared pair fixture, the REAL pipelines, and the
 * EmbeddedChannel honesty notes live in {@link CoupledPairHarness}; the egress-leg behaviors
 * (the AD-25 couple unit) are {@code RelayEgressHandlerTest}'s.
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
@SuppressWarnings("FutureReturnValueIgnored") // reason: EmbeddedChannel.close()/writeInbound in tests are
// synchronous fire-and-forget — the assertions observe the channels' outbound queues and lifecycle state,
// never the close/write futures themselves.
@Timeout(value = 10, threadMode = ThreadMode.SEPARATE_THREAD) // a hung handler chain must FAIL a test,
// not hang the suite (the BindInterceptorTest pattern).
class RelayIngressHandlerTest extends CoupledPairHarness {

    // ---------- RELAY-002: ingress pre-couple non-bind → AD-32 bare close ----------

    @Test
    @DisplayName("RELAY-002 (mid-adjudication): a pre-couple submit_sm on the ingress closes with NO response "
            + "PDU, no egress pair, the in-flight ROPC cancelled + password zeroized (the AC3 teardown ordering)")
    void ingressPreCoupleNonBindPduBareClosesMidAdjudication() {
        // Park the bind mid-adjudication (latch held) so the pre-couple window is wide open.
        ingress.writeInbound(inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 1, "legacy1", "pw123456")));
        assertThat(registry.size()).isEqualTo(1);

        ingress.writeInbound(inbound(opaquePdu(SUBMIT_SM, 7)));

        assertThat(ingress.<ByteBuf>readOutbound())
                .as("AD-32 uniform bare-close: NO synthetic _resp, NO bind_resp — the wire stays empty")
                .isNull();
        assertThat(ingress.isOpen()).as("the offending connection is closed").isFalse();
        assertThat(connector.targets).as("no egress was ever opened for the violating connection").isEmpty();
        assertThat(registry.size()).as("the entry is removed BEFORE close (AC3 ordering) — registry empty").isZero();
        assertThat(verifier.cancelHttpCalls).as("the in-flight adjudication is cancelled via the AD-12 handle").hasValue(1);
        assertThat(zeroized(verifier.capturedCredentials.get(0).password().value()))
                .as("the pending password is zeroized in the same teardown").isTrue();
        assertThat(observer.connectionCloses())
                .as("the bare close is observed with the pre-couple reason, exactly once")
                .containsExactly(new CapturingRelayObserver.ConnectionClose(Direction.INGRESS, CloseReason.PRE_COUPLE_NON_BIND_PDU));
        assertThat(observer.bindRejects()).as("a violation is not a Verdict — no onBindReject (AD-27)").isEmpty();
        assertThat(observer.bindAccepts()).isEmpty();
    }

    @Test
    @DisplayName("RELAY-002 (post-egress, pre-couple): an enquire_link after the egress connected but before the "
            + "couple bare-closes BOTH legs with NO deny — the egress-leg AD-33 arm loses the teardown race (Q1)")
    void ingressPreCoupleViolationAfterEgressConnectBareClosesBothLegs() {
        awaitingBindResp(); // egress connected, bind forwarded, NOT yet coupled

        ingress.writeInbound(inbound(opaquePdu(ENQUIRE_LINK, 8)));

        assertThat(ingress.<ByteBuf>readOutbound())
                .as("bare close even with a live egress — Q1 emits no bind_resp on a violation (AD-32)")
                .isNull();
        assertThat(ingress.isOpen()).isFalse();
        assertThat(egress.isOpen()).as("the coupled egress leg is torn down too").isFalse();
        assertThat(registry.size()).isZero();
        assertThat(observer.connectionCloses())
                .extracting(CapturingRelayObserver.ConnectionClose::direction)
                .as("both legs' closes are observed")
                .containsExactlyInAnyOrder(Direction.INGRESS, Direction.EGRESS);
    }

    // ---------- AC6, structural half: no bind arm on the ingress leg ----------

    @Test
    @DisplayName("AC6 structural half: a stray decoded bind_resp on the INGRESS leg (unreachable today — the "
            + "interceptor releases client-sent bind-responses upstream) fails CLOSED: bare-close, never "
            + "couples, never a ClassCastException on the decoded record")
    void strayDecodedBindRespOnIngressLegFailsClosedNeverCouples() {
        // Drive the arm DIRECTLY: with the real interceptor in the pipeline a client-sent bind_resp is
        // released upstream and never reaches this handler, so this row builds the leg without one —
        // since Story 3.4 T6 the handler tears down through the state manager DIRECTLY (the pre-T6
        // interceptor delegation is gone), so this interceptor-less leg runs the FULL manager ordering
        // (remove + mark → cancelHttp + zeroize → close), not a defensive half.
        ingress.finishAndReleaseAll(); // recycle the @BeforeEach channel; this row builds its own leg
        observer.clear(); // the recycled channel's own exactly-once close (INGRESS/OTHER) is noise here
        ingress = new EmbeddedChannel(DefaultChannelId.newInstance(),
                new SmppFrameDecoder(), new SmppCodec(), new RelayIngressHandler(manager, observer));
        manager.register(ingress, new SystemId(new AsciiString("legacy1")));

        ByteBuf frame = inbound(bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0, "SMSC01", new byte[0]));
        ingress.writeInbound(frame);

        assertThat(observer.bindAccepts()).as("the ingress class cannot couple — no bind arm exists (AC6)").isEmpty();
        assertThat(observer.framedPdus()).as("nothing is relayed from a violation").isEmpty();
        assertThat(ingress.isOpen()).as("the stray bind_resp bare-closes its leg").isFalse();
        assertThat(observer.connectionCloses())
                .as("the fail-closed close is observed with the pre-couple violation reason, exactly once")
                .containsExactly(new CapturingRelayObserver.ConnectionClose(Direction.INGRESS, CloseReason.PRE_COUPLE_NON_BIND_PDU));
        assertThat(frame.refCnt()).as("the stray PDU's frame is released, not leaked").isZero();
    }

    // ---------- RELAY-008: post-couple half-close propagation + drain ----------

    @Test
    @DisplayName("RELAY-008: a post-couple half-close on the ingress propagates to BOTH legs + the registry; the "
            + "in-flight PDU is drained WHOLE (sequence/boundary integrity); teardown observed on both legs")
    void postCoupleHalfClosePropagatesAndDrainsWholePdus() {
        couple();
        byte[] submit = opaquePdu(SUBMIT_SM, 31);
        ingress.writeInbound(inbound(submit)); // in flight toward the SMSC
        ByteBuf crossed = egress.readOutbound();
        assertThat(crossed).as("precondition: the PDU crossed the relay").isNotNull();
        crossed.release();   // readOutbound hands the reader ownership (the T7 trap)

        ingress.close(); // the legacy client half-closes

        ByteBuf drained = egress.readOutbound();
        assertThat(drained).as("no second PDU — exactly one was in flight").isNull();
        assertThat(egress.isOpen()).as("the peer leg is torn down by the propagation").isFalse();
        assertThat(registry.size()).as("the pair leaves the registry").isZero();
        assertThat(observer.connectionCloses())
                .as("both legs' teardown is OBSERVED (never a silent drop), exactly once each")
                .containsExactlyInAnyOrder(
                        new CapturingRelayObserver.ConnectionClose(Direction.INGRESS, CloseReason.PEER_HALF_CLOSE),
                        new CapturingRelayObserver.ConnectionClose(Direction.EGRESS, CloseReason.PEER_HALF_CLOSE));
    }

    // ---------- RELAY-009: the write/close micro-race ----------

    @Test
    @DisplayName("RELAY-009: a relayed PDU racing its source leg's close yields ZERO or EXACTLY ONE complete "
            + "framed PDU at the peer — never a partial length-prefix — and the raced frame never leaks")
    void relayedPduRacingCloseIsWholeOrNothing() {
        couple();

        // (a) The drain side: the write landed in the peer's outbound queue, then the source closes.
        byte[] submit = opaquePdu(SUBMIT_SM, 41);
        ByteBuf source = inbound(submit);
        ingress.writeInbound(source);
        ingress.close(); // races the flush

        ByteBuf atSmsc = egress.readOutbound();
        if (atSmsc != null) { // zero-or-one is the contract; when present it must be WHOLE
            assertThat(atSmsc.readableBytes()).as("a complete framed PDU — its own length prefix").isEqualTo(atSmsc.getInt(0));
            assertThat(bytesOf(atSmsc)).isEqualTo(submit);
            atSmsc.release();   // readOutbound hands the reader ownership (the T7 trap)
        }
        assertThat(observer.connectionCloses()).isNotEmpty();
        assertThat(registry.size()).isZero();

        // (b) The dead-pair side: a frame delivered to a leg whose entry is already torn down is CONSUMED
        // (released + fail-closed close) — never written to the dead pair, never a partial frame. The
        // registry's beginTeardown leaves the closes to the caller, so clearing the entry here reproduces
        // the delivery-race window deterministically (the channel is still open at writeInbound time).
        // (No null guard — couple() above guarantees the field is assigned; the pre-split suite's guard
        // was dead code, chunk-B review 2026-09-01.)
        egress.finishAndReleaseAll(); // (a)'s egress was closed by the teardown propagation
        freshIngress(); // a fresh coupled pair for (b)
        couple();
        assertThat(registry.beginTeardown(egress)).as("precondition: (b) starts from a torn-down entry").isNotNull();
        int ingressOutboundBefore = countOutbound(ingress);
        ByteBuf raced = inbound(opaquePdu(OPAQUE_DLR_TAG, 42));
        egress.writeInbound(raced);
        assertThat(countOutbound(ingress)).as("no partial/new frame reaches a torn-down pair").isEqualTo(ingressOutboundBefore);
        assertThat(raced.refCnt()).as("the raced frame is released, not leaked").isZero();
    }

    // ---------- RELAY-010: RST mid-relay → observed teardown ----------

    @Test
    @DisplayName("RELAY-010: a peer RST mid-relay (IOException surfaced pre-inactive, as on a live NIO channel) "
            + "tears down BOTH legs + the registry and the teardown is OBSERVED as PEER_RST")
    void peerRstMidRelayTearsDownBothLegsAndIsObserved() {
        couple();

        ingress.pipeline().fireExceptionCaught(new IOException("Connection reset by peer"));

        assertThat(ingress.isOpen()).as("the reset leg closes").isFalse();
        assertThat(egress.isOpen()).as("the peer leg is torn down too").isFalse();
        assertThat(registry.size()).isZero();
        assertThat(observer.connectionCloses())
                .as("the RST teardown is OBSERVED — never a silent drop of in-flight PDUs")
                .containsExactlyInAnyOrder(
                        new CapturingRelayObserver.ConnectionClose(Direction.INGRESS, CloseReason.PEER_RST),
                        new CapturingRelayObserver.ConnectionClose(Direction.EGRESS, CloseReason.PEER_RST));
    }

    // ---------- AC5: exactly-once onConnectionClosed ----------

    @Test
    @DisplayName("AC5: onConnectionClosed fires EXACTLY ONCE per channel across the whole lifecycle — the couple, "
            + "the relayed traffic, and the teardown never double-fire a leg's close")
    void connectionClosedFiresExactlyOncePerChannel() {
        couple();
        ingress.writeInbound(inbound(opaquePdu(SUBMIT_SM, 51)));
        egress.writeInbound(inbound(opaquePdu(OPAQUE_DLR_TAG, 52)));
        // A redundant/duplicate channelInactive delivery while the handlers are still installed —
        // whatever violates Netty's fire-once contract (an event-loop replay, a redundant fire) is
        // exactly what the AC5 CAS guards. NOTE: this must be delivered PRE-close — EmbeddedChannel's
        // close() tears the pipeline down, so a post-close fire propagates through an empty pipeline
        // and never reaches the handler (empirically probed — a post-close duplicate is a NO-OP, not
        // a biter). The first fire tears the pair down (EGRESS closes by propagation); the duplicate
        // and the real close's own channelInactive must both be swallowed.
        ingress.pipeline().fireChannelInactive();
        ingress.pipeline().fireChannelInactive(); // the duplicate
        ingress.close();                          // the real close's own channelInactive — also swallowed

        assertThat(observer.connectionCloses())
                .as("exactly two events total — one INGRESS + one EGRESS, each exactly once — the "
                        + "duplicate delivery and the real close's own inactive were swallowed by the CAS")
                .hasSize(2)
                .extracting(CapturingRelayObserver.ConnectionClose::direction)
                .containsExactlyInAnyOrder(Direction.INGRESS, Direction.EGRESS);
    }
}
