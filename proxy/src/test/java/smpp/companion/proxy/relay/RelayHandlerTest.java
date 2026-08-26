package smpp.companion.proxy.relay;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
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
import io.netty.channel.DefaultChannelId;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.observability.CapturingSpliceObserver;
import smpp.companion.proxy.observability.CloseReason;
import smpp.companion.proxy.observability.Direction;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.relay.netty.RelayEgressInitializer;
import smpp.companion.proxy.tls.SmppLegTlsFactory;
import smpp.companion.proxy.security.BindCredential;
import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.security.RequestContext;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.security.VerdictRequest;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 2.2 Task 8 / AC3+AC7 &mdash; the {@code RelayHandler} data-plane contract: the AD-25
 * single-flipper (decoded ROK {@code bind_*_resp} only), the AD-32 pre-couple uniform bare-close on
 * BOTH legs (with case-4's SMSC-response verbatim forwarding), the post-flip opaque framed-byte
 * splice (REL-1: no drop/dup/corrupt, boundaries preserved), the race-free teardown ordering, and
 * the pinned {@code SpliceObserver} triggers (onBindAccept exactly at the flip;
 * onConnectionClosed exactly-once per channel).
 *
 * <p>Every test drives the REAL pipelines ({@code framer → codec → BindInterceptor → RelayHandler}
 * on the ingress, {@code framer → codec → RelayHandler} on the egress — the production
 * {@link RelayEgressInitializer} plus the T7 connect assembly's {@code EgressLeg}) on
 * {@link EmbeddedChannel}s with unique {@link DefaultChannelId}s (the T4 singleton-id trap), fed
 * hand-authored wire PDUs (independent of the codec under test, mirroring {@code BindInterceptorTest}'s
 * builders). Real-socket end-to-end (including RST injection on a live socket) is T9's in-JVM mock.
 *
 * <p><b>EmbeddedChannel honesty notes:</b> (1) read-ARMING ({@code ctx.read()} /
 * write-completes-gates-read / the low-water re-arm) is a no-op observable on an embedded channel —
 * the substrate options are pinned by {@code RelayChannelOptionsTest}, the demand-driven behavior
 * proves out on T9's real sockets. (2) An RST is simulated by firing {@code IOException} through the
 * pipeline ({@code fireExceptionCaught}) — exactly how a real reset surfaces to the handler on a
 * live NIO channel, pre-inactive.
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
@SuppressWarnings("FutureReturnValueIgnored") // reason: EmbeddedChannel.close()/writeInbound in tests are
// synchronous fire-and-forget — the assertions observe the channels' outbound queues and lifecycle state,
// never the close/write futures themselves.
@Timeout(value = 10, threadMode = ThreadMode.SEPARATE_THREAD) // a hung handler chain must FAIL a test,
// not hang the suite (the BindInterceptorTest pattern).
class RelayHandlerTest {

    private static final int HEADER = 16;

    /** AD-33 Q2 — the ratified generic bind-failure code, pinned independently of the production constant. */
    private static final int ESME_RBINDFAIL = 0x0000000D;

    /** SMPP 3.4 §4.1.2 opaque PDUs (never parsed — the codec passes them through on the command_id alone). */
    private static final int SUBMIT_SM = 0x00000004;
    private static final int DELIVER_SM = 0x00000105;
    private static final int ENQUIRE_LINK = 0x00000015;
    private static final int GENERIC_NACK = 0x80000000;

    private ConnectionRegistry registry;
    private CapturingSpliceObserver observer;
    private LatchedBindCredentialVerifier verifier;
    private FakeEgressConnector connector;
    private RelayEgressInitializer egressInitializer;
    private EmbeddedChannel ingress;
    private EmbeddedChannel egress;
    private final List<ByteBuf> toRelease = new ArrayList<>();

    @BeforeEach
    void freshIngress() {
        if (ingress != null) {
            ingress.finishAndReleaseAll();
        }
        registry = new ConnectionRegistry();
        observer = new CapturingSpliceObserver();
        verifier = new LatchedBindCredentialVerifier();
        connector = new FakeEgressConnector();
        egressInitializer = new RelayEgressInitializer(registry, observer);
        ProxyCompanionProperties properties = RelayTestFixtures.modeBProperties(RelayTestFixtures.freePort(), 1);
        RelayChannelOptions channelOptions = new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT);
        // Story 3.3: the role-split graph — the routing table + per-cell TLS factory resolve from the
        // SAME properties (mode-b: no routing, no TLS — the reverse arm's plaintext dial).
        BindInterceptor interceptor = new BindInterceptor(
                verifier, registry, observer, properties, egressInitializer, channelOptions,
                new RoutingTable(properties), new SmppLegTlsFactory(properties, Runnable::run), connector);
        ingress = new EmbeddedChannel(DefaultChannelId.newInstance(),
                new SmppFrameDecoder(), new SmppCodec(), interceptor,
                new RelayHandler(registry, observer, Direction.INGRESS));
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

    // ---------- RELAY-001: the AD-25 single flipper ----------

    @Test
    @DisplayName("RELAY-001a/e + REL-1: the flip fires ONLY on the decoded ROK bind_resp (never at the "
            + "verdict Allow) — onBindAccept exactly at the flip; post-flip PDUs splice opaquely both "
            + "directions, boundaries preserved (multi-chunk feed)")
    void flipsOnlyOnDecodedRokBindRespThenSplicesOpaquely() {
        couple();
        assertThat(observer.bindAccepts())
                .as("RELAY-001e: Verdict.Allow WITHOUT a bind_resp flips NOTHING (the flip ratifies the SMSC's ROK)")
                .isEmpty();
        assertThat(observer.framedPdus()).as("no spliced PDU pre-flip").isEmpty();

        egress.writeInbound(inbound(bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0, "SMSC01", new byte[0])));

        assertThat(observer.bindAccepts())
                .as("onBindAccept fires exactly at the AD-25 flip — once, with the bound identity")
                .singleElement()
                .isEqualTo(new smpp.companion.proxy.security.SystemId(new AsciiString("legacy1")));
        ByteBuf toLegacy = ingress.readOutbound();
        assertThat(toLegacy).as("the ROK bind_resp is forwarded verbatim by the EgressLeg (T7 split)").isNotNull();
        assertThat(bytesOf(toLegacy)).isEqualTo(bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0, "SMSC01", new byte[0]));
        assertThat(registry.size()).as("the pair stays registered — it is splicing now").isEqualTo(1);

        // Post-flip ingress→egress splice: a submit_sm (opaque) crosses INGRESS.
        byte[] submit = opaquePdu(SUBMIT_SM, 101);
        ByteBuf submitSource = inbound(submit);
        ingress.writeInbound(submitSource);
        ByteBuf atSmsc = egress.readOutbound();
        assertThat(atSmsc).as("REL-1: the submit_sm is spliced toward the SMSC, byte-exact").isNotNull();
        assertThat(bytesOf(atSmsc)).isEqualTo(submit);

        // Post-flip egress→ingress splice: a deliver_sm fed in MULTIPLE chunks (the RecordingAllocator-bypass
        // trap — one writeInbound of a whole buffer is tautological; chunked input exercises the framer's
        // reassembly through the REAL path) yields exactly ONE complete framed PDU at the legacy side.
        byte[] deliver = opaquePdu(DELIVER_SM, 202);
        byte[] firstHalf = java.util.Arrays.copyOfRange(deliver, 0, 9);
        byte[] secondHalf = java.util.Arrays.copyOfRange(deliver, 9, deliver.length);
        egress.writeInbound(inbound(firstHalf));
        assertThat(ingress.<ByteBuf>readOutbound()).as("no partial frame ever reaches the wire (AD-2)").isNull();
        egress.writeInbound(inbound(secondHalf));
        ByteBuf atLegacy = ingress.readOutbound();
        assertThat(atLegacy).as("the reassembled deliver_sm is spliced toward the legacy client, byte-exact").isNotNull();
        assertThat(bytesOf(atLegacy)).isEqualTo(deliver);

        assertThat(observer.framedPdus())
                .as("onFramedPdu fires once per spliced PDU, on the leg it crossed (the bind_resp itself is "
                        + "the handshake plane, not the splice)")
                .containsExactly(Direction.INGRESS, Direction.EGRESS);
        // readOutbound() hands the reader ownership (the T7 trap) — release the captured frame FIRST,
        // then the shared underlying wrapper reaching zero proves the splice's ownership is clean.
        atSmsc.release();
        atLegacy.release();
        assertThat(submitSource.refCnt()).as("the spliced submit_sm's frame is fully released after capture").isZero();
    }

    @Test
    @DisplayName("RELAY-001b + AC3 non-ROK teardown guard: a decoded NON-ROK bind_resp does NOT flip — it is "
            + "forwarded verbatim FIRST (RELAY-002c), then both legs tear down (BIND_FAILED_NON_ROK)")
    void nonRokBindRespDoesNotFlipAndTearsDownAfterVerbatimForward() {
        couple();
        byte[] nonRok = bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0x0000000E, "SMSC01", new byte[0]);
        egress.writeInbound(inbound(nonRok));

        assertThat(observer.bindAccepts()).as("no ROK — no flip, ever (AD-25)").isEmpty();
        ByteBuf toLegacy = ingress.readOutbound();
        assertThat(toLegacy).as("the SMSC's own non-ROK answer reaches the legacy client VERBATIM (AD-32 case 4)").isNotNull();
        assertThat(bytesOf(toLegacy)).isEqualTo(nonRok);
        assertThat(ingress.<ByteBuf>readOutbound()).as("nothing follows the verbatim answer (no proxy deny synthesis)").isNull();
        assertThat(ingress.isOpen()).as("non-ROK → do NOT flip; tear down (AC3)").isFalse();
        assertThat(egress.isOpen()).as("both legs of the failed pair close").isFalse();
        assertThat(registry.size()).as("the failed pair leaves the registry").isZero();
        assertThat(observer.connectionCloses())
                .as("the teardown is OBSERVED on both legs with the non-ROK reason")
                .containsExactlyInAnyOrder(
                        new CapturingSpliceObserver.ConnectionClose(Direction.EGRESS, CloseReason.BIND_FAILED_NON_ROK),
                        new CapturingSpliceObserver.ConnectionClose(Direction.INGRESS, CloseReason.BIND_FAILED_NON_ROK));
    }

    @Test
    @DisplayName("RELAY-001 flip re-check: a bind_resp arriving AFTER the pair tore down flips NOTHING and "
            + "forwards nothing — both halves: entry ABSENT, and entry TEARING-DOWN with attrs still "
            + "cached (the exact race window a late flip would corrupt)")
    void lateBindRespAfterTeardownDoesNotFlip() {
        couple();
        // (a) Entry ABSENT: the pair's entry is removed + attrs cleared (the teardown winner's state)
        // while the egress channel is still delivering — the registry's beginTeardown leaves the CLOSES
        // to the caller, so this is exactly the window a racing bind_resp sees.
        assertThat(registry.beginTeardown(egress)).as("precondition: this call wins the teardown").isNotNull();
        assertThat(registry.size()).isZero();

        egress.writeInbound(inbound(bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0, "SMSC01", new byte[0])));

        assertThat(observer.bindAccepts()).as("(a) a torn-down pair must not flip (re-check: entry absent)").isEmpty();
        assertThat(ingress.<ByteBuf>readOutbound()).as("nothing is forwarded to a dead pair").isNull();
        assertThat(egress.isOpen()).as("the stale delivery fail-closes its own leg").isFalse();

        // (b) Entry TEARING-DOWN but still cached on the channel: the CAS is won while the attrs are
        // not yet cleared — the other half of the same race (ConnectionEntry.beginTearingDown is the
        // CAS without the attr clear, so this fabricates the window deterministically).
        egress.finishAndReleaseAll();
        freshIngress();
        couple();
        ConnectionEntry stale = registry.entryFor(egress);
        assertThat(stale).as("precondition: the entry is still cached on the egress leg").isNotNull();
        assertThat(stale.beginTearingDown()).as("precondition: the teardown CAS is already won").isTrue();

        egress.writeInbound(inbound(bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0, "SMSC01", new byte[0])));

        assertThat(observer.bindAccepts()).as("(b) a tearing-down entry must not flip (the re-check's conjunct)").isEmpty();
        assertThat(egress.isOpen()).as("the racing delivery fail-closes its leg").isFalse();
    }

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
                .containsExactly(new CapturingSpliceObserver.ConnectionClose(Direction.INGRESS, CloseReason.PRE_COUPLE_NON_BIND_PDU));
        assertThat(observer.bindRejects()).as("a violation is not a Verdict — no onBindReject (AD-27)").isEmpty();
        assertThat(observer.bindAccepts()).isEmpty();
    }

    @Test
    @DisplayName("RELAY-002 (post-egress, pre-flip): an enquire_link after the egress connected but before the "
            + "flip bare-closes BOTH legs with NO deny — the egress-leg AD-33 arm loses the teardown race (Q1)")
    void ingressPreCoupleViolationAfterEgressConnectBareClosesBothLegs() {
        couple(); // egress connected, bind forwarded, NOT yet flipped

        ingress.writeInbound(inbound(opaquePdu(ENQUIRE_LINK, 8)));

        assertThat(ingress.<ByteBuf>readOutbound())
                .as("bare close even with a live egress — Q1 emits no bind_resp on a violation (AD-32)")
                .isNull();
        assertThat(ingress.isOpen()).isFalse();
        assertThat(egress.isOpen()).as("the coupled egress leg is torn down too").isFalse();
        assertThat(registry.size()).isZero();
        assertThat(observer.connectionCloses())
                .extracting(CapturingSpliceObserver.ConnectionClose::direction)
                .as("both legs' closes are observed")
                .containsExactlyInAnyOrder(Direction.INGRESS, Direction.EGRESS);
    }

    // ---------- RELAY-003: egress pre-couple non-bind → not leaked ----------

    @Test
    @DisplayName("RELAY-003: a pre-couple deliver_sm on the egress leg is NOT leaked to the legacy client — the "
            + "egress closes with PRE_COUPLE_NON_BIND_PDU and the bind fails via the AD-33 collapse")
    void egressPreCoupleNonBindPduIsNotLeaked() {
        couple();
        byte[] deliver = opaquePdu(DELIVER_SM, 9);
        ByteBuf frame = inbound(deliver);
        egress.writeInbound(frame);

        ByteBuf toLegacy = ingress.readOutbound();
        assertThat(toLegacy).as("the bind-failure propagation reaches the legacy client (R32)").isNotNull();
        assertThat(toLegacy.readableBytes()).as("the ONLY ingress-bound PDU is the header-only AD-33 deny").isEqualTo(HEADER);
        assertThat(toLegacy.getInt(8)).isEqualTo(ESME_RBINDFAIL);
        assertThat(bytesOf(toLegacy)).as("…and it is NOT the deliver_sm bytes — zero leak").isNotEqualTo(deliver);
        assertThat(egress.isOpen()).as("the violating egress leg closes").isFalse();
        assertThat(ingress.isOpen()).as("the unanswered bind tears the ingress down too").isFalse();
        assertThat(registry.size()).isZero();
        assertThat(observer.framedPdus()).as("nothing crossed the splice — no onFramedPdu(INGRESS) leak").isEmpty();
        assertThat(observer.connectionCloses())
                .as("the egress close carries the pre-couple reason")
                .contains(new CapturingSpliceObserver.ConnectionClose(Direction.EGRESS, CloseReason.PRE_COUPLE_NON_BIND_PDU));
        assertThat(frame.refCnt()).as("the never-forwarded deliver_sm frame is released").isZero();
    }

    // ---------- RELAY-002c: SMSC generic_nack pre-bind_resp → verbatim + teardown ----------

    @Test
    @DisplayName("RELAY-002c: a pre-couple generic_nack from the SMSC is forwarded VERBATIM as the bind result, "
            + "no flip, both legs torn down (AD-32 case 4)")
    void genericNackPreBindRespIsForwardedVerbatimThenTearsDown() {
        couple();
        byte[] nack = opaquePdu(GENERIC_NACK, 5);
        egress.writeInbound(inbound(nack));

        ByteBuf toLegacy = ingress.readOutbound();
        assertThat(toLegacy).as("the SMSC's own answer is ground truth — forwarded unchanged").isNotNull();
        assertThat(bytesOf(toLegacy)).isEqualTo(nack);
        assertThat(ingress.<ByteBuf>readOutbound()).as("nothing follows the verbatim nack (no proxy deny on top)").isNull();
        assertThat(observer.bindAccepts()).as("a nack never flips the splice").isEmpty();
        assertThat(ingress.isOpen()).as("both legs tear down after the forwarded answer").isFalse();
        assertThat(egress.isOpen()).isFalse();
        assertThat(registry.size()).isZero();
        assertThat(observer.connectionCloses())
                .containsExactlyInAnyOrder(
                        new CapturingSpliceObserver.ConnectionClose(Direction.EGRESS, CloseReason.GENERIC_NACK_PRE_BIND),
                        new CapturingSpliceObserver.ConnectionClose(Direction.INGRESS, CloseReason.GENERIC_NACK_PRE_BIND));
    }

    // ---------- CODEC-021 sibling (Risk Note 2, second vector) ----------

    @Test
    @DisplayName("CODEC-021 sibling: a 0-byte-body (header-only) bind_resp NEVER reaches isOk() — the codec throws "
            + "pre-build; assert the channelInactive teardown (DECODE_ERROR) + the AD-33 collapse, not isOk()==false")
    void headerOnlyBindRespTearsDownViaDecodeErrorNeverReachingIsOk() {
        couple();
        // 16 bytes, bind_transceiver_resp, EMPTY body — readAscii(system_id) finds no NUL → DecoderException
        // inside SmppCodec.decode, BEFORE SmppBindResponse is built (Risk Note 2's second vector).
        egress.writeInbound(inbound(assemble(SmppCommandIds.BIND_TRANSCEIVER_RESP, 0x0000000A, 5, 0, out -> {})));

        assertThat(observer.bindAccepts()).as("isOk() was never reached — no flip, nothing else").isEmpty();
        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("the failed bind collapses to the AD-33 generic deny (the EgressLeg arm)").isNotNull();
        assertThat(deny.getInt(8)).isEqualTo(ESME_RBINDFAIL);
        assertThat(deny.getInt(12)).as("correlates the still-pending bind").isEqualTo(5);
        assertThat(ingress.isOpen()).isFalse();
        assertThat(egress.isOpen()).isFalse();
        assertThat(registry.size()).isZero();
        assertThat(observer.connectionCloses())
                .as("the decode reject is observed as DECODE_ERROR on the egress leg")
                .contains(new CapturingSpliceObserver.ConnectionClose(Direction.EGRESS, CloseReason.DECODE_ERROR));
    }

    // ---------- RELAY-008: post-couple half-close propagation + drain ----------

    @Test
    @DisplayName("RELAY-008: a post-couple half-close on the ingress propagates to BOTH legs + the registry; the "
            + "in-flight PDU is drained WHOLE (sequence/boundary integrity); teardown observed on both legs")
    void postCoupleHalfClosePropagatesAndDrainsWholePdus() {
        coupleAndFlip();
        byte[] submit = opaquePdu(SUBMIT_SM, 31);
        ingress.writeInbound(inbound(submit)); // in flight toward the SMSC
        assertThat(egress.<ByteBuf>readOutbound()).as("precondition: the PDU crossed the splice").isNotNull();

        ingress.close(); // the legacy client half-closes

        ByteBuf drained = egress.readOutbound();
        assertThat(drained).as("no second PDU — exactly one was in flight").isNull();
        assertThat(egress.isOpen()).as("the peer leg is torn down by the propagation").isFalse();
        assertThat(registry.size()).as("the pair leaves the registry").isZero();
        assertThat(observer.connectionCloses())
                .as("both legs' teardown is OBSERVED (never a silent drop), exactly once each")
                .containsExactlyInAnyOrder(
                        new CapturingSpliceObserver.ConnectionClose(Direction.INGRESS, CloseReason.PEER_HALF_CLOSE),
                        new CapturingSpliceObserver.ConnectionClose(Direction.EGRESS, CloseReason.PEER_HALF_CLOSE));
    }

    // ---------- RELAY-009: the write/close micro-race ----------

    @Test
    @DisplayName("RELAY-009: a spliced PDU racing its source leg's close yields ZERO or EXACTLY ONE complete "
            + "framed PDU at the peer — never a partial length-prefix — and the raced frame never leaks")
    void splicedPduRacingCloseIsWholeOrNothing() {
        coupleAndFlip();

        // (a) The drain side: the write landed in the peer's outbound queue, then the source closes.
        byte[] submit = opaquePdu(SUBMIT_SM, 41);
        ByteBuf source = inbound(submit);
        ingress.writeInbound(source);
        ingress.close(); // races the flush

        ByteBuf atSmsc = egress.readOutbound();
        if (atSmsc != null) { // zero-or-one is the contract; when present it must be WHOLE
            assertThat(atSmsc.readableBytes()).as("a complete framed PDU — its own length prefix").isEqualTo(atSmsc.getInt(0));
            assertThat(bytesOf(atSmsc)).isEqualTo(submit);
        }
        assertThat(observer.connectionCloses()).isNotEmpty();
        assertThat(registry.size()).isZero();

        // (b) The dead-pair side: a frame delivered to a leg whose entry is already torn down is CONSUMED
        // (released + fail-closed close) — never written to the dead pair, never a partial frame. The
        // registry's beginTeardown leaves the closes to the caller, so clearing the entry here reproduces
        // the delivery-race window deterministically (the channel is still open at writeInbound time).
        if (egress != null) {
            egress.finishAndReleaseAll(); // (a)'s egress was closed by the teardown propagation
        }
        freshIngress(); // a fresh coupled pair for (b)
        coupleAndFlip();
        assertThat(registry.beginTeardown(egress)).as("precondition: (b) starts from a torn-down entry").isNotNull();
        int ingressOutboundBefore = countOutbound(ingress);
        ByteBuf raced = inbound(opaquePdu(DELIVER_SM, 42));
        egress.writeInbound(raced);
        assertThat(countOutbound(ingress)).as("no partial/new frame reaches a torn-down pair").isEqualTo(ingressOutboundBefore);
        assertThat(raced.refCnt()).as("the raced frame is released, not leaked").isZero();
    }

    // ---------- RELAY-010: RST mid-splice → observed teardown ----------

    @Test
    @DisplayName("RELAY-010: a peer RST mid-splice (IOException surfaced pre-inactive, as on a live NIO channel) "
            + "tears down BOTH legs + the registry and the teardown is OBSERVED as PEER_RST")
    void peerRstMidSpliceTearsDownBothLegsAndIsObserved() {
        coupleAndFlip();

        ingress.pipeline().fireExceptionCaught(new IOException("Connection reset by peer"));

        assertThat(ingress.isOpen()).as("the reset leg closes").isFalse();
        assertThat(egress.isOpen()).as("the peer leg is torn down too").isFalse();
        assertThat(registry.size()).isZero();
        assertThat(observer.connectionCloses())
                .as("the RST teardown is OBSERVED — never a silent drop of in-flight PDUs")
                .containsExactlyInAnyOrder(
                        new CapturingSpliceObserver.ConnectionClose(Direction.INGRESS, CloseReason.PEER_RST),
                        new CapturingSpliceObserver.ConnectionClose(Direction.EGRESS, CloseReason.PEER_RST));
    }

    // ---------- AC5: exactly-once onConnectionClosed ----------

    @Test
    @DisplayName("AC5: onConnectionClosed fires EXACTLY ONCE per channel across the whole lifecycle — the flip, "
            + "the splice traffic, and the teardown never double-fire a leg's close")
    void connectionClosedFiresExactlyOncePerChannel() {
        coupleAndFlip();
        ingress.writeInbound(inbound(opaquePdu(SUBMIT_SM, 51)));
        egress.writeInbound(inbound(opaquePdu(DELIVER_SM, 52)));
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
                .extracting(CapturingSpliceObserver.ConnectionClose::direction)
                .containsExactlyInAnyOrder(Direction.INGRESS, Direction.EGRESS);
    }

    // ---------- fixtures ----------

    /** Completes the Allow path with a fake (Embedded) egress leg carrying the REAL pipelines (T7 assembly). */
    private void couple() {
        verifier.completeAllow();
        egress = new EmbeddedChannel(DefaultChannelId.newInstance(), egressInitializer);
        connector.result = egress.newSucceededFuture();
        ingress.writeInbound(inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 5, "legacy1", "pw123456")));
        assertThat(egress.<ByteBuf>readOutbound()).as("precondition: the bind reached the SMSC").isNotNull();
    }

    /** Couples AND flips (the ROK bind_resp from the SMSC) — the post-couple splice plane is live. */
    private void coupleAndFlip() {
        couple();
        egress.writeInbound(inbound(bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0, "SMSC01", new byte[0])));
        assertThat(observer.bindAccepts()).as("precondition: the flip fired").hasSize(1);
        assertThat(ingress.<ByteBuf>readOutbound()).as("precondition: the ROK reached the legacy client").isNotNull();
    }

    /**
     * The injected egress connect (RELAY-006's sanctioned seam): records the assembled {@link Bootstrap}
     * (+ target) and returns the test-chosen {@link ChannelFuture}.
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

    // ---------- hand-authored PDU builders (raw bytes — independent of the codec) ----------

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

    /** An OPAQUE non-bind PDU: a valid 16-octet header + an arbitrary opaque body (never parsed, AD-3). */
    private static byte[] opaquePdu(int commandId, int sequence) {
        byte[] body = new byte[] {0x01, 0x02, 0x03, 0x04};
        return assemble(commandId, 0, sequence, body.length, out -> out.put(body));
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

    private static int countOutbound(EmbeddedChannel channel) {
        int n = 0;
        while (channel.<ByteBuf>readOutbound() != null) {
            n++;
        }
        return n;
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
}
