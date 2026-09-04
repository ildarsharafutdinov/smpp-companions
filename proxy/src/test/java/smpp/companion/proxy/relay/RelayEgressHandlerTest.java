package smpp.companion.proxy.relay;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Timeout.ThreadMode;

import io.netty.buffer.ByteBuf;

import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.proxy.observability.CapturingRelayObserver;
import smpp.companion.proxy.observability.CloseReason;
import smpp.companion.proxy.observability.Direction;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 2.2 Task 8 / AC3+AC6+AC7 (the egress half of the Story 3.4 T5 split of
 * {@code RelayHandlerTest}) &mdash; the {@code RelayEgressHandler} contract: the AD-25 single couple
 * unit (decoded ROK {@code bind_*_resp} only — structural-by-type: only this class can call
 * {@code ConnectionEntry.couple()}, pinned by {@code RelayCoupleSiteArchitectureTest}), the non-ROK
 * forward-then-teardown, the case-4 {@code generic_nack} verbatim arm, the egress-leg AD-32
 * bare-close (RELAY-003), and the decode-error sibling (CODEC-021). The post-couple opaque relay is
 * exercised here in both directions (the couple's own row). The shared pair fixture, the REAL
 * pipelines, and the EmbeddedChannel honesty notes live in {@link CoupledPairHarness}; the
 * ingress-leg behaviors are {@code RelayIngressHandlerTest}'s.
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
@SuppressWarnings("FutureReturnValueIgnored") // reason: EmbeddedChannel.close()/writeInbound in tests are
// synchronous fire-and-forget — the assertions observe the channels' outbound queues and lifecycle state,
// never the close/write futures themselves.
@Timeout(value = 10, threadMode = ThreadMode.SEPARATE_THREAD) // a hung handler chain must FAIL a test,
// not hang the suite (the BindInterceptorTest pattern).
class RelayEgressHandlerTest extends CoupledPairHarness {

    // ---------- RELAY-001: the AD-25 single couple unit ----------

    @Test
    @DisplayName("RELAY-001a/e + REL-1: the couple fires ONLY on the decoded ROK bind_resp (never at the "
            + "verdict Allow) — onBindAccept exactly at the couple; post-couple PDUs relay opaquely both "
            + "directions, boundaries preserved (multi-chunk feed)")
    void couplesOnlyOnDecodedRokBindRespThenRelaysOpaquely() {
        awaitingBindResp();
        assertThat(observer.bindAccepts())
                .as("RELAY-001e: Verdict.Allow WITHOUT a bind_resp couples NOTHING (the couple ratifies the SMSC's ROK)")
                .isEmpty();
        assertThat(observer.framedPdus()).as("no relayed PDU pre-couple").isEmpty();

        egress.writeInbound(inbound(bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0, "SMSC01", new byte[0])));

        assertThat(observer.bindAccepts())
                .as("onBindAccept fires exactly at the AD-25 couple — once, with the bound identity")
                .singleElement()
                .isEqualTo(new smpp.companion.proxy.security.SystemId(new io.netty.util.AsciiString("legacy1")));
        ByteBuf toLegacy = ingress.readOutbound();
        assertThat(toLegacy).as("the ROK bind_resp is forwarded verbatim by the EgressLeg (T7 split)").isNotNull();
        assertThat(bytesOf(toLegacy)).isEqualTo(bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0, "SMSC01", new byte[0]));
        toLegacy.release();   // readOutbound hands the reader ownership (the T7 trap)
        assertThat(registry.size()).as("the pair stays registered — it is relaying now").isEqualTo(1);

        // Post-couple ingress→egress relay: a submit_sm (opaque) crosses INGRESS.
        byte[] submit = opaquePdu(SUBMIT_SM, 101);
        ByteBuf submitSource = inbound(submit);
        ingress.writeInbound(submitSource);
        ByteBuf atSmsc = egress.readOutbound();
        assertThat(atSmsc).as("REL-1: the submit_sm is relayed toward the SMSC, byte-exact").isNotNull();
        assertThat(bytesOf(atSmsc)).isEqualTo(submit);

        // Post-couple egress→ingress relay: a deliver_sm fed in MULTIPLE chunks (the RecordingAllocator-bypass
        // trap — one writeInbound of a whole buffer is tautological; chunked input exercises the framer's
        // reassembly through the REAL path) yields exactly ONE complete framed PDU at the legacy side.
        byte[] deliver = opaquePdu(OPAQUE_DLR_TAG, 202);
        byte[] firstHalf = java.util.Arrays.copyOfRange(deliver, 0, 9);
        byte[] secondHalf = java.util.Arrays.copyOfRange(deliver, 9, deliver.length);
        egress.writeInbound(inbound(firstHalf));
        assertThat(ingress.<ByteBuf>readOutbound()).as("no partial frame ever reaches the wire (AD-2)").isNull();
        egress.writeInbound(inbound(secondHalf));
        ByteBuf atLegacy = ingress.readOutbound();
        assertThat(atLegacy).as("the reassembled deliver_sm is relayed toward the legacy client, byte-exact").isNotNull();
        assertThat(bytesOf(atLegacy)).isEqualTo(deliver);

        assertThat(observer.framedPdus())
                .as("onFramedPdu fires once per relayed PDU, on the leg it crossed (the bind_resp itself is "
                        + "the handshake plane, not the relay)")
                .containsExactly(Direction.INGRESS, Direction.EGRESS);
        // readOutbound() hands the reader ownership (the T7 trap) — release the captured frame FIRST,
        // then the shared underlying wrapper reaching zero proves the relay's ownership is clean.
        atSmsc.release();
        atLegacy.release();
        assertThat(submitSource.refCnt()).as("the relayed submit_sm's frame is fully released after capture").isZero();
    }

    @Test
    @DisplayName("RELAY-001b + AC3 non-ROK teardown guard: a decoded NON-ROK bind_resp does NOT couple — it is "
            + "forwarded verbatim FIRST (RELAY-002c), then both legs tear down (BIND_FAILED_NON_ROK)")
    void nonRokBindRespDoesNotCoupleAndTearsDownAfterVerbatimForward() {
        awaitingBindResp();
        byte[] nonRok = bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0x0000000E, "SMSC01", new byte[0]);
        egress.writeInbound(inbound(nonRok));

        assertThat(observer.bindAccepts()).as("no ROK — no couple, ever (AD-25)").isEmpty();
        ByteBuf toLegacy = ingress.readOutbound();
        assertThat(toLegacy).as("the SMSC's own non-ROK answer reaches the legacy client VERBATIM (AD-32 case 4)").isNotNull();
        assertThat(bytesOf(toLegacy)).isEqualTo(nonRok);
        toLegacy.release();   // readOutbound hands the reader ownership (the T7 trap)
        assertThat(ingress.<ByteBuf>readOutbound()).as("nothing follows the verbatim answer (no proxy deny synthesis)").isNull();
        assertThat(ingress.isOpen()).as("non-ROK → do NOT couple; tear down (AC3)").isFalse();
        assertThat(egress.isOpen()).as("both legs of the failed pair close").isFalse();
        assertThat(registry.size()).as("the failed pair leaves the registry").isZero();
        assertThat(observer.connectionCloses())
                .as("the teardown is OBSERVED on both legs with the non-ROK reason")
                .containsExactlyInAnyOrder(
                        new CapturingRelayObserver.ConnectionClose(Direction.EGRESS, CloseReason.BIND_FAILED_NON_ROK),
                        new CapturingRelayObserver.ConnectionClose(Direction.INGRESS, CloseReason.BIND_FAILED_NON_ROK));
    }

    @Test
    @DisplayName("RELAY-001 couple re-check: a bind_resp arriving AFTER the pair tore down couples NOTHING and "
            + "forwards nothing — both halves: entry ABSENT, and entry TEARING-DOWN with attrs still "
            + "cached (the exact race window a late couple would corrupt)")
    void lateBindRespAfterTeardownDoesNotCouple() {
        awaitingBindResp();
        // (a) Entry ABSENT: the pair's entry is removed + attrs cleared (the teardown winner's state)
        // while the egress channel is still delivering — the registry's beginTeardown leaves the CLOSES
        // to the caller, so this is exactly the window a racing bind_resp sees.
        assertThat(registry.beginTeardown(egress)).as("precondition: this call wins the teardown").isNotNull();
        assertThat(registry.size()).isZero();

        egress.writeInbound(inbound(bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0, "SMSC01", new byte[0])));

        assertThat(observer.bindAccepts()).as("(a) a torn-down pair must not couple (re-check: entry absent)").isEmpty();
        assertThat(ingress.<ByteBuf>readOutbound()).as("nothing is forwarded to a dead pair").isNull();
        assertThat(egress.isOpen()).as("the stale delivery fail-closes its own leg").isFalse();

        // (b) Entry TEARING-DOWN but still cached on the channel: the CAS is won while the attrs are
        // not yet cleared — the other half of the same race (ConnectionEntry.beginTearingDown is the
        // CAS without the attr clear, so this fabricates the window deterministically).
        egress.finishAndReleaseAll();
        freshIngress();
        awaitingBindResp();
        ConnectionEntry stale = registry.entryFor(egress);
        assertThat(stale).as("precondition: the entry is still cached on the egress leg").isNotNull();
        assertThat(stale.beginTearingDown()).as("precondition: the teardown CAS is already won").isTrue();

        egress.writeInbound(inbound(bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0, "SMSC01", new byte[0])));

        assertThat(observer.bindAccepts()).as("(b) a tearing-down entry must not couple (the re-check's conjunct)").isEmpty();
        assertThat(egress.isOpen()).as("the racing delivery fail-closes its leg").isFalse();
    }

    // ---------- RELAY-003: egress pre-couple non-bind → not leaked ----------

    @Test
    @DisplayName("RELAY-003: a pre-couple deliver_sm on the egress leg is NOT leaked to the legacy client — the "
            + "egress closes with PRE_COUPLE_NON_BIND_PDU and the bind fails via the AD-33 collapse")
    void egressPreCoupleNonBindPduIsNotLeaked() {
        awaitingBindResp();
        byte[] deliver = opaquePdu(OPAQUE_DLR_TAG, 9);
        ByteBuf frame = inbound(deliver);
        egress.writeInbound(frame);

        ByteBuf toLegacy = ingress.readOutbound();
        assertThat(toLegacy).as("the bind-failure propagation reaches the legacy client (R32)").isNotNull();
        assertThat(toLegacy.readableBytes()).as("the ONLY ingress-bound PDU is the header-only AD-33 deny").isEqualTo(HEADER);
        assertThat(toLegacy.getInt(8)).isEqualTo(ESME_RBINDFAIL);
        assertThat(bytesOf(toLegacy)).as("…and it is NOT the deliver_sm bytes — zero leak").isNotEqualTo(deliver);
        toLegacy.release();   // readOutbound hands the reader ownership (the T7 trap)
        assertThat(egress.isOpen()).as("the violating egress leg closes").isFalse();
        assertThat(ingress.isOpen()).as("the unanswered bind tears the ingress down too").isFalse();
        assertThat(registry.size()).isZero();
        assertThat(observer.framedPdus()).as("nothing crossed the relay — no onFramedPdu(INGRESS) leak").isEmpty();
        assertThat(observer.connectionCloses())
                .as("the egress close carries the pre-couple reason")
                .contains(new CapturingRelayObserver.ConnectionClose(Direction.EGRESS, CloseReason.PRE_COUPLE_NON_BIND_PDU))
                .as("Story 4.1 T4 hoist: the EgressLeg collapse that synthesized the deny stashed "
                        + "EGRESS_CONNECT_FAILED on the INGRESS leg (single-direction semantics)")
                .contains(new CapturingRelayObserver.ConnectionClose(Direction.INGRESS, CloseReason.EGRESS_CONNECT_FAILED));
        assertThat(frame.refCnt()).as("the never-forwarded deliver_sm frame is released").isZero();
    }

    // ---------- RELAY-002c: SMSC generic_nack pre-bind_resp → verbatim + teardown ----------

    @Test
    @DisplayName("RELAY-002c: a pre-couple generic_nack from the SMSC is forwarded VERBATIM as the bind result, "
            + "no couple, both legs torn down (AD-32 case 4)")
    void genericNackPreBindRespIsForwardedVerbatimThenTearsDown() {
        awaitingBindResp();
        byte[] nack = opaquePdu(GENERIC_NACK, 5);
        egress.writeInbound(inbound(nack));

        ByteBuf toLegacy = ingress.readOutbound();
        assertThat(toLegacy).as("the SMSC's own answer is ground truth — forwarded unchanged").isNotNull();
        assertThat(bytesOf(toLegacy)).isEqualTo(nack);
        toLegacy.release();   // readOutbound hands the reader ownership (the T7 trap)
        assertThat(ingress.<ByteBuf>readOutbound()).as("nothing follows the verbatim nack (no proxy deny on top)").isNull();
        assertThat(observer.bindAccepts()).as("a nack never couples the pair").isEmpty();
        assertThat(ingress.isOpen()).as("both legs tear down after the forwarded answer").isFalse();
        assertThat(egress.isOpen()).isFalse();
        assertThat(registry.size()).isZero();
        assertThat(observer.connectionCloses())
                .containsExactlyInAnyOrder(
                        new CapturingRelayObserver.ConnectionClose(Direction.EGRESS, CloseReason.GENERIC_NACK_PRE_BIND),
                        new CapturingRelayObserver.ConnectionClose(Direction.INGRESS, CloseReason.GENERIC_NACK_PRE_BIND));
    }

    // ---------- CODEC-021 sibling (Risk Note 2, second vector) ----------

    @Test
    @DisplayName("CODEC-021 sibling: a 0-byte-body (header-only) bind_resp NEVER reaches isOk() — the codec throws "
            + "pre-build; assert the channelInactive teardown (DECODE_ERROR) + the AD-33 collapse, not isOk()==false")
    void headerOnlyBindRespTearsDownViaDecodeErrorNeverReachingIsOk() {
        awaitingBindResp();
        // 16 bytes, bind_transceiver_resp, EMPTY body — readAscii(system_id) finds no NUL → DecoderException
        // inside SmppCodec.decode, BEFORE SmppBindResponse is built (Risk Note 2's second vector).
        egress.writeInbound(inbound(assemble(SmppCommandIds.BIND_TRANSCEIVER_RESP, 0x0000000A, 5, 0, out -> {})));

        assertThat(observer.bindAccepts()).as("isOk() was never reached — no couple, nothing else").isEmpty();
        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("the failed bind collapses to the AD-33 generic deny (the EgressLeg arm)").isNotNull();
        assertThat(deny.getInt(8)).isEqualTo(ESME_RBINDFAIL);
        assertThat(deny.getInt(12)).as("correlates the still-pending bind").isEqualTo(5);
        deny.release();   // readOutbound hands the reader ownership (the T7 trap)
        assertThat(ingress.isOpen()).isFalse();
        assertThat(egress.isOpen()).isFalse();
        assertThat(registry.size()).isZero();
        assertThat(observer.connectionCloses())
                .as("the decode reject is observed as DECODE_ERROR on the egress leg")
                .contains(new CapturingRelayObserver.ConnectionClose(Direction.EGRESS, CloseReason.DECODE_ERROR))
                .as("Story 4.1 T4 hoist: the EgressLeg collapse behind the deny stashed "
                        + "EGRESS_CONNECT_FAILED on the INGRESS leg")
                .contains(new CapturingRelayObserver.ConnectionClose(Direction.INGRESS, CloseReason.EGRESS_CONNECT_FAILED));
    }
}
