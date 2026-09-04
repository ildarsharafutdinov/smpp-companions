package smpp.companion.proxy.observability;

import java.util.EnumSet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Timeout.ThreadMode;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import ch.qos.logback.classic.Level;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;
import org.slf4j.LoggerFactory;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.relay.BindInterceptor;
import smpp.companion.proxy.relay.ConnectionEntry;
import smpp.companion.proxy.relay.ConnectionRegistry;
import smpp.companion.proxy.relay.RelayIngressHandler;
import smpp.companion.proxy.relay.RelayStateManager;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayEgressInitializer;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.tls.SmppLegTlsFactory;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 4.1 T4 (checkpoint 20) &mdash; the seam-hardening proof: a {@link ThrowingRelayObserver}
 * armed on each of the four seam methods in turn (and on all four at once for the full cycle)
 * leaves EVERY relay invariant intact &mdash; PDU forwarded, deny synthesized, teardown complete, close
 * exactly-once &mdash; and each swallowed throw produced exactly one bounded WARN (AC2, the I/O
 * matrix's throwing-observer row). The isolation under test lives at the FIRE SITES
 * ({@code CoupledRelayHandler.fireGuarded}), not inside any observer impl, which is why the double
 * throws instead of self-guarding.
 *
 * <p><b>The observability-side mirror of {@code relay/}'s CoupledPairHarness:</b> this suite lives in
 * {@code observability/} (the story's file map) and so reaches the relay only through its PUBLIC
 * production wiring &mdash; the real pipelines ({@code framer -> codec -> handler}), the real
 * {@link RelayEgressInitializer} couple site, and the real {@link BindInterceptor} deny plane
 * (public constructor; the deny path never dials, so no connector seam is needed). The pair is
 * coupled by REGISTER + ATTACH + the ROK {@code bind_resp} through the real
 * {@code RelayEgressHandler} (the single production couple unit). The ONE deviation from the T7
 * assembly: no {@code EgressLeg} forwarder can be appended from this package (it is private to
 * {@code BindInterceptor}), so the decoded ROK lands on the egress channel's inbound queue and the
 * test releases it &mdash; ownership-wise the same tail the forwarder's ingress write would have
 * consumed.
 *
 * <p>RED-on-neuter: delete any fire site's {@code fireGuarded} wrap and the matching row fails on the
 * un-caught {@code IllegalStateException} (relay invariant or WARN count); drop the deny-path reason
 * stash and the BIND_REJECTED assertion fails with OTHER.
 */
@Tag("unit")
@Tag("relay")
@Tag("observability")
@Tag("p1")
@SuppressWarnings("FutureReturnValueIgnored") // reason: EmbeddedChannel.close()/writeInbound in tests are
// synchronous fire-and-forget — the assertions observe the channels' outbound queues and lifecycle state,
// never the close/write futures themselves.
@Timeout(value = 10, threadMode = ThreadMode.SEPARATE_THREAD) // a hung handler chain must FAIL a test,
// not hang the suite (the BindInterceptorTest pattern).
@ExtendWith(OutputCaptureExtension.class)
class ThrowingObserverHardeningTest extends ObservabilityPairHarness {

    /** AD-33 Q2 — the ratified generic bind-failure code, pinned independently of the production constant. */
    private static final int ESME_RBINDFAIL = 0x0000000D;

    private ConnectionRegistry registry;
    private RelayStateManager manager;
    private ProxyCompanionProperties properties;
    private RoutingTable routingTable;
    private SmppLegTlsFactory tlsFactory;
    private RelayChannelOptions channelOptions;
    private EmbeddedChannel ingress;
    private EmbeddedChannel egress;

    @BeforeEach
    void sharedBeans() {
        registry = new ConnectionRegistry();
        manager = new RelayStateManager(registry);
        properties = RelayTestFixtures.modeBProperties(RelayTestFixtures.freePort(), 1);
        routingTable = new RoutingTable(properties);
        tlsFactory = new SmppLegTlsFactory(properties, Runnable::run);
        channelOptions = new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT);
    }

    // ---------- row 1: a throwing onBindAccept leaves the couple + relay plane intact ----------

    @Test
    @DisplayName("onBindAccept throws → the couple STILL completes (registry keeps the pair), the "
            + "post-couple relay forwards byte-exact, exactly ONE WARN")
    void throwingOnBindAcceptLeavesTheCoupleAndRelayIntact(CapturedOutput out) {
        ThrowingRelayObserver observer = new ThrowingRelayObserver(EnumSet.of(ThrowingRelayObserver.Trigger.BIND_ACCEPT));
        coupledPair(observer);

        assertThat(observer.bindAccepts())
                .as("the throw is ISOLATED at the fire site — the trigger was still delivered")
                .hasSize(1);
        assertThat(registry.size()).as("the couple completed — the pair stays registered").isEqualTo(1);
        assertThat(ingress.isOpen()).as("no leg closed over a telemetry throw").isTrue();
        assertThat(isolationWarns(out, "onBindAccept"))
                .as("exactly one bounded WARN per swallowed throw").isEqualTo(1);
        assertThat(isolationWarns(out, "onFramedPdu"))
                .as("unarmed methods neither throw nor WARN").isZero();

        byte[] submit = opaquePdu(SUBMIT_SM, 101);
        ingress.writeInbound(inbound(submit));
        ByteBuf atSmsc = egress.readOutbound();
        assertThat(atSmsc).as("the relayed PDU crosses despite the earlier accept throw").isNotNull();
        assertThat(bytesOf(atSmsc)).isEqualTo(submit);
        atSmsc.release(); // readOutbound hands the reader ownership (the T7 trap)
    }

    // ---------- row 2: a throwing onFramedPdu never eats the frame ----------

    @Test
    @DisplayName("onFramedPdu throws → the frame is STILL forwarded byte-exact (forward proceeds past "
            + "the throw), exactly ONE WARN")
    void throwingOnFramedPduStillForwardsTheFrame(CapturedOutput out) {
        ThrowingRelayObserver observer = new ThrowingRelayObserver(EnumSet.of(ThrowingRelayObserver.Trigger.FRAMED_PDU));
        coupledPair(observer);

        byte[] submit = opaquePdu(SUBMIT_SM, 102);
        ingress.writeInbound(inbound(submit));

        ByteBuf atSmsc = egress.readOutbound();
        assertThat(atSmsc).as("THE hot-path invariant: the count trigger throwing must not eat the frame")
                .isNotNull();
        assertThat(bytesOf(atSmsc)).isEqualTo(submit);
        atSmsc.release(); // readOutbound hands the reader ownership (the T7 trap)
        assertThat(observer.framedPdus()).containsExactly(Direction.INGRESS);
        assertThat(isolationWarns(out, "onFramedPdu")).isEqualTo(1);
        assertThat(ingress.isOpen()).as("the relay plane stays up").isTrue();
    }

    // ---------- row 3: a throwing onConnectionClosed degrades accounting, never the close ----------

    @Test
    @DisplayName("onConnectionClosed throws → teardown + exactly-once close still hold (duplicate "
            + "inactive swallowed by the CAS), one WARN per leg")
    void throwingOnConnectionClosedKeepsTeardownAndExactlyOnce(CapturedOutput out) {
        ThrowingRelayObserver observer =
                new ThrowingRelayObserver(EnumSet.of(ThrowingRelayObserver.Trigger.CONNECTION_CLOSED));
        coupledPair(observer);

        ingress.pipeline().fireChannelInactive(); // the first close: teardown + BOTH legs' fires (each throws)
        ingress.pipeline().fireChannelInactive(); // a duplicate delivery — the CAS must swallow it regardless
        ingress.close();                          // the real close's own inactive — also swallowed

        assertThat(observer.connectionCloses())
                .as("exactly-once per channel holds UNDER the throwing observer — one INGRESS + one EGRESS")
                .hasSize(2)
                .extracting(ThrowingRelayObserver.ConnectionClose::direction)
                .containsExactlyInAnyOrder(Direction.INGRESS, Direction.EGRESS);
        assertThat(ingress.isOpen()).as("the closes themselves proceeded").isFalse();
        assertThat(egress.isOpen()).as("the propagation closed the peer leg").isFalse();
        assertThat(registry.size()).as("the pair left the registry").isZero();
        assertThat(isolationWarns(out, "onConnectionClosed"))
                .as("one WARN per swallowed close throw (two legs)").isEqualTo(2);
    }

    // ---------- row 4: a throwing onBindReject — the worst arm — still denies and tears down ----------

    @Test
    @DisplayName("onBindReject throws → the AD-33 deny is STILL synthesized (header-only, 0x0D, "
            + "sequence correlates), the pooled frame released, teardown complete, and the deny-path "
            + "close carries BIND_REJECTED (the T4 hoist — not OTHER)")
    void throwingOnBindRejectStillSynthesizesTheDenyAndTearsDown(CapturedOutput out) {
        ThrowingRelayObserver observer = new ThrowingRelayObserver(EnumSet.of(ThrowingRelayObserver.Trigger.BIND_REJECT));
        ingress = channel(new SmppFrameDecoder(), new SmppCodec(),
                new BindInterceptor(denyingVerifier(), manager, observer, properties,
                        new RelayEgressInitializer(manager, observer), channelOptions, routingTable, tlsFactory),
                new RelayIngressHandler(manager, observer));

        ByteBuf frame = inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 42, "legacy1", "pw123456"));
        ingress.writeInbound(frame);

        ByteBuf deny = ingress.readOutbound();
        assertThat(deny).as("the deny synthesis is NOT skipped by the throw (the client never hangs)")
                .isNotNull();
        assertThat(deny.readableBytes()).as("header-only synth — the ONE PDU the relay builds").isEqualTo(HEADER);
        assertThat(deny.getInt(4)).isEqualTo(SmppCommandIds.BIND_TRANSCEIVER_RESP);
        assertThat(deny.getInt(8)).as("AD-33: the generic ESME_RBINDFAIL 0x0000000D").isEqualTo(ESME_RBINDFAIL);
        assertThat(deny.getInt(12)).as("sequence_number correlates the denied request").isEqualTo(42);
        deny.release(); // readOutbound hands the reader ownership (the T7 trap)
        assertThat(frame.refCnt()).as("the original pooled frame is released — no leak past the throw").isZero();
        assertThat(ingress.isOpen()).as("deny → then close").isFalse();
        assertThat(registry.size()).as("the optimistically-registered entry is removed").isZero();
        assertThat(observer.bindRejects())
                .as("the reject trigger was delivered before the throw")
                .singleElement()
                .satisfies(reject -> {
                    assertThat(reject.systemId()).isEqualTo(new SystemId(new AsciiString("legacy1")));
                    assertThat(reject.verdict()).isEqualTo(new Verdict.DenyInvalid());
                });
        assertThat(observer.connectionCloses())
                .as("the T4 hoist: the deny-path close is OBSERVED with BIND_REJECTED, not the OTHER default")
                .containsExactly(new ThrowingRelayObserver.ConnectionClose(
                        Direction.INGRESS, CloseReason.BIND_REJECTED));
        assertThat(isolationWarns(out, "onBindReject")).isEqualTo(1);
        assertThat(isolationWarns(out, "onConnectionClosed"))
                .as("the (unarmed) close trigger neither threw nor WARNed").isZero();
    }

    // ---------- the full cycle with ALL FOUR armed ----------

    @Test
    @DisplayName("full bind→relay→close cycle with ALL FOUR methods throwing: couple, forwards, and "
            + "exactly-once closes all hold; 5 WARNs total (1 accept + 2 PDU + 2 close)")
    void fullCycleWithEveryTriggerThrowingHoldsEveryInvariant(CapturedOutput out) {
        ThrowingRelayObserver observer = new ThrowingRelayObserver(EnumSet.allOf(ThrowingRelayObserver.Trigger.class));
        coupledPair(observer);

        byte[] submit = opaquePdu(SUBMIT_SM, 201);
        ingress.writeInbound(inbound(submit));
        byte[] deliver = opaquePdu(OPAQUE_DLR_TAG, 202);
        egress.writeInbound(inbound(deliver));

        ByteBuf atSmsc = egress.readOutbound();
        assertThat(atSmsc).as("ingress→egress forward intact under the all-throwing observer").isNotNull();
        assertThat(bytesOf(atSmsc)).isEqualTo(submit);
        atSmsc.release(); // readOutbound hands the reader ownership (the T7 trap)
        ByteBuf atLegacy = ingress.readOutbound();
        assertThat(atLegacy).as("egress→ingress forward intact").isNotNull();
        assertThat(bytesOf(atLegacy)).isEqualTo(deliver);
        atLegacy.release(); // readOutbound hands the reader ownership (the T7 trap)

        ingress.close();

        assertThat(ingress.isOpen()).isFalse();
        assertThat(egress.isOpen()).as("the teardown propagation closed the peer").isFalse();
        assertThat(registry.size()).isZero();
        assertThat(observer.connectionCloses())
                .as("close exactly-once per channel across the whole cycle")
                .hasSize(2);
        assertThat(observer.framedPdus())
                .as("both relayed PDUs were counted before their throws")
                .containsExactly(Direction.INGRESS, Direction.EGRESS);
        assertThat(isolationWarns(out, "onBindAccept")).isEqualTo(1);
        assertThat(isolationWarns(out, "onFramedPdu")).isEqualTo(2);
        assertThat(isolationWarns(out, "onConnectionClosed")).isEqualTo(2);
        assertThat(isolationWarns(out, "onBindReject"))
                .as("no deny on the accept path").isZero();
    }

    // ---------- the TRACE privacy row: bodies at TRACE, bind-family redacted, password never ----------

    @Test
    @DisplayName("TRACE on the PDU logger: opaque bodies appear (hex), a stray post-couple re-bind is "
            + "REDACTED (bind family) — the password's hex can never cross; TRACE off by default")
    void traceBodiesShowOpaquePdusButNeverTheBindFamily(CapturedOutput out) {
        ch.qos.logback.classic.Logger pduLogger =
                (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(PDU_BODY_LOGGER);
        Level original = pduLogger.getLevel();
        pduLogger.setLevel(Level.TRACE);
        try {
            ThrowingRelayObserver observer =
                    new ThrowingRelayObserver(EnumSet.noneOf(ThrowingRelayObserver.Trigger.class));
            coupledPair(observer);

            byte[] submit = opaquePdu(SUBMIT_SM, 301);
            ingress.writeInbound(inbound(submit));
            byte[] deliver = opaquePdu(OPAQUE_DLR_TAG, 302);
            egress.writeInbound(inbound(deliver));
            // The residual password carrier: a stray post-couple re-bind decodes and relays as its
            // ORIGINAL frame — the one bind-family PDU that can reach the TRACE site.
            byte[] strayRebind = bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 303, "legacy1", "sekrit-pw");
            ingress.writeInbound(inbound(strayRebind));

            assertThat(out.getAll()).contains("relayed pdu: direction=" + Direction.INGRESS);
            assertThat(out.getAll()).contains("relayed pdu: direction=" + Direction.EGRESS);
            assertThat(countOf(out, "body=0x"))
                    .as("the two OPAQUE bodies are logged (TRACE on)")
                    .isEqualTo(2);
            assertThat(countOf(out, "<redacted: bind family>"))
                    .as("the stray re-bind's body is redacted — metadata only")
                    .isEqualTo(1);
            // Mutation-resistant privacy pin: the FULL stray-bind hex (which embeds the password's
            // hex) must not appear anywhere — drop the redaction branch and this fails.
            assertThat(out.getAll())
                    .as("the bind password can never cross at ANY level")
                    .doesNotContain(hex(strayRebind))
                    .doesNotContain("sekrit-pw");
        } finally {
            pduLogger.setLevel(original); // never leak TRACE into the other rows
        }
    }

    @Test
    @DisplayName("TRACE off (the default): relayed traffic logs NO bodies at all")
    void traceOffByDefaultLogsNoBodies(CapturedOutput out) {
        ThrowingRelayObserver observer =
                new ThrowingRelayObserver(EnumSet.noneOf(ThrowingRelayObserver.Trigger.class));
        coupledPair(observer);
        ingress.writeInbound(inbound(opaquePdu(SUBMIT_SM, 401)));

        assertThat(out.getAll())
                .as("the body logger is off by default — the relay is silent about content")
                .doesNotContain("relayed pdu:")
                .doesNotContain("body=0x");
        ByteBuf atSmsc = egress.readOutbound();
        assertThat(atSmsc).as("the forward itself is unaffected by the gating").isNotNull();
        atSmsc.release(); // readOutbound hands the reader ownership (the T7 trap)
    }

    // ---------- fixtures -------------------------------------------------------------------

    /**
     * Wires a COUPLED pair through the REAL production handlers: register + attach (the public
     * state-manager transitions), then the ROK {@code bind_resp} driven through the real
     * {@code RelayEgressHandler} — the single production couple site — so {@code onBindAccept} fires
     * exactly as in production. Without the (package-private) {@code EgressLeg} forwarder the decoded
     * ROK lands on the egress inbound queue; the tail releases it (see the class javadoc).
     */
    private void coupledPair(ThrowingRelayObserver observer) {
        ingress = channel(new SmppFrameDecoder(), new SmppCodec(), new RelayIngressHandler(manager, observer));
        egress = channel(new RelayEgressInitializer(manager, observer));
        ConnectionEntry entry = manager.register(ingress, new SystemId(new AsciiString("legacy1")));
        manager.attachEgress(ingress.id(), egress);

        egress.writeInbound(inbound(
                bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0, "SMSC01", new byte[0])));

        assertThat(entry.coupled())
                .as("the ROK drove the REAL couple unit — the pair is relaying (a throwing "
                        + "onBindAccept must not have prevented it)")
                .isTrue();
        drainInbound(egress); // the decoded ROK (no EgressLeg from this package — see class javadoc)
        drainInbound(ingress);
    }

    /** Counts the throw-isolation WARN lines for one seam method (the marker is unique per method). */
    private static long isolationWarns(CapturedOutput out, String trigger) {
        return out.getAll().lines()
                .filter(line -> line.contains("RelayObserver." + trigger + " threw"))
                .count();
    }

    /** Substring occurrence count (AssertJ's containsOnce has no count flavor for plain strings). */
    private static long countOf(CapturedOutput out, String marker) {
        return out.getAll().lines().filter(line -> line.contains(marker)).count();
    }

    private static byte[] bytesOf(ByteBuf buf) {
        byte[] out = new byte[buf.readableBytes()];
        buf.getBytes(buf.readerIndex(), out);
        return out;
    }
}
