package smpp.companion.proxy.relay;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

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
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.observability.CapturingRelayObserver;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayEgressInitializer;
import smpp.companion.proxy.tls.SmppLegTlsFactory;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 3.4 T5 — the shared fixture of the SPLIT relay-handler suites ({@code RelayIngressHandlerTest} /
 * {@code RelayEgressHandlerTest}; the pre-split {@code RelayHandlerTest} carried it inline): the
 * coupled {@link EmbeddedChannel} PAIR driven through the REAL production pipelines
 * ({@code framer → codec → BindInterceptor → RelayIngressHandler} on the ingress,
 * {@code framer → codec → RelayEgressHandler} on the egress — the production
 * {@link RelayEgressInitializer} plus the T7 connect assembly's {@code EgressLeg}) with unique
 * {@link DefaultChannelId}s (the T4 singleton-id trap), fed hand-authored wire PDUs (independent of
 * the codec under test, mirroring {@code BindInterceptorTest}'s builders). The egress leg is built
 * by {@link #awaitingBindResp()} through the real initializer + the {@link FakeEgressConnector}
 * seam (RELAY-006's sanctioned injected-future), so the pair under test is the production wiring,
 * not a hand-rolled pipeline.
 *
 * <p><b>EmbeddedChannel honesty notes (inherited from the pre-split suite):</b> (1) read-ARMING
 * ({@code ctx.read()} / write-completes-gates-read / the low-water re-arm) is a no-op observable on
 * an embedded channel — the substrate options are pinned by {@code RelayChannelOptionsTest}, the
 * demand-driven behavior proves out on the real-socket suites. (2) An RST is simulated by firing
 * {@code IOException} through the pipeline ({@code fireExceptionCaught}) — exactly how a real reset
 * surfaces to the handler on a live NIO channel, pre-inactive.
 */
@SuppressWarnings("FutureReturnValueIgnored") // reason: EmbeddedChannel.close()/writeInbound in tests are
// synchronous fire-and-forget — the assertions observe the channels' outbound queues and lifecycle state,
// never the close/write futures themselves.
abstract class CoupledPairHarness {

    protected static final int HEADER = 16;

    /** AD-33 Q2 — the ratified generic bind-failure code, pinned independently of the production constant. */
    protected static final int ESME_RBINDFAIL = 0x0000000D;

    /** SMPP 3.4 §4.1.2 opaque PDUs (never parsed — the codec passes them through on the command_id alone). */
    protected static final int SUBMIT_SM = 0x00000004;
    protected static final int DELIVER_SM = 0x00000105;
    protected static final int ENQUIRE_LINK = 0x00000015;
    protected static final int GENERIC_NACK = 0x80000000;

    protected ConnectionRegistry registry;
    protected CapturingRelayObserver observer;
    protected LatchedBindCredentialVerifier verifier;
    protected FakeEgressConnector connector;
    protected RelayEgressInitializer egressInitializer;
    protected EmbeddedChannel ingress;
    protected EmbeddedChannel egress;
    protected final List<ByteBuf> toRelease = new ArrayList<>();

    @BeforeEach
    void freshIngress() {
        if (ingress != null) {
            ingress.finishAndReleaseAll();
        }
        registry = new ConnectionRegistry();
        observer = new CapturingRelayObserver();
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
                new RelayIngressHandler(registry, observer));
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

    // ---------- shared pair-state helpers ----------

    /**
     * Wires the pair to awaiting-bind_resp: completes the Allow path with a fake (Embedded) egress leg
     * carrying the REAL pipelines (T7 assembly).
     */
    protected void awaitingBindResp() {
        verifier.completeAllow();
        egress = new EmbeddedChannel(DefaultChannelId.newInstance(), egressInitializer);
        connector.result = egress.newSucceededFuture();
        ingress.writeInbound(inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 5, "legacy1", "pw123456")));
        assertThat(egress.<ByteBuf>readOutbound()).as("precondition: the bind reached the SMSC").isNotNull();
    }

    /** Wires the pair AND couples it on the ROK bind_resp from the SMSC — the post-couple relay plane is live. */
    protected void couple() {
        awaitingBindResp();
        egress.writeInbound(inbound(bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 5, 0, "SMSC01", new byte[0])));
        assertThat(observer.bindAccepts()).as("precondition: the couple fired").hasSize(1);
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

    protected static byte[] bindRequest(int commandId, int sequence, String systemId, String password) {
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

    protected static byte[] bindResponse(int commandId, int sequence, int commandStatus, String systemId, byte[] tlvTail) {
        byte[] id = ascii(systemId);
        int body = (id.length + 1) + tlvTail.length;
        return assemble(commandId, commandStatus, sequence, body, out -> {
            out.put(id).put((byte) 0);
            out.put(tlvTail);
        });
    }

    /** An OPAQUE non-bind PDU: a valid 16-octet header + an arbitrary opaque body (never parsed, AD-3). */
    protected static byte[] opaquePdu(int commandId, int sequence) {
        byte[] body = new byte[] {0x01, 0x02, 0x03, 0x04};
        return assemble(commandId, 0, sequence, body.length, out -> out.put(body));
    }

    protected interface BodyWriter {
        void writeTo(java.nio.ByteBuffer out);
    }

    protected static byte[] assemble(int commandId, int commandStatus, int sequence, int bodyLen, BodyWriter writer) {
        java.nio.ByteBuffer out = java.nio.ByteBuffer.allocate(HEADER + bodyLen);
        out.putInt(HEADER + bodyLen).putInt(commandId).putInt(commandStatus).putInt(sequence);
        writer.writeTo(out);
        return out.array();
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    protected ByteBuf inbound(byte[] pdu) {
        ByteBuf buf = Unpooled.wrappedBuffer(pdu);
        toRelease.add(buf); // backstop release; the normal path releases via the pipeline
        return buf;
    }

    protected static byte[] bytesOf(ByteBuf buf) {
        byte[] out = new byte[buf.readableBytes()];
        buf.getBytes(buf.readerIndex(), out);
        return out;
    }

    protected static int countOutbound(EmbeddedChannel channel) {
        int n = 0;
        while (channel.<ByteBuf>readOutbound() != null) {
            n++;
        }
        return n;
    }

    /** {@code true} iff every value octet of the (shared-backing) password {@link AsciiString} is zero. */
    protected static boolean zeroized(AsciiString value) {
        byte[] array = value.array();
        for (int i = value.arrayOffset(); i < value.arrayOffset() + value.length(); i++) {
            if (array[i] != 0) {
                return false;
            }
        }
        return true;
    }
}
