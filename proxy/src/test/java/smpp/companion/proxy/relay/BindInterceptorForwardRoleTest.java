package smpp.companion.proxy.relay;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Timeout.ThreadMode;
import org.junit.jupiter.api.io.TempDir;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.DefaultChannelId;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslHandler;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.observability.CapturingRelayObserver;
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
 * Story 3.3 T5 (AC2) — the {@code BindInterceptor} FORWARD arm under the ratified [B] topology: the
 * per-{@code system_id} ROUTING GATE (AD-29/AD-11) ahead of adjudication, the miss's AD-33 collapse
 * (header-only deny + close; log-only — never {@code onBindReject}, which fires only for returned
 * {@link Verdict}s, AD-27), and the hit's per-session egress DIAL to the routing target with the
 * per-entry TLS client handler prepended (SslHandler FIRST — the ORIGINAL bind rides the TLS record
 * layer, AD-14). The reverse arms (route-everything-to-the-SMSC) stay pinned by
 * {@code BindInterceptorTest}; the full TLS handshake + SMSC roundtrip is the T7 e2e suite.
 *
 * <p>Same discipline as {@code BindInterceptorTest}: a REAL pipeline on an {@link EmbeddedChannel}
 * with a unique {@link DefaultChannelId}, hand-authored wire PDUs (independent of the codec), and
 * the {@link BindInterceptor.EgressConnector} seam with a recording fake whose succeeded future
 * hands back a REAL dial channel built from the captured {@link Bootstrap} handler — so the dial's
 * pipeline shape (the TLS wiring) is asserted, not assumed.
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
@SuppressWarnings("FutureReturnValueIgnored") // reason: EmbeddedChannel writeInbound in tests is a
// synchronous fire-and-forget — the assertions observe the outbound queue, the registry, and the
// dial channel's pipeline, never the write's own future.
@Timeout(value = 10, threadMode = ThreadMode.SEPARATE_THREAD)
class BindInterceptorForwardRoleTest {

    /** AD-33 Q2 — the ratified generic bind-failure code, pinned independently of the production constant. */
    private static final int ESME_RBINDFAIL = 0x0000000D;

    private static final int HEADER = 16;

    /** The forward fixture's single routing entry (AD-29 1:1: carrierOne -> the reverse's dial target). */
    private static final String REVERSE_HOST = "127.0.0.1";
    private static final int REVERSE_PORT = 42776;

    @Test
    @DisplayName("routing miss: AD-33 header-only deny + close, NO adjudication, NO pair, NO onBindReject")
    void routingMissDeniesOnTheWireWithoutAdjudication(@TempDir java.nio.file.Path dir) {
        CountingAllowVerifier verifier = new CountingAllowVerifier();
        ConnectionRegistry registry = new ConnectionRegistry();
        RelayStateManager manager = new RelayStateManager(registry);
        CapturingRelayObserver observer = new CapturingRelayObserver();
        ProxyCompanionProperties properties = RelayTestFixtures.forwardAProperties(
                RelayTestFixtures.freePort(), 8, RelayTestFixtures.smppTlsLegs(dir), REVERSE_HOST, REVERSE_PORT);
        BindInterceptor interceptor = new BindInterceptor(
                verifier, manager, observer, properties,
                new RelayEgressInitializer(manager, observer),
                new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT),
                new RoutingTable(properties), new SmppLegTlsFactory(properties, Runnable::run),
                (bootstrap, host, port) -> {
                    throw new AssertionError("a routing miss must never dial (AD-11: no default route)");
                });
        EmbeddedChannel ingress = pipeline(interceptor, manager, observer);
        try {
            // system_id "intruder" is NOT in the table (only carrierOne is).
            ingress.writeInbound(inbound(bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 7, "intruder", "pw123456")));

            ByteBuf deny = ingress.readOutbound();
            assertThat(deny).as("the routing miss answers with the AD-33 collapse").isNotNull();
            assertThat(deny.readableBytes()).as("header-only construct (16 octets, AD-32/AD-33)").isEqualTo(HEADER);
            assertThat(deny.getInt(4)).as("bind_transceiver_resp answering bind_transceiver").isEqualTo(
                    SmppCommandIds.BIND_TRANSCEIVER_RESP);
            assertThat(deny.getInt(8)).as("the ONE generic bind-failure status (AD-33 Q2, literal pin)")
                    .isEqualTo(ESME_RBINDFAIL);
            assertThat(deny.getInt(12)).as("the deny answers the REQUEST's sequence_number").isEqualTo(7);

            assertThat(ingress.isOpen()).as("the miss closes after the deny ('bind_resp error, then close')").isFalse();
            assertThat(registry.size()).as("no pair was ever created — the miss precedes registration").isZero();
            assertThat(verifier.seen).as("the miss precedes adjudication (no ROPC, no IdP amplification)").isEmpty();
            assertThat(observer.bindRejects())
                    .as("a routing miss is NOT a returned Verdict — never onBindReject (AD-27)")
                    .isEmpty();
            assertThat(observer.bindAccepts()).isEmpty();
        } finally {
            ingress.finishAndReleaseAll();
        }
    }

    @Test
    @DisplayName("routing hit: adjudication runs, the dial targets the ROUTING entry, and the dial pipeline "
            + "prepends the per-entry SslHandler")
    void routingHitAdjudicatesAndDialsTheRoutingTargetWithTls(@TempDir java.nio.file.Path dir) {
        CountingAllowVerifier verifier = new CountingAllowVerifier();
        ConnectionRegistry registry = new ConnectionRegistry();
        RelayStateManager manager = new RelayStateManager(registry);
        CapturingRelayObserver observer = new CapturingRelayObserver();
        ProxyCompanionProperties properties = RelayTestFixtures.forwardAProperties(
                RelayTestFixtures.freePort(), 8, RelayTestFixtures.smppTlsLegs(dir), REVERSE_HOST, REVERSE_PORT);
        DialCapturingConnector connector = new DialCapturingConnector();
        BindInterceptor interceptor = new BindInterceptor(
                verifier, manager, observer, properties,
                new RelayEgressInitializer(manager, observer),
                new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT),
                new RoutingTable(properties), new SmppLegTlsFactory(properties, Runnable::run), connector);
        EmbeddedChannel ingress = pipeline(interceptor, manager, observer);
        try {
            byte[] bind = bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 9, "carrierOne", "pw123456");
            ingress.writeInbound(inbound(bind));

            assertThat(verifier.seen).as("a permitted system_id IS adjudicated (the forward arm keeps the port call)")
                    .hasSize(1);
            // The Allow verdict is pre-completed: the connect listener ran synchronously (the fake's
            // succeeded future fires inline on the embedded event loop).
            assertThat(connector.targets).as("the dial targets the ROUTING entry, never an SMSC (SEC-097)")
                    .containsExactly(REVERSE_HOST + ":" + REVERSE_PORT);
            assertThat(connector.dials).as("exactly one per-session dial (1:1:1 — no pooling, [B])").hasSize(1);

            EmbeddedChannel dial = connector.dials.get(0);
            List<String> names = dial.pipeline().names();
            int ssl = indexOfPrefix(names, "SslHandler");
            int framer = indexOfPrefix(names, "SmppFrameDecoder");
            assertThat(ssl).as("the per-session dial carries the TLS client handler").isGreaterThanOrEqualTo(0);
            assertThat(ssl).as("the ORIGINAL bind rides the TLS record layer — SslHandler BEFORE the framer")
                    .isLessThan(framer);
            assertThat(dial.pipeline().get(SslHandler.class)).isNotNull();

            // AD-14 ownership: the connect assembly handed the verbatim bind to the (TLS-queued) write;
            // under SslHandler it stays queued until the handshake — the byte-exact forward over a REAL
            // handshake is the T7 e2e pin, this unit pins the wiring (target + pipeline + adjudication).
            assertThat(registry.size()).as("the pair registered (RELAY-006 optimistic entry)").isEqualTo(1);
        } finally {
            connector.dials.forEach(EmbeddedChannel::close);
            ingress.finishAndReleaseAll();
        }
    }

    // ---------- fixtures --------------------------------------------------------------------------

    /** The forward arm's verifier: records every credential, Allow pre-completed (the wired stand-in). */
    private static final class CountingAllowVerifier implements BindCredentialVerifier {
        final List<BindCredential> seen = new CopyOnWriteArrayList<>();

        @Override
        public VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx) {
            seen.add(cred);
            CompletableFuture<Verdict> future = new CompletableFuture<>();
            future.complete(new Verdict.Allow());
            return new VerdictRequest() {
                @Override
                public CompletableFuture<Verdict> future() {
                    return future;
                }

                @Override
                public void cancelHttp() {
                    // nothing in flight — the pre-completed verdict
                }
            };
        }
    }

    /**
     * The forward-arm egress seam: builds a REAL dial {@link EmbeddedChannel} from the captured
     * {@link Bootstrap}'s handler (so {@code initChannel} runs the production initializer) and hands
     * back its succeeded future — the connect listener then runs synchronously, exactly as on a loop.
     */
    private static final class DialCapturingConnector implements BindInterceptor.EgressConnector {
        final List<String> targets = new CopyOnWriteArrayList<>();
        final List<EmbeddedChannel> dials = new CopyOnWriteArrayList<>();

        @Override
        public ChannelFuture connect(Bootstrap bootstrap, String host, int port) {
            targets.add(host + ":" + port);
            EmbeddedChannel dial = new EmbeddedChannel(bootstrap.config().handler());
            dials.add(dial);
            return dial.newSucceededFuture();
        }
    }

    private static EmbeddedChannel pipeline(
            BindInterceptor interceptor, RelayStateManager manager, CapturingRelayObserver observer) {
        return new EmbeddedChannel(
                DefaultChannelId.newInstance(), new SmppFrameDecoder(), new SmppCodec(), interceptor,
                new RelayIngressHandler(manager, observer));
    }

    // ---------- hand-authored PDU builders (raw bytes — independent of the codec) ----------

    private static byte[] bindRequest(int commandId, int sequence, String systemId, String password) {
        byte[] id = ascii(systemId);
        byte[] pw = ascii(password);
        byte[] type = ascii("SMPP");
        byte[] range = ascii("");
        int body = (id.length + 1) + (pw.length + 1) + (type.length + 1) + 3 + (range.length + 1);
        java.nio.ByteBuffer out = java.nio.ByteBuffer.allocate(HEADER + body);
        out.putInt(HEADER + body).putInt(commandId).putInt(0).putInt(sequence);
        out.put(id).put((byte) 0);
        out.put(pw).put((byte) 0);
        out.put(type).put((byte) 0);
        out.put((byte) 0x34).put((byte) 0).put((byte) 0);
        out.put(range).put((byte) 0);
        return out.array();
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static ByteBuf inbound(byte[] pdu) {
        return Unpooled.wrappedBuffer(pdu);
    }

    private static int indexOfPrefix(List<String> names, String prefix) {
        for (int i = 0; i < names.size(); i++) {
            if (names.get(i).startsWith(prefix)) {
                return i;
            }
        }
        return -1;
    }
}
