package smpp.companion.proxy.relay.netty;

import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslHandler;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.observability.CapturingRelayObserver;
import smpp.companion.proxy.relay.BindInterceptor;
import smpp.companion.proxy.relay.ConnectionRegistry;
import smpp.companion.proxy.relay.RelayEgressHandler;
import smpp.companion.proxy.relay.RelayIngressHandler;
import smpp.companion.proxy.relay.RelayStateManager;
import smpp.companion.proxy.testsupport.RelayTestFixtures;
import smpp.companion.proxy.tls.SmppLegTlsFactory;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC4 &mdash; the pipeline shape on BOTH legs (owner decision 2026-08-15: codec-only prefix in T6; the
 * {@code BindInterceptor} (T7) and per-leg relay-handler (T8) entries are appended at the documented
 * attachment points — both LANDED; Story 3.4 T5 split the relay entry into
 * {@code RelayIngressHandler}/{@code RelayEgressHandler} over the shared {@code CoupledRelayHandler}
 * base — the slice's pipelines are complete). Pins the structural
 * contracts: (a) order &mdash; {@code SmppFrameDecoder → SmppCodec → BindInterceptor → RelayIngressHandler}
 * (INGRESS) and {@code SmppFrameDecoder → SmppCodec → RelayEgressHandler} (EGRESS) (the framer feeds the
 * codec, the codec feeds the interceptor, the interceptor hands the post-couple plane to the relay
 * handler); (b) CODEC-014 &mdash; PER-CHANNEL instances of every handler (two channels must never
 * share a framer — nor the stateful per-connection interceptor, nor the per-leg relay
 * handler); (c) NO {@link SslHandler} on either leg (plaintext slice &mdash; TLS is Epic 3).
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
@SuppressWarnings("FutureReturnValueIgnored") // reason: EmbeddedChannel.close() in test teardown is
// fire-and-forget — the close future can only fail on an already-finished test channel, and there is
// nothing to observe in a pipeline-shape test.
class RelayPipelineInitializersTest {

    /** The real production wiring — the shared fixture (all beans direct-constructed, per-channel stateful). */
    private static RelayIngressInitializer ingressInitializer() {
        return RelayTestFixtures.modeBIngressInitializer(RelayTestFixtures.freePort());
    }

    /**
     * The real production egress wiring SHAPE — a fresh, deliberately ISOLATED manager-over-registry
     * pair per fixture: this suite pins pipeline shape, not the production singleton sharing (Spring
     * injects ONE shared manager/registry into BOTH initializers — the sharing {@code RelayTestFixtures}
     * wires into its harness records; chunk-B review 2026-09-01).
     */
    private static RelayEgressInitializer egressInitializer() {
        return new RelayEgressInitializer(
                new RelayStateManager(new ConnectionRegistry()), new CapturingRelayObserver());
    }

    @Test
    @DisplayName("ingress: framer → codec → BindInterceptor → RelayIngressHandler in order, exactly those "
            + "four, no SslHandler (AC4)")
    void ingressWiresFramerCodecInterceptorIngressRelayHandler() {
        EmbeddedChannel channel = new EmbeddedChannel(ingressInitializer());
        try {
            List<String> names = channel.pipeline().names();
            int framer = indexOfPrefix(names, "SmppFrameDecoder");
            int codec = indexOfPrefix(names, "SmppCodec");
            int interceptor = indexOfPrefix(names, "BindInterceptor");
            int relayHandler = indexOfPrefix(names, "RelayIngressHandler");
            assertThat(framer).as("the ingress leg must carry a SmppFrameDecoder").isGreaterThanOrEqualTo(0);
            assertThat(codec).as("the ingress leg must carry an SmppCodec").isGreaterThanOrEqualTo(0);
            assertThat(interceptor)
                    .as("T7 landed: the ingress leg carries the BindInterceptor after the codec (AC4)")
                    .isGreaterThanOrEqualTo(0);
            assertThat(relayHandler)
                    .as("T8 landed: the ingress leg carries the RelayIngressHandler after the interceptor "
                            + "(AC4; the Story 3.4 T5 split)")
                    .isGreaterThanOrEqualTo(0);
            assertThat(framer).as("the framer FEEDS the codec — it must sit first").isLessThan(codec);
            assertThat(codec).as("the codec FEEDS the interceptor — it must sit between").isLessThan(interceptor);
            assertThat(interceptor)
                    .as("the interceptor hands the post-couple plane to the relay handler — it must sit between")
                    .isLessThan(relayHandler);
            assertThat(userHandlers(names))
                    .as("the ingress pipeline is EXACTLY framer + codec + BindInterceptor + RelayIngressHandler")
                    .hasSize(4);
            assertThat(channel.pipeline().get(SslHandler.class))
                    .as("no SslHandler on the ingress leg — plaintext slice (TLS is Epic 3)")
                    .isNull();
        } finally {
            channel.close();
        }
    }

    @Test
    @DisplayName("egress: framer → codec → RelayEgressHandler (the couple unit rides the egress leg), exactly "
            + "those three, no SslHandler (AC4)")
    void egressWiresFramerCodecEgressRelayHandler() {
        EmbeddedChannel channel = new EmbeddedChannel(egressInitializer());
        try {
            List<String> names = channel.pipeline().names();
            int framer = indexOfPrefix(names, "SmppFrameDecoder");
            int codec = indexOfPrefix(names, "SmppCodec");
            int relayHandler = indexOfPrefix(names, "RelayEgressHandler");
            assertThat(framer).as("the egress leg must carry a SmppFrameDecoder").isGreaterThanOrEqualTo(0);
            assertThat(codec).as("the egress leg must carry an SmppCodec").isGreaterThanOrEqualTo(0);
            assertThat(relayHandler)
                    .as("T8 landed: the egress leg carries the RelayEgressHandler after the codec — the AD-25 "
                            + "couple fires here (the bind_resp arrives from the SMSC on this leg, which rides "
                            + "the ingress event loop, AD-2; the Story 3.4 T5 split)")
                    .isGreaterThanOrEqualTo(0);
            assertThat(framer).as("the framer FEEDS the codec — it must sit first").isLessThan(codec);
            assertThat(codec).as("the codec FEEDS the relay handler — it must sit between").isLessThan(relayHandler);
            assertThat(userHandlers(names))
                    .as("the egress pipeline is EXACTLY framer + codec + RelayEgressHandler (T7's per-pair "
                            + "EgressLeg is appended later by the connect assembly, per-bind)")
                    .hasSize(3);
            assertThat(channel.pipeline().get(SslHandler.class))
                    .as("no SslHandler on the egress leg either — plaintext to the SMSC (TLS is Epic 3)")
                    .isNull();
        } finally {
            channel.close();
        }
    }

    @Test
    @DisplayName("CODEC-014: every channel gets its OWN framer, codec, interceptor — and relay handler — "
            + "instances (both legs)")
    void eachChannelGetsItsOwnDecoderInstances() {
        EmbeddedChannel ingressA = new EmbeddedChannel(ingressInitializer());
        EmbeddedChannel ingressB = new EmbeddedChannel(ingressInitializer());
        EmbeddedChannel egressA = new EmbeddedChannel(egressInitializer());
        EmbeddedChannel egressB = new EmbeddedChannel(egressInitializer());
        try {
            assertThat(ingressA.pipeline().get(SmppFrameDecoder.class))
                    .as("two ingress channels must never share a SmppFrameDecoder (CODEC-014)")
                    .isNotSameAs(ingressB.pipeline().get(SmppFrameDecoder.class));
            assertThat(ingressA.pipeline().get(SmppCodec.class))
                    .isNotSameAs(ingressB.pipeline().get(SmppCodec.class));
            assertThat(ingressA.pipeline().get(BindInterceptor.class))
                    .as("two ingress channels must never share the STATEFUL BindInterceptor "
                            + "(per-connection adjudication handles)")
                    .isNotSameAs(ingressB.pipeline().get(BindInterceptor.class));
            assertThat(ingressA.pipeline().get(RelayIngressHandler.class))
                    .as("two ingress channels must never share the RelayIngressHandler "
                            + "(per-leg close marker + direction in the shared base)")
                    .isNotSameAs(ingressB.pipeline().get(RelayIngressHandler.class));
            assertThat(egressA.pipeline().get(SmppFrameDecoder.class))
                    .as("two egress channels must never share a SmppFrameDecoder (CODEC-014)")
                    .isNotSameAs(egressB.pipeline().get(SmppFrameDecoder.class));
            assertThat(egressA.pipeline().get(SmppCodec.class))
                    .isNotSameAs(egressB.pipeline().get(SmppCodec.class));
            assertThat(egressA.pipeline().get(RelayEgressHandler.class))
                    .as("two egress channels must never share the RelayEgressHandler (the per-pair couple + per-leg "
                            + "close marker are channel-scoped)")
                    .isNotSameAs(egressB.pipeline().get(RelayEgressHandler.class));
        } finally {
            ingressA.close();
            ingressB.close();
            egressA.close();
            egressB.close();
        }
    }

    // --- Story 3.3 (T4): the TLS cells' pipeline shape — SslHandler FIRST, before the framer -------

    /**
     * The reverse internet-leg listener pipeline: the spine's {@code SslHandler → SmppFrameDecoder →
     * SmppCodec → BindInterceptor → RelayIngressHandler} order — the TLS handshake terminates BEFORE any SMPP
     * byte is framed, and the handler is a per-channel instance (the engine is per-connection state).
     */
    @Test
    @DisplayName("reverse.mode-a ingress: SslHandler → framer → codec → interceptor → ingress relay handler, in order")
    void reverseTlsIngressPrependsSslHandlerBeforeTheFramer(@TempDir Path dir) {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        RelayTestFixtures.RelayHarness harness = RelayTestFixtures.relayHarness(
                RelayTestFixtures.reverseAProperties(RelayTestFixtures.freePort(), 8, legs, "127.0.0.1", 2775),
                new smpp.companion.proxy.security.AlwaysAllowBindCredentialVerifier());
        EmbeddedChannel channel = new EmbeddedChannel(harness.ingressInitializer());
        try {
            List<String> names = channel.pipeline().names();
            int ssl = indexOfPrefix(names, "SslHandler");
            int framer = indexOfPrefix(names, "SmppFrameDecoder");
            assertThat(ssl).as("the TLS listener cell carries an SslHandler").isGreaterThanOrEqualTo(0);
            assertThat(ssl).as("TLS terminates BEFORE framing — the SslHandler must sit FIRST").isLessThan(framer);
            assertThat(userHandlers(names))
                    .as("the TLS ingress pipeline is EXACTLY SslHandler + the four plaintext handlers")
                    .hasSize(5);
        } finally {
            channel.close();
        }
    }

    /** The forward's per-dial egress pipeline: SslHandler first, then the codec prefix + couple unit. */
    @Test
    @DisplayName("forward egress (TargetTls): SslHandler → framer → codec → relay handler, in order")
    void forwardTlsEgressPrependsSslHandlerBeforeTheFramer(@TempDir Path dir) {
        RelayTestFixtures.SmppTlsLegs legs = RelayTestFixtures.smppTlsLegs(dir);
        RelayTestFixtures.RelayHarness harness = RelayTestFixtures.relayHarness(
                RelayTestFixtures.forwardAProperties(RelayTestFixtures.freePort(), 8, legs, "127.0.0.1", 2776),
                new smpp.companion.proxy.security.AlwaysAllowBindCredentialVerifier());
        smpp.companion.proxy.config.ProxyCompanionProperties.RoutingEntry target =
                new smpp.companion.proxy.config.ProxyCompanionProperties.RoutingEntry("carrierOne", "127.0.0.1", 2776, null);
        RelayEgressInitializer tlsEgress = new RelayEgressInitializer(
                harness.manager(), harness.observer(),
                ch -> harness.tlsFactory().newEgressSslHandler(ch.alloc(), target));
        EmbeddedChannel channel = new EmbeddedChannel(tlsEgress);
        try {
            List<String> names = channel.pipeline().names();
            int ssl = indexOfPrefix(names, "SslHandler");
            int framer = indexOfPrefix(names, "SmppFrameDecoder");
            assertThat(ssl).as("the TLS dial carries an SslHandler").isGreaterThanOrEqualTo(0);
            assertThat(ssl).as("the ORIGINAL bind rides the TLS record layer — SslHandler FIRST").isLessThan(framer);
            assertThat(userHandlers(names)).hasSize(4);
        } finally {
            channel.close();
        }
    }

    /** The plaintext singleton (the reverse's SMSC leg) still carries NO SslHandler ([B]: SMSC leg is trusted). */
    @Test
    @DisplayName("reverse SMSC egress singleton: no SslHandler — the SMSC leg is plaintext in every mode")
    void reverseSmscEgressSingletonStaysPlaintext() {
        EmbeddedChannel channel = new EmbeddedChannel(egressInitializer());
        try {
            assertThat(channel.pipeline().get(SslHandler.class))
                    .as("no TLS on the SMSC leg (AD-12 amended — trusted network in every mode)")
                    .isNull();
        } finally {
            channel.close();
        }
    }

    /** pipeline().names() includes Netty's internal TailContext — count only USER handlers. */
    private static List<String> userHandlers(List<String> names) {
        return names.stream()
                .filter(n -> !n.startsWith("DefaultChannelPipeline$"))
                .toList();
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
