package smpp.companion.proxy.relay.netty;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslHandler;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.relay.BindInterceptor;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC4 &mdash; the pipeline shape on BOTH legs (owner decision 2026-08-15: codec-only prefix in T6; the
 * {@code BindInterceptor}/{@code RelayHandler} entries are appended by T7/T8 at the documented
 * attachment points). Pins the structural contracts: (a) order &mdash; {@code SmppFrameDecoder} then
 * {@code SmppCodec} then (INGRESS, since T7) {@code BindInterceptor} (the framer feeds the codec, the
 * codec feeds the interceptor); (b) CODEC-014 &mdash; PER-CHANNEL instances of every handler (two
 * channels must never share a framer — nor the stateful per-connection interceptor);
 * (c) NO {@link SslHandler} on either leg (plaintext slice &mdash; TLS is Epic 3).
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

    @Test
    @DisplayName("ingress: framer → codec → BindInterceptor in order, exactly those three, no SslHandler (AC4)")
    void ingressWiresFramerCodecThenBindInterceptor() {
        EmbeddedChannel channel = new EmbeddedChannel(ingressInitializer());
        try {
            List<String> names = channel.pipeline().names();
            int framer = indexOfPrefix(names, "SmppFrameDecoder");
            int codec = indexOfPrefix(names, "SmppCodec");
            int interceptor = indexOfPrefix(names, "BindInterceptor");
            assertThat(framer).as("the ingress leg must carry a SmppFrameDecoder").isGreaterThanOrEqualTo(0);
            assertThat(codec).as("the ingress leg must carry an SmppCodec").isGreaterThanOrEqualTo(0);
            assertThat(interceptor)
                    .as("T7 landed: the ingress leg carries the BindInterceptor after the codec (AC4)")
                    .isGreaterThanOrEqualTo(0);
            assertThat(framer).as("the framer FEEDS the codec — it must sit first").isLessThan(codec);
            assertThat(codec).as("the codec FEEDS the interceptor — it must sit between").isLessThan(interceptor);
            assertThat(userHandlers(names))
                    .as("the ingress pipeline is exactly framer + codec + BindInterceptor (T8 appends RelayHandler)")
                    .hasSize(3);
            assertThat(channel.pipeline().get(SslHandler.class))
                    .as("no SslHandler on the ingress leg — plaintext slice (TLS is Epic 3)")
                    .isNull();
        } finally {
            channel.close();
        }
    }

    @Test
    @DisplayName("egress: the SAME framer → codec prefix, no SslHandler (AC4)")
    void egressWiresTheSamePrefix() {
        EmbeddedChannel channel = new EmbeddedChannel(new RelayEgressInitializer());
        try {
            assertCodecPrefixOnly(channel, "egress");
            assertThat(channel.pipeline().get(SslHandler.class))
                    .as("no SslHandler on the egress leg either — plaintext to the SMSC (TLS is Epic 3)")
                    .isNull();
        } finally {
            channel.close();
        }
    }

    @Test
    @DisplayName("CODEC-014: every channel gets its OWN framer, codec — and interceptor — instances (both legs)")
    void eachChannelGetsItsOwnDecoderInstances() {
        EmbeddedChannel ingressA = new EmbeddedChannel(ingressInitializer());
        EmbeddedChannel ingressB = new EmbeddedChannel(ingressInitializer());
        EmbeddedChannel egressA = new EmbeddedChannel(new RelayEgressInitializer());
        EmbeddedChannel egressB = new EmbeddedChannel(new RelayEgressInitializer());
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
            assertThat(egressA.pipeline().get(SmppFrameDecoder.class))
                    .as("two egress channels must never share a SmppFrameDecoder (CODEC-014)")
                    .isNotSameAs(egressB.pipeline().get(SmppFrameDecoder.class));
            assertThat(egressA.pipeline().get(SmppCodec.class))
                    .isNotSameAs(egressB.pipeline().get(SmppCodec.class));
        } finally {
            ingressA.close();
            ingressB.close();
            egressA.close();
            egressB.close();
        }
    }

    /** The egress codec prefix: framer strictly before codec, and NOTHING else (T8 appends RelayHandler). */
    private static void assertCodecPrefixOnly(EmbeddedChannel channel, String leg) {
        List<String> names = channel.pipeline().names();
        int framer = indexOfPrefix(names, "SmppFrameDecoder");
        int codec = indexOfPrefix(names, "SmppCodec");
        assertThat(framer)
                .as(leg + " leg must carry a SmppFrameDecoder").isGreaterThanOrEqualTo(0);
        assertThat(codec)
                .as(leg + " leg must carry an SmppCodec").isGreaterThanOrEqualTo(0);
        assertThat(framer)
                .as("the framer FEEDS the codec — it must sit first").isLessThan(codec);
        assertThat(userHandlers(names))
                .as(leg + " wires ONLY the codec prefix (T8 appends the egress RelayHandler)")
                .hasSize(2);
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
