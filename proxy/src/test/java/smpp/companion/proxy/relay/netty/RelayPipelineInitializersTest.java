package smpp.companion.proxy.relay.netty;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslHandler;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.framer.SmppFrameDecoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC4 &mdash; the T6 codec-prefix pipeline shape on BOTH legs (owner decision 2026-08-15: codec-only
 * prefix; the {@code BindInterceptor}/{@code RelayHandler} entries are appended by T7/T8 at the
 * documented attachment points). Pins the three structural contracts of subtask 1 that land in T6:
 * (a) order &mdash; {@code SmppFrameDecoder} then {@code SmppCodec} (the framer feeds the codec);
 * (b) CODEC-014 &mdash; PER-CHANNEL decoder instances (two channels must never share a framer);
 * (c) NO {@link SslHandler} on either leg (plaintext slice &mdash; TLS is Epic 3).
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
@SuppressWarnings("FutureReturnValueIgnored") // reason: EmbeddedChannel.close() in test teardown is
// fire-and-forget — the close future can only fail on an already-finished test channel, and there is
// nothing to observe in a pipeline-shape test.
class RelayPipelineInitializersTest {

    @Test
    @DisplayName("ingress: framer → codec in order, exactly the codec prefix, no SslHandler (AC4)")
    void ingressWiresFramerThenCodecOnly() {
        EmbeddedChannel channel = new EmbeddedChannel(new RelayIngressInitializer());
        try {
            assertCodecPrefixOnly(channel, "ingress");
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
    @DisplayName("CODEC-014: every channel gets its OWN framer and codec instances (both legs)")
    void eachChannelGetsItsOwnDecoderInstances() {
        EmbeddedChannel ingressA = new EmbeddedChannel(new RelayIngressInitializer());
        EmbeddedChannel ingressB = new EmbeddedChannel(new RelayIngressInitializer());
        EmbeddedChannel egressA = new EmbeddedChannel(new RelayEgressInitializer());
        EmbeddedChannel egressB = new EmbeddedChannel(new RelayEgressInitializer());
        try {
            assertThat(ingressA.pipeline().get(SmppFrameDecoder.class))
                    .as("two ingress channels must never share a SmppFrameDecoder (CODEC-014)")
                    .isNotSameAs(ingressB.pipeline().get(SmppFrameDecoder.class));
            assertThat(ingressA.pipeline().get(SmppCodec.class))
                    .isNotSameAs(ingressB.pipeline().get(SmppCodec.class));
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

    /** The T6 codec prefix: framer strictly before codec, and NOTHING else in the pipeline. */
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
        // pipeline().names() includes Netty's internal TailContext — count only USER handlers.
        List<String> userHandlers = names.stream()
                .filter(n -> !n.startsWith("DefaultChannelPipeline$"))
                .toList();
        assertThat(userHandlers)
                .as("T6 wires ONLY the codec prefix (the handler entries land with T7/T8)")
                .hasSize(2);
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
