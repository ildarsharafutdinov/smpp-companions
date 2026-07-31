package smpp.companion.codec.framer;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CODEC-012 (AC7, P1, R3/REL-1/SEC-2): jqwik split-invariance property for {@link SmppFrameDecoder}. For ANY
 * valid PDU and ANY partition of its bytes into {@code [1..N]} contiguous pieces, feeding the pieces
 * sequentially reassembles to the IDENTICAL single frame. Generalizes CODEC-002 (which split at every byte
 * boundary) across arbitrary boundaries — defense-in-depth on P1 framing integrity (a frame corrupted by
 * chunking would splice the wrong bytes downstream).
 *
 * <p>Runs jqwik's default bounded tries on the PR tier; continuous expansion is a nightly concern.
 *
 * <p><b>jqwik gotcha (verified 2026-07-31):</b> a Jupiter {@code @DisplayName} or {@code @Tag} on a jqwik
 * {@code @Property} method makes jqwik SILENTLY SKIP execution (discovered but never run; build stays green).
 * The {@code @Property} method here therefore carries NO Jupiter annotations — the tier tag + display name
 * live at the CLASS level (which jqwik honors).
 */

@Tag("fuzz")
@Tag("codec")
@Tag("p1")
@DisplayName("SmppFrameDecoder property — CODEC-012 (any chunking reassembles identically)")
class SmppFrameDecoderPropertyTest {

    /** Max generated body — bounds the property's time without losing generality. */
    private static final int MAX_BODY = 200;
    private static final int HEADER = 16;

    /** Records any exception the pipeline fires; a valid PDU reassembles without throwing, so the property fails LOUD with the real cause. */
    private static final class ExceptionCapture extends ChannelInboundHandlerAdapter {
        private Throwable cause;

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            this.cause = cause; // recorded — surfaced (not swallowed) by the property below
        }
    }

    /** A self-consistent PDU: {@code command_length ==} byte count, arbitrary command_id, arbitrary body. */
    @Provide
    Arbitrary<byte[]> validPdu() {
        return Arbitraries.bytes().array(byte[].class).ofMinSize(0).ofMaxSize(MAX_BODY)
                .map(SmppFrameDecoderPropertyTest::toPdu);
    }

    private static byte[] toPdu(byte[] body) {
        ByteBuffer b = ByteBuffer.allocate(HEADER + body.length);
        b.putInt(HEADER + body.length); // command_length == total PDU length (self-consistent)
        b.putInt(0x00000015);           // command_id (enquire_link — any; the framer is command-agnostic)
        b.putInt(0);                    // command_status
        b.putInt(1);                    // sequence_number
        b.put(body);
        return b.array();
    }

    /** Arbitrary raw cut points in {@code [0, MAX_PDU]}; clamped/sorted/de-duplicated inside the property. */
    @Provide
    Arbitrary<List<Integer>> partition() {
        return Arbitraries.integers().between(0, HEADER + MAX_BODY).list().ofMinSize(0).ofMaxSize(12);
    }

    @Property
    // NOTE: a Jupiter @DisplayName on a jqwik @Property makes jqwik SILENTLY SKIP execution (verified
    // 2026-07-31) — omitted here for that reason; the class @DisplayName carries the label.
    void anyChunkingReassemblesIdentically(@ForAll("validPdu") byte[] pdu,
                                           @ForAll("partition") List<Integer> rawCuts) {
        ExceptionCapture capture = new ExceptionCapture();
        EmbeddedChannel channel = new EmbeddedChannel(new SmppFrameDecoder(), capture);
        try {
            // Ordered, clamped cut set with 0 and pdu.length as the outer boundaries.
            List<Integer> cuts = new ArrayList<>(rawCuts);
            cuts.add(0);
            cuts.add(pdu.length);
            cuts.replaceAll(c -> Math.max(0, Math.min(c, pdu.length)));
            cuts.sort(null);

            // Feed contiguous slices between successive distinct cuts (zero-length pieces are harmless no-ops).
            int prev = -1;
            for (int cut : cuts) {
                if (prev >= 0 && cut > prev) {
                    channel.writeInbound(Unpooled.wrappedBuffer(pdu, prev, cut - prev));
                }
                prev = cut;
            }

            // A valid PDU reassembles without throwing; surface the real cause (not a downstream size failure).
            if (capture.cause != null) {
                throw new AssertionError("pipeline threw unexpectedly while reassembling a valid PDU", capture.cause);
            }

            // Assert exactly one frame, byte-identical to the original PDU.
            List<byte[]> frames = new ArrayList<>();
            ByteBuf frame;
            while ((frame = (ByteBuf) channel.readInbound()) != null) {
                byte[] bytes = new byte[frame.readableBytes()];
                frame.getBytes(frame.readerIndex(), bytes);
                frames.add(bytes);
                frame.release();
            }
            assertThat(frames).as("exactly one frame reassembled, regardless of chunking").hasSize(1);
            assertThat(frames.get(0)).as("byte-identical reassembly").isEqualTo(pdu);
        } finally {
            channel.finishAndReleaseAll();
        }
    }
}
