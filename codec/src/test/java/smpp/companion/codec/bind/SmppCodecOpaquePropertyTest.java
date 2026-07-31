package smpp.companion.codec.bind;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
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
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrame;
import smpp.companion.codec.framer.SmppFrameDecoder;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CODEC-038 (AC7, fuzz, P1, R3/R14; AD-2/AD-3): jqwik property — opaque non-bind PDUs (arbitrary
 * {@code command_id} ∉ BIND_FAMILY + arbitrary body) forward byte-identical with NO decode/re-serialize path:
 * the codec emits no typed object and the framed buffer is untouched.
 *
 * <p><b>jqwik gotcha (verified 2026-07-31):</b> a Jupiter {@code @DisplayName} or {@code @Tag} on a jqwik
 * {@code @Property} method makes jqwik SILENTLY SKIP execution (discovered but never run; build stays green).
 * The {@code @Property} method here therefore carries NO Jupiter annotations — the tier tag + display name
 * live at the CLASS level (which jqwik honors).
 */
@Tag("fuzz")
@Tag("codec")
@Tag("p1")
@DisplayName("SmppCodec property — CODEC-038 (opaque non-bind PDU forwards byte-identical, no typed object)")
class SmppCodecOpaquePropertyTest {

    private static final int HEADER = SmppFrame.HEADER_LENGTH;

    /** Records any exception the pipeline fires; an opaque PDU must forward without throwing, so the property fails LOUD with the real cause. */
    private static final class ExceptionCapture extends ChannelInboundHandlerAdapter {
        private Throwable cause;

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            this.cause = cause; // recorded — surfaced (not swallowed) by the property below
        }
    }

    /** Any {@code command_id} that is NOT a bind-family member (the parsed-vs-opaque boundary, AD-3). */
    @Provide
    Arbitrary<Integer> nonBindCommandId() {
        return Arbitraries.integers().filter(id -> !SmppCommandIds.isBindFamily(id));
    }

    /** A body small enough that {@code command_length ≤ MAX_COMMAND_LENGTH} (so the framer forwards a frame). */
    @Provide
    Arbitrary<byte[]> boundedBody() {
        return Arbitraries.bytes().array(byte[].class).ofMinSize(0).ofMaxSize(1000);
    }

    @Property
    void opaquePdu_forwardsByteIdentical(@ForAll("nonBindCommandId") int commandId,
                                         @ForAll("boundedBody") byte[] body) {
        byte[] pdu = opaquePdu(commandId, body);
        ExceptionCapture capture = new ExceptionCapture();
        EmbeddedChannel channel = new EmbeddedChannel(new SmppFrameDecoder(), new SmppCodec(), capture);
        try {
            channel.writeInbound(Unpooled.wrappedBuffer(pdu));
            // An opaque PDU must forward without throwing; surface the real cause (not a downstream null failure).
            if (capture.cause != null) {
                throw new AssertionError("pipeline threw unexpectedly on an opaque PDU", capture.cause);
            }
            Object out = channel.readInbound();
            assertThat(out)
                    .as("an opaque PDU forwards as the untouched framed ByteBuf, never a typed PDU")
                    .isInstanceOf(ByteBuf.class)
                    .isNotInstanceOf(SmppBindPdu.class);
            try {
                assertThat(ByteBufUtil.getBytes((ByteBuf) out))
                        .as("opaque forward is byte-identical (bytes in == bytes out)")
                        .isEqualTo(pdu);
            } finally {
                ((ByteBuf) out).release();
            }
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private static byte[] opaquePdu(int commandId, byte[] body) {
        ByteBuffer b = ByteBuffer.allocate(HEADER + body.length);
        b.putInt(HEADER + body.length); // command_length (self-consistent, ≤ MAX)
        b.putInt(commandId);            // non-bind -> opaque forward (AD-3)
        b.putInt(0);                    // command_status
        b.putInt(1);                    // sequence_number
        b.put(body);
        return b.array();
    }
}
