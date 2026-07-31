package smpp.companion.codec.bind;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrameDecoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CODEC-037 (AC7, unit, P1, R14/R3; AD-12): jqwik property — after parsing an arbitrary VALID bind request,
 * the ORIGINAL framed buffer is byte-identical and un-mutated (the original bind is relayed to the SMSC
 * verbatim; the parser must not corrupt the forward unit). Generalizes the deterministic CODEC-037 unit test
 * across arbitrary bind fields.
 *
 * <p><b>jqwik gotcha (verified 2026-07-31):</b> a Jupiter {@code @DisplayName} or {@code @Tag} on a jqwik
 * {@code @Property} method makes jqwik SILENTLY SKIP execution (discovered but never run; build stays green).
 * The {@code @Property} method here therefore carries NO Jupiter annotations — the tier tag + display name
 * live at the CLASS level (which jqwik honors).
 */
@Tag("unit")
@Tag("codec")
@Tag("p1")
@DisplayName("SmppCodec property — CODEC-037 (parsing a bind request leaves the ORIGINAL frame byte-exact)")
class SmppCodecForwardingPropertyTest {

    /** Records any exception the pipeline fires; a valid input must not throw, so the property fails LOUD with the real cause. */
    private static final class ExceptionCapture extends ChannelInboundHandlerAdapter {
        private Throwable cause;

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            this.cause = cause; // recorded — surfaced (not swallowed) by the property below
        }
    }

    /** An arbitrary VALID bind request (any of the three request ids + spec-length ASCII C-octet fields). */
    @Provide
    Arbitrary<SmppBindRequest> validBindRequest() {
        Arbitrary<Integer> commandId = Arbitraries.of(
                SmppCommandIds.BIND_RECEIVER, SmppCommandIds.BIND_TRANSMITTER, SmppCommandIds.BIND_TRANSCEIVER);
        Arbitrary<AsciiString> systemId = cOctet(15);   // system_id ≤16 incl. NUL terminator
        Arbitrary<AsciiString> password = cOctet(8);    // password ≤9 incl. NUL
        Arbitrary<AsciiString> systemType = cOctet(12); // system_type ≤13 incl. NUL
        Arbitrary<AsciiString> addressRange = cOctet(40); // address_range ≤41 incl. NUL
        Arbitrary<Byte> interfaceVersion = Arbitraries.bytes();
        Arbitrary<Byte> addrTon = Arbitraries.bytes();
        Arbitrary<Byte> addrNpi = Arbitraries.bytes();
        return Combinators.combine(commandId, systemId, password, systemType,
                        interfaceVersion, addrTon, addrNpi, addressRange)
                .as((Integer cmdId, AsciiString sid, AsciiString pw, AsciiString st,
                     Byte iv, Byte ton, Byte npi, AsciiString ar) -> {
                    // originalFrame is unused by the encoder (it rebuilds from the fields); a throwaway buffer
                    // carries the slot, released by the property after encoding.
                    ByteBuf dummy = Unpooled.buffer(1);
                    return new SmppBindRequest(cmdId, 0, 1, sid, pw, st, iv, ton, npi, ar, dummy);
                });
    }

    /** A C-octet-string field value: ASCII octets 1..127 (no embedded NUL), length ≤ maxFieldBytes. */
    private static Arbitrary<AsciiString> cOctet(int maxFieldBytes) {
        return Arbitraries.bytes().between((byte) 1, (byte) 127)
                .array(byte[].class).ofMinSize(0).ofMaxSize(maxFieldBytes)
                .map(AsciiString::new);
    }

    @Property
    void parsedBindRequest_leavesOriginalFrameByteExact(@ForAll("validBindRequest") SmppBindRequest seedReq) {
        ExceptionCapture capture = new ExceptionCapture();
        EmbeddedChannel channel = new EmbeddedChannel(new SmppFrameDecoder(), new SmppCodec(), capture);
        ByteBuf encoded = null;
        try {
            encoded = SmppBindEncoder.encode(seedReq, UnpooledByteBufAllocator.DEFAULT);
            byte[] snapshot = ByteBufUtil.getBytes(encoded); // the exact input bytes, copied out before parse
            channel.writeInbound(encoded); // ownership -> pipeline; originalFrame is a retained slice of it
            encoded = null; // pipeline owns the buffer now (finishAndReleaseAll releases it)
            // A valid bind request must not throw; surface the real cause (not a confusing downstream null/size failure).
            if (capture.cause != null) {
                throw new AssertionError("pipeline threw unexpectedly on a valid bind request", capture.cause);
            }
            SmppBindPdu out = (SmppBindPdu) channel.readInbound();
            assertThat(out)
                    .as("a valid bind request decodes to a typed request")
                    .isInstanceOf(SmppBindRequest.class);
            try {
                assertThat(ByteBufUtil.getBytes(out.originalFrame()))
                        .as("the ORIGINAL frame is byte-identical to the parsed input (AD-12 forward unit)")
                        .isEqualTo(snapshot);
            } finally {
                out.originalFrame().release();
            }
        } finally {
            if (encoded != null) {
                encoded.release(); // only if writeInbound never took ownership (e.g. encode/getBytes threw)
            }
            channel.finishAndReleaseAll(); // releases the cumulation + any unread inbound
            seedReq.originalFrame().release(); // the throwaway buffer the seed carried (unused by encode)
        }
    }
}
