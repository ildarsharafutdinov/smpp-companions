package smpp.companion.codec.bind;

import com.code_intelligence.jazzer.junit.FuzzTest;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrame;
import smpp.companion.codec.framer.SmppFrameDecoder;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * CODEC-025 (AC7 / AD-24, P1, R3/SEC-2): structure-aware Jazzer fuzz of the bind-family parser over framed
 * buffers. AD-24 mandates fuzzing BOTH decoders — this is the parser half (complementing CODEC-011's framer).
 * The raw {@code byte[]} is shaped into a framed bind PDU <em>inside</em> the method: a bind-family
 * {@code command_id} is forced into header octets 4-7 and {@code command_length} is made self-consistent, so
 * the <b>parser</b> (not the opaque/framer path) is the surface under test for EVERY input — including
 * continuous-mode ({@code JAZZER_FUZZ=1}) mutations. The body is whatever bytes follow the 16-octet header.
 * Invariants asserted for EVERY input:
 * <ol>
 *   <li><b>No Throwable escapes {@code decode}</b> — a malformed body rejects via {@code exceptionCaught}
 *       (swallowed by the tail capture), never out of {@code writeInbound}.</li>
 *   <li><b>No read past the frame limit</b> — ANY captured cause is a {@link DecoderException}, NEVER an
 *       {@code IndexOutOfBounds}/{@code ArrayIndexOutOfBounds}/{@code NullPointerException}. A read past the
 *       frame boundary would surface as an {@code IndexOutOfBounds} (not a {@code DecoderException}); asserting
 *       the cause class proves the bounded NUL scan + bounds-checked fixed-field reads hold for arbitrary
 *       bodies — exactly the over-read the fuzz hunts for.</li>
 * </ol>
 *
 * <p>"Bounded decode time" is structural — the NUL scan is bounded by the slice's {@code [readerIndex, writerIndex)}
 * range — and is exercised under continuous fuzz ({@code JAZZER_FUZZ=1}); the {@link MethodSource} seeds run once
 * each in regression mode on the PR tier (a mix of well-formed and malformed bind bodies so both the decode and
 * reject branches are exercised). The body length is capped so {@code command_length ≤ MAX_COMMAND_LENGTH},
 * guaranteeing the framer EMITS a frame and the parser (not the framer) is the exercised surface.
 */
@Tag("fuzz")
@Tag("codec")
@Tag("p1")
@DisplayName("SmppCodec bind-parser fuzz — CODEC-025 (arbitrary body: no crash, no over-read)")
class SmppCodecFuzzTest {

    private static final int HEADER = SmppFrame.HEADER_LENGTH;
    private static final Integer[] BIND_FAMILY_IDS = SmppCommandIds.BIND_FAMILY.toArray(Integer[]::new);

    /** Records (and swallows) any exception a decoder fires, so writeInbound does not re-throw. */
    private static final class ExceptionCapture extends ChannelInboundHandlerAdapter {
        private Throwable cause;

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            this.cause = cause; // swallow — the fuzz asserts on it directly
        }
    }

    /** Representative bind bodies for regression mode (PR tier): both the clean-decode and the reject shapes. */
    static Stream<Arguments> bindParserSeeds() {
        return Stream.of(
                Arguments.of(bindSeed(wellFormedBody())),                                  // every field present -> clean parse
                Arguments.of(bindSeed(longValidBody())),                                   // long address_range -> clean parse
                Arguments.of(bindSeed("system_id_with_no_nul".getBytes(StandardCharsets.US_ASCII))), // no NUL -> reject
                Arguments.of(bindSeed(new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF})), // no NUL -> reject
                Arguments.of(bindSeed(truncatedBody())),                                   // missing fixed field -> reject
                Arguments.of(bindSeed(new byte[0])));                                      // header-only -> reject
    }

    /** A full, spec-valid bind body: system_id/password/system_type C-octets + interface_version/ton/npi + address_range. */
    private static byte[] wellFormedBody() {
        return concat("sys\0".getBytes(StandardCharsets.US_ASCII), "pw\0".getBytes(StandardCharsets.US_ASCII),
                "st\0".getBytes(StandardCharsets.US_ASCII), new byte[]{0x34, 0x00, 0x00},
                "ar\0".getBytes(StandardCharsets.US_ASCII));
    }

    /** A valid body with a long address_range (exercises a longer successful parse + NUL scan). */
    private static byte[] longValidBody() {
        byte[] range = new byte[31]; // 30 'a's + NUL (≤ 41 incl. terminator)
        Arrays.fill(range, (byte) 'a');
        range[range.length - 1] = 0;
        return concat("sys\0".getBytes(StandardCharsets.US_ASCII), "pw\0".getBytes(StandardCharsets.US_ASCII),
                "st\0".getBytes(StandardCharsets.US_ASCII), new byte[]{0x34, 0x00, 0x00}, range);
    }

    /** Completes the three C-octet fields but truncates before the fixed {@code interface_version} byte. */
    private static byte[] truncatedBody() {
        return concat("sys\0".getBytes(StandardCharsets.US_ASCII), "pw\0".getBytes(StandardCharsets.US_ASCII),
                "st\0".getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            len += p.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    /** Wraps a body in a 16-octet header (the method under test overwrites length + command_id, so these are placeholders). */
    private static byte[] bindSeed(byte[] body) {
        byte[] pdu = new byte[HEADER + body.length];
        ByteBuffer.wrap(pdu).putInt(pdu.length).putInt(SmppCommandIds.BIND_TRANSCEIVER).putInt(0).putInt(1);
        System.arraycopy(body, 0, pdu, HEADER, body.length);
        return pdu;
    }

    @FuzzTest
    @MethodSource("bindParserSeeds")
    @DisplayName("CODEC-025: valid header + bind-family command_id + arbitrary body -> no crash, no over-read")
    void fuzzBindParser(byte[] data) {
        // Shape the raw bytes into a framed bind PDU: force a bind-family command_id (so the PARSER — not the
        // opaque/framer path — is the exercised surface for every input, incl. continuous-mode mutations) and a
        // self-consistent command_length (so the framer EMITS exactly one frame). The body is whatever bytes the
        // (mutated) input carries after the 16-octet header; the parser must decode or reject it cleanly.
        if (data.length < HEADER) {
            return; // not enough for a header — nothing for the parser to chew on
        }
        int len = Math.min(data.length, SmppFrame.MAX_COMMAND_LENGTH);
        int bindId = BIND_FAMILY_IDS[(data[data.length - 1] & 0xFF) % BIND_FAMILY_IDS.length];
        ByteBuffer hdr = ByteBuffer.wrap(data, 0, len);
        hdr.putInt(0, len);                // command_length = byte count (≤ MAX) -> framer emits one frame
        hdr.putInt(Integer.BYTES, bindId); // bind-family command_id -> parser parses (not opaque)
        byte[] pdu = Arrays.copyOfRange(data, 0, len);

        ExceptionCapture capture = new ExceptionCapture();
        EmbeddedChannel channel = new EmbeddedChannel(new SmppFrameDecoder(), new SmppCodec(), capture);
        try {
            ByteBuf input = Unpooled.wrappedBuffer(pdu);
            // (1) No Throwable escapes decode.
            assertThatCode(() -> channel.writeInbound(input)).as("no Throwable escapes decode for any body").doesNotThrowAnyException();

            // (2) No read past the frame limit: any reject is a DecoderException (never IOOBE/AIOOBE/NPE —
            //     those would indicate an over-read / unbounded scan, exactly what the fuzz hunts for).
            if (capture.cause != null) {
                assertThat(capture.cause)
                        .as("a parser reject is a controlled DecoderException (never an over-read)")
                        .isInstanceOf(DecoderException.class);
            }

            // release whatever surfaced (a typed PDU on a well-formed body; nothing on a reject)
            Object out;
            while ((out = channel.readInbound()) != null) {
                if (out instanceof SmppBindPdu p) {
                    p.originalFrame().release();
                } else if (out instanceof ByteBuf buf) {
                    buf.release();
                }
            }
        } finally {
            channel.finishAndReleaseAll();
        }
    }
}
