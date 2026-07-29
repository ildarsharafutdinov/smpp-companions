package smpp.companion.codec.bind;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.handler.codec.DecoderException;
import io.netty.util.AsciiString;
import lombok.experimental.UtilityClass;

/**
 * SMPP 3.4 byte-level read/write helpers (§3.1 C-octet-strings + single-octet fields + the big-endian
 * header u32). Package-private: the only consumers are {@link SmppCodec} (decode) and {@link SmppBindEncoder}
 * (encode).
 *
 * <p><b>Bounded read (R3 / SEC-2):</b> the NUL scan uses {@link ByteBuf#bytesBefore(byte)}, which is bounded
 * by the slice's {@code [readerIndex, writerIndex)} range, so an unterminated C-octet-string (CODEC-021) is
 * rejected with a {@link DecoderException} rather than over-reading or spinning. The scan never moves the
 * underlying forward buffer's reader index (CODEC-037); it advances only the slice's own reader index past
 * the terminator on success. A truncated body (CODEC-022) surfaces when a subsequent mandatory field has no
 * bytes left ({@link #readByte}).
 *
 * <p>Every C-octet-string field — including the password — is a lossless Netty {@link AsciiString}: the raw
 * ASCII bytes (high-bit octets preserved), a {@link CharSequence}, zero-conversion to {@link ByteBuf}, and
 * not an array (no record-array identity wart). The encode is lossless + zero-alloc via
 * {@link ByteBufUtil#copy(AsciiString, ByteBuf)} over the backing array.
 *
 * <p><b>Password zeroization (CODEC-024/PRIV-1, revised — user-directed):</b> the password is an
 * {@link AsciiString}, not a {@code char[]}. Its backing bytes ARE reachable for wiping via
 * {@link AsciiString#array()} ({@code Arrays.fill(pw.array(), pw.arrayOffset(), pw.arrayOffset()+pw.length(), (byte)0)}),
 * but {@link AsciiString} lazily caches {@link AsciiString#toString()}, so a {@code toString()} call would
 * leave a {@code String} copy that survives a backing-array wipe — the seam is therefore fragile (callers
 * must avoid {@code toString()} on the password). See the Dev Agent Record (Story 1.2) for the CODEC-024
 * deviation this user-directed choice entails.
 */
@UtilityClass
class SmppBytes {

    /**
     * Bounded NUL scan — returns the C-octet octets EXCLUDING the terminator; advances the slice's reader
     * index past the terminator.
     *
     * @throws DecoderException if no NULL terminator is found before the slice end (CODEC-021)
     */
    private static byte[] readNullTerminated(ByteBuf slice, String fieldName) {
        int nullIndex = slice.bytesBefore((byte) 0); // bounded by [readerIndex, writerIndex) — CODEC-021
        if (nullIndex < 0) {
            throw new DecoderException(
                    "SMPP bind: unterminated C-octet-string (no NULL before frame end) — field " + fieldName);
        }
        byte[] out = new byte[nullIndex];
        slice.readBytes(out); // consume the field bytes (advances the slice's own reader index only — CODEC-037)
        slice.skipBytes(1);   // consume the NULL terminator
        return out;
    }

    /**
     * Reads one C-octet-string as a lossless {@link AsciiString} (every field, including the password).
     */
    static AsciiString readAscii(ByteBuf slice, String fieldName) {
        return new AsciiString(readNullTerminated(slice, fieldName)); // AsciiString's own defensive copy
    }

    /**
     * Reads one mandatory octet (unsigned, 0–255); a missing byte means a truncated body (CODEC-022) — reject, never AIOOBE.
     */
    static byte readByte(ByteBuf slice, String fieldName) {
        if (slice.readableBytes() < 1) {
            throw new DecoderException("SMPP bind: truncated body (mandatory field " + fieldName + " absent)");
        }
        return slice.readByte();
    }

    /**
     * Writes one SMPP big-endian unsigned-32 header field (command_length / command_id / command_status / sequence_number) — the raw 4-octet bit pattern (a Netty {@link ByteBuf} is big-endian by default).
     */
    static void writeInt(ByteBuf out, int value) {
        out.writeInt(value);
    }

    /** Writes one single-octet field (interface_version / addr_ton / addr_npi). */
    static void writeByte(ByteBuf out, byte value) {
        out.writeByte(value);
    }

    /**
     * Writes the {@link AsciiString}'s raw bytes + NUL — lossless + zero-alloc via the backing array.
     */
    static void writeAscii(ByteBuf out, AsciiString s) {
        ByteBufUtil.copy(s, out); // writes s.length() raw bytes at writerIndex — zero-alloc via the backing array
        out.writeByte(0);
    }
}
