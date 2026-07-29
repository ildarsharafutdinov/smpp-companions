package smpp.companion.codec.bind;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import smpp.companion.codec.command.SmppCommandIds;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link SmppBindEncoder} — the encode→bytes half of bind-family conformance. The full golden-corpus
 * round-trip (CODEC-032) lands in T5 with the jSMPP oracle; this T3 test proves the encoder is the
 * exact inverse of the wire format by (a) encoding a typed request to byte-identical hand-authored
 * bytes and (b) a decode(encode(·)) symmetry loop. Encoding is offline only — AD-32 forbids the codec
 * from synthesising/reserialising PDUs on the relay hot path; this encoder exists for conformance.
 */
@Tag("unit")
@Tag("codec")
@Tag("p1")
@DisplayName("SmppBindEncoder — bind-family encode round-trip (T3 encoder validation)")
class SmppBindEncoderTest {

    @Test
    @DisplayName("encode a typed bind_transceiver request -> byte-identical hand-authored wire bytes")
    void encodeProducesExactWireBytes() {
        SmppBindRequest req = new SmppBindRequest(
                SmppCommandIds.BIND_TRANSCEIVER, 0x00000000, 42,
                new AsciiString("ESME_001"), new AsciiString("secret"), new AsciiString("SMPP"),
                SmppCommandIds.INTERFACE_VERSION_3_4, (byte) 0, (byte) 0, new AsciiString(""), Unpooled.EMPTY_BUFFER);

        ByteBuf out = SmppBindEncoder.encode(req, UnpooledByteBufAllocator.DEFAULT);
        try {
            assertThat(ByteBufUtil.getBytes(out)).isEqualTo(bindRequestBytes(
                    SmppCommandIds.BIND_TRANSCEIVER, 42, "ESME_001", "secret", "SMPP", 0x34, 0, 0, ""));
        } finally {
            out.release();
        }
    }

    @Test
    @DisplayName("decode(encode(req)) round-trips every field (encoder is the decoder's inverse)")
    void decodeEncodeRoundTrips() {
        SmppBindRequest original = new SmppBindRequest(
                SmppCommandIds.BIND_TRANSMITTER, 0x00000000, 123,
                new AsciiString("SID"), new AsciiString("pw"), new AsciiString("TYPE"),
                SmppCommandIds.INTERFACE_VERSION_3_4, (byte) 5, (byte) 9, new AsciiString("555"), Unpooled.EMPTY_BUFFER);

        ByteBuf encoded = SmppBindEncoder.encode(original, UnpooledByteBufAllocator.DEFAULT);
        EmbeddedChannel channel = new EmbeddedChannel(new SmppCodec());
        SmppBindRequest roundTripped;
        try {
            channel.writeInbound(encoded);
            roundTripped = channel.readInbound();
        } finally {
            channel.finishAndReleaseAll();
        }
        try {
            // originalFrame is the transient AD-2 forward unit (a retained view of the encoded bytes), not PDU
            // identity — assert every field equals the original EXCEPT it.
            assertThat(roundTripped)
                    .usingRecursiveComparison()
                    .ignoringFields("originalFrame")
                    .isEqualTo(original);
        } finally {
            roundTripped.originalFrame().release();
        }
    }

    // --- hand-authored wire bytes (raw ByteBuffer — independent of the codec under test) ---

    private static byte[] bindRequestBytes(int commandId, int sequence, String systemId, String password,
                                           String systemType, int interfaceVersion, int addrTon, int addrNpi,
                                           String addressRange) {
        byte[] id = ascii(systemId);
        byte[] pw = ascii(password);
        byte[] type = ascii(systemType);
        byte[] range = ascii(addressRange);
        int body = (id.length + 1) + (pw.length + 1) + (type.length + 1) + 3 + (range.length + 1);
        ByteBuffer out = ByteBuffer.allocate(16 + body);
        out.putInt(16 + body).putInt(commandId).putInt(0x00000000).putInt(sequence);
        out.put(id).put((byte) 0);
        out.put(pw).put((byte) 0);
        out.put(type).put((byte) 0);
        out.put((byte) interfaceVersion).put((byte) addrTon).put((byte) addrNpi);
        out.put(range).put((byte) 0);
        return out.array();
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }
}
