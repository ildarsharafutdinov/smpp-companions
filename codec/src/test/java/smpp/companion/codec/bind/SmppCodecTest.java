package smpp.companion.codec.bind;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import io.netty.util.AsciiString;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import smpp.companion.codec.command.SmppCommandIds;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * CODEC-016..023 + 028 + 037 (the EmbeddedChannel half): {@link SmppCodec} bind-family parsing. Every
 * bind PDU fed here is hand-authored from the SMPP 3.4 spec wire-format (raw {@link ByteBuffer}) —
 * NEVER produced by invoking the codec under test — so these are R14/R33 spec-conformance anchors, not
 * codec-synthesised tautologies. The structural fuzz (CODEC-025) and the jqwik byte-exact property
 * (CODEC-037 corpus expansion) are Level {@code fuzz}, mapped to AC7, and land in T6.
 *
 * <p>Conventions: every harness installs a tail {@link ExceptionCapture} that records (and swallows)
 * any exception the decoder fires, so a malformed-body reject is observable as {@code capture.cause}
 * without {@code writeInbound} re-throwing — the contained, exceptionCaught-routed form CODEC-013 set
 * for the framer and CODEC-021/022 require for the parser (R3: no Throwable escapes decode). Every
 * retained buffer read off the channel is released in the test; {@link #drainAndRelease()} is the
 * {@code @AfterEach} backstop.
 */
@Tag("unit")
@Tag("codec")
@Tag("p1")
@DisplayName("SmppCodec — SMPP 3.4 bind-family parser (CODEC-016..023, 028, 037)")
class SmppCodecTest {

    /** SMPP 3.4 §4.1 header size (octets): command_length | command_id | command_status | sequence_number. */
    private static final int HEADER = 16;
    private static final int ESME_RINVPASWD = 0x0000000E;

    private final Deque<ByteBuf> toRelease = new ArrayDeque<>();
    private EmbeddedChannel channel;
    private ExceptionCapture capture;

    // ---------- harness ----------

    /** Records the decoder's reject exception WITHOUT propagating (so writeInbound does not re-throw). */
    private static final class ExceptionCapture extends ChannelInboundHandlerAdapter {
        private Throwable cause;

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            this.cause = cause; // swallow — the test asserts on it directly
        }
    }

    /** Fresh pipeline: the bind decoder + the exception-capture tail. */
    private void freshChannel() {
        capture = new ExceptionCapture();
        channel = new EmbeddedChannel(new SmppCodec(), capture);
    }

    @AfterEach
    void drainAndRelease() {
        if (channel != null) {
            channel.finishAndReleaseAll();
        }
        toRelease.forEach(b -> {
            if (b.refCnt() > 0) {
                b.release();
            }
        });
        toRelease.clear();
    }

    // ---------- hand-authored PDU builders (raw ByteBuffer — independent of the codec) ----------

    /** A complete bind-REQUEST PDU with NUL-terminated C-octet fields (SMPP 3.4 §4.1.1–§4.1.4). */
    private static byte[] bindRequest(int commandId, int sequence, String systemId, String password,
                                      String systemType, int interfaceVersion, int addrTon, int addrNpi,
                                      String addressRange) {
        byte[] id = ascii(systemId);
        byte[] pw = ascii(password);
        byte[] type = ascii(systemType);
        byte[] range = ascii(addressRange);
        int body = (id.length + 1) + (pw.length + 1) + (type.length + 1) + 3 + (range.length + 1);
        return assemble(commandId, 0, sequence, body, out -> {
            terminate(out, id);
            terminate(out, pw);
            terminate(out, type);
            out.put((byte) interfaceVersion).put((byte) addrTon).put((byte) addrNpi);
            terminate(out, range);
        });
    }

    /** A complete bind-RESPONSE PDU: system_id + an optional opaque TLV tail (unparsed — AD-3). */
    private static byte[] bindResponse(int commandId, int sequence, int commandStatus, String systemId,
                                       byte[] tlvTail) {
        byte[] id = ascii(systemId);
        int body = (id.length + 1) + tlvTail.length;
        return assemble(commandId, commandStatus, sequence, body, out -> {
            terminate(out, id);
            out.put(tlvTail);
        });
    }

    /** A complete non-bind PDU (opaque): header + arbitrary body — exercises the pass-through path. */
    private static byte[] opaquePdu(int commandId, int sequence, byte[] body) {
        return assemble(commandId, 0x00000000, sequence, body.length, out -> out.put(body));
    }

    /** A bind-REQUEST header + a raw (possibly malformed) body, for the CODEC-021/022 reject cases. */
    private static byte[] bindWithRawBody(int commandId, int sequence, byte[] body) {
        return assemble(commandId, 0, sequence, body.length, out -> out.put(body));
    }

    private interface BodyWriter {
        void writeTo(ByteBuffer out);
    }

    private static byte[] assemble(int commandId, int commandStatus, int sequence, int bodyLen, BodyWriter writer) {
        ByteBuffer out = ByteBuffer.allocate(HEADER + bodyLen);
        out.putInt(HEADER + bodyLen).putInt(commandId).putInt(commandStatus).putInt(sequence);
        writer.writeTo(out);
        return out.array();
    }

    private static void terminate(ByteBuffer out, byte[] field) {
        out.put(field).put((byte) 0);
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private ByteBuf inbound(byte[] pdu) {
        ByteBuf buf = Unpooled.wrappedBuffer(pdu);
        toRelease.add(buf); // backstop release; normal-path buffers are released via readInbound
        return buf;
    }

    // ---------- CODEC-016: golden bind_transceiver decode, every field ----------

    @Test
    @DisplayName("CODEC-016: decode golden bind_transceiver — exact header + every body field")
    void decodeGoldenBindTransceiverAllFields() {
        freshChannel();
        byte[] pdu = bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 42,
                "ESME_001", "secret", "SMPP", SmppCommandIds.INTERFACE_VERSION_3_4, 0, 0, "");

        assertThat(channel.writeInbound(inbound(pdu))).as("a typed bind PDU was produced").isTrue();

        Object msg = channel.readInbound();
        assertThat(msg).isInstanceOf(SmppBindRequest.class);
        SmppBindRequest req = (SmppBindRequest) msg;
        toRelease.add(req.originalFrame());

        assertThat(req.commandId()).isEqualTo(SmppCommandIds.BIND_TRANSCEIVER);
        assertThat(req.commandStatus()).isEqualTo(0x00000000); // requests carry zero status
        assertThat(req.sequenceNumber()).isEqualTo(42);
        assertThat((CharSequence) req.systemId()).isEqualTo(new AsciiString("ESME_001"));
        assertThat((CharSequence) req.password()).isEqualTo(new AsciiString("secret"));
        assertThat((CharSequence) req.systemType()).isEqualTo(new AsciiString("SMPP"));
        assertThat(req.interfaceVersion()).isEqualTo((byte) SmppCommandIds.INTERFACE_VERSION_3_4);
        assertThat(req.addrTon()).isEqualTo((byte) 0);
        assertThat(req.addrNpi()).isEqualTo((byte) 0);
        assertThat((CharSequence) req.addressRange()).isEqualTo(new AsciiString(""));
    }

    // ---------- CODEC-017: all three bind request types ----------

    @ParameterizedTest
    @ValueSource(ints = {SmppCommandIds.BIND_RECEIVER, SmppCommandIds.BIND_TRANSMITTER, SmppCommandIds.BIND_TRANSCEIVER})
    @DisplayName("CODEC-017: decode golden bind_receiver / bind_transmitter / bind_transceiver — command_id differentiation")
    void decodeEachBindRequestType(int commandId) {
        freshChannel();
        byte[] pdu = bindRequest(commandId, 7, "SID", "pw", "T",
                SmppCommandIds.INTERFACE_VERSION_3_4, 1, 1, "123");

        assertThat(channel.writeInbound(inbound(pdu))).isTrue();
        Object msg = channel.readInbound();
        assertThat(msg).isInstanceOf(SmppBindRequest.class);
        SmppBindRequest req = (SmppBindRequest) msg;
        toRelease.add(req.originalFrame());

        assertThat(req.commandId()).isEqualTo(commandId);
        assertThat((CharSequence) req.systemId()).isEqualTo(new AsciiString("SID"));
    }

    // ---------- CODEC-018: ROK predicate true on a golden bind_*_resp ----------

    @Test
    @DisplayName("CODEC-018: golden bind_transceiver_resp command_status==ESME_ROK -> isOk() true (AD-25 flip trigger)")
    void bindRespRokPredicateTrue() {
        freshChannel();
        byte[] pdu = bindResponse(SmppCommandIds.BIND_TRANSCEIVER_RESP, 42,
                SmppBindPdu.ESME_ROK, "SMSC_01", new byte[0]);

        assertThat(channel.writeInbound(inbound(pdu))).isTrue();
        Object msg = channel.readInbound();
        assertThat(msg).isInstanceOf(SmppBindResponse.class);
        SmppBindResponse resp = (SmppBindResponse) msg;
        toRelease.add(resp.originalFrame());

        assertThat(resp.commandStatus()).isEqualTo(SmppBindPdu.ESME_ROK);
        assertThat((CharSequence) resp.systemId()).isEqualTo(new AsciiString("SMSC_01"));
        assertThat(resp.isOk()).as("AD-25: the decoded ROK is the splice-flip trigger").isTrue();
    }

    // ---------- CODEC-019: non-ROK bind_*_resp decodes cleanly, predicate false ----------

    @Test
    @DisplayName("CODEC-019: non-ROK bind_*_resp (ESME_RINVPASWD) decodes without raising; isOk() false")
    void bindRespNonRokPredicateFalse() {
        freshChannel();
        byte[] pdu = bindResponse(SmppCommandIds.BIND_RECEIVER_RESP, 9,
                ESME_RINVPASWD, "SMSC_01", new byte[0]);

        assertThat(channel.writeInbound(inbound(pdu))).isTrue();
        Object msg = channel.readInbound();
        assertThat(msg).isInstanceOf(SmppBindResponse.class);
        SmppBindResponse resp = (SmppBindResponse) msg;
        toRelease.add(resp.originalFrame());

        assertThat(resp.commandStatus()).isEqualTo(ESME_RINVPASWD);
        assertThat(resp.isOk()).as("a false-positive ROK would splice an unauthenticated session").isFalse();
    }

    // ---------- CODEC-020: C-octet-string edge cases ----------

    @Test
    @DisplayName("CODEC-020: all-fields-empty bind body (each C-octet a single 0x00) decodes to empty values")
    void allFieldsEmptyDecode() {
        freshChannel();
        byte[] pdu = bindRequest(SmppCommandIds.BIND_TRANSMITTER, 1, "", "", "",
                SmppCommandIds.INTERFACE_VERSION_3_4, 0, 0, "");

        assertThat(channel.writeInbound(inbound(pdu))).isTrue();
        SmppBindRequest req = (SmppBindRequest) channel.readInbound();
        toRelease.add(req.originalFrame());

        assertThat((CharSequence) req.systemId()).isEqualTo(new AsciiString(""));
        assertThat((CharSequence) req.password()).isEqualTo(new AsciiString(""));
        assertThat((CharSequence) req.systemType()).isEqualTo(new AsciiString(""));
        assertThat((CharSequence) req.addressRange()).isEqualTo(new AsciiString(""));
    }

    @Test
    @DisplayName("CODEC-020: spec-max-length C-octet fields (16/9/13/41 incl. terminator) decode to exact values")
    void maxLengthFieldsDecode() {
        freshChannel();
        // system_id ≤16, password ≤9, system_type ≤13, address_range ≤41 — octet counts INCLUDE the NUL.
        String maxId = repeat('A', 15);
        String maxPw = repeat('B', 8);
        String maxType = repeat('C', 12);
        String maxRange = repeat('D', 40); // address_range ≤41 octets incl. terminator (40 chars + NUL)
        byte[] pdu = bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 1, maxId, maxPw, maxType,
                SmppCommandIds.INTERFACE_VERSION_3_4, 0, 0, maxRange);

        assertThat(channel.writeInbound(inbound(pdu))).isTrue();
        SmppBindRequest req = (SmppBindRequest) channel.readInbound();
        toRelease.add(req.originalFrame());

        assertThat((CharSequence) req.systemId()).isEqualTo(new AsciiString(maxId));
        assertThat((CharSequence) req.password()).isEqualTo(new AsciiString(maxPw));
        assertThat((CharSequence) req.systemType()).isEqualTo(new AsciiString(maxType));
        assertThat((CharSequence) req.addressRange()).isEqualTo(new AsciiString(maxRange));
    }

    // ---------- CODEC-021: unterminated C-octet-string — bounded reject, no over-read, no spin ----------

    @Test
    @DisplayName("CODEC-021: unterminated C-octet-string -> reject (DecoderException), no over-read, no spin")
    void unterminatedCoctetRejectsBoundedly() {
        freshChannel();
        // A body of all 'A' with no NUL anywhere: the system_id scan runs to the frame end without a terminator.
        // SmppBytes.read scans a finite [readerIndex, writerIndex) range, so it cannot spin (R3 no-spin).
        byte[] pdu = bindWithRawBody(SmppCommandIds.BIND_TRANSCEIVER, 1, ascii(repeat('A', 10)));

        assertThatCode(() -> channel.writeInbound(inbound(pdu)))
                .as("the reject is contained — no Throwable escapes writeInbound")
                .doesNotThrowAnyException();

        assertThat((ByteBuf) channel.readInbound()).as("unterminated -> no typed PDU emitted").isNull();
        assertThat(capture.cause).as("bounded reject, not a raw AIOOBE/over-read").isInstanceOf(DecoderException.class);
    }

    // ---------- CODEC-022: truncated bind body — graceful reject, no AIOOBE / negative-size ----------

    @Test
    @DisplayName("CODEC-022: truncated bind body (declared fields exceed remaining bytes) -> reject, no AIOOBE")
    void truncatedBodyRejectsCleanly() {
        freshChannel();
        // Body = just system_id "id\0" (3 octets); password/system_type/interface_version/… are absent.
        byte[] pdu = bindWithRawBody(SmppCommandIds.BIND_TRANSCEIVER, 1, new byte[] {'i', 'd', 0});

        assertThatCode(() -> channel.writeInbound(inbound(pdu))).doesNotThrowAnyException();
        assertThat((ByteBuf) channel.readInbound()).as("truncated -> no typed PDU emitted").isNull();
        assertThat(capture.cause).as("graceful reject, no ArrayIndexOutOfBounds").isInstanceOf(DecoderException.class);
    }

    // ---------- CODEC-023: header decodes correctly even with a junk body ----------

    @Test
    @DisplayName("CODEC-023: header (command_id/status/sequence) parses even when the body is junk")
    void headerParsesWithJunkBody() {
        freshChannel();
        // A structurally-valid (NUL-terminated) but content-garbage body: the header must still be exact,
        // and the body must parse without crashing — so the relay can route/reject on command_id (AD-32).
        byte[] junkBody = {0x58, 0x58, 0, 0x59, 0, 0x5A, 0, 0x11, 0x22, 0x33, 0x00, 0x00};
        byte[] pdu = bindWithRawBody(SmppCommandIds.BIND_TRANSCEIVER, 99, junkBody);
        // Overwrite command_status (bytes 8..11) to a non-zero sentinel — header parse must surface it exactly.
        pdu[8] = (byte) 0xFF; pdu[9] = (byte) 0xEE; pdu[10] = (byte) 0xDD; pdu[11] = (byte) 0xCC;

        assertThat(channel.writeInbound(inbound(pdu))).isTrue();
        SmppBindRequest req = (SmppBindRequest) channel.readInbound();
        toRelease.add(req.originalFrame());

        assertThat(req.commandId()).isEqualTo(SmppCommandIds.BIND_TRANSCEIVER);
        assertThat(req.commandStatus()).isEqualTo(0xFFEEDDCC);
        assertThat(req.sequenceNumber()).isEqualTo(99);
    }

    // ---------- CODEC-028: non-bind command_ids are opaque pass-through (no typed object) ----------

    @ParameterizedTest
    @ValueSource(ints = {
            0x00000004, // submit_sm
            0x00000005, // deliver_sm
            0x00000015, // enquire_link
            0x00000006, // unbind
            0x0000000B, // outbind (NOT bind-family)
            0x80000000, // generic_nack (NOT bind-family)
    })
    @DisplayName("CODEC-028: non-bind command_ids pass through as an untouched ByteBuf (opaque, AD-3/AD-27)")
    void nonBindOpaquePassthrough(int commandId) {
        freshChannel();
        byte[] body = {0x01, 0x02, 0x03, 0x04, 0x05};
        byte[] pdu = opaquePdu(commandId, 5, body);

        assertThat(channel.writeInbound(inbound(pdu))).isTrue();
        Object msg = channel.readInbound();
        assertThat(msg).as("non-bind -> untouched framed ByteBuf, never a SmppBindPdu").isInstanceOf(ByteBuf.class);
        ByteBuf forwarded = (ByteBuf) msg;
        toRelease.add(forwarded);

        assertThat(ByteBufUtil.getBytes(forwarded)).isEqualTo(pdu);
        assertThat(forwarded.readerIndex()).as("forward unit untouched — reader index never advanced").isZero();
    }

    // ---------- CODEC-037: byte-exact forwarding — original framed ByteBuf un-mutated ----------

    @Test
    @DisplayName("CODEC-037: after parsing a bind request the original framed ByteBuf is byte-identical, reader index restored")
    void originalFrameIsByteExactAndUnmutated() {
        freshChannel();
        byte[] pdu = bindRequest(SmppCommandIds.BIND_TRANSCEIVER, 77,
                "ESME_001", "secret", "SMPP", 0x34, 0, 0, "");
        ByteBuf buf = Unpooled.wrappedBuffer(pdu);
        ByteBuf watch = buf.retainedDuplicate(); // independent reader index + survives the decode-release
        toRelease.add(watch);

        byte[] before = pdu.clone();
        assertThat(watch.readerIndex()).isZero();

        channel.writeInbound(buf);

        // The forward buffer is un-mutated (content) and its reader index is restored (never moved).
        assertThat(ByteBufUtil.getBytes(watch)).isEqualTo(before);
        assertThat(watch.readerIndex()).as("parser reads a slice/absolute gets — reader index never advances").isZero();

        SmppBindRequest req = (SmppBindRequest) channel.readInbound();
        toRelease.add(req.originalFrame());
        // The typed object carries the ORIGINAL bytes byte-exact (AD-2/AD-12 forward unit).
        assertThat(ByteBufUtil.getBytes(req.originalFrame())).isEqualTo(before);
    }

    private static String repeat(char c, int n) {
        char[] arr = new char[n];
        java.util.Arrays.fill(arr, c);
        return new String(arr);
    }
}
