package smpp.companion.codec.golden;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import io.netty.util.AsciiString;
import org.jsmpp.bean.Bind;
import org.jsmpp.bean.BindResp;
import org.jsmpp.util.DefaultDecomposer;
import org.jsmpp.util.PDUDecomposer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import smpp.companion.codec.bind.SmppBindEncoder;
import smpp.companion.codec.bind.SmppBindPdu;
import smpp.companion.codec.bind.SmppBindRequest;
import smpp.companion.codec.bind.SmppBindResponse;
import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.framer.SmppFrameDecoder;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Bind-family conformance for the CODEC-030 golden corpus — AC6 / CODEC-031, CODEC-032, CODEC-033. These
 * tests prove the codec agrees with TWO independent oracles on the SAME hand-authored bytes:
 * <ul>
 *   <li><b>CODEC-031 (P1, R14/R33):</b> for each golden POSITIVE, the codec's decode equals jSMPP 3.0.2's
 *       decode field-by-field. jSMPP is the 2nd independent oracle (the corpus is the 1st); two stacks
 *       agreeing on the same bytes is strong spec-conformance evidence. Closes the deferred "no per-vector
 *       command_id pin" item (jSMPP keys on command_id and pins every field per vector).
 *   <li><b>CODEC-032 (P1, R14):</b> for each golden REQUEST, codec-decode then {@link SmppBindEncoder} encode
 *       reproduces the golden bytes byte-for-byte (no length/field drift) — the encoder is the decoder's
 *       exact inverse, at corpus scale.
 *   <li><b>CODEC-033 (P1, R3/R33):</b> each golden NEGATIVE rejects (or, for an incomplete header, is
 *       awaited) through the REAL framer→parser pipeline, at the STAGE its tag asserts (framer-reject vs framer-await vs parser-reject) — closing the T4
 *       finding that the negative tag was never tied to the bytes (user decision 2026-07-29 → defer to T5).
 * </ul>
 *
 * <p>Lives in the {@code golden} package (not {@code bind}) to reach the package-private {@link GoldenVectors}
 * loader; the codec types it exercises are all public. The harness runs each vector through a real
 * {@code SmppFrameDecoder → SmppCodec} pipeline (the decode path a relay channel runs) with an
 * {@link ExceptionCapture} tail that swallows rejects — so a reject is observable as {@code capture.cause}
 * without {@code writeInbound} re-throwing (the contained form CODEC-013 set).
 *
 * <p>jSMPP is the POSITIVE field-agreement oracle only. It is NOT asserted on negatives: jSMPP assumes
 * well-formed input from a trusted SMSC (no bounds-checked NUL scan), so its behavior on adversarial bytes
 * is implementation-defined, not a spec oracle. The deterministic negative oracle is the spec-derived
 * expected outcome asserted against OUR decoder (CODEC-033).
 *
 * <p>Note on the password (CODEC-024): jSMPP yields a {@code String}; comparing it to the codec's
 * {@code AsciiString} password via {@code new AsciiString(jsmppPassword)} avoids {@code toString()} on the
 * password (the fragile seam documented on {@code SmppBindRequest}).
 */
@Tag("conformance")
@Tag("codec")
@Tag("p1")
@DisplayName("Bind-family conformance — CODEC-031 (jSMPP cross-oracle) / 032 (encode byte-identity) / 033 (negative biting oracle)")
class BindConformanceTest {

    /** jSMPP 3.0.2 — the 2nd independent decode oracle (R33/R14). Single-threaded tests; one shared instance. */
    private static final PDUDecomposer JSMPP = new DefaultDecomposer();

    private final Deque<ByteBuf> toRelease = new ArrayDeque<>();
    private EmbeddedChannel channel;
    private ExceptionCapture capture;

    /** Records (and swallows) any exception a decoder fires, so writeInbound does not re-throw. */
    private static final class ExceptionCapture extends ChannelInboundHandlerAdapter {
        private Throwable cause;

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            this.cause = cause; // swallow — the test asserts on it directly
        }
    }

    /** A fresh framer → bind-parser → exception-capture pipeline. */
    private void freshPipeline() {
        capture = new ExceptionCapture();
        channel = new EmbeddedChannel(new SmppFrameDecoder(), new SmppCodec(), capture);
    }

    @AfterEach
    void release() {
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

    // ---------- parametrized sources ----------

    static Stream<GoldenVectors.Vector> positiveVectors() {
        return GoldenVectors.load().stream().filter(v -> !v.negative());
    }

    static Stream<GoldenVectors.Vector> positiveRequestVectors() {
        return GoldenVectors.load().stream().filter(v -> !v.negative() && !v.isResponse());
    }

    static Stream<GoldenVectors.Vector> negativeVectors() {
        return GoldenVectors.load().stream().filter(GoldenVectors.Vector::negative);
    }

    // ---------- CODEC-031: codec decode == jSMPP decode, field-by-field ----------

    @ParameterizedTest(name = "[{0}] CODEC-031: codec decode == jSMPP decode (field-by-field)")
    @MethodSource("positiveVectors")
    void codecDecodeAgreesWithJsmpp(GoldenVectors.Vector v) throws Exception {
        SmppBindPdu pdu = decodeOne(v.bytes());
        assertThat(pdu)
                .as("%s: the codec must decode a golden positive into a typed bind PDU", v.name())
                .isNotNull();
        try {
            if (pdu instanceof SmppBindRequest req) {
                Bind oracle = JSMPP.bind(v.bytes()); // full PDU bytes (incl. the 16-octet header)
                assertThat(req.commandId()).as("%s: command_id", v.name()).isEqualTo(oracle.getCommandId());
                assertThat(req.commandStatus()).as("%s: command_status", v.name()).isEqualTo(oracle.getCommandStatus());
                assertThat(req.sequenceNumber()).as("%s: sequence_number", v.name()).isEqualTo(oracle.getSequenceNumber());
                assertThat((CharSequence) req.systemId()).as("%s: system_id", v.name())
                        .isEqualTo(jsmppCString2Ascii(oracle.getSystemId()));
                assertThat((CharSequence) req.password()).as("%s: password", v.name())
                        .isEqualTo(jsmppCString2Ascii(oracle.getPassword())); // no toString() on the password (CODEC-024)
                assertThat((CharSequence) req.systemType()).as("%s: system_type", v.name())
                        .isEqualTo(jsmppCString2Ascii(oracle.getSystemType()));
                assertThat(req.interfaceVersion()).as("%s: interface_version", v.name())
                        .isEqualTo(oracle.getInterfaceVersion());
                assertThat(req.addrTon()).as("%s: addr_ton", v.name()).isEqualTo(oracle.getAddrTon());
                assertThat(req.addrNpi()).as("%s: addr_npi", v.name()).isEqualTo(oracle.getAddrNpi());
                assertThat((CharSequence) req.addressRange()).as("%s: address_range", v.name())
                        .isEqualTo(jsmppCString2Ascii(oracle.getAddressRange()));
            } else {
                SmppBindResponse resp = (SmppBindResponse) pdu;
                BindResp oracle = JSMPP.bindResp(v.bytes());
                assertThat(resp.commandId()).as("%s: command_id", v.name()).isEqualTo(oracle.getCommandId());
                assertThat(resp.commandStatus()).as("%s: command_status", v.name()).isEqualTo(oracle.getCommandStatus());
                assertThat(resp.sequenceNumber()).as("%s: sequence_number", v.name()).isEqualTo(oracle.getSequenceNumber());
                assertThat((CharSequence) resp.systemId()).as("%s: system_id", v.name())
                        .isEqualTo(jsmppCString2Ascii(oracle.getSystemId()));
                // The TLV tail (e.g. sc_interface_version) is intentionally opaque in the codec (AD-3) — not
                // compared here; byte-exact forwarding of the whole frame is CODEC-037's concern.
            }
        } finally {
            pdu.originalFrame().release();
        }
    }

    // ---------- CODEC-032: codec encode reproduces the golden wire bytes exactly (request round-trip) ----------

    @ParameterizedTest(name = "[{0}] CODEC-032: codec encode reproduces the golden wire bytes exactly")
    @MethodSource("positiveRequestVectors")
    void encodeReproducesGoldenBytesExactly(GoldenVectors.Vector v) {
        SmppBindPdu pdu = decodeOne(v.bytes());
        try {
            assertThat(pdu).as("%s: expected a bind request", v.name()).isInstanceOf(SmppBindRequest.class);
            SmppBindRequest req = (SmppBindRequest) pdu;
            ByteBuf encoded = SmppBindEncoder.encode(req, UnpooledByteBufAllocator.DEFAULT);
            toRelease.add(encoded);
            assertThat(ByteBufUtil.getBytes(encoded))
                    .as("%s: decode(·)→encode(·) must be byte-identical to the golden vector "
                            + "(no command_length drift, no field reordering, correct NUL terminators)", v.name())
                    .isEqualTo(v.bytes());
        } finally {
            if (pdu != null) {
                pdu.originalFrame().release(); // release on EVERY exit path; null-guard — a positive that rejected
                // (decodeOne returns null) must not mask the real failure with an NPE here
            }
        }
    }

    // ---------- CODEC-033: every golden negative rejects/handles as tagged (the biting oracle) ----------

    @ParameterizedTest(name = "[{0}] CODEC-033: negative vector rejects as tagged")
    @MethodSource("negativeVectors")
    void negativeVectorRejectsAsTagged(GoldenVectors.Vector v) {
        freshPipeline();
        channel.writeInbound(inbound(v.bytes()));
        Object out = channel.readInbound();
        if (out instanceof SmppBindPdu p) { // defensive — a negative must never surface a typed PDU
            p.originalFrame().release();
        }
        assertThat(out)
                .as("%s: a negative vector must NOT decode into a typed bind PDU (the T4 concern)", v.name())
                .isNull();

        switch (v.rejectCode()) {
            case "CODEC-005", "CODEC-008" -> { // AD-30 floor / ceiling — rejected at the FRAMER before any frame
                assertThat(capture.cause).as("%s: framer must reject", v.name()).isNotNull();
                assertThat(capture.cause)
                        .as("%s: framer reject is a DecoderException (TooLongFrameException is one)", v.name())
                        .isInstanceOf(DecoderException.class);
                assertThat(channel.isActive())
                        .as("%s: a reject must fail-closed the channel (R3)", v.name()).isFalse();
            }
            case "CODEC-009" -> { // incomplete header — the framer WAITS; no reject, no partial frame (clean)
                assertThat(capture.cause)
                        .as("%s: an incomplete header is awaited (REL-1), not rejected", v.name())
                        .isNull();
                assertThat(channel.isActive())
                        .as("%s: an awaited header must NOT close the channel", v.name()).isTrue();
            }
            case "CODEC-021", "CODEC-022" -> { // length-self-consistent — framer emits a frame, PARSER rejects. NOTE: 021-vs-022 is NOT distinguished at the assertion level (both => DecoderException); 021 trips the unterminated-C-octet path, 022 trips the readByte truncated-fixed-field path — see the class javadoc.
                assertThat(capture.cause).as("%s: parser must reject", v.name()).isNotNull();
                assertThat(capture.cause)
                        .as("%s: parser reject is a DecoderException", v.name())
                        .isInstanceOf(DecoderException.class);
                assertThat(channel.isActive())
                        .as("%s: a reject must fail-closed the channel (R3)", v.name()).isFalse();
            }
            default -> throw new AssertionError(
                    "negative vector " + v.name() + " carries an unmapped reject code: " + v.rejectCode()
                            + " — map it in negativeVectorRejectsAsTagged");
        }
    }

    // ---------- harness ----------

    /**
     * Normalizes a cross-oracle representation difference surfaced by CODEC-031: jSMPP's {@code readCString}
     * returns {@code null} for an empty C-octet string (a single NUL — SMPP §3.1), whereas the codec decodes
     * the same bytes as an empty {@code AsciiString}. Both agree the field is empty; this maps the oracle's
     * null to "" so the field-by-field compare stays exact (and it never calls {@code toString()} on a
     * password — the value is rebuilt as an {@link AsciiString} for a byte-level compare, CODEC-024).
     */
    private static AsciiString jsmppCString2Ascii(String jsmppValue) {
        return jsmppValue == null ? AsciiString.EMPTY_STRING : new AsciiString(jsmppValue);
    }


    /** Decodes one golden positive through the real framer→parser pipeline; the caller owns originalFrame(). */
    private SmppBindPdu decodeOne(byte[] bytes) {
        freshPipeline();
        channel.writeInbound(inbound(bytes));
        return (SmppBindPdu) channel.readInbound();
    }

    private ByteBuf inbound(byte[] pdu) {
        ByteBuf buf = Unpooled.wrappedBuffer(pdu);
        toRelease.add(buf); // backstop release; normal-path buffers are released via readInbound/originalFrame
        return buf;
    }
}
