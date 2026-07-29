package smpp.companion.codec.bind;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.MessageToMessageDecoder;
import io.netty.util.AsciiString;
import java.util.List;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrame;

/**
 * SMPP 3.4 bind-family parser (AC2; AD-3, AD-7, AD-12, AD-25, AD-27). Sits one hop downstream of
 * {@link smpp.companion.codec.framer.SmppFrameDecoder} and consumes its framed {@link ByteBuf} output
 * (one whole PDU). It owns the codec's single parsed-vs-opaque boundary: a {@code command_id} in
 * {@link SmppCommandIds#BIND_FAMILY} is parsed into a typed {@link SmppBindPdu}; every other PDU is
 * forwarded untouched as the opaque framed {@code ByteBuf} (AD-3/AD-32 — no TLV parser, no non-bind body
 * parsing).
 *
 * <p><b>Non-mutating, byte-exact (CODEC-037 / AD-12):</b> the whole PDU is read through a single
 * <em>unretained</em> {@code slice} (the header via {@code readInt}, the body via {@link SmppBytes}); the
 * slice carries its own reader index, so the input buffer's content AND reader index are never touched (the
 * parser must not corrupt the AD-2 forward unit — the ORIGINAL bind is relayed to the SMSC). The retained
 * original is attached to the emitted {@link SmppBindPdu} ONLY after the whole body parses, so a
 * malformed-body throw (CODEC-021/022) retains nothing and leaks nothing.
 *
 * <p><b>Fail-closed (R3 / SEC-2):</b> a structurally malformed bind body — an unterminated C-octet-string
 * (CODEC-021) or a body too short for its mandatory fields (CODEC-022) — is rejected with a
 * {@link DecoderException} via bounds-checked reads (never an {@code ArrayIndexOutOfBounds}, never an
 * unbounded scan). The overridden {@link #exceptionCaught} fires that reject downstream (observability)
 * then closes the channel (drop + close) — a Throwable never escapes {@code decode} unchecked.
 *
 * <p>Precondition: the input is a framed PDU delivered by the framer (so {@code readableBytes ≥ 16} and the
 * reader index is 0); the framer enforces both.
 */
public final class SmppCodec extends MessageToMessageDecoder<ByteBuf> {

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf buf, List<Object> out) {
        // Read the whole PDU through one unretained slice — it carries its OWN reader index, so `buf`'s content
        // AND reader index are never touched (CODEC-037 / AD-12: the ORIGINAL bind must be relayed byte-exact).
        ByteBuf pdu = buf.slice();
        pdu.skipBytes(4); // command_length field — the framer already enforced AD-30 on it; advance to command_id
        int commandId = pdu.readInt();

        if (!SmppCommandIds.isBindFamily(commandId)) {
            // AD-2/AD-32: non-bind is opaque — forward the exact framed buffer, zero-copy + untouched.
            // retain() compensates for MessageToMessageDecoder's auto-release of the input after decode.
            out.add(buf.retain());
            return;
        }

        int base = buf.readerIndex();
        int commandStatus = pdu.readInt();
        int sequenceNumber = pdu.readInt();
        // `pdu`'s reader index is now at the body (offset 16); the reads below advance `pdu`'s own index only.
        // If the body parse throws, nothing has been retained (no leak on the reject path — CODEC-015).
        out.add(SmppCommandIds.isResponse(commandId)
                ? decodeResponse(commandId, commandStatus, sequenceNumber, pdu, buf, base)
                : decodeRequest(commandId, commandStatus, sequenceNumber, pdu, buf, base));
    }

    private static SmppBindRequest decodeRequest(int commandId, int commandStatus, int sequenceNumber,
                                                 ByteBuf body, ByteBuf frame, int base) {
        AsciiString systemId = SmppBytes.readAscii(body, "system_id");
        AsciiString password = SmppBytes.readAscii(body, "password"); // CODEC-024/PRIV-1 — zeroize via array() (see SmppBindRequest)
        AsciiString systemType = SmppBytes.readAscii(body, "system_type");
        byte interfaceVersion = SmppBytes.readByte(body, "interface_version");
        byte addrTon = SmppBytes.readByte(body, "addr_ton");
        byte addrNpi = SmppBytes.readByte(body, "addr_npi");
        AsciiString addressRange = SmppBytes.readAscii(body, "address_range");
        // Retain the ORIGINAL only once the whole body has parsed — success path only (no leak on throw).
        ByteBuf originalFrame = frame.retainedSlice(base, frame.readableBytes());
        return new SmppBindRequest(commandId, commandStatus, sequenceNumber, systemId, password, systemType,
                interfaceVersion, addrTon, addrNpi, addressRange, originalFrame);
    }

    private static SmppBindResponse decodeResponse(int commandId, int commandStatus, int sequenceNumber,
                                                   ByteBuf body, ByteBuf frame, int base) {
        AsciiString systemId = SmppBytes.readAscii(body, "system_id"); // SMSC system_id; TLV tail stays in originalFrame (AD-3)
        ByteBuf originalFrame = frame.retainedSlice(base, frame.readableBytes());
        return new SmppBindResponse(commandId, commandStatus, sequenceNumber, systemId, originalFrame);
    }

    /**
     * Fail-closed containment (R3): a {@code decode} reject is fired downstream FIRST (so the relay/tests
     * observe it), then the channel is closed — drop + close. A Throwable never escapes {@code decode}
     * unchecked. Mirrors {@link smpp.companion.codec.framer.SmppFrameDecoder#exceptionCaught}; this fires
     * solely for this decoder's own {@code decode} throws (propagation is forward-only/inbound).
     */
    @Override
    @SuppressWarnings("FutureReturnValueIgnored") // reason: ctx.close() returns Netty's ChannelFuture; the
            // close is best-effort fail-closed — a failed close merely means the channel was already closed
            // (the desired end state). The codec has no logging surface to report close completion (AD-27).
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ctx.fireExceptionCaught(cause); // surface the reject to the relay/tests (observability)
        ctx.close();                    // fail-closed drop + close (R3)
    }
}
