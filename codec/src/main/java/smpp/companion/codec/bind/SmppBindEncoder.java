package smpp.companion.codec.bind;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import lombok.experimental.UtilityClass;
import smpp.companion.codec.framer.SmppFrame;

/**
 * Encodes a typed {@link SmppBindRequest} back to its SMPP 3.4 wire bytes (the encode half of bind-family
 * conformance, AC6 / CODEC-032). <b>Offline only</b> — AD-32 forbids the codec from synthesising or
 * reserialising PDUs on the relay hot path (the relay forwards the ORIGINAL framed buffer, AD-2/AD-12);
 * this encoder exists for conformance (the CODEC-032 round-trip against the golden corpus) and as a
 * utility. It is deliberately NOT a Netty outbound handler.
 *
 * <p>The layout is the SMPP 3.4 §4.1.1–§4.1.4 request body:
 * {@code command_length | command_id | command_status | sequence_number} (16-octet command header —
 * {@link SmppFrame#HEADER_LENGTH}, written via {@link SmppHeaderEncoder#writeHeader}) then
 * {@code system_id | password | system_type | interface_version | addr_ton | addr_npi | address_range},
 * each C-octet-string NUL-terminated. {@code command_length} is computed exactly (no length-field drift),
 * field order is fixed, and every C-octet carries its terminator — so a request decoded then re-encoded is
 * byte-identical to the original (the {@code decode(encode(·))} symmetry + the byte-identity vs the golden
 * vector). C-octet fields are written losslessly + zero-alloc via {@link SmppBytes#writeAscii(ByteBuf, AsciiString)};
 * single-octet fields via {@link SmppBytes#writeByte(ByteBuf, byte)}.
 */
@UtilityClass
public class SmppBindEncoder {

    /**
     * Encodes {@code req} to a freshly-allocated {@link ByteBuf} (caller-owned lifecycle). The allocator
     * chooses heap vs direct; the buffer is sized exactly to {@code command_length}.
     */
    public static ByteBuf encode(SmppBindRequest req, ByteBufAllocator alloc) {
        int body = (req.systemId().length() + 1)
                + (req.password().length() + 1)
                + (req.systemType().length() + 1)
                + 3 // interface_version(1) + addr_ton(1) + addr_npi(1)
                + (req.addressRange().length() + 1);
        int commandLength = SmppFrame.HEADER_LENGTH + body;
        ByteBuf out = alloc.buffer(commandLength);
        SmppHeaderEncoder.writeHeader(out, commandLength, req.commandId(), req.commandStatus(), req.sequenceNumber());
        SmppBytes.writeAscii(out, req.systemId());
        SmppBytes.writeAscii(out, req.password());
        SmppBytes.writeAscii(out, req.systemType());
        SmppBytes.writeByte(out, req.interfaceVersion());
        SmppBytes.writeByte(out, req.addrTon());
        SmppBytes.writeByte(out, req.addrNpi());
        SmppBytes.writeAscii(out, req.addressRange());
        return out;
    }
}
