package smpp.companion.codec.bind;

import io.netty.buffer.ByteBuf;
import lombok.experimental.UtilityClass;

/**
 * Encodes the 16-octet SMPP 3.4 command header (§4.1): {@code command_length | command_id | command_status |
 * sequence_number}, each a big-endian unsigned-32. Package-private: the only consumer is {@link SmppBindEncoder}.
 * The fixed field order is grouped here so the header composition has one named home; the byte-level u32
 * primitive it builds on is {@link SmppBytes#writeInt(ByteBuf, int)}.
 */
@UtilityClass
class SmppHeaderEncoder {

    /**
     * Writes the four big-endian header fields in the SMPP 3.4 §4.1 fixed order. {@code commandLength} is the
     * total PDU length (computed exactly by the caller — no length-field drift).
     */
    static void writeHeader(ByteBuf out, int commandLength, int commandId, int commandStatus, int sequenceNumber) {
        SmppBytes.writeInt(out, commandLength);
        SmppBytes.writeInt(out, commandId);
        SmppBytes.writeInt(out, commandStatus);
        SmppBytes.writeInt(out, sequenceNumber);
    }
}
