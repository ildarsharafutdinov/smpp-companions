package smpp.companion.codec.bind;

import io.netty.buffer.ByteBuf;
import io.netty.util.AsciiString;

/**
 * A parsed SMPP 3.4 bind-RESPONSE ({@code bind_receiver_resp}/{@code bind_transmitter_resp}/
 * {@code bind_transceiver_resp}). The response body is the C-octet {@code system_id} (the SMSC's identity)
 * followed by optional TLVs (e.g. {@code sc_interface_version}); only {@code system_id} is parsed — the TLV
 * tail stays in {@link #originalFrame()} and is forwarded opaquely (AD-3: no TLV parser).
 *
 * <p>{@link #isOk()} is the exact AD-25 signal: the relay flips the splice ONLY on a decoded
 * {@code bind_*_resp} whose {@code command_status == ESME_ROK}. The predicate lives here (not on the
 * shared interface) so a {@link SmppBindRequest} can never be "OK" — a request carries status zero,
 * which equals {@code ESME_ROK}, so placing it on the common type would be a footgun. A non-ROK
 * response (e.g. {@code ESME_RINVPASWD 0x0000000E}) decodes cleanly and reports {@code isOk() == false}
 * (CODEC-019) — no accidental splice of an unauthenticated session.
 *
 * @param commandId      a bind-response {@code command_id} (a {@code BIND_FAMILY} response member).
 * @param commandStatus  the SMSC's verdict ({@link SmppBindPdu#ESME_ROK} on success, a denial code otherwise).
 * @param sequenceNumber the response's {@code sequence_number} (correlates the originating request).
 * @param systemId       the C-octet {@code system_id} the SMSC identified itself with (≤16 octets).
 * @param originalFrame  the retained, byte-exact ORIGINAL framed buffer (AD-2 forward unit).
 */
public record SmppBindResponse(
        int commandId,
        int commandStatus,
        int sequenceNumber,
        AsciiString systemId,
        ByteBuf originalFrame) implements SmppBindPdu {

    /**
     * {@code true} iff this response's {@code command_status} is {@link SmppBindPdu#ESME_ROK} — the AD-25
     * splice-flip trigger. The relay flips ONLY on this decoded predicate (never a peeked command_id, never
     * an undecoded frame).
     */
    public boolean isOk() {
        return commandStatus == SmppBindPdu.ESME_ROK;
    }
}
