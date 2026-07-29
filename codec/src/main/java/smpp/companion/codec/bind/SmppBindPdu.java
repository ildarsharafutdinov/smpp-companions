package smpp.companion.codec.bind;

import io.netty.buffer.ByteBuf;

/**
 * A parsed SMPP 3.4 bind-family PDU (AC2; AD-3, AD-12, AD-25). Sealed to the two bind shapes: a
 * {@link SmppBindRequest} (the client's bind — carries the credential fields the verifier adjudicates)
 * and a {@link SmppBindResponse} (the SMSC's {@code bind_*_resp} — carries the {@link SmppBindResponse#isOk()}
 * predicate the relay flips the splice on, AD-25). Every other PDU is opaque and never becomes a
 * {@link SmppBindPdu} — opacity is structural (the decoder parses {@code BIND_FAMILY} only).
 *
 * <p>All three header fields are exposed because the relay reads {@code command_id}/{@code sequence_number}
 * for case selection and {@code command_status} for the ROK flip (AD-25/AD-32). {@link #originalFrame()}
 * is the retained, byte-exact ORIGINAL framed buffer — the AD-2 forward unit: the relay forwards it to
 * the SMSC verbatim (AD-12 — the token is discarded, the original bind is relayed). The consumer owns
 * its reference-count lifecycle (release after forwarding).
 *
 * <p>This is a pure data type (AD-23 — no reflection): a sealed interface of records, dispatched by
 * static type, never by runtime annotation/MethodHandle.
 *
 * @see smpp.companion.codec.command.SmppCommandIds#BIND_FAMILY
 */
public sealed interface SmppBindPdu permits SmppBindRequest, SmppBindResponse {

    /** SMPP 3.4 §5.1.2.3 / the command_status table: success (the AD-25 flip value). */
    int ESME_ROK = 0x00000000;

    /** The PDU's {@code command_id} (bit 31 set on a response). Always a {@code BIND_FAMILY} member here. */
    int commandId();

    /** The PDU's {@code command_status} (zero on a request; the ROK/denial verdict on a response). */
    int commandStatus();

    /** The PDU's {@code sequence_number} (the relay's request/response correlation key, AD-32). */
    int sequenceNumber();

    /** The retained, byte-exact ORIGINAL framed buffer — the AD-2 forward unit. Consumer-owned lifecycle. */
    ByteBuf originalFrame();
}
