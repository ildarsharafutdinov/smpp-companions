package smpp.companion.codec.bind;

import io.netty.buffer.ByteBuf;
import io.netty.util.AsciiString;

/**
 * A parsed SMPP 3.4 bind-REQUEST ({@code bind_receiver}/{@code bind_transmitter}/{@code bind_transceiver},
 * SMPP 3.4 §4.1.1–§4.1.4). Carries the credential fields the {@code BindCredentialVerifier} adjudicates
 * (AD-25), plus the full mandatory body so the encoder ({@link SmppBindEncoder}) can reproduce the exact
 * wire bytes (CODEC-032 round-trip).
 *
 * <p>Every C-octet-string field — including the {@code password} — is a Netty {@link AsciiString}: the raw,
 * lossless ASCII bytes (high-bit octets preserved), a {@link CharSequence} for direct verifier matching,
 * and not an array (no record-array identity wart). {@code interface_version}/{@code addr_ton}/
 * {@code addr_npi} single-octet fields are carried as {@code byte} — the natural 1-octet wire type (valid
 * SMPP values fit a signed byte; read unsigned, then narrowed at the decode site).
 * {@code command_status} is carried for header completeness but is always zero on a request.
 *
 * <p><b>Password zeroization (CODEC-024/PRIV-1, revised — user-directed, 2026-07-28):</b> the password is an
 * {@link AsciiString}, NOT a {@code char[]} (overriding AC2's {@code char[]}/{@code byte[]} clause for full
 * type-uniformity). Its backing bytes are reachable for wiping via {@link AsciiString#array()}
 * ({@code Arrays.fill(password().array(), password().arrayOffset(), password().arrayOffset()+password().length(), (byte)0)}),
 * <b>but</b> {@link AsciiString} lazily caches {@link AsciiString#toString()} — so a {@code toString()} call
 * would leave a {@code String} copy that survives a backing-array wipe. The seam is therefore fragile:
 * callers must avoid {@code toString()} on the password. See the Dev Agent Record (Story 1.2).
 *
 * <p>{@link #originalFrame()} lifecycle is consumer-owned (release after the relay forwards it).
 *
 * @param commandId        a bind-request {@code command_id} (a {@code BIND_FAMILY} request member).
 * @param commandStatus    always {@code 0} on a request; carried for header symmetry.
 * @param sequenceNumber   the request's {@code sequence_number}.
 * @param systemId         the C-octet {@code system_id} (≤16 octets incl. terminator).
 * @param password         the C-octet {@code password} as an {@link AsciiString} (≤9 octets); zeroize via the
 *                         backing {@link AsciiString#array()} — see the class zeroization note (do NOT call
 *                         {@code toString()} on it).
 * @param systemType       the C-octet {@code system_type} (≤13 octets incl. terminator).
 * @param interfaceVersion the 1-octet {@code interface_version} ({@link smpp.companion.codec.command.SmppCommandIds#INTERFACE_VERSION_3_4}
 *                         = SMPP 3.4).
 * @param addrTon          the 1-octet {@code addr_ton}.
 * @param addrNpi          the 1-octet {@code addr_npi}.
 * @param addressRange     the C-octet {@code address_range} (≤41 octets incl. terminator).
 * @param originalFrame    the retained, byte-exact ORIGINAL framed buffer (AD-2 forward unit).
 */
public record SmppBindRequest(
        int commandId,
        int commandStatus,
        int sequenceNumber,
        AsciiString systemId,
        AsciiString password,
        AsciiString systemType,
        byte interfaceVersion,
        byte addrTon,
        byte addrNpi,
        AsciiString addressRange,
        ByteBuf originalFrame) implements SmppBindPdu {
}
