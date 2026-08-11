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
 * callers must avoid {@code toString()} on the password — now statically enforced by the CODEC-024 P2 / AI-5
 * source scan (forbids {@code .toString()} on the password across {@code codec} + {@code proxy/security} +
 * {@code proxy/relay}), and this record's own {@link #toString()} redacts it. See the Dev Agent Record (Story 1.2).
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

    /**
     * Identified as a {@code bind_*_req} without rendering — or {@code toString()}-caching — the password. The
     * record's auto-generated {@code toString} would render every component, invoking {@link AsciiString#toString()}
     * on the password — rendering the cleartext AND caching an immortal {@code String} that the backing-array
     * zeroization wipe (CODEC-024) cannot reach (a plausible relay debug/error leak path). This override redacts the
     * password ({@code ***}) and omits {@code originalFrame} (its bytes embed the cleartext password — a
     * {@link ByteBuf} summary carries no content, but the secret is kept off this debug/log surface regardless).
     * Mirrors {@code Password.toString()} and {@code BindCredential.toString()}.
     *
     * <p><b>RELAY logging rule (AC9 / AI-5):</b> relay/logging code logs {@code SystemId} ONLY — NEVER the
     * {@code SmppBindRequest}, {@code Password}, or {@code BindCredential} objects, and never the raw
     * {@code password()} {@link AsciiString} (this override redacts, but passing that {@link AsciiString} straight to
     * a logger bypasses it and caches the cleartext). Enforced for future code by the CODEC-024 P2 / AI-5 source scan.
     */
    @Override
    public String toString() {
        return "SmppBindRequest[commandId=0x" + Integer.toHexString(commandId)
                + ", sequenceNumber=" + sequenceNumber
                + ", systemId=" + systemId
                + ", password=***"
                + ", systemType=" + systemType
                + ", interfaceVersion=0x" + Integer.toHexString(interfaceVersion & 0xFF)
                + ", addrTon=" + (addrTon & 0xFF)
                + ", addrNpi=" + (addrNpi & 0xFF)
                + ", addressRange=" + addressRange
                + "]";
    }
}
