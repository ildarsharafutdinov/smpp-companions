package smpp.companion.codec.command;

import java.util.Set;

import lombok.experimental.UtilityClass;
import org.jspecify.annotations.NullMarked;

/**
 * SMPP 3.4 {@code command_id} source of truth (AD-27, AD-3). Owns the single parsed-vs-opaque
 * boundary: {@link #BIND_FAMILY} is the EXHAUSTIVE set of {@code command_id}s the codec ever parses
 * into typed objects. Every other {@code command_id} is opaque framed bytes — never inspected, never
 * re-serialized (AD-3 / AD-32). Consumed (never redefined) by {@code relay/}.
 *
 * <p><b>Spec reconciliation #1 (Story 1.2 "Read first"):</b> {@code bind_transceiver = 0x00000009},
 * not {@code 0x0F}. {@code 0x0F} is the {@code ESME_RINVSYSID} <em>status</em> code — the likely typo
 * origin in the TEA scenario catalog (CODEC-026 / 029). Verified against the primary source
 * ({@code docs/SMPP_v3_4_Issue1_2.pdf}, SMPP 3.4 Issue 1.2 §5.1.2) and the jSMPP 3.0.2 oracle (CODEC-031).
 *
 * <p>The wire encoding is 4-octet unsigned big-endian, carried here as a Java {@code int} — the exact
 * bit pattern Netty's {@code ByteBuf.getInt} returns — so a response {@code command_id} reads as a
 * negative {@code int}. Membership comparisons are by bit pattern, which is correct.
 */
@NullMarked
@UtilityClass
// Lombok: makes the class final + generates the private no-arg constructor (CODEC-040 permits org.projectlombok as compile-time-only).
public class SmppCommandIds {

    /**
     * AD-30: the codec's hard cap on a PDU's declared {@code command_length}. Covers the
     * {@code message_payload} TLV maximum. The framer's drop+close policy references this constant,
     * and from Story 1.3 it is the single input to the relay direct-memory formula and the config
     * default — one named value so codec max and allocator budget cannot drift.
     *
     * <p><b>Framer handoff note (T2):</b> {@code command_length} is a 4-octet <em>unsigned</em>
     * big-endian field, but Netty's {@code ByteBuf.getInt} returns a <em>signed</em> Java {@code int}.
     * An overflow-class length such as {@code 0xFFFFFFFF} reads as {@code -1} and would slip a naive
     * {@code length > MAX_COMMAND_LENGTH} check. The framer MUST reject {@code length < 16} first —
     * that floor catches every negative value before any signed comparison or allocation (CODEC-005/010).
     */
    public static final int MAX_COMMAND_LENGTH = 65536;

    // --- Bind-family REQUEST command_ids (SMPP 3.4 §5.1.2) ---
    public static final int BIND_RECEIVER = 0x00000001;
    public static final int BIND_TRANSMITTER = 0x00000002;
    /**
     * Spec reconciliation #1: 0x00000009, NOT 0x0F.
     */
    public static final int BIND_TRANSCEIVER = 0x00000009;

    // --- Bind-family RESPONSE command_ids (request | RESPONSE_BIT) ---
    public static final int BIND_RECEIVER_RESP = 0x80000001;
    public static final int BIND_TRANSMITTER_RESP = 0x80000002;
    public static final int BIND_TRANSCEIVER_RESP = 0x80000009;

    /**
     * SMPP 3.4 §3.2: bit 31 distinguishes a response PDU from its request.
     */
    private static final int RESPONSE_BIT = 0x80000000;

    /**
     * Mask that clears bit 31, yielding the underlying request {@code command_id}.
     */
    private static final int RESPONSE_MASK = 0x7FFFFFFF;

    /**
     * AD-27 / AD-3: the EXHAUSTIVE set of {@code command_id}s the codec parses into typed objects —
     * the three bind requests and their three responses, no more, no less. Every {@code command_id}
     * not in this set is opaque framed bytes. Immutable; the single source of truth for the parsed
     * attack surface (AD-24: exactly two decoders touch this set).
     */
    public static final Set<Integer> BIND_FAMILY =
            Set.of(
                    BIND_RECEIVER, BIND_TRANSMITTER, BIND_TRANSCEIVER,
                    BIND_RECEIVER_RESP, BIND_TRANSMITTER_RESP, BIND_TRANSCEIVER_RESP);

    /**
     * {@code true} iff {@code commandId} carries the SMPP response bit (bit 31 set).
     */
    public static boolean isResponse(int commandId) {
        return (commandId & RESPONSE_BIT) != 0;
    }

    /**
     * The request {@code command_id} underlying a response (bit 31 cleared). Identity for a request
     * {@code command_id}.
     *
     * <p>Only meaningful for bind-family response ids. For an id outside that set the result is
     * undefined — e.g. {@code requestIdOf(generic_nack = 0x80000000)} returns {@code 0x00000000}
     * (unassigned), because {@code generic_nack} has no underlying request. Such ids are opaque and
     * never reach this method on the bind path.
     */
    public static int requestIdOf(int commandId) {
        return commandId & RESPONSE_MASK;
    }

    /**
     * {@code true} iff {@code commandId} belongs to the parsed bind family (request or response).
     */
    public static boolean isBindFamily(int commandId) {
        return BIND_FAMILY.contains(commandId);
    }
}
