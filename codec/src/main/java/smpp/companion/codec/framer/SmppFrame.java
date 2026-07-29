package smpp.companion.codec.framer;

import lombok.experimental.UtilityClass;
import org.jspecify.annotations.NullMarked;

/**
 * SMPP 3.4 PDU <em>frame-length</em> bounds — the AD-30 {@code [min, max]} source of truth (AD-7, AD-30).
 * Frame-length bounds are distinct from {@code command_id}s ({@link smpp.companion.codec.command.SmppCommandIds}),
 * so they live here, in the {@code framer} package (the frame concept's owner). Consumed by the framer
 * ({@link SmppFrameDecoder}), the bind parser/encoder ({@code smpp.companion.codec.bind}), and — from
 * Story 1.3 — the relay's AD-30 direct-memory formula and the config default, all referencing ONE constant
 * so the codec max and the allocator budget cannot drift.
 */
@NullMarked
@UtilityClass
public class SmppFrame {

    /**
     * AD-30 floor: the minimum legal {@code command_length}. A PDU is at least the 16-octet header
     * (header-only PDUs: {@code unbind}, {@code enquire_link}, {@code generic_nack}). The framer rejects
     * a {@code command_length < MIN_COMMAND_LENGTH} before any allocation (CODEC-005). Co-located with
     * {@link #MAX_COMMAND_LENGTH} so the AD-30 {@code [min, max]} bounds are one source of truth.
     */
    public static final int HEADER_LENGTH = 16;
    public static final int MIN_COMMAND_LENGTH = HEADER_LENGTH;

    /**
     * AD-30 ceiling: the codec's hard cap on a PDU's declared {@code command_length}. Covers the
     * {@code message_payload} TLV maximum. The framer's drop+close policy references this constant,
     * and from Story 1.3 it is the single input to the relay direct-memory formula and the config
     * default — one named value so codec max and allocator budget cannot drift.
     *
     * <p><b>Framer handoff note ({@code SmppFrameDecoder} is a {@code LengthFieldBasedFrameDecoder}
     * subclass):</b> the framer reads {@code command_length} <em>unsigned</em> (LFBD's
     * {@code getUnadjustedFrameLength} → {@code getUnsignedInt}), so an overflow-class length reads as a
     * large positive — e.g. {@code 0xFFFFFFFF} → 4294967295, <em>not</em> {@code -1} — and is caught by
     * this ceiling ({@code > MAX_COMMAND_LENGTH} → {@code TooLongFrameException} before allocation,
     * CODEC-006/008/010). {@link #MIN_COMMAND_LENGTH} is the undersized-PDU floor; both bounds reject
     * before the only happy-path slice. (Contrast a naive framer reading <em>signed</em>
     * {@code ByteBuf.getInt}, where {@code 0xFFFFFFFF} reads as {@code -1} and slips a bare
     * {@code > MAX} check — the prior custom decoder leaned on the {@code < MIN} floor to catch that;
     * under LFBD's unsigned read the ceiling is the overflow guard.)
     */
    public static final int MAX_COMMAND_LENGTH = 65536;
}
