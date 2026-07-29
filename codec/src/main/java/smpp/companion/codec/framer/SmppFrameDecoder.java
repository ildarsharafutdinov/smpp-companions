package smpp.companion.codec.framer;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import java.nio.ByteOrder;

/**
 * SMPP 3.4 length-framing decoder (AC1; AD-2, AD-7, AD-30). Generic over every PDU — it parses NO
 * protocol field except {@code command_length}, emitting one framed {@link ByteBuf} per PDU that
 * downstream handlers (the T3 bind parser, the relay splice) consume as the AD-2 forward unit.
 *
 * <p><b>Shape — a {@link LengthFieldBasedFrameDecoder} subclass (the {@code -4} lengthAdjustment recipe):</b>
 * SMPP's {@code command_length} is the TOTAL PDU length (the 4-octet field + the whole 16-octet header +
 * the body), so {@code lengthAdjustment = -4} reconciles LFBD's default "bytes following the field"
 * semantics with total-length-inclusive framing (Context7-confirmed Netty 4.2). {@code initialBytesToStrip = 0}
 * forwards the full PDU (the AD-2 forward unit); {@code extractFrame} is a zero-copy {@code retainedSlice}.
 * LFBD owns the reassembly/chunking mechanics (reader-index discipline, {@code frameLengthInt} caching
 * across split reads, the coalesced-PDU loop) — the codec contributes only the AD-30 policy.
 *
 * <p><b>AD-30 reject (fail-closed, before any allocation):</b> the policy is split across two LFBD length
 * hooks, but BOTH fire before the only slice ({@code extractFrame}) on the happy path:
 * <ul>
 *   <li><b>Ceiling ({@code > MAX_COMMAND_LENGTH}):</b> LFBD's native {@code maxFrameLength} check. The
 *       comparison is strict {@code >}, so {@code == 65536} is accepted and {@code 65537} rejected (the
 *       CODEC-008 off-by-one). {@code failFast} (the 5-arg-ctor default) throws
 *       {@code TooLongFrameException} on the FIRST length read, before the body is read or allocated — so
 *       an overflow-class length ({@code 0x7FFFFFFF}, {@code 0x80000000}, {@code 0xFFFFFFFF}) rejects with
 *       no oversized allocation (CODEC-006/010/015). LFBD reads the length UNSIGNED
 *       ({@code getUnsignedInt}), so these overflow values pass the floor and are caught HERE — under LFBD
 *       the ceiling, not the floor, rejects overflow. (Contrast the prior custom decoder, which read
 *       signed {@code getInt} so the {@code < 16} floor caught overflow; same observable outcome.)
 *   <li><b>Floor ({@code <} {@link SmppFrame#MIN_COMMAND_LENGTH}):</b> {@link #getUnadjustedFrameLength} is overridden
 *       to throw a {@link DecoderException} when the unsigned {@code command_length < 16}. This hook is the
 *       earliest point LFBD reads the field (called once the 4-octet field is present, so a mid-header
 *       split reassembles first — CODEC-002) and it precedes the {@code maxFrameLength} check, so an
 *       undersized PDU rejects before {@code extractFrame} (CODEC-005). The hook's contract permits
 *       {@code @throws DecoderException} and forbids mutating the buffer — it only reads and throws.
 * </ul>
 *
 * <p><b>Failure model:</b> both reject throws propagate through {@code ByteToMessageDecoder.callDecode} to
 * the overridden {@link #exceptionCaught}, which fires the exception downstream (so the relay/tests observe
 * the reject — CODEC-013) then closes the channel (drop + close, AC1). Each channel owns its own decoder
 * instance, so a reject on one channel's context cannot touch another's pipeline (per-channel isolation,
 * CODEC-014). Neither reject path reaches {@code extractFrame}, so there is no allocated-then-thrown buffer
 * to leak (CODEC-015).
 */
public final class SmppFrameDecoder extends LengthFieldBasedFrameDecoder {

    /**
     * SMPP 3.4 framing over LFBD. {@code command_length} (offset 0, 4 octets, big-endian) is the TOTAL PDU
     * length, so {@code lengthAdjustment = -4} reconciles it with LFBD's "bytes following the field" default;
     * {@code initialBytesToStrip = 0} forwards the whole PDU (AD-2); {@code maxFrameLength} is the AD-30
     * ceiling (strict {@code >}: {@code == 65536} accepted, {@code 65537}+ rejected — CODEC-008);
     * {@code failFast} (the 5-arg-ctor default) rejects before the body is read or allocated. The cap is
     * pinned to {@link SmppFrame#MAX_COMMAND_LENGTH} here; a future config-derived cap (Story 1.3's
     * AD-30 formula) would widen this constructor rather than change the policy logic.
     */
    public SmppFrameDecoder() {
        super(
                SmppFrame.MAX_COMMAND_LENGTH, // maxFrameLength — AD-30 ceiling (CODEC-006/008/010)
                0,                                 // lengthFieldOffset — command_length is at octet 0
                4,                                 // lengthFieldLength — 4-octet big-endian int
                -4,                                // lengthAdjustment — command_length includes the field itself
                0);                                // initialBytesToStrip — forward the whole PDU (AD-2)
    }

    /**
     * AD-30 floor: reject a {@code command_length <} {@link SmppFrame#MIN_COMMAND_LENGTH} BEFORE any allocation. The earliest
     * length read in LFBD (called once the 4-octet field is present, before the adjusted-length /
     * {@code maxFrameLength} checks); throwing here rejects an undersized PDU before {@code extractFrame}.
     * {@code super} reads {@code getUnsignedInt}, so {@code raw} is the true unsigned command_length —
     * overflow-class values ({@code >= 16}) pass here and are caught by {@code maxFrameLength} downstream.
     * Must not mutate the buffer (hook contract) — it only reads and conditionally throws.
     */
    @Override
    protected long getUnadjustedFrameLength(ByteBuf buf, int offset, int length, ByteOrder order) {
        long raw = super.getUnadjustedFrameLength(buf, offset, length, order);
        if (raw < SmppFrame.MIN_COMMAND_LENGTH) {
            throw new DecoderException(
                    "SMPP framer: command_length " + raw + " < " + SmppFrame.MIN_COMMAND_LENGTH);
        }
        return raw;
    }

    /**
     * Fail-closed (AC1/AD-30): any failure reaching this handler's {@code exceptionCaught} closes the
     * channel. The exception is fired downstream FIRST (so the relay/tests observe the reject —
     * CODEC-013), then the channel is closed — drop + close, per AC1. Doing it here (after the decode
     * throw has fully unwound to {@code exceptionCaught}) keeps the exception observable before the
     * pipeline tears down. Propagation is forward-only (inbound), so a downstream handler's exception
     * never reaches back here — this fires solely for this decoder's own {@code decode} /
     * {@code getUnadjustedFrameLength} throws.
     */
    @Override
    @SuppressWarnings("FutureReturnValueIgnored") // reason: ctx.close() returns Netty's ChannelFuture; the
            // close is best-effort fail-closed — a failed close merely means the channel was already closed
            // (the desired end state). The codec has no logging surface to report close completion (AD-27).
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ctx.fireExceptionCaught(cause); // surface the reject to the relay/tests (observability, CODEC-013)
        ctx.close();                    // fail-closed drop + close (AC1)
    }
}
