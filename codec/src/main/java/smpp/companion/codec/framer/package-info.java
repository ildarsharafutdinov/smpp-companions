/**
 * SMPP 3.4 length-framing. {@link smpp.companion.codec.framer.SmppFrameDecoder} is a Netty
 * {@code LengthFieldBasedFrameDecoder} ({@code lengthAdjustment = -4}, since SMPP's
 * {@code command_length} is the TOTAL PDU length) that emits one framed {@code ByteBuf} per PDU on both
 * legs — the AD-2 splice forward unit — reassembling across arbitrary TCP segmentation/coalescing and
 * enforcing the AD-30 length bounds ({@code <16} floor via a {@code getUnadjustedFrameLength} override;
 * {@code >65536} ceiling via {@code maxFrameLength}; overflow-class caught by the ceiling's unsigned
 * read — all rejecting before any allocation).
 *
 * <p>It parses NO protocol field except {@code command_length}: every PDU, bind-family or otherwise,
 * is opaque framed bytes here. Field-level parsing (the bind family) is a later handler
 * ({@code smpp.companion.codec.bind}, Story 1.2 T3); non-bind PDUs stay opaque end-to-end (AD-3/AD-32).
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.codec.framer;

import org.jspecify.annotations.NullMarked;
