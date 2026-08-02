package smpp.companion.codec.perf;

import io.netty.buffer.AbstractByteBufAllocator;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import smpp.companion.codec.bind.SmppBindEncoder;
import smpp.companion.codec.bind.SmppBindRequest;
import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.command.SmppCommandIds;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PERF-006 (AC8, P2, R26): a fast UNIT guard (no JMH) backing PERF-004's allocation assumption. It wraps the
 * channel allocator with a counting delegate (the codec purity seam AD-7 makes this instant and isolated) and
 * asserts the exact {@link ByteBuf}-allocation counts routed through that allocator:
 * <ul>
 *   <li><b>Encode</b> — exactly one framed {@link ByteBuf} (the AD-2 splice unit) and ZERO scratch ByteBufs.
 *       Fully guarded: {@link SmppBindEncoder#encode} allocates once via {@code alloc.buffer(commandLength)}, so
 *       a regression adding a per-op scratch {@link ByteBuf} IS caught here.</li>
 *   <li><b>Decode</b> — ZERO allocator-routed {@link ByteBuf}s ({@link SmppCodec} reads via an unretained
 *       {@code slice} + a {@code retainedSlice}, both allocator-bypassing). The durable decode invariant is
 *       {@code originalFrame().refCnt() == 1} ("decode retains no extras", asserted below) — NOT the allocator
 *       count, which is zero by construction and stays zero even if decode grows transient heap scratch.</li>
 * </ul>
 * <p>Slice/duplicate views do NOT route through the counting delegate (they are derived from an existing buffer,
 * not a fresh allocation), and {@code SmppBytes.readAscii}'s transient {@code byte[]}/{@link AsciiString}
 * field-reading allocations are likewise NOT allocator-routed — so the count reflects ONLY fresh {@link ByteBuf}s
 * the codec requested via the channel allocator. That is exactly the encode property the guard can bite on;
 * decode's allocation profile is bounded/characterized by PERF-004 ({@code -prof gc}), not by this count.
 */
@Tag("unit")
@Tag("codec")
@Tag("p2")
@Tag("perf")
@DisplayName("PERF-006 — codec encode/decode ByteBuf-allocation guard (encode: one framed + zero scratch; decode: zero via allocator, refCnt==1)")
class CodecAllocationGuardTest {

    /** Golden bind_transceiver all-fields vector (codec/src/test/resources/golden-vectors/…). */
    private static final byte[] GOLDEN_BIND_TRANSCEIVER = HexFormat.of().parseHex(
            "0000002900000009000000000000002a45534d455f3030310073656372657400534d50500034000000");

    /**
     * Counts the buffers driven through the allocator — overrides the two abstract factory methods every
     * {@code alloc.buffer(...)} routes through. Slice/duplicate views do NOT route here, so the count
     * reflects ONLY fresh allocations.
     */
    private static final class CountingAllocator extends AbstractByteBufAllocator {
        private final ByteBufAllocator delegate;
        private int allocations;

        CountingAllocator(ByteBufAllocator delegate) {
            super(true);
            this.delegate = delegate;
        }

        int allocations() {
            return allocations;
        }

        void reset() {
            allocations = 0;
        }

        @Override
        protected ByteBuf newHeapBuffer(int initialCapacity, int maxCapacity) {
            allocations++;
            return delegate.heapBuffer(initialCapacity, maxCapacity);
        }

        @Override
        protected ByteBuf newDirectBuffer(int initialCapacity, int maxCapacity) {
            allocations++;
            return delegate.directBuffer(initialCapacity, maxCapacity);
        }

        @Override
        public boolean isDirectBufferPooled() {
            return delegate.isDirectBufferPooled();
        }
    }

    @Test
    @DisplayName("encode allocates exactly one framed ByteBuf, zero scratch ByteBufs")
    void encodeProducesExactlyOneFramedBuffer() {
        CountingAllocator alloc = new CountingAllocator(UnpooledByteBufAllocator.DEFAULT);
        SmppBindRequest request = allFieldsBindTransceiver();

        ByteBuf encoded = SmppBindEncoder.encode(request, alloc);
        try {
            assertThat(alloc.allocations())
                    .as("encode allocates exactly one framed ByteBuf (the AD-2 splice unit), zero scratch")
                    .isEqualTo(1);
            assertThat(encoded.writerIndex())
                    .as("the single allocation holds the full PDU (command_length octets)")
                    .isEqualTo(GOLDEN_BIND_TRANSCEIVER.length);
        } finally {
            encoded.release(); // EMPTY_BUFFER originalFrame is a shared singleton — no release needed
        }
    }

    @Test
    @DisplayName("decode routes zero ByteBuf allocations through the allocator (slice/retainedSlice bypass it; refCnt==1 is the durable invariant)")
    void decodeDrivesNoScratchAllocations() {
        CountingAllocator alloc = new CountingAllocator(UnpooledByteBufAllocator.DEFAULT);
        ByteBuf goldenFrame = Unpooled.wrappedBuffer(GOLDEN_BIND_TRANSCEIVER);
        EmbeddedChannel channel = new EmbeddedChannel(new SmppCodec());
        channel.config().setAllocator(alloc);

        try {
            alloc.reset(); // ignore any channel-construction allocations; measure ONLY the decode path
            channel.writeInbound(goldenFrame);
            SmppBindRequest pdu = channel.readInbound();

            assertThat(pdu).as("a valid golden bind decodes to a typed PDU").isNotNull();
            assertThat(alloc.allocations())
                    .as("decode routes zero ByteBuf allocations through the channel allocator (it slices the input; "
                            + "transient byte[]/AsciiString field reads are not allocator-routed — refCnt==1 below is the durable invariant)")
                    .isZero();
            assertThat(pdu.originalFrame().refCnt())
                    .as("decode retains exactly the one original-frame slice (the AD-2 forward unit)")
                    .isEqualTo(1);
            assertThat(pdu.commandId())
                    .as("sanity: decode ran the bind path (command_id == bind_transceiver), not a no-op")
                    .isEqualTo(SmppCommandIds.BIND_TRANSCEIVER);
            pdu.originalFrame().release();
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private static SmppBindRequest allFieldsBindTransceiver() {
        return new SmppBindRequest(
                SmppCommandIds.BIND_TRANSCEIVER,
                0,
                0x2a,
                new AsciiString("ESME_001"),
                new AsciiString("secret"),
                new AsciiString("SMPP"),
                SmppCommandIds.INTERFACE_VERSION_3_4,
                (byte) 0,
                (byte) 0,
                AsciiString.EMPTY_STRING,
                Unpooled.EMPTY_BUFFER);
    }
}
