package smpp.companion.codec.framer;

import io.netty.buffer.AbstractByteBufAllocator;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import io.netty.util.ResourceLeakDetector;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import smpp.companion.codec.command.SmppCommandIds;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * CODEC-001..015 (the EmbeddedChannel half): {@link SmppFrameDecoder} framing behaviour. The
 * structure-aware fuzz (CODEC-011) and the jqwik chunking property (CODEC-012) are Level {@code fuzz},
 * mapped to AC7, and land in T6 with the fuzz/property libraries — there is no fuzz harness here.
 *
 * <p>Conventions: every harness installs a tail {@link ExceptionCapture} that records (and swallows)
 * any exception fired by the framer, so a reject is observable as {@code capture.cause} without
 * {@code writeInbound} re-throwing — the contained, exceptionCaught-routed form CODEC-013 asserts.
 */
@Tag("unit")
@Tag("codec")
@Tag("p1")
@DisplayName("SmppFrameDecoder — SMPP 3.4 length-framing (CODEC-001..015)")
class SmppFrameDecoderTest {

    /** SMPP 3.4 §4.1 header size (octets): command_length | command_id | command_status | sequence_number. */
    private static final int HEADER = 16;
    private static final int MAX = SmppCommandIds.MAX_COMMAND_LENGTH;

    // ---------- harness ----------

    /** Records the framer's reject exception WITHOUT propagating (so writeInbound does not re-throw). */
    private static final class ExceptionCapture extends ChannelInboundHandlerAdapter {
        private Throwable cause;

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            this.cause = cause; // swallow — the test asserts on it directly
        }
    }

    /**
     * Wraps an allocator and records the largest requested capacity + the allocation count — proves the
     * framer never drives an oversized (or extra) allocation on the reject path (CODEC-006/008/010/015).
     * {@code readRetainedSlice} does NOT allocate (it is a view). To make the bound provable the reject-path
     * tests route their input through this allocator (via {@code alloc.buffer(...)}); otherwise a single
     * {@code writeInbound} of an {@link Unpooled#buffer(int)} bypasses {@code ctx.alloc()} (MERGE_CUMULATOR
     * returns the input directly when the cumulation is empty + contiguous) and leaves {@code maxRequested}
     * at 0 — i.e. the assertion would hold for any decoder. With the input routed through here,
     * {@code maxRequested} equals the test input size and {@code allocationCount == 1}, proving the framer
     * allocated nothing on the reject path: no oversized alloc (CODEC-010), no allocated-then-dropped buffer
     * to leak (CODEC-015).
     */
    private static final class RecordingAllocator extends AbstractByteBufAllocator {
        private final ByteBufAllocator delegate;
        private int maxRequested;
        private int allocationCount;

        RecordingAllocator(ByteBufAllocator delegate) {
            super(true);
            this.delegate = delegate;
        }

        int maxRequested() {
            return maxRequested;
        }

        int allocationCount() {
            return allocationCount;
        }

        @Override
        protected ByteBuf newHeapBuffer(int initialCapacity, int maxCapacity) {
            recordCapacity(initialCapacity);
            allocationCount++;
            return delegate.heapBuffer(initialCapacity, maxCapacity);
        }

        @Override
        protected ByteBuf newDirectBuffer(int initialCapacity, int maxCapacity) {
            recordCapacity(initialCapacity);
            allocationCount++;
            return delegate.directBuffer(initialCapacity, maxCapacity);
        }

        @Override
        public boolean isDirectBufferPooled() {
            return delegate.isDirectBufferPooled();
        }

        private void recordCapacity(int capacity) {
            if (capacity > maxRequested) {
                maxRequested = capacity;
            }
        }
    }

    /** A decoder + tail capture on an EmbeddedChannel (both share ImmediateEventExecutor.INSTANCE). */
    private static final class Harness {
        final EmbeddedChannel channel;
        final ExceptionCapture capture;

        Harness() {
            this.capture = new ExceptionCapture();
            this.channel = new EmbeddedChannel(new SmppFrameDecoder(), capture);
        }

        RecordingAllocator useRecordingAllocator() {
            RecordingAllocator allocator = new RecordingAllocator(UnpooledByteBufAllocator.DEFAULT);
            channel.config().setAllocator(allocator);
            return allocator;
        }
    }

    // ---------- byte helpers ----------

    /** A complete PDU: 16-byte header + body, command_length == HEADER + body.length. */
    private static ByteBuf pdu(int commandId, byte[] body) {
        int length = HEADER + body.length;
        ByteBuf buf = Unpooled.buffer(length);
        buf.writeInt(length);        // command_length (total PDU length)
        buf.writeInt(commandId);     // command_id
        buf.writeInt(0);             // command_status (zero in requests)
        buf.writeInt(1);             // sequence_number
        buf.writeBytes(body);
        return buf;
    }

    /** A 16-byte header-only PDU with the given command_id (command_length == 16). */
    private static ByteBuf headerOnlyPdu(int commandId) {
        return pdu(commandId, new byte[0]);
    }

    /** Bytes whose first 4 octets are the big-endian declared command_length, followed by filler body. */
    private static ByteBuf declaringLength(int declaredLength, int fillerBytes) {
        ByteBuf buf = Unpooled.buffer(HEADER + fillerBytes);
        buf.writeInt(declaredLength);
        for (int i = 0; i < fillerBytes; i++) {
            buf.writeByte(0);
        }
        return buf;
    }

    /**
     * As {@link #declaringLength(int, int)} but allocates via the given allocator, so a
     * {@link RecordingAllocator} records the input allocation — making the reject-path allocation bound
     * provable (CODEC-006/008/010/015). Routing the input through {@code ctx.alloc()} is what lets
     * {@code maxRequested} / {@code allocationCount} actually reflect the framer's behaviour.
     */
    private static ByteBuf declaringLength(ByteBufAllocator alloc, int declaredLength, int fillerBytes) {
        ByteBuf buf = alloc.buffer(HEADER + fillerBytes);
        buf.writeInt(declaredLength);
        for (int i = 0; i < fillerBytes; i++) {
            buf.writeByte(0);
        }
        return buf;
    }

    private static void release(Object maybeBuf) {
        if (maybeBuf instanceof ByteBuf buf) {
            buf.release();
        }
    }

    // ---------- CODEC-001: one complete PDU in a single read -> exactly one framed ByteBuf ----------

    @Test
    @DisplayName("CODEC-001: one well-formed PDU in a single read -> exactly one reader-aligned frame")
    void oneCompletePdu_singleRead_emitsOneReaderAlignedFrame() {
        Harness h = new Harness();
        ByteBuf pdu = headerOnlyPdu(0x00000015); // enquire_link, 16 bytes

        assertThat(h.channel.writeInbound(pdu)).as("a frame was produced").isTrue();

        ByteBuf frame = h.channel.readInbound();
        assertThat(frame).isNotNull();
        assertThat(frame.readerIndex()).as("reader-aligned").isZero();
        assertThat(frame.readableBytes()).as("exact PDU length").isEqualTo(HEADER);
        release(frame);
        assertThat(h.channel.isActive()).isTrue();
        h.channel.finishAndReleaseAll();
    }

    // ---------- CODEC-002: split across reads, including inside the 4-octet length header ----------

    @Test
    @DisplayName("CODEC-002: a PDU split at every byte boundary (incl. mid-header) reassembles to one frame")
    void splitAcrossReads_includingMidHeader_reassemblesToOneFrame() {
        ByteBuf full = pdu(0x00000015, new byte[]{1, 2, 3, 4}); // 20-byte PDU
        byte[] bytes = new byte[full.readableBytes()];
        full.readBytes(bytes);
        full.release();

        for (int split = 0; split <= bytes.length; split++) {
            Harness h = new Harness();
            // feed the PDU as two fragments at every split point — including 0 (all in the second
            // read), mid-header (split 1..3), mid-body, and full (split == len, all in the first read).
            h.channel.writeInbound(Unpooled.wrappedBuffer(bytes, 0, split));
            h.channel.writeInbound(Unpooled.wrappedBuffer(bytes, split, bytes.length - split));

            List<ByteBuf> frames = new ArrayList<>();
            ByteBuf emitted;
            while ((emitted = h.channel.readInbound()) != null) {
                frames.add(emitted);
            }
            assertThat(frames).as("split=%d: exactly one frame reassembled", split).hasSize(1);
            assertThat(frames.get(0).readableBytes()).as("split=%d: exact length", split).isEqualTo(bytes.length);
            assertThat(toArray(frames.get(0))).as("split=%d: byte-identical reassembly", split).isEqualTo(bytes);
            frames.forEach(SmppFrameDecoderTest::release);
            assertThat(h.channel.isActive()).as("split=%d: channel open", split).isTrue();
            h.channel.finishAndReleaseAll();
        }
    }

    // ---------- CODEC-003: N coalesced PDUs in one read -> N distinct frames in order ----------

    @Test
    @DisplayName("CODEC-003: three PDUs coalesced in one read -> three frames out in arrival order")
    void coalescedPdus_oneRead_emitsFramesInOrder() {
        Harness h = new Harness();
        byte[] a = toArray(pdu(0x00000001, new byte[]{0xA}));   // bind_receiver
        byte[] b = toArray(pdu(0x00000002, new byte[]{0xB, 0xB})); // bind_transmitter
        byte[] c = toArray(pdu(0x00000009, new byte[]{0xC, 0xC, 0xC})); // bind_transceiver
        ByteBuf coalesced = Unpooled.wrappedBuffer(a, b, c);

        h.channel.writeInbound(coalesced);

        assertThat(toArray(h.channel.readInbound())).as("frame 1").isEqualTo(a);
        assertThat(toArray(h.channel.readInbound())).as("frame 2").isEqualTo(b);
        assertThat(toArray(h.channel.readInbound())).as("frame 3").isEqualTo(c);
        assertThat((ByteBuf) h.channel.readInbound()).as("no extra frame").isNull();
        h.channel.finishAndReleaseAll();
    }

    // ---------- CODEC-004: partial PDU left at channelInactive -> no truncated frame ----------

    @Test
    @DisplayName("CODEC-004: a partial PDU left at channel close emits no truncated frame")
    void partialPduAtClose_emitsNoTruncatedFrame() {
        Harness h = new Harness();
        // a full first PDU, then a header declaring 32 with only 4 body bytes (incomplete)
        h.channel.writeInbound(headerOnlyPdu(0x00000015));
        release(h.channel.readInbound()); // consume the complete frame
        h.channel.writeInbound(declaringLength(32, 4)); // partial — 16 bytes declared-worth short

        assertThat((ByteBuf) h.channel.readInbound()).as("no premature frame").isNull();

        // closing must NOT synthesize a truncated frame from the leftover partial bytes
        assertThatCode(() -> h.channel.finishAndReleaseAll()).doesNotThrowAnyException();
        assertThat(h.capture.cause).as("clean close, no reject").isNull();
    }

    // ---------- CODEC-005: command_length < 16 -> drop + close ----------

    @Test
    @DisplayName("CODEC-005: command_length < 16 (0, 1, 15) -> drop + close, no frame, no reject-exception escape")
    void lengthBelow16_dropAndClose() {
        for (int length : new int[]{0, 1, 15}) {
            Harness h = new Harness();
            h.channel.writeInbound(declaringLength(length, 4));

            assertThat((ByteBuf) h.channel.readInbound()).as("len=%d: no frame", length).isNull();
            assertThat(h.channel.isActive()).as("len=%d: channel closed", length).isFalse();
            assertThat(h.capture.cause)
                    .as("len=%d: reject reaches exceptionCaught", length)
                    .isInstanceOf(DecoderException.class);
            h.channel.finishAndReleaseAll();
        }
    }

    // ---------- CODEC-006: command_length > 65536 (mid-range) -> drop + close, no oversized allocation ----------

    @Test
    @DisplayName("CODEC-006: command_length > 65536 (65537, 70000, 100000) -> drop + close, no oversized alloc")
    void lengthAboveMax_dropAndCloseWithoutOversizedAllocation() {
        for (int length : new int[]{65537, 70000, 100000}) {
            Harness h = new Harness();
            RecordingAllocator alloc = h.useRecordingAllocator();
            h.channel.writeInbound(declaringLength(alloc, length, 4));

            assertThat((ByteBuf) h.channel.readInbound()).as("len=%d: no frame", length).isNull();
            assertThat(h.channel.isActive()).as("len=%d: channel closed", length).isFalse();
            assertThat(h.capture.cause)
                    .as("len=%d: reject reaches exceptionCaught", length)
                    .isInstanceOf(DecoderException.class);
            assertThat(alloc.maxRequested())
                    .as("len=%d: no allocation driven by the malformed length (bound = actual input size)", length)
                    .isLessThanOrEqualTo(HEADER + 4);
            h.channel.finishAndReleaseAll();
        }
    }

    // ---------- CODEC-007: command_length == 16 (header-only PDU) accepted ----------

    @Test
    @DisplayName("CODEC-007: command_length == 16 (header-only PDU) is a valid frame")
    void lengthExactly16_accepted() {
        Harness h = new Harness();
        h.channel.writeInbound(headerOnlyPdu(0x00000006)); // unbind, 16 bytes

        ByteBuf frame = h.channel.readInbound();
        assertThat(frame).isNotNull();
        assertThat(frame.readableBytes()).isEqualTo(HEADER);
        assertThat(h.channel.isActive()).as("channel stays open for a valid header-only PDU").isTrue();
        release(frame);
        h.channel.finishAndReleaseAll();
    }

    // ---------- CODEC-008: command_length == 65536 accepted; 65537 rejected (off-by-one) ----------

    @Test
    @DisplayName("CODEC-008: command_length == 65536 accepted; 65537 rejected (off-by-one boundary)")
    void lengthAt65536Boundary_acceptedAndRejected() {
        // accepted: a full 65536-byte PDU
        Harness accepted = new Harness();
        accepted.channel.writeInbound(pdu(0x00000015, new byte[MAX - HEADER]));
        ByteBuf big = accepted.channel.readInbound();
        assertThat(big).as("65536 -> one frame").isNotNull();
        assertThat(big.readableBytes()).isEqualTo(MAX);
        assertThat(accepted.channel.isActive()).as("65536 -> channel open").isTrue();
        release(big);
        accepted.channel.finishAndReleaseAll();

        // rejected: 65537
        Harness rejected = new Harness();
        RecordingAllocator alloc = rejected.useRecordingAllocator();
        rejected.channel.writeInbound(declaringLength(alloc, MAX + 1, 4));
        assertThat((ByteBuf) rejected.channel.readInbound()).as("65537 -> no frame").isNull();
        assertThat(rejected.channel.isActive()).as("65537 -> channel closed").isFalse();
        assertThat(rejected.capture.cause).isInstanceOf(DecoderException.class);
        assertThat(alloc.maxRequested())
                .as("65537 -> no allocation driven by the malformed length (bound = actual input size)")
                .isLessThanOrEqualTo(HEADER + 4);
        rejected.channel.finishAndReleaseAll();
    }

    // ---------- CODEC-009: declared length exceeds buffered bytes -> wait (no partial frame, no spin) ----------

    @Test
    @DisplayName("CODEC-009: declared length > buffered bytes -> wait (no partial frame); completion emits one frame")
    void declaredLengthExceedsBuffered_waitsThenCompletesToOneFrame() {
        Harness h = new Harness();
        byte[] full = toArray(pdu(0x00000015, new byte[84])); // length 100 (16 header + 84 body)
        ByteBuf part = Unpooled.wrappedBuffer(full, 0, 66); // 16-byte header + 50 body (< 100)
        ByteBuf rest = Unpooled.wrappedBuffer(full, 66, full.length - 66);

        h.channel.writeInbound(part); // incomplete -> no frame, no busy-spin
        assertThat((ByteBuf) h.channel.readInbound()).as("no premature partial frame").isNull();

        h.channel.writeInbound(rest); // completion -> exactly one frame
        ByteBuf frame = h.channel.readInbound();
        assertThat(frame).isNotNull();
        assertThat(frame.readableBytes()).isEqualTo(full.length);
        assertThat(toArray(frame)).isEqualTo(full);
        release(frame);
        h.channel.finishAndReleaseAll();
    }

    // ---------- CODEC-010: overflow-class lengths (0x7FFFFFFF / 0x80000000 / 0xFFFFFFFF) reject before alloc ----------

    @Test
    @DisplayName("CODEC-010: overflow-class lengths reject BEFORE any allocation — no OOM, no arithmetic wrap")
    void overflowClassLengths_rejectBeforeAnyAllocation() {
        int[] overflowLengths = {0x7FFFFFFF, 0x80000000, 0xFFFFFFFF};
        for (int declared : overflowLengths) {
            Harness h = new Harness();
            RecordingAllocator alloc = h.useRecordingAllocator();
            // Tempt a naive pre-allocating decoder: a large declared length with a modest body present.
            // The input is routed through the recorded allocator (alloc) so the bound below is provable —
            // otherwise a single writeInbound of an Unpooled.buffer bypasses ctx.alloc() and maxRequested
            // stays 0, making the assertion hold for any decoder.
            h.channel.writeInbound(declaringLength(alloc, declared, 60));

            assertThat((ByteBuf) h.channel.readInbound()).as("0x%08X: no frame", declared).isNull();
            assertThat(h.channel.isActive()).as("0x%08X: channel closed", declared).isFalse();
            assertThat(h.capture.cause)
                    .as("0x%08X: reject reaches exceptionCaught as a DecoderException (not OOM)", declared)
                    .isInstanceOf(DecoderException.class);
            // The critical AD-30 invariant: no allocation driven by the malformed length. The largest
            // allocation is the test's own input (HEADER + 60), never the overflow declared value.
            assertThat(alloc.maxRequested())
                    .as("0x%08X: no oversized allocation (bound = actual input size)", declared)
                    .isLessThanOrEqualTo(HEADER + 60);
            h.channel.finishAndReleaseAll();
        }
    }

    // ---------- CODEC-013: a malformed input's exception is contained in exceptionCaught ----------

    @Test
    @DisplayName("CODEC-013: malformed/overflow input's exception is contained — does not escape writeInbound unchecked")
    void malformedInput_exceptionContainedInExceptionCaught() {
        Harness h = new Harness();
        ByteBuf overflow = declaringLength(0xFFFFFFFF, 8); // unsigned 4294967295 — rejected by the maxFrameLength ceiling (TooLongFrameException), not the <16 floor

        // The DecoderException is routed to exceptionCaught (contained), never bubbled out of decode
        // unchecked to kill a shared event-loop thread (R3 relay-wide-DoS dimension).
        assertThatCode(() -> h.channel.writeInbound(overflow)).doesNotThrowAnyException();
        assertThat(h.capture.cause)
                .as("reject reaches exceptionCaught as a controlled DecoderException")
                .isInstanceOf(DecoderException.class);
        assertThat(h.channel.isActive()).as("fail-closed: channel closed").isFalse();

        // Event-loop-equivalent intactness: a fresh decoder on the shared executor still frames a good PDU.
        Harness fresh = new Harness();
        fresh.channel.writeInbound(headerOnlyPdu(0x00000015));
        ByteBuf frame = fresh.channel.readInbound();
        assertThat(frame).as("a second channel still decodes after the first rejected").isNotNull();
        release(frame);
        fresh.channel.finishAndReleaseAll();
        h.channel.finishAndReleaseAll();
    }

    // ---------- CODEC-014: per-channel isolation — a malformed A does not corrupt a healthy B ----------

    @Test
    @DisplayName("CODEC-014: a malformed frame on channel A closes A without affecting a healthy frame on B")
    void perChannelIsolation_malformedChannelAClosesHealthyChannelBUnaffected() {
        // Two EmbeddedChannels share ImmediateEventExecutor.INSTANCE (a single shared executor),
        // each owning its own SmppFrameDecoder instance + cumulation buffer.
        Harness a = new Harness();
        Harness b = new Harness();

        a.channel.writeInbound(declaringLength(0x7FFFFFFF, 4)); // malformed -> A closes
        assertThat(a.channel.isActive()).as("A closed").isFalse();
        assertThat(a.capture.cause).isInstanceOf(DecoderException.class);

        b.channel.writeInbound(headerOnlyPdu(0x00000015)); // golden -> B frames it
        ByteBuf frame = b.channel.readInbound();
        assertThat(frame).as("B unaffected: golden frame decoded").isNotNull();
        assertThat(b.channel.isActive()).as("B still open").isTrue();
        release(frame);

        a.channel.finishAndReleaseAll();
        b.channel.finishAndReleaseAll();
    }

    // ---------- CODEC-015: retain/release correctness on the normal and reject paths ----------

    @Test
    @DisplayName("CODEC-015: normal frame is a releasable retained slice; reject path allocates nothing (PARANOID)")
    void retainReleaseCorrectOnNormalAndRejectPaths() {
        ResourceLeakDetector.Level original = ResourceLeakDetector.getLevel();
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.PARANOID);
        try {
            // Normal path: the emitted frame is a retained slice (refCnt 1); releasing it frees it.
            Harness normal = new Harness();
            normal.channel.writeInbound(headerOnlyPdu(0x00000015));
            ByteBuf frame = normal.channel.readInbound();
            assertThat(frame).isNotNull();
            assertThat(frame.refCnt()).as("retained slice has refCnt 1 on the normal path").isEqualTo(1);
            assertThat(frame.release()).as("the test owns and releases the forward unit").isTrue();
            assertThat(frame.refCnt()).isZero();
            normal.channel.finishAndReleaseAll();

            // Reject path: route the input through the recorded allocator so the reject-path allocation
            // bound is provable, then prove the framer allocated NOTHING beyond the test's own input —
            // no oversized alloc (CODEC-010) and no allocated-then-dropped buffer to leak (CODEC-015).
            // (finishAndReleaseAll releases the cumulation, which is the input buffer itself.)
            Harness reject = new Harness();
            RecordingAllocator alloc = reject.useRecordingAllocator();
            reject.channel.writeInbound(declaringLength(alloc, 0x7FFFFFFF, 4));
            assertThat(reject.channel.isActive()).isFalse();
            assertThat(alloc.maxRequested())
                    .as("reject path: no allocation driven by the malformed length (bound = actual input size)")
                    .isLessThanOrEqualTo(HEADER + 4);
            // Leak guard: exactly one allocation (the input) was made via ctx.alloc(); the framer added
            // none, so there is no allocated-then-dropped buffer to leak on the reject path.
            assertThat(alloc.allocationCount())
                    .as("reject path: framer allocated no extra buffer (only the test input) -> nothing to leak")
                    .isEqualTo(1);
            assertThatCode(() -> reject.channel.finishAndReleaseAll())
                    .as("closing the channel after a reject does not throw")
                    .doesNotThrowAnyException();
        } finally {
            ResourceLeakDetector.setLevel(original);
        }
    }

    // ---------- small util ----------

    private static byte[] toArray(ByteBuf buf) {
        byte[] out = new byte[buf.readableBytes()];
        buf.getBytes(buf.readerIndex(), out);
        return out;
    }
}
