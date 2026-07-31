package smpp.companion.codec.framer;

import com.code_intelligence.jazzer.junit.FuzzTest;
import io.netty.buffer.AbstractByteBufAllocator;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.ByteBuffer;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * CODEC-011 (AC7 / AD-24, P1, R3/SEC-2): structure-agnostic Jazzer fuzz of {@link SmppFrameDecoder} over
 * arbitrary byte streams. AD-24 mandates fuzzing the framing decoder (the MORE-EXPOSED surface); the fuzz
 * finds crash/DoS paths the enumerated reject cases (CODEC-005/006/008/010) cannot foresee. Invariants
 * asserted for EVERY input:
 * <ol>
 *   <li><b>No Throwable escapes {@code decode}</b> — a reject is routed to {@code exceptionCaught} (swallowed
 *       by the tail capture), never bubbled out of {@code writeInbound} (the R3 relay-wide-DoS dimension).</li>
 *   <li><b>Bounded memory</b> — the framer drives no oversized allocation: every capacity it requests via
 *       {@code ctx.alloc()} stays {@code ≤ MAX_COMMAND_LENGTH × 2} (the small factor covers Netty's cumulation
 *       growth headroom). The fuzz input is minted by {@link Unpooled} (NOT {@code ctx.alloc()}), so the
 *       recorded bound reflects ONLY the framer's own allocations — a malformed declared length drives no
 *       oversized/OOM allocation regardless of its value (the CODEC-010 guard, generalized). <em>The input is
 *       fed in small chunks so {@code MERGE_CUMULATOR} cumulation growth actually routes through
 *       {@code ctx.alloc()}</em> (a single {@code writeInbound} hits the empty-cumulation fast path and
 *       allocates nothing, which would leave {@code maxRequested == 0} and the bound unexercised).</li>
 *   <li><b>Controlled + oversize closure</b> — any framer-driven close is a {@link DecoderException} (a
 *       controlled fail-closed reject, never an unchecked crash), AND an oversize declared length
 *       ({@code > MAX_COMMAND_LENGTH}) positively fail-closes the channel (the AD-30 ceiling, not a silent drop).</li>
 * </ol>
 *
 * <p>Seeds (via {@link MethodSource}) run once each in Jazzer <b>regression mode</b> on the PR tier (a real,
 * bounded set of representative streams — well-formed, oversize, overflow-class, undersize, partial-header,
 * coalesced); under {@code JAZZER_FUZZ=1} the same {@code @FuzzTest} mutates them for continuous
 * coverage-guided fuzzing (nightly).
 */
@Tag("fuzz")
@Tag("codec")
@Tag("p1")
@DisplayName("SmppFrameDecoder fuzz — CODEC-011 (arbitrary byte streams: no crash, bounded memory)")
class SmppFrameDecoderFuzzTest {

    private static final int MAX = SmppFrame.MAX_COMMAND_LENGTH;
    private static final int CHUNK = 7; // small enough that any multi-byte PDU triggers cumulation growth

    // ---------- harness (mirrors SmppFrameDecoderTest's; duplicated to keep this file standalone) ----------

    /** Records (and swallows) any exception the framer fires, so writeInbound does not re-throw. */
    private static final class ExceptionCapture extends ChannelInboundHandlerAdapter {
        private Throwable cause;

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            this.cause = cause; // swallow — the fuzz asserts on it directly
        }
    }

    /**
     * Records the largest capacity the framer drove through {@code ctx.alloc()} — i.e. its OWN allocations
     * (cumulation growth), NOT the fuzz input (which is minted by {@link Unpooled}).
     * {@code readRetainedSlice} (the framer's only happy-path emit) allocates nothing (it is a view), so a
     * non-zero {@code maxRequested} reflects cumulation growth, bounded by the AD-30 cap.
     */
    private static final class RecordingAllocator extends AbstractByteBufAllocator {
        private final ByteBufAllocator delegate;
        private int maxRequested;

        RecordingAllocator(ByteBufAllocator delegate) {
            super(true);
            this.delegate = delegate;
        }

        int maxRequested() {
            return maxRequested;
        }

        @Override
        protected ByteBuf newHeapBuffer(int initialCapacity, int maxCapacity) {
            recordCapacity(initialCapacity);
            return delegate.heapBuffer(initialCapacity, maxCapacity);
        }

        @Override
        protected ByteBuf newDirectBuffer(int initialCapacity, int maxCapacity) {
            recordCapacity(initialCapacity);
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

    /** Representative byte streams for regression mode (PR tier): the framer-relevant length/boundary shapes. */
    static Stream<Arguments> framerSeeds() {
        return Stream.of(
                Arguments.of(stream(40, 40)),                 // well-formed: decodes cleanly, chunked cumulation grows
                Arguments.of(stream(200, 200)),               // larger well-formed body: more cumulation growth
                Arguments.of(stream(70000, 20)),              // declared > MAX (65536): ceiling reject — no big alloc
                Arguments.of(stream(0xFFFFFFFF, 20)),         // overflow-class declared length: ceiling reject
                Arguments.of(stream(10, 16)),                 // declared < 16 (floor): reject once the length field is read
                Arguments.of(new byte[3]),                    // partial header (<4): framer waits, channel stays open
                Arguments.of(twoPduStream(40, 40)));          // two coalesced PDUs: exercises the decode loop
    }

    /** A byte stream whose first 4 octets encode {@code declaredLength} (the {@code command_length} the framer reads). */
    private static byte[] stream(int declaredLength, int totalBytes) {
        byte[] b = new byte[totalBytes];
        ByteBuffer.wrap(b).putInt(declaredLength);
        return b;
    }

    /** Two self-consistent PDUs concatenated (a coalesced TCP read). */
    private static byte[] twoPduStream(int firstLen, int secondLen) {
        byte[] b = new byte[firstLen + secondLen];
        ByteBuffer.wrap(b).putInt(firstLen).putInt(0x00000015).putInt(0).putInt(1);
        ByteBuffer.wrap(b, firstLen, secondLen).putInt(secondLen).putInt(0x00000015).putInt(0).putInt(2);
        return b;
    }

    /** The unsigned {@code command_length} declared in the first 4 octets, or {@code -1} if fewer than 4 are present. */
    private static long declaredLength(byte[] data) {
        if (data.length < Integer.BYTES) {
            return -1;
        }
        return (data[0] & 0xFFL) << 24 | (data[1] & 0xFFL) << 16 | (data[2] & 0xFFL) << 8 | (data[3] & 0xFFL);
    }

    @FuzzTest
    @MethodSource("framerSeeds")
    @DisplayName("CODEC-011: arbitrary byte stream -> no Throwable escapes, bounded memory, controlled close")
    void fuzzFramer(byte[] data) {
        ExceptionCapture capture = new ExceptionCapture();
        RecordingAllocator alloc = new RecordingAllocator(UnpooledByteBufAllocator.DEFAULT);
        EmbeddedChannel channel = new EmbeddedChannel(new SmppFrameDecoder(), capture);
        channel.config().setAllocator(alloc);

        try {
            // (1) No Throwable escapes decode: feed the stream in small chunks (each minted by Unpooled, so NOT
            //     counted by the recording allocator) so MERGE_CUMULATOR cumulation growth routes through
            //     ctx.alloc(); a reject on any chunk is routed to exceptionCaught (swallowed), never re-thrown.
            assertThatCode(() -> {
                for (int off = 0; off < data.length; off += CHUNK) {
                    if (!channel.isActive()) {
                        break; // once fail-closed, stop feeding the closed channel
                    }
                    channel.writeInbound(Unpooled.wrappedBuffer(data, off, Math.min(CHUNK, data.length - off)));
                }
            }).as("no Throwable escapes decode for any byte stream").doesNotThrowAnyException();

            // (2) Bounded memory: the framer's own cumulation-growth allocations never exceed cap × small factor —
            //     a malformed/oversize declared length drives no oversized/OOM allocation. Chunked feeding makes
            //     this non-trivial (a single writeInbound would leave maxRequested == 0).
            assertThat(alloc.maxRequested())
                    .as("no allocation driven by a (malformed) command_length exceeds cap × small factor")
                    .isLessThanOrEqualTo(MAX * 2);

            // (3) Controlled + oversize closure: an oversize declared length MUST fail-closed the channel (AD-30
            //     ceiling — not a silent drop), and ANY framer-driven close is a controlled DecoderException reject.
            long declared = declaredLength(data);
            if (declared > MAX) {
                assertThat(channel.isActive())
                        .as("an oversize declared length (%d) fail-closed the channel (AD-30 ceiling)", declared)
                        .isFalse();
            }
            if (!channel.isActive()) {
                assertThat(capture.cause)
                        .as("a framer-driven close is a controlled DecoderException reject")
                        .isNotNull()
                        .isInstanceOf(DecoderException.class);
            }

            // release any framed output the fuzz happened to produce
            Object out;
            while ((out = channel.readInbound()) != null) {
                if (out instanceof ByteBuf b) {
                    b.release();
                }
            }
        } finally {
            // finishAndReleaseAll releases the cumulation + any unread inbound.
            channel.finishAndReleaseAll();
        }
    }
}
