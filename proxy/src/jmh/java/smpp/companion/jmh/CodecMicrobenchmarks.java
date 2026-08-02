package smpp.companion.jmh;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AsciiString;
import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import smpp.companion.codec.bind.SmppBindEncoder;
import smpp.companion.codec.bind.SmppBindRequest;
import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrameDecoder;

/**
 * PERF-001 / PERF-002 / PERF-003 (AC8) — JMH microbenchmarks for the codec's three hot paths: bind-family
 * encode, bind-family decode, and generic length-framing. Throughput (ops/s/core) bands are
 * CHARACTERIZATION targets recorded from a {@code ./gradlew :proxy:jmh} run. PERF-006's unit allocation guard
 * is the SOLE durable in-CI guard (a unit test in {@code :codec:test}); PERF-005's fork-variance CoV&lt;5% /
 * warmup-convergence is a MANUAL characterization from such a run, not an in-CI assertion (no CoV gate exists,
 * and the {@code :proxy:jmh} task is nightly-tier — not wired into {@code build}/{@code check} (AC8), so a JMH
 * breakage cannot fail the PR build).
 *
 * <p><b>Spec reconciliation (see the Story 1.2 Dev Agent Record):</b> PERF-001/002 name {@code submit_sm},
 * but the codec is BIND-ONLY (AD-3/AD-7/AD-32 — {@link SmppCodec} parses only {@link SmppCommandIds#BIND_FAMILY}
 * and {@link SmppBindEncoder} is the codec's only encode path). AC8 pins {@code "input = golden-vector
 * bytes"} while AC5 makes the golden corpus bind-only, so PERF-001/002 bench the codec's REAL encode/decode
 * surfaces on the golden {@code bind_transceiver} all-fields vector. PERF-003 honors {@code submit_sm}
 * literally where it is valid — framing is PDU-agnostic (the framer reads only {@code command_length}), and
 * {@code submit_sm} is the high-volume PDU the framer sees per-PDU for a connection's lifetime.
 *
 * <p>Inputs are constructed in the @State (field-initialized). PERF-001 (encode) introduces no allocation into
 * the measured path beyond the encode output buffer (the subject of the measurement); PERF-002/PERF-003
 * (decode/frame) feed the EmbeddedChannel via {@code goldenFrame.retainedDuplicate()} /
 * {@code submitFrame.retainedDuplicate()} per invocation — a NECESSARY per-op wrapper allocation
 * ({@link SmppCodec} and {@link SmppFrameDecoder} release their input after decode, so the shared @State buffer
 * cannot be fed directly) that is harness overhead in PERF-004's {@code -prof gc} count, not codec allocation.
 * Each emitted buffer is Blackholed then released to keep the fork from exhausting memory across millions of
 * operations. Forks carry {@code --enable-preview} to match the process-wide compile flag.
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 2, jvmArgsAppend = {"--enable-preview"})
@Warmup(iterations = 5, time = 1) // 5 points so the warmup series can show flattening (PERF-005 convergence)
@Measurement(iterations = 3, time = 1)
@Threads(1)
@State(Scope.Thread)
public class CodecMicrobenchmarks {

    /** The golden bind_transceiver all-fields vector (codec/src/test/resources/golden-vectors/…). */
    private static final byte[] GOLDEN_BIND_TRANSCEIVER = HexFormat.of().parseHex(
            "0000002900000009000000000000002a"
                    + "45534d455f3030310073656372657400534d50500034000000");

    /** A submit_sm-shaped opaque PDU: command_length 64, command_id 0x00000004, then a 48-byte body the framer never reads. */
    private static final byte[] SUBMIT_SM_FRAME = submitSmFrame();

    private final SmppBindRequest encodeInput = allFieldsBindTransceiver();
    private final EmbeddedChannel codecChannel = new EmbeddedChannel(new SmppCodec());
    private final EmbeddedChannel frameChannel = new EmbeddedChannel(new SmppFrameDecoder());
    private final ByteBuf goldenFrame = Unpooled.wrappedBuffer(GOLDEN_BIND_TRANSCEIVER);
    private final ByteBuf submitFrame = Unpooled.wrappedBuffer(SUBMIT_SM_FRAME);

    /** PERF-001 — bind encode: {@link SmppBindEncoder} produces one framed ByteBuf (the result is Blackholed). */
    @Benchmark
    public void encodeBindRequest(Blackhole bh) {
        ByteBuf encoded = SmppBindEncoder.encode(encodeInput, PooledByteBufAllocator.DEFAULT);
        bh.consume(encoded);
        encoded.release();
    }

    /** PERF-002 — bind decode: {@link SmppCodec} parses the golden framed bind into a typed PDU (the decoded object is Blackholed). */
    @Benchmark
    public void decodeBindRequest(Blackhole bh) {
        codecChannel.writeInbound(goldenFrame.retainedDuplicate());
        SmppBindRequest pdu = codecChannel.readInbound();
        if (pdu != null) {
            // Consuming the decoded object alone defeats DCE for the whole decode: every field is a record
            // constructor argument, so the {@link SmppCodec} field-reads (SmppBytes.readAscii/readByte) MUST
            // execute for `pdu` to exist. Per-field bh.consume(...) would be redundant harness overhead (JMH:
            // passing the aggregate to the Blackhole is sufficient). release() handles the retained-slice refcount.
            bh.consume(pdu);
            pdu.originalFrame().release();
        }
    }

    /** PERF-003 — generic framing: {@link SmppFrameDecoder} frames one submit_sm per invocation (the per-PDU hot path). */
    @Benchmark
    public void frameSubmitSm(Blackhole bh) {
        frameChannel.writeInbound(submitFrame.retainedDuplicate());
        ByteBuf framed = frameChannel.readInbound();
        if (framed != null) {
            bh.consume(framed);
            framed.release();
        }
    }

    @TearDown
    public void tearDown() {
        codecChannel.finishAndReleaseAll();
        frameChannel.finishAndReleaseAll();
        goldenFrame.release();
        submitFrame.release();
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

    private static byte[] submitSmFrame() {
        byte[] b = new byte[64];
        ByteBuffer.wrap(b)
                .putInt(64) // command_length
                .putInt(0x00000004) // command_id = submit_sm
                .putInt(0) // command_status
                .putInt(1); // sequence_number; body bytes 16..63 stay zero (the framer never reads them)
        return b;
    }
}
