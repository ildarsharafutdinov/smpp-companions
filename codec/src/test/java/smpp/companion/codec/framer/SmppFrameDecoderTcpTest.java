package smpp.companion.codec.framer;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CODEC-034..036: the framer over a REAL loopback TCP socket pair (not {@code ByteBuf} slices). Only a
 * real socket exercises actual TCP segmentation/coalescing and the half-close path. The reader side is a
 * Netty {@link NioServerSocketChannel} pipeline carrying {@link SmppFrameDecoder}; the writer is a raw
 * {@link Socket} with {@code TCP_NODELAY} so split writes surface as separate segments (loopback may still
 * coalesce them — but the framer's reassembly invariant holds either way, which is what is asserted).
 *
 * <p>Determinism: every wait is a {@link CountDownLatch#await} with a generous timeout (no {@code Thread.sleep});
 * a real defect fails the latch rather than hanging the build.
 */
@Tag("conformance")
@Tag("codec")
@Tag("p1")
@DisplayName("SmppFrameDecoder — real loopback TCP reassembly (CODEC-034..036)")
class SmppFrameDecoderTcpTest {

    private static final int HEADER = 16;
    private static final long AWAIT_SECONDS = 10;

    /** Collects framed {@code ByteBuf}s as byte arrays; latches on N frames and on channel-inactive. */
    private static final class FrameCollector extends SimpleChannelInboundHandler<ByteBuf> {
        final List<byte[]> frames = Collections.synchronizedList(new ArrayList<>());
        final CountDownLatch framesLatch;
        final CountDownLatch closed = new CountDownLatch(1);

        FrameCollector(int expectedFrames) {
            this.framesLatch = new CountDownLatch(expectedFrames);
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
            byte[] copy = new byte[msg.readableBytes()];
            msg.getBytes(msg.readerIndex(), copy);
            frames.add(copy);
            framesLatch.countDown();
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            closed.countDown();
            super.channelInactive(ctx);
        }
    }

    /** A loopback Netty server on an ephemeral port with the framer + collector in its child pipeline. */
    private static final class TcpServer implements AutoCloseable {
        private final EventLoopGroup group;
        private final Channel serverChannel;
        final int port;

        TcpServer(FrameCollector collector) throws Exception {
            // Netty 4.2 transport API: NioEventLoopGroup is deprecated — use MultiThreadIoEventLoopGroup
            // backed by an NioIoHandler. Single thread -> deterministic frame ordering.
            this.group = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
            this.serverChannel = new ServerBootstrap()
                    .group(group)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ch.pipeline().addLast(new SmppFrameDecoder(), collector);
                        }
                    })
                    .bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                    .sync()
                    .channel();
            this.port = ((InetSocketAddress) serverChannel.localAddress()).getPort();
        }

        @Override
        public void close() {
            serverChannel.close().syncUninterruptibly();
            group.shutdownGracefully(0, 5, TimeUnit.SECONDS).awaitUninterruptibly();
        }
    }

    private static Socket connect(int port) throws Exception {
        Socket socket = new Socket();
        socket.setTcpNoDelay(true); // disable Nagle so split writes become separate segments
        socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
        return socket;
    }

    // ---------- byte helpers ----------

    /** A complete PDU (16-byte header + body) as a byte array, command_length == HEADER + body.length. */
    private static byte[] pdu(int commandId, byte[] body) {
        int length = HEADER + body.length;
        ByteBuf buf = Unpooled.buffer(length);
        buf.writeInt(length).writeInt(commandId).writeInt(0).writeInt(1).writeBytes(body);
        byte[] out = new byte[buf.readableBytes()];
        buf.getBytes(0, out);
        buf.release();
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) {
            total += p.length;
        }
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    private static byte[] half(byte[] pdu) {
        return Arrays.copyOfRange(pdu, 0, pdu.length / 2);
    }

    private static byte[] rest(byte[] pdu) {
        return Arrays.copyOfRange(pdu, pdu.length / 2, pdu.length);
    }

    // ---------- CODEC-034: split at every byte boundary reassembles one frame ----------

    @Test
    @DisplayName("CODEC-034: a PDU split at every byte boundary over a real socket reassembles into one frame")
    void pduSplitAtEveryByteBoundary_realSocket_reassemblesToOneFrame() throws Exception {
        byte[] pdu = pdu(0x00000015, new byte[]{1, 2, 3, 4}); // 20-byte PDU (enquire_link + 4-byte body)

        for (int split = 0; split <= pdu.length; split++) {
            FrameCollector collector = new FrameCollector(1);
            try (TcpServer server = new TcpServer(collector);
                 Socket socket = connect(server.port)) {
                OutputStream out = socket.getOutputStream();
                out.write(pdu, 0, split);
                out.flush();
                out.write(pdu, split, pdu.length - split);
                out.flush();

                assertThat(collector.framesLatch.await(AWAIT_SECONDS, TimeUnit.SECONDS))
                        .as("split=%d: one frame received", split)
                        .isTrue();
            }
            assertThat(collector.frames).as("split=%d: exactly one frame", split).hasSize(1);
            assertThat(collector.frames.get(0))
                    .as("split=%d: byte-identical reassembly", split)
                    .isEqualTo(pdu);
        }
    }

    // ---------- CODEC-035: interleaved multi-PDU + partials reassemble in order ----------

    @Test
    @DisplayName("CODEC-035: interleaved PDUs and partial fragments over a real socket reassemble in order")
    void interleavedPdusAndPartials_realSocket_reassembleInOrder() throws Exception {
        byte[] p1 = pdu(0x00000001, new byte[]{0xA});             // bind_receiver
        byte[] p2 = pdu(0x00000002, new byte[]{0xB, 0xB});        // bind_transmitter
        byte[] p3 = pdu(0x00000009, new byte[]{0xC, 0xC, 0xC});   // bind_transceiver
        byte[] p4 = pdu(0x00000006, new byte[]{0xD, 0xD});        // unbind

        FrameCollector collector = new FrameCollector(4);
        try (TcpServer server = new TcpServer(collector);
             Socket socket = connect(server.port)) {
            OutputStream out = socket.getOutputStream();
            // write 1: PDU1 fully
            out.write(p1);
            out.flush();
            // write 2: PDU2 fully + first half of PDU3 (coalesced, mid-PDU3 boundary)
            out.write(concat(p2, half(p3)));
            out.flush();
            // write 3: second half of PDU3 + PDU4 fully (coalesced)
            out.write(concat(rest(p3), p4));
            out.flush();

            assertThat(collector.framesLatch.await(AWAIT_SECONDS, TimeUnit.SECONDS))
                    .as("four frames received").isTrue();
        }
        assertThat(collector.frames)
                .as("frames in arrival order, byte-exact")
                .containsExactly(p1, p2, p3, p4);
    }

    // ---------- CODEC-036: writer closes mid-PDU -> no truncated frame, clean close ----------

    @Test
    @DisplayName("CODEC-036: writer closes mid-PDU -> reader emits no truncated frame and sees a clean close")
    void writerClosesMidPdu_noTruncatedFrameCleanClose() throws Exception {
        byte[] p1 = pdu(0x00000015, new byte[]{1, 2});          // a full first PDU
        byte[] p2 = pdu(0x00000006, new byte[]{3, 4, 5, 6, 7}); // a second PDU whose tail is never sent

        FrameCollector collector = new FrameCollector(1); // expect ONLY the first frame
        try (TcpServer server = new TcpServer(collector);
             Socket socket = connect(server.port)) {
            OutputStream out = socket.getOutputStream();
            out.write(p1);
            out.flush();
            out.write(half(p2)); // half of PDU2, then the writer vanishes
            out.flush();
            socket.shutdownOutput(); // TCP half-close: signal EOF to the reader (mid-PDU)

            // Awaits run WHILE the server is alive (closing the socket/server before the read loop
            // drains the kernel buffer would RST-drop the in-flight bytes). The complete first PDU is
            // framed before the FIN is processed...
            assertThat(collector.framesLatch.await(AWAIT_SECONDS, TimeUnit.SECONDS))
                    .as("the complete first PDU was framed").isTrue();
            // ...then the reader processes the close (decodeLast path) with no truncated second frame.
            assertThat(collector.closed.await(AWAIT_SECONDS, TimeUnit.SECONDS))
                    .as("the reader saw the channel close").isTrue();
            assertThat(collector.frames)
                    .as("no truncated frame synthesized from the leftover partial bytes")
                    .hasSize(1);
            assertThat(collector.frames.get(0)).isEqualTo(p1);
        }
    }
}
