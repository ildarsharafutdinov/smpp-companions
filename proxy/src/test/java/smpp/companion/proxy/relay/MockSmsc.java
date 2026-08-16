package smpp.companion.proxy.relay;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

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
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.util.concurrent.DefaultThreadFactory;

import smpp.companion.codec.bind.SmppBindPdu;
import smpp.companion.codec.bind.SmppBindRequest;
import smpp.companion.codec.bind.SmppBindResponse;
import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrameDecoder;

/**
 * The T9 in-JVM mock SMSC (AD-24; RELAY-011's prescribed tooling) — an embedded Netty server on the
 * <b>PRODUCTION codec</b> ({@code SmppFrameDecoder → SmppCodec}, per-channel instances), accepting
 * bind requests and answering ROK, capturing every forwarded PDU's bytes for byte-exact assertion,
 * and letting the test inject a {@code deliver_sm} on the exact SMSC socket that received a given
 * bind (the carrier-side session-affinity EMULATION).
 *
 * <p><b>NEVER an oracle for A-1 or codec correctness.</b> This mock shares the production codec's
 * bugs AND assumes A-1 (it delivers on the socket it chooses, by construction): it validates the
 * RELAY's pair-isolation mechanics, not the carrier's affinity behavior and not the codec's
 * conformance. The independent CI oracle is the T10 jSMPP server-side mock; the only genuine A-1
 * falsification is the non-CI real-carrier plan ({@code docs/a-1-carrier-test-plan.md},
 * OBS-035/036/037).
 *
 * <p><b>Programming surface (the subtask's "programs" list):</b>
 * <ul>
 *   <li>N concurrent binds under one {@code system_id} (or many) — every {@link SmppBindRequest} is
 *       answered {@code ESME_ROK} with the matching response {@code command_id} + the request's
 *       {@code sequence_number}; one accepted TCP connection = one {@link Session}.</li>
 *   <li>{@code deliver_sm} injection per session socket — {@link Session#deliver(byte[])} writes the
 *       caller's framed bytes on THAT session's channel (the affinity emulation: whatever socket
 *       received the bind is the socket the DLR leaves on).</li>
 *   <li>Injectable delay/stall — {@link #start(long)} delays every bind response by the given
 *       millis; {@link #stallBinds()} / {@link #releaseBinds()} hold responses on a gate
 *       (non-blocking: the response is chained on a {@link CompletableFuture}, never an event-loop
 *       block).</li>
 *   <li>Byte-exact captures — {@link Session#bindFrame()} (the relay's AD-14 verbatim forward) and
 *   {@link Session#received()} (every spliced PDU, one entry per framed PDU: the mock's own
 *   production framer guarantees the boundary).</li>
 * </ul>
 *
 * <p>Test-tier only ({@code proxy/src/test}); the mock's socket is plaintext loopback (TLS is Epic 3).
 */
@SuppressWarnings("FutureReturnValueIgnored") // reason: writeAndFlush()/close() on the mock's own
// channels are fire-and-forget — a failed write/close merely means the peer already went away (the
// desired end state for a mock); Netty releases a buffer whose write fails.
public final class MockSmsc implements AutoCloseable {

    /** Bounded-poll deadline for the await helpers (generous for a loaded CI runner). */
    private static final long AWAIT_TIMEOUT_MILLIS = 5_000;

    private final EventLoopGroup group;
    private final long bindResponseDelayMillis;
    private final List<Session> sessions = new CopyOnWriteArrayList<>();
    /** The injectable stall: bind responses chain on this gate (completed = no stall). */
    private volatile CompletableFuture<Void> bindGate = CompletableFuture.completedFuture(null);
    private volatile Channel serverChannel;

    private MockSmsc(EventLoopGroup group, long bindResponseDelayMillis) {
        this.group = group;
        this.bindResponseDelayMillis = bindResponseDelayMillis;
    }

    /**
     * Starts the mock on a free loopback ephemeral port, delaying every bind response by
     * {@code bindResponseDelayMillis} (0 = answer immediately; the injectable delay).
     */
    public static MockSmsc start(long bindResponseDelayMillis) {
        EventLoopGroup group = new MultiThreadIoEventLoopGroup(
                1, new DefaultThreadFactory("mock-smsc"), NioIoHandler.newFactory());
        MockSmsc mock = new MockSmsc(group, bindResponseDelayMillis);
        ServerBootstrap bootstrap = new ServerBootstrap()
                .group(group)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<Channel>() {
                    @Override
                    protected void initChannel(Channel ch) {
                        // The production codec, per-channel instances (CODEC-014) — the mock is NOT a
                        // second codec implementation (that would make it a codec oracle; it is not).
                        ch.pipeline().addLast(new SmppFrameDecoder(), new SmppCodec(), new MockSmscHandler(mock));
                    }
                });
        try {
            mock.serverChannel = bootstrap
                    .bind(InetAddress.getLoopbackAddress(), 0)
                    .syncUninterruptibly()
                    .channel();
        } catch (RuntimeException e) {
            group.shutdownGracefully(0, 500, TimeUnit.MILLISECONDS);
            throw e;
        }
        return mock;
    }

    /** Convenience overload: answer binds immediately. */
    public static MockSmsc start() {
        return start(0);
    }

    /** The loopback port the mock's acceptor bound. */
    public int port() {
        return ((java.net.InetSocketAddress) serverChannel.localAddress()).getPort();
    }

    /** Holds every subsequent bind response until {@link #releaseBinds()} (the injectable stall). */
    public void stallBinds() {
        this.bindGate = new CompletableFuture<>();
    }

    /** Releases a {@link #stallBinds()} gate (a no-op on an open gate). */
    public void releaseBinds() {
        bindGate.complete(null);
    }

    /** The accepted sessions in accept order (session i = the i-th connection the relay opened). */
    public List<Session> sessions() {
        return List.copyOf(sessions);
    }

    /** Waits (bounded) for the i-th session to exist, then returns it. */
    public Session awaitSession(int index) {
        pollUntil(() -> sessions.size() > index);
        return sessions.get(index);
    }

    @Override
    public void close() {
        Channel acceptor = serverChannel;
        if (acceptor != null) {
            acceptor.close().syncUninterruptibly();
        }
        // A mock owes no graceful drain — quiesce immediately so the suite stays fast.
        group.shutdownGracefully(0, 500, TimeUnit.MILLISECONDS).syncUninterruptibly();
    }

    private Session newSession(Channel channel) {
        Session session = new Session(channel);
        sessions.add(session);
        return session;
    }

    /** Chains the ROK response on delay-then-gate (both non-blocking on the event loop). */
    private void scheduleBindResponse(Channel channel, int requestCommandId, int sequenceNumber) {
        CompletableFuture<Void> ready = bindResponseDelayMillis <= 0
                ? CompletableFuture.completedFuture(null)
                : CompletableFuture.supplyAsync(
                        () -> null, CompletableFuture.delayedExecutor(bindResponseDelayMillis, TimeUnit.MILLISECONDS));
        ready.thenCompose(_ -> bindGate).thenRun(() -> {
            if (channel.isActive()) { // a stalled-then-abandoned bind answers nothing
                channel.writeAndFlush(bindResponse(requestCommandId, sequenceNumber));
            }
        });
    }

    /** A hand-authored ROK {@code bind_*_resp}: header + {@code system_id} C-octet (decodes clean). */
    private static ByteBuf bindResponse(int requestCommandId, int sequenceNumber) {
        int responseId = switch (requestCommandId) {
            case SmppCommandIds.BIND_RECEIVER -> SmppCommandIds.BIND_RECEIVER_RESP;
            case SmppCommandIds.BIND_TRANSMITTER -> SmppCommandIds.BIND_TRANSMITTER_RESP;
            case SmppCommandIds.BIND_TRANSCEIVER -> SmppCommandIds.BIND_TRANSCEIVER_RESP;
            default -> throw new IllegalArgumentException(
                    "not a bind-family request command_id: 0x" + Integer.toHexString(requestCommandId));
        };
        byte[] systemId = "SMSC01".getBytes(StandardCharsets.US_ASCII);
        int commandLength = 16 + systemId.length + 1;
        return Unpooled.buffer(commandLength)
                .writeInt(commandLength)
                .writeInt(responseId)
                .writeInt(0) // ESME_ROK
                .writeInt(sequenceNumber)
                .writeBytes(systemId)
                .writeByte(0);
    }

    /** Bounded poll — the mock's await discipline (never an unbounded sleep in a test). */
    static void pollUntil(BooleanSupplier condition) {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(AWAIT_TIMEOUT_MILLIS);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new IllegalStateException("mock SMSC condition not reached within " + AWAIT_TIMEOUT_MILLIS + "ms");
            }
            sleepQuietly(10);
        }
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while awaiting the mock SMSC", e);
        }
    }

    /** One accepted SMSC-side connection: the socket that received a bind, its captures, its injector. */
    public static final class Session {

        private final Channel channel;
        private final List<byte[]> received = new CopyOnWriteArrayList<>();
        private volatile byte[] bindFrame = new byte[0];

        private Session(Channel channel) {
            this.channel = channel;
        }

        /** The bind request bytes the relay forwarded (AD-14 verbatim, captured pre-release). */
        public byte[] bindFrame() {
            return bindFrame;
        }

        /** Every framed PDU the relay spliced onto THIS SMSC socket, in arrival order. */
        public List<byte[]> received() {
            return List.copyOf(received);
        }

        /** Waits (bounded) for at least {@code n} captured PDUs, then returns the captures. */
        public List<byte[]> awaitPdus(int n) {
            pollUntil(() -> received.size() >= n);
            return received();
        }

        /** Waits (bounded) for the bind to have arrived on this socket. */
        public void awaitBind() {
            pollUntil(() -> bindFrame.length > 0);
        }

        /** True once the SMSC-side socket has gone inactive (the relay tore the pair down). */
        public boolean closed() {
            return !channel.isActive();
        }

        /** Injects framed bytes on THIS session's socket — the carrier-affinity emulation. */
        public void deliver(byte[] framedPdu) {
            channel.writeAndFlush(Unpooled.wrappedBuffer(framedPdu));
        }

        /**
         * Injects several framed PDUs in ONE coalesced write — the receiving side's framer must
         * reassemble the boundaries (REL-1's "boundaries preserved" probe).
         */
        public void deliverAll(byte[] framedPdus) {
            channel.writeAndFlush(Unpooled.wrappedBuffer(framedPdus));
        }

        void recordBind(byte[] frame) {
            this.bindFrame = frame;
        }

        void recordPdu(byte[] frame) {
            received.add(frame);
        }
    }

    /** The per-connection SMSC behavior: answer binds ROK, capture everything, nothing else. */
    private static final class MockSmscHandler extends SimpleChannelInboundHandler<Object> {

        private final MockSmsc mock;
        private Session session;

        private MockSmscHandler(MockSmsc mock) {
            this.mock = mock;
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) {
            session = mock.newSession(ctx.channel());
            ctx.fireChannelActive();
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, Object msg) {
            if (msg instanceof SmppBindRequest req) {
                // Capture a COPY, then release the retained frame (the decoded record is not
                // refcounted — the base class's auto-release is a no-op on it).
                byte[] frame = new byte[req.originalFrame().readableBytes()];
                req.originalFrame().getBytes(req.originalFrame().readerIndex(), frame);
                session.recordBind(frame);
                req.originalFrame().release();
                mock.scheduleBindResponse(ctx.channel(), req.commandId(), req.sequenceNumber());
            } else if (msg instanceof SmppBindResponse) {
                // A response PDU from the ESME side is a direction violation — capture nothing.
                ((SmppBindPdu) msg).originalFrame().release();
            } else {
                // Opaque spliced PDU (submit_sm etc.): capture the bytes; the base class's
                // auto-release owns the ByteBuf.
                ByteBuf frame = (ByteBuf) msg;
                byte[] bytes = new byte[frame.readableBytes()];
                frame.getBytes(frame.readerIndex(), bytes);
                session.recordPdu(bytes);
            }
        }
    }
}
