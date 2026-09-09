package smpp.companion.proxy.relay.netty;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Timeout.ThreadMode;

import io.netty.channel.Channel;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.util.concurrent.DefaultThreadFactory;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.observability.CapturingRelayObserver;
import smpp.companion.proxy.observability.CloseReason;
import smpp.companion.proxy.observability.Direction;
import smpp.companion.proxy.relay.IdleWatchdogHarness;
import smpp.companion.proxy.relay.RelayIngressHandler;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 4.4 T4 (F13 residue) — the FIRST direct {@link ConnectionCapHandler}-level coverage: the
 * cap-reclaim proof. The over-cap refusal itself was only ever observed through whole-app boots
 * (the lifecycle suites); this suite constructs the package-private handler DIRECTLY and drives it
 * the way Netty's acceptor does — {@code channelRead(SocketChannel)} on the server channel's
 * pipeline, carried here by an {@link EmbeddedChannel}.
 *
 * <p>The reclaim half glues two package-private seams that live on OPPOSITE sides of the package
 * boundary: the cap handler (this package) and the seam-carrying {@code BindInterceptor} whose
 * {@code ChannelTimer} test constructor lives in {@code relay/} — that side is bridged by
 * {@link IdleWatchdogHarness}. The accepted children are REAL {@code NioSocketChannel}s over a
 * loopback listener, registered on a real one-thread loop (so {@code channelActive} genuinely fires
 * and the watchdog's close genuinely completes the closeFuture the cap's release rides), while the
 * watchdog itself is FIRED from the captured task — the deterministic-seam idiom, no wall-clock
 * idle waits.
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
@Timeout(value = 30, threadMode = ThreadMode.SEPARATE_THREAD) // real sockets + a real loop: bound the
// rig so a wedged accept/register surfaces as a failure, never a silent hang
class ConnectionCapHandlerTest {

    /** The cap under test: {@code companion.memory.concurrent-pairs} at the common()/matrix minimum. */
    private static final int CAP = 1;

    private final List<SocketChannel> clientSides = new ArrayList<>();
    private final List<NioSocketChannel> children = new ArrayList<>();
    private ServerSocketChannel listener;
    private MultiThreadIoEventLoopGroup loop;
    private EmbeddedChannel server;

    @AfterEach
    void releaseEverything() {
        // Exception-safe teardown (the house rule): every socket/channel/loop this rig opened is
        // closed even when an assertion threw mid-row — nothing strands the test JVM.
        for (SocketChannel client : clientSides) {
            try {
                client.close();
            } catch (Exception ignored) {
                // teardown only
            }
        }
        for (NioSocketChannel child : children) {
            try {
                child.unsafe().closeForcibly(); // works on the never-registered children too
            } catch (Exception ignored) {
                // teardown only
            }
        }
        if (server != null) {
            server.finishAndReleaseAll();
        }
        if (loop != null) {
            loop.shutdownGracefully(0, 100, TimeUnit.MILLISECONDS).syncUninterruptibly();
        }
        if (listener != null) {
            try {
                listener.close();
            } catch (Exception ignored) {
                // teardown only
            }
        }
    }

    @Test
    @DisplayName("F13 residue (Story 4.4 T4): a never-binding socket holds its concurrent-pairs slot until "
            + "the pre-couple idle watchdog closes it — the closeFuture-riding release admits the next accept")
    void idleWatchdogReclaimReleasesTheCapSlotForTheNextAccept() throws Exception {
        listener = ServerSocketChannel.open();
        listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        loop = new MultiThreadIoEventLoopGroup(1, new DefaultThreadFactory("cap-reclaim-rig"), NioIoHandler.newFactory());
        IdleWatchdogHarness rig = new IdleWatchdogHarness(
                RelayTestFixtures.modeBProperties(RelayTestFixtures.freePort(), 1));
        // The server channel's pipeline carrier: Netty's acceptor fires channelRead(SocketChannel)
        // through exactly this shape — the handler admits/refuses on it, forwarding an admitted
        // accept to Netty's ServerBootstrapAcceptor (the EmbeddedChannel's inbound queue stands in).
        server = new EmbeddedChannel(new ConnectionCapHandler(CAP));

        // (1) A real accepted, REGISTERED socket carrying the real ingress pipeline: registration
        // fired channelActive, so the idle watchdog is ALREADY armed (the first capture).
        NioSocketChannel first = acceptedRegistered(listener, loop, rig);
        assertThat(server.writeInbound(first))
                .as("the first accept is admitted — the slot is live")
                .isTrue();
        // writeInbound reports the CUMULATIVE inbound queue, so drain each admitted accept out of it
        // (identity check doubles as the forwarded-to-Netty's-acceptor pin — the refused writes below
        // must return false on their OWN, not inherit an occupied queue).
        assertThat(server.<Channel>readInbound())
                .as("the admitted accept is forwarded to Netty's ServerBootstrapAcceptor")
                .isSameAs(first);
        assertThat(rig.tasks())
                .as("the watchdog is armed at channelActive (T4) — the arm the reclaim rides")
                .hasSize(1);
        assertThat(rig.delays().get(0))
                .as("armed at the configured companion.bind.pre-couple-idle-timeout millis")
                .isEqualTo(RelayTestFixtures.DEFAULT_PRE_COUPLE_IDLE_TIMEOUT.toMillis());

        // (2) The socket never binds — nothing is ever sent — and it still holds the only slot: the
        // second accept is refused (closed forcibly, never reaching a child pipeline).
        NioSocketChannel second = accepted(listener);
        assertThat(server.writeInbound(second))
                .as("the never-binding socket still holds the cap: the second accept is refused (F13)")
                .isFalse();
        assertThat(second.isOpen())
                .as("the refused accept is closed forcibly, unregistered")
                .isFalse();

        // (3) The idle window elapses: fire the captured watchdog ON THE OWNING LOOP (production
        // fidelity — the loop is what fires it in a real boot) → the uniform pre-couple bare close.
        first.eventLoop().submit(rig.tasks().get(0)).syncUninterruptibly();
        assertThat(first.closeFuture().await(5, TimeUnit.SECONDS))
                .as("the watchdog's bare close completed — the closeFuture the cap's release rides")
                .isTrue();
        // Netty fires channelInactive via invokeLater (queued, AFTER the closeFuture completes), so
        // one more FIFO barrier makes the close observation deterministic before it is asserted.
        first.eventLoop().submit(() -> { }).syncUninterruptibly();
        assertThat(first.isOpen()).isFalse();
        assertThat(rig.observer().connectionCloses())
                .as("the close was the uniform pre-couple bare close (enum-identical, the T4 WARN "
                        + "line distinguishes the cause) — tying the reclaim to the watchdog's close")
                .containsExactly(new CapturingRelayObserver.ConnectionClose(
                        Direction.INGRESS, CloseReason.PRE_COUPLE_NON_BIND_PDU));

        // (4) The slot was reclaimed BY THAT CLOSE: the next accept is admitted again.
        NioSocketChannel third = accepted(listener);
        assertThat(server.writeInbound(third))
                .as("the reclaimed slot admits the next accept — the release rode the watchdog's close")
                .isTrue();
        assertThat(server.<Channel>readInbound())
                .as("the reclaimed-slot accept is the one forwarded to Netty's acceptor")
                .isSameAs(third);
    }

    // ---------- rig: real accepted NioSocketChannels over the loopback listener -----------------------

    /**
     * One accepted {@link SocketChannel} pair (a blocking client side that stays open + the wrapped
     * server side), NOT registered — the refused-accept shape (the cap closes it before any
     * registration could happen).
     */
    private NioSocketChannel accepted(ServerSocketChannel listener) throws Exception {
        clientSides.add(SocketChannel.open((InetSocketAddress) listener.getLocalAddress()));
        NioSocketChannel child = new NioSocketChannel(listener.accept());
        children.add(child);
        return child;
    }

    /**
     * One accepted pair carrying the REAL ingress pipeline (framer → codec → the harness's
     * seam-carrying interceptor → the relay handler), registered on the loop: registration of a
     * connected channel fires {@code channelActive} on the loop thread, arming the watchdog. The
     * trailing no-op submit is the FIFO barrier that makes the arm OBSERVABLE before this method
     * returns — {@code register0} completes its promise BEFORE firing channelActive, so the
     * promise's {@code sync} alone does not order the arm.
     */
    private NioSocketChannel acceptedRegistered(
            ServerSocketChannel listener, MultiThreadIoEventLoopGroup loop, IdleWatchdogHarness rig) throws Exception {
        clientSides.add(SocketChannel.open((InetSocketAddress) listener.getLocalAddress()));
        NioSocketChannel child = new NioSocketChannel(listener.accept());
        children.add(child);
        child.pipeline().addLast(
                new SmppFrameDecoder(), new SmppCodec(), rig.newInterceptor(),
                new RelayIngressHandler(rig.manager(), rig.observer()));
        loop.register(child).syncUninterruptibly();
        child.eventLoop().submit(() -> { }).syncUninterruptibly();
        return child;
    }
}
