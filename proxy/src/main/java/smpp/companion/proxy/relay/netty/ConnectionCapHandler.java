package smpp.companion.proxy.relay.netty;

import java.util.concurrent.atomic.AtomicInteger;

import lombok.extern.slf4j.Slf4j;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.socket.SocketChannel;

/**
 * F13 (Story 3.3) — the accepted-connection cap at the ACCEPTOR: once {@code
 * companion.memory.concurrent-pairs} legs are live, every further accept is REFUSED (immediate
 * close + a WARN log — AD-11 over-cap refusal; no response PDU, no observer fire — pre-bind
 * identity is untrusted and the observer seam is bind-scoped anyway). Rides the SERVER channel's
 * pipeline ({@code ServerBootstrap.handler(...)} — ahead of Netty's acceptor, so a refused
 * connection never reaches the child pipeline). The cap IS the AD-30 budget input itself (every
 * accepted connection can become a budgeted coupled pair — one number, no separate bind knob).
 *
 * <p><b>Counting:</b> an {@link AtomicInteger} incremented per accepted {@link SocketChannel},
 * decremented exactly once on the child's {@code closeFuture} (which fires exactly once per
 * channel — no double-decrement window). A refused child decrements immediately and is closed
 * WITHOUT being forwarded to Netty's acceptor. Not {@code @Sharable}: exactly one instance per
 * acceptor {@code start()}.
 */
@Slf4j
@SuppressWarnings("FutureReturnValueIgnored") // reason: child.close() on a REFUSED accept is
// fire-and-forget — the close future can only fail on an already-closed socket (the desired end
// state); nothing is observable from it here.
final class ConnectionCapHandler extends ChannelInboundHandlerAdapter {

    private final int maxConnections;
    private final AtomicInteger live = new AtomicInteger();

    ConnectionCapHandler(int maxConnections) {
        this.maxConnections = maxConnections;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (!(msg instanceof SocketChannel child)) {
            ctx.fireChannelRead(msg); // not an accept (defensive) — pass through untouched
            return;
        }
        if (live.incrementAndGet() > maxConnections) {
            live.decrementAndGet(); // this connection never counts — it is refused
            // F13/AD-11: over-cap accept — refuse (close + log). No PDU, no observer, no counter
            // label (AD-19's cardinality rule; metrics are Epic 4 regardless).
            log.warn("connection refused: companion.memory.concurrent-pairs={} is exhausted (F13 cap) — closing {}",
                    maxConnections, child.remoteAddress());
            // closeForcibly (NOT close()): the accepted channel is NOT yet registered on an event
            // loop here — Netty's own ServerBootstrapAcceptor failure path uses exactly this for the
            // same unregistered-child situation (close()'s promise creation would throw
            // "channel not registered to an event loop").
            child.unsafe().closeForcibly();
            return;
        }
        child.closeFuture().addListener(future -> live.decrementAndGet()); // fires exactly once
        ctx.fireChannelRead(msg); // hand the accept to Netty's ServerBootstrapAcceptor
    }
}
