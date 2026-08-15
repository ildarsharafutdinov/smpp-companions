package smpp.companion.proxy.relay.netty;

import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;

import smpp.companion.proxy.bootstrap.ProxyCompanionLifecycle;
import smpp.companion.proxy.config.ProxyCompanionProperties;

/**
 * The relay's SMPP acceptor {@link SmartLifecycle} (AC4; AD-1/AD-2/AD-16) — the 2nd
 * {@code SmartLifecycle} in the application, with an EXPLICIT phase so it stops BEFORE
 * {@link ProxyCompanionLifecycle}: AD-22's first shutdown step is "stop the Netty SMPP acceptor (no
 * new binds)", and Spring stops higher-phase beans first ({@link #RELAY_ACCEPTOR_PHASE} &gt;
 * {@link ProxyCompanionLifecycle#APP_PHASE} — the deferred-work 2nd-SmartLifecycle ordering item).
 * The full AD-22 7-step drain body is Epic 4; this bean owns only the acceptor window: start = bind;
 * stop = close the acceptor, then quiesce the shared event loop.
 *
 * <p><b>Driven directly (AD-16):</b> the {@link ServerBootstrap} is built here — Netty's own API, no
 * Spring messaging integration, no WebFlux/Reactor. Group = the ONE shared event loop bean (AD-1/AD-2
 * — platform threads; virtual threads never carry the data plane), channel = {@code Nio}, child
 * pipeline = {@link RelayIngressInitializer} (codec prefix; T7/T8 append the handlers), child options
 * = {@link RelayChannelOptions} (AD-21 allocator, AD-2 {@code AUTO_READ=false}, AD-30 watermark).
 * {@code bind(...).syncUninterruptibly()} — a bind failure (port occupied) throws THROUGH
 * {@code start()} &rarr; context refresh aborts &rarr; non-zero exit (AD-17 fail-fast), never a
 * silently-unbound acceptor.
 *
 * <p><b>Slice scope.</b> The acceptor starts ONLY for the {@code reverse.mode-b} cell — the cell this
 * story wires (plaintext, single egress). Every other cell leaves the lifecycle not-running (no port
 * bind, no event-loop churn); Epic 3 wires the forward/mode-a/c acceptors. Unlike the AD-30 memory
 * self-check (unconditional — the budget is a JVM-wide property), the acceptor is genuinely per-cell
 * wiring, so the guard here is slice-correct, not an omission.
 *
 * <p><b>Stop discipline.</b> {@link #stop(Runnable)} mirrors {@link ProxyCompanionLifecycle}: the
 * callback runs in {@code finally} (releases the shutdown latch within the per-phase graceful window,
 * {@code spring.lifecycle.timeout-per-shutdown-phase: 30s}). The body closes the server channel
 * first (no new binds), then {@code shutdownGracefully()} (Netty's default quiet window) — awaited so
 * the phase completes deterministically: the port is released and the loop threads are gone before
 * the next phase runs. Both shutdown paths are idempotent; the bean's own destroy method
 * ({@code shutdownGracefully} on the group bean) is the never-started-cell backstop.
 */
@Component
@RequiredArgsConstructor
public final class RelayServerLifecycle implements SmartLifecycle {

    /**
     * The relay acceptor's stop-order phase: strictly greater than
     * {@link ProxyCompanionLifecycle#APP_PHASE}, so Spring stops the acceptor FIRST (AD-22 step 1)
     * and the app-level lifecycle (the future AD-22 drain coordinator) stops after the data plane is
     * down. Starts after the app lifecycle (ascending phase) — harmless today (the app lifecycle's
     * start is a flag) and the correct nesting for Epic 4's coordinator.
     */
    public static final int RELAY_ACCEPTOR_PHASE = ProxyCompanionLifecycle.APP_PHASE + 1000;

    private final ProxyCompanionProperties properties;
    private final EventLoopGroup eventLoopGroup;
    private final RelayChannelOptions channelOptions;
    private final RelayIngressInitializer ingressInitializer;

    private volatile boolean running;
    private volatile @Nullable Channel serverChannel;

    @Override
    public void start() {
        ProxyCompanionProperties.@Nullable Reverse reverse = properties.reverse();
        if (reverse == null || reverse.modeB() == null) {
            return; // not this slice's cell — the relay mounts reverse.mode-b only (Epic 3 widens)
        }
        ServerBootstrap bootstrap = new ServerBootstrap()
                .group(eventLoopGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(ingressInitializer);
        channelOptions.applyToIngress(bootstrap);
        serverChannel = bootstrap.bind(properties.bind().port()).syncUninterruptibly().channel();
        running = true;
    }

    @Override
    public void stop(Runnable callback) {
        try {
            stop();
        } finally {
            // MUST invoke — releases the shutdown latch within the per-phase graceful-shutdown window
            // (mirrors ProxyCompanionLifecycle).
            callback.run();
        }
    }

    @Override
    public void stop() {
        if (!running) {
            return; // never started (non-mode-b cell) or already stopped — idempotent
        }
        running = false;
        Channel acceptor = serverChannel;
        serverChannel = null;
        if (acceptor != null) {
            acceptor.close().syncUninterruptibly(); // no new binds (AD-22 step 1)
        }
        eventLoopGroup.shutdownGracefully().syncUninterruptibly(); // bounded by Netty's defaults (2s quiet / 15s cap)
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    @Override
    public int getPhase() {
        return RELAY_ACCEPTOR_PHASE;
    }
}
