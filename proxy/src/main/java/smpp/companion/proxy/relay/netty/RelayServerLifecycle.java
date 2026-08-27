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
 * <p><b>Slice scope (widened by Story 3.3, [B] topology).</b> The acceptor starts for EVERY cell:
 * the reverse's internet leg ({@code mode-b} plaintext direct leg — byte-identical to Story 2.2 —
 * or {@code mode-a}/{@code mode-c} TLS listener via {@link RelayIngressInitializer}'s {@code
 * SmppLegTlsFactory}) and the forward's trusted leg (plaintext — AD-15; the forward DIALS the
 * reverse per session rather than listening for it). The per-cell TLS/plaintext split is
 * startup-static and owned by the initializer; this lifecycle owns only the bind ({@code
 * companion.bind.host:port}, F13) and the accepted-connection cap ({@link ConnectionCapHandler},
 * sourced from {@code companion.memory.concurrent-pairs}).
 * Unlike the AD-30 memory self-check (unconditional — the budget is a JVM-wide property), a boot
 * with no cell at all leaves the lifecycle not-running — unreachable post-validation (AD-17).
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
        if (properties.forward() == null && properties.reverse() == null) {
            return; // unreachable post-validation (AD-17 compact ctor) — defensive tripwire
        }
        // Story 3.3 ([B] topology): EVERY cell listens on companion.bind.host:port — the reverse's
        // internet leg (mode-b plaintext / mode-a,c TLS via the initializer's SmppLegTlsFactory) and
        // the forward's trusted leg (plaintext, AD-15). The TLS-vs-plaintext split is startup-static
        // per cell and owned by RelayIngressInitializer, not this lifecycle.
        ServerBootstrap bootstrap = new ServerBootstrap()
                .group(eventLoopGroup)
                .channel(NioServerSocketChannel.class)
                // F13 cap at the acceptor — sourced from the AD-30 budget input itself (one number:
                // every accepted connection can become a budgeted pair; no separate bind knob).
                .handler(new ConnectionCapHandler(properties.memory().concurrentPairs()))
                .childHandler(ingressInitializer);
        channelOptions.applyToIngress(bootstrap);
        serverChannel = bootstrap.bind(properties.bind().host(), properties.bind().port())
                .syncUninterruptibly().channel();
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
            return; // never started (no-cell boot — unreachable post-validation) or already stopped — idempotent
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
