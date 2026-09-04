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
 * The AD-22 5-step drain body is Epic 4; this bean owns only step 1's window: start = bind;
 * stop = close the acceptor ONLY — the shared event loop SURVIVES the stop (Story 4.2 T2 re-authored
 * the quiesce out: every deny-time continuation executes on that loop, so killing it here would
 * strand the fail-closed {@code bind_resp}s AD-22 step 2 owes the clients). The quiesce — an explicit
 * short quiet period, never Netty's 2s default — is the shutdown coordinator's final step
 * ({@link ProxyCompanionLifecycle}, Story 4.2 T3), with the group bean's
 * {@code destroyMethod="shutdownGracefully"} backstop ({@code RelayNettyConfig}) behind it.
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
 * {@code spring.lifecycle.timeout-per-shutdown-phase: 30s}). The body closes the server channel and
 * NOTHING else (Story 4.2 T2) — the port is released deterministically (no new binds, AD-22 step 1)
 * but the shared loop SURVIVES this phase: the deny window runs strictly after it (ADJUDICATION_PHASE
 * &lt; {@link #RELAY_ACCEPTOR_PHASE}), and every cancelled adjudication's continuation hops
 * {@code channel.eventLoop().execute(...)} — a quiesced loop would reject that and strand the
 * fail-closed {@code bind_resp} (the residue AD-22 exists to kill). The quiesce — an explicit short
 * quiet period (the {@code MetricsEndpointLifecycle} 100ms/2s pattern, never Netty's 2s default) —
 * is the shutdown coordinator's final step at the app phase (Story 4.2 T3); the group bean's
 * {@code destroyMethod="shutdownGracefully"} backstop is what guarantees the loop still dies at
 * full-app close until then, and a no-op re-fire after the coordinator (both paths idempotent; it is
 * also the never-started-cell backstop — non-acceptor boots never call this stop).
 */
@Component
@RequiredArgsConstructor
public final class RelayServerLifecycle implements SmartLifecycle {

    /**
     * The relay acceptor's stop-order phase: strictly greater than
     * {@link ProxyCompanionLifecycle#APP_PHASE}, so Spring stops the acceptor FIRST (AD-22 step 1)
     * and the app-level lifecycle (the AD-22 shutdown coordinator) stops after the acceptor is
     * closed — with the shared loop still LIVE across that gap (the deny continuations need it; the
     * loop dies at the coordinator's own quiesce, its final step). Starts after the app lifecycle
     * (ascending phase) — harmless today (the app lifecycle's start is a flag) and the correct
     * nesting for the coordinator.
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
        // AD-22 step 1 — and the WHOLE stop body (Story 4.2 T2): close the acceptor, no new binds.
        // The shared loop is NOT quiesced here — it must stay live for the deny continuations (the
        // coordinator, Story 4.2 T3, owns the explicit-args quiesce at the app phase; the group bean's
        // destroyMethod is the backstop that still kills the loop at full-app close).
        if (acceptor != null) {
            acceptor.close().syncUninterruptibly();
        }
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
