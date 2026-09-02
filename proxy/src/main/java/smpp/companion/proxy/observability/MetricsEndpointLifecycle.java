package smpp.companion.proxy.observability;

import java.util.concurrent.TimeUnit;

import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.util.concurrent.DefaultThreadFactory;

import smpp.companion.proxy.bootstrap.ProxyCompanionLifecycle;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.relay.netty.RelayServerLifecycle;

/**
 * Story 4.1 (FR-OBS-1): the read-only Prometheus {@code /metrics} endpoint's {@link SmartLifecycle}
 * — a DEDICATED 1-thread {@code companion-metrics} event loop + HTTP pipeline bound to the literal
 * loopback (dedicated-loop isolation, AD-19/AD-28: the scrape surface never shares the shared
 * {@code companion-relay-*} data-plane loop — a scrape cannot compete with, or block on, relay
 * traffic). Direct Netty ({@code ServerBootstrap}), mirroring {@link RelayServerLifecycle}'s
 * AD-16 direct-driven posture: no web stack, no Reactor, no actuator (OBS-013).
 *
 * <p><b>Loopback by construction (Design Note):</b> the bind address is the LITERAL {@link
 * #LOOPBACK_BIND_HOST} — there is NO host config key, so a non-loopback exposure cannot be
 * misconfigured into existence; loopback IPv4 is the endpoint's sole authentication. The port is
 * {@code companion.metrics.port} (required when the node is present; yml ships 9090). An ABSENT
 * {@code companion.metrics} node leaves the endpoint down — programmatic fixtures construct without
 * it, and {@link #start()} then returns not-running (the {@code RelayServerLifecycle} no-cell
 * tripwire pattern; unreachable for yml-loading boots).
 *
 * <p><b>Phase plan:</b> {@link #METRICS_ENDPOINT_PHASE} sits strictly between the relay acceptor
 * ({@link RelayServerLifecycle#RELAY_ACCEPTOR_PHASE}, stops FIRST — no new relay binds) and the app
 * lifecycle ({@link ProxyCompanionLifecycle#APP_PHASE}, stops last — the future AD-22 drain
 * coordinator): scrapes stay live LATE in shutdown, after the data plane has closed but before the
 * app window, so an operator's final scrape still sees the drain's counters.
 *
 * <p><b>Bind and stop discipline</b> (mirrors {@code RelayServerLifecycle}): {@code
 * bind(...).syncUninterruptibly()} — an occupied port throws THROUGH {@code start()} &rarr; context
 * refresh aborts (AD-17 fail-fast, never a silently-unbound endpoint); on that failure the freshly
 * created group is quiesced before the throw (no leaked loop). {@code stop(Runnable)} runs the
 * callback in {@code finally} (releases the shutdown latch within the per-phase window); the body
 * closes the server channel first (port released deterministically), then {@code
 * shutdownGracefully(100ms quiet, 2s cap)} — an EXPLICIT short quiet period (the endpoint's only
 * work is microsecond request/response cycles; Netty's 2s default quiet period would needlessly
 * stretch the shutdown phase), awaited so the phase completes with the loop thread gone. Both paths
 * idempotent. No acceptor-level connection cap: the listener is loopback-only (the operator's own
 * scraper), not an untrusted ingress surface.
 */
@Component
@RequiredArgsConstructor
public final class MetricsEndpointLifecycle implements SmartLifecycle {

    /**
     * The metrics endpoint's stop-order phase: strictly between the relay acceptor
     * ({@code APP_PHASE + 1000}, stops first) and the app lifecycle ({@code APP_PHASE}, stops last)
     * — see the class javadoc's phase plan.
     */
    public static final int METRICS_ENDPOINT_PHASE = ProxyCompanionLifecycle.APP_PHASE + 500;

    /**
     * The endpoint's sole bind address — the LITERAL loopback IPv4 (no host key exists; Design Note:
     * simpler and more fail-closed than a validator). Source-pinned by {@code MetricsEndpointTest}.
     */
    public static final String LOOPBACK_BIND_HOST = "127.0.0.1";

    /** The shutdown quiet period — explicitly short (see class javadoc). */
    private static final long SHUTDOWN_QUIET_PERIOD_MS = 100;

    /** The shutdown cap — the per-phase ceiling is 30s; 2s bounds this phase's worst case. */
    private static final long SHUTDOWN_TIMEOUT_MS = 2_000;

    private final ProxyCompanionProperties properties;
    private final PrometheusMeterRegistry registry;

    private volatile boolean running;
    private volatile @Nullable Channel serverChannel;
    private volatile @Nullable EventLoopGroup metricsEventLoopGroup;

    @Override
    public void start() {
        ProxyCompanionProperties.@Nullable Metrics metrics = properties.metrics();
        if (metrics == null) {
            return; // endpoint down by config absence — not-running, no loop created (yml boots always carry it)
        }
        // Created HERE, not as a shared bean: the loop is this lifecycle's own (dedicated-loop
        // isolation) and an absent metrics node must allocate nothing. Netty 4.2 idiom (the 4.2
        // IoHandle refactor deprecated NioEventLoopGroup) — mirrors RelayNettyConfig.
        EventLoopGroup group = new MultiThreadIoEventLoopGroup(1,
                new DefaultThreadFactory("companion-metrics"), NioIoHandler.newFactory());
        ServerBootstrap bootstrap = new ServerBootstrap()
                .group(group)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<Channel>() {
                    @Override
                    protected void initChannel(Channel channel) {
                        // Bounded request shape — the caps are the endpoint contract's own constants
                        // (MetricsHttpHandler owns them; the pipeline and the contract share one source).
                        channel.pipeline()
                                .addLast(new HttpServerCodec(MetricsHttpHandler.MAX_INITIAL_LINE_LENGTH,
                                        MetricsHttpHandler.MAX_HEADER_SIZE,
                                        MetricsHttpHandler.MAX_CONTENT_LENGTH))
                                .addLast(new HttpObjectAggregator(MetricsHttpHandler.MAX_CONTENT_LENGTH))
                                .addLast(new MetricsHttpHandler(registry));
                    }
                });
        Channel channel;
        try {
            channel = bootstrap.bind(LOOPBACK_BIND_HOST, metrics.port()).syncUninterruptibly().channel();
        } catch (RuntimeException e) {
            // AD-17 fail-fast propagates — but not with a freshly created loop left behind.
            group.shutdownGracefully(SHUTDOWN_QUIET_PERIOD_MS, SHUTDOWN_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            throw e;
        }
        metricsEventLoopGroup = group;
        serverChannel = channel;
        running = true;
    }

    @Override
    public void stop(Runnable callback) {
        try {
            stop();
        } finally {
            // MUST invoke — releases the shutdown latch within the per-phase graceful-shutdown window
            // (mirrors RelayServerLifecycle / ProxyCompanionLifecycle).
            callback.run();
        }
    }

    @Override
    public void stop() {
        if (!running) {
            return; // never started (absent metrics node) or already stopped — idempotent
        }
        running = false;
        Channel acceptor = serverChannel;
        serverChannel = null;
        EventLoopGroup group = metricsEventLoopGroup;
        metricsEventLoopGroup = null;
        if (acceptor != null) {
            acceptor.close().syncUninterruptibly(); // port released (deterministic, before the loop quiesces)
        }
        if (group != null) {
            group.shutdownGracefully(SHUTDOWN_QUIET_PERIOD_MS, SHUTDOWN_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                    .syncUninterruptibly(); // awaited: the loop thread is gone when the phase completes
        }
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    @Override
    public int getPhase() {
        return METRICS_ENDPOINT_PHASE;
    }
}
