package smpp.companion.proxy.relay;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import io.netty.buffer.PooledByteBufAllocator;
import io.netty.util.concurrent.ScheduledFuture;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.observability.CapturingRelayObserver;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayEgressInitializer;
import smpp.companion.proxy.security.AlwaysAllowBindCredentialVerifier;
import smpp.companion.proxy.tls.SmppLegTlsFactory;

/**
 * Story 4.4 T4 (F13 residue) — the cross-package bridge for the
 * {@code ConnectionCapHandler}-level cap-reclaim row: that row lives in {@code relay/netty} (the cap
 * handler is package-private THERE), while the seam-carrying {@link BindInterceptor} — the
 * package-private test constructor that accepts the {@code ChannelTimer} — can only be built HERE.
 * This public harness in the relay test package lets the one row that needs BOTH halves hold them
 * together: {@link #newInterceptor()} hands back a fresh per-channel interceptor (the per-channel
 * contract — one per accepted socket) whose every scheduled task is CAPTURED for manual firing,
 * the deterministic-seam idiom (no real wall-clock waits), beside the shared
 * registry/manager/observer the caller wires into the rest of the pipeline.
 */
public final class IdleWatchdogHarness {

    private final ProxyCompanionProperties properties;
    private final RelayStateManager manager;
    private final CapturingRelayObserver observer = new CapturingRelayObserver();
    private final RelayEgressInitializer egressInitializer;
    private final RelayChannelOptions channelOptions;
    private final RoutingTable routingTable;
    private final SmppLegTlsFactory tlsFactory;
    private final NewAdjudicationGate gate = new NewAdjudicationGate();

    /** Every capture across every interceptor this rig built, in arm order (delay millis per task). */
    private final List<Long> delays = new CopyOnWriteArrayList<>();
    private final List<Runnable> tasks = new CopyOnWriteArrayList<>();
    private final List<ScheduledFuture<?>> futures = new CopyOnWriteArrayList<>();

    public IdleWatchdogHarness(ProxyCompanionProperties properties) {
        this.properties = properties;
        ConnectionRegistry registry = new ConnectionRegistry();
        this.manager = new RelayStateManager(registry);
        this.egressInitializer = new RelayEgressInitializer(manager, observer);
        this.channelOptions = new RelayChannelOptions(properties, PooledByteBufAllocator.DEFAULT);
        this.routingTable = new RoutingTable(properties);
        this.tlsFactory = new SmppLegTlsFactory(properties, Runnable::run);
    }

    /**
     * A fresh PER-CHANNEL interceptor (the per-channel contract) capturing every task it schedules —
     * the first is always the idle watchdog armed at {@code channelActive}. The connector arm is
     * fail-loud: the idle rows never dial an egress leg (nothing is ever sent), so a dial attempt is
     * a rig bug, not a condition to fake.
     */
    public BindInterceptor newInterceptor() {
        return new BindInterceptor(
                new AlwaysAllowBindCredentialVerifier(), manager, observer, properties, egressInitializer,
                channelOptions, routingTable, tlsFactory, gate,
                (bootstrap, host, port) -> {
                    throw new AssertionError("the idle rows never dial an egress leg (rig bug)");
                },
                (channel, delayMillis, task) -> {
                    delays.add(delayMillis);
                    tasks.add(task);
                    ScheduledFuture<?> handle =
                            channel.eventLoop().schedule(() -> { }, delayMillis, TimeUnit.MILLISECONDS);
                    futures.add(handle);
                    return handle;
                });
    }

    /** The captured scheduled tasks (fire manually — the deterministic seam). */
    public List<Runnable> tasks() {
        return tasks;
    }

    /** The configured delay each captured task was armed at, in arm order (millis). */
    public List<Long> delays() {
        return delays;
    }

    /** The shared observer the caller's {@code RelayIngressHandler} was wired with. */
    public CapturingRelayObserver observer() {
        return observer;
    }

    /** The shared state manager (wire the caller's {@code RelayIngressHandler} with this + the observer). */
    public RelayStateManager manager() {
        return manager;
    }
}
