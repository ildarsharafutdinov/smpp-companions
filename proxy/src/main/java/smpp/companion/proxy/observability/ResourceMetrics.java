package smpp.companion.proxy.observability;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.netty.buffer.PooledByteBufAllocator;

import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.security.RopcBindCredentialVerifier;

/**
 * Story 4.1 T3 (checkpoint 9): the resource gauges on the one shared registry (AD-27) &mdash;
 * memory and adjudication-pool visibility neither Micrometer's built-in binders nor the JVM give an
 * operator:
 *
 * <ul>
 *   <li>{@link #DIRECT_MEMORY_GAUGE} &mdash; direct memory in use by the SHARED relay allocator
 *       ({@code RelayNettyConfig}'s {@code PooledByteBufAllocator.DEFAULT}, AD-21), read live off
 *       its {@code ByteBufAllocatorMetric#usedDirectMemory()}. The AD-30 startup check compares the
 *       derived BUDGET to the ceiling once at boot; this gauge is the runtime answer to "is the data
 *       plane actually eating the arena set" &mdash; the allocator's own metric is the authoritative
 *       live number (no /proc, no reflection into JDK internals).</li>
 *   <li>{@link #ACTIVE_ADJUDICATIONS_GAUGE} &mdash; in-flight ROPC bind adjudications (the
 *       {@code ropc-adjudication} virtual-thread pool). No {@code jvm_threads_*} binder is bound on
 *       this registry (deliberate, story scope: actuator is purity-banned, and those binders count
 *       platform threads only &mdash; they cannot see VTs anyway), which is why the pool counts
 *       itself: the adapter increments at submit and decrements in the pool task's {@code finally}
 *       (its sanctioned VT-gauge seam &mdash; no pool restructuring), and this gauge only READS
 *       {@link RopcBindCredentialVerifier#activeAdjudications()}. Registered ONLY when the cell's
 *       verifier IS the ROPC adapter (reverse cells); a forward cell has no such pool, so the gauge's
 *       absence there is truthful, not a gap.</li>
 * </ul>
 *
 * <p>Gauges are registered at CONSTRUCTION (context refresh) so the scrape surface is complete
 * before the endpoint's {@code SmartLifecycle} starts serving. Micrometer holds gauge state objects
 * weakly, but both sources are Spring singletons (the allocator bean, the verifier bean) &mdash;
 * strongly reachable for the context's lifetime &mdash; so the gauges can never silently flatline
 * to "not collected" between scrapes.
 */
@Component
public final class ResourceMetrics {

    /** Direct memory in use by the shared relay pooled allocator ({@code relay_direct_memory_used_bytes}). */
    public static final String DIRECT_MEMORY_GAUGE = "relay.direct.memory.used";

    /** In-flight ROPC adjudications — the VT pool's active count ({@code ropc_adjudications_active}). */
    public static final String ACTIVE_ADJUDICATIONS_GAUGE = "ropc.adjudications.active";

    /**
     * @param registry         the one shared registry ({@code ObservabilityConfig}; AD-27)
     * @param allocator        the shared relay allocator (AD-21) &mdash; the direct-memory source
     * @param verifierProvider the cell's verifier; absent in slices, the stand-in on forward cells
     *                         (then no VT gauge is registered &mdash; there is no pool to observe)
     */
    public ResourceMetrics(PrometheusMeterRegistry registry, PooledByteBufAllocator allocator,
            ObjectProvider<BindCredentialVerifier> verifierProvider) {
        Gauge.builder(DIRECT_MEMORY_GAUGE, allocator, a -> a.metric().usedDirectMemory())
                .description("Direct memory currently in use by the shared relay pooled allocator "
                        + "(AD-21/AD-30 — live usage, not the derived startup budget).")
                .baseUnit("bytes")
                .register(registry);
        BindCredentialVerifier verifier = verifierProvider.getIfAvailable();
        if (verifier instanceof RopcBindCredentialVerifier adapter) {
            Gauge.builder(ACTIVE_ADJUDICATIONS_GAUGE, adapter, RopcBindCredentialVerifier::activeAdjudications)
                    .description("In-flight ROPC bind adjudications — the ropc-adjudication "
                            + "virtual-thread pool's active count (Micrometer jvm_threads_* does not "
                            + "count virtual threads).")
                    .register(registry);
        }
    }
}
