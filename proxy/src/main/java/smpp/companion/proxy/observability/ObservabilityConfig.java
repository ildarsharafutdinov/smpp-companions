package smpp.companion.proxy.observability;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.micrometer.core.instrument.binder.MeterBinder;
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmThreadMetrics;
import io.micrometer.core.instrument.binder.system.ProcessorMetrics;
import io.micrometer.core.instrument.binder.system.UptimeMetrics;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;

/**
 * Story 4.1 (FR-OBS-1): the ONE Micrometer registry behind the read-only {@code /metrics} endpoint
 * and (from T3) the production {@code RelayObserver}. Actuator is OBS-013-purity-banned, so its
 * auto-configuration is ABSENT from the classpath and nothing else provides a registry &mdash; this
 * bean is the sole provider, declared explicitly next to the endpoint that scrapes it. A single
 * registry keeps every meter on one scrape surface (AD-27: one counter source, no second registry to
 * drift into).
 *
 * <p>Story 5.1 T4 (deferred-work :710 resolved here): the standard Micrometer JVM binder set
 * (memory / GC / threads / processor / uptime) is bound on that one registry, beside the custom
 * relay/ROPC gauges. With actuator absent there is also no {@code MeterRegistryPostProcessor} to
 * bind {@code MeterBinder} beans automatically, so the registry bean binds every {@link MeterBinder}
 * bean itself at construction &mdash; the whole surface is registered before the endpoint lifecycle
 * starts serving scrapes (the same construction-time contract {@link ResourceMetrics} keeps). Every
 * binder family is eager at {@code bindTo} except {@link JvmGcMetrics}' timer families ({@code
 * jvm_gc_pause}, and {@code jvm_gc_concurrent_phase_time} &mdash; the latter exists at all only on
 * concurrent collectors): both are created lazily on the first GC notification, so an operator
 * should expect them to appear only after the first collection ({@code
 * jvm_gc_memory_promoted_bytes_total}, likewise, exists only on generational collectors). The set
 * is deliberately the five-family core above &mdash; Boot's {@code ClassLoaderMetrics} and {@code
 * FileDescriptorMetrics} stay unbound (no operator demand recorded; binding them is open scope,
 * not an oversight &mdash; review round 1, [B10]).
 *
 * <p>{@link PrometheusConfig#DEFAULT} &mdash; the registry's own defaults (no yml surface; the only
 * operator input is {@code companion.metrics.port}). Spring's inferred destroy ({@code close()}) is
 * harmless: it fires at bean destruction, AFTER the endpoint lifecycle's phase (500) has already
 * stopped serving scrapes.
 */
@Configuration
public class ObservabilityConfig {

    /**
     * The shared {@link PrometheusMeterRegistry} (micrometer 1.17 &mdash; the {@code
     * io.micrometer.prometheusmetrics} client). Scraped read-only by {@link MetricsHttpHandler};
     * written only by the observability impls. Binds every {@link MeterBinder} bean to the registry
     * before returning it (actuator's auto-binding is absent &mdash; OBS-013; Story 5.1 T4), so the
     * binder beans below are the JVM gauge surface, not dead wiring.
     */
    @Bean
    public PrometheusMeterRegistry prometheusMeterRegistry(List<MeterBinder> meterBinders) {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        meterBinders.forEach(binder -> binder.bindTo(registry));
        return registry;
    }

    /** Heap/non-heap pool gauges ({@code jvm_memory_used/committed/max_bytes}) + buffer pools. */
    @Bean
    public JvmMemoryMetrics jvmMemoryMetrics() {
        return new JvmMemoryMetrics();
    }

    /**
     * GC gauges/counters ({@code jvm_gc_live/max_data_size_bytes}, {@code
     * jvm_gc_memory_allocated/promoted_bytes_total}, {@code jvm_gc_cpu_time}; the {@code
     * jvm_gc_pause} and {@code jvm_gc_concurrent_phase_time} timers appear on the first GC
     * notification &mdash; the concurrent family on concurrent collectors only). A bean
     * &mdash; not an inline {@code bindTo} &mdash; deliberately: it is {@code AutoCloseable}, and
     * Spring's inferred destroy calls {@code close()} at context stop, removing the JVM-wide GC
     * notification listeners this binder registers (no listener leak across test boots or
     * restarts).
     */
    @Bean
    public JvmGcMetrics jvmGcMetrics() {
        return new JvmGcMetrics();
    }

    /**
     * Platform-thread gauges ({@code jvm_threads_live/daemon/peak/states/started}). Virtual threads
     * stay invisible to these &mdash; the reason {@link ResourceMetrics}' VT gauge counts the
     * adjudication pool itself.
     */
    @Bean
    public JvmThreadMetrics jvmThreadMetrics() {
        return new JvmThreadMetrics();
    }

    /** CPU gauges ({@code system_cpu_count/system_cpu_usage}, {@code process_cpu_usage}, load average). */
    @Bean
    public ProcessorMetrics processorMetrics() {
        return new ProcessorMetrics();
    }

    /** Process liveness ({@code process_uptime_seconds}, {@code process_start_time_seconds}). */
    @Bean
    public UptimeMetrics uptimeMetrics() {
        return new UptimeMetrics();
    }
}
