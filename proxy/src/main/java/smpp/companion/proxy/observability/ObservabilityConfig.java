package smpp.companion.proxy.observability;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
     * written only by the observability impls.
     */
    @Bean
    public PrometheusMeterRegistry prometheusMeterRegistry() {
        return new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
    }
}
