package smpp.companion.proxy.bootstrap;

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import smpp.companion.proxy.config.ProxyCompanionProperties;

/**
 * Story 4.3 T5 (AD-22 step 3) &mdash; the shutdown coordinator's wiring: the repo's FIRST
 * {@link Clock} bean plus the {@code companion.shutdown.*} slice exposed as its own bean (the
 * {@code RelayNettyConfig}/{@code VerifierWiringConfig} shape &mdash; a tiny documented
 * {@code @Configuration} sitting next to its consumer). ONE consumer by design: the AD-22 shutdown
 * coordinator ({@code ProxyCompanionLifecycle}), whose drain polls the drain-timeout deadline on
 * the clock &mdash; the only place production time is read on the shutdown path;
 * {@code BindInterceptor}'s {@code Instant.now()} adjudication arming belongs to 4.4's
 * relay-timeout round and stays untouched (the story's Ask-First on widening time surfaces
 * respected: nothing else consumes a {@link Clock}).
 *
 * <p>A {@link Clock} BEAN rather than an inline {@code Clock.systemUTC()} so the deadline is
 * INJECTABLE: the direct-construction test tier drives the OBS-020 deadline force-close
 * deterministically with a mutable clock &mdash; advance past the budget, never a wall-clock wait
 * (RELAY-022; the catalog's OBS-020 blind-spot 5). UTC so deadline arithmetic is zone-stable
 * regardless of the host.
 *
 * <p>The {@link ProxyCompanionProperties.Shutdown} bean is the SAME instance the bound root record
 * holds (a plain derived singleton, NOT a second {@code @ConfigurationProperties} surface &mdash;
 * the root stays the single binding point, {@code ignoreUnknownFields = false} included): the
 * coordinator's ctor names only the slice it consumes, while Spring wires the nested record no
 * other way.
 */
@Configuration
public class ShutdownWiringConfig {

    /** The production drain-deadline time source ({@code Clock.systemUTC()}). */
    @Bean
    public Clock systemUtcClock() {
        return Clock.systemUTC();
    }

    /**
     * The {@code companion.shutdown.*} slice off the bound root &mdash; the coordinator's drain
     * deadline ({@code drain-timeout}); the same instance the root carries.
     */
    @Bean
    public ProxyCompanionProperties.Shutdown shutdownProperties(ProxyCompanionProperties properties) {
        return properties.shutdown();
    }
}
