package smpp.companion.proxy.observability;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import net.logstash.logback.argument.StructuredArgument;

import smpp.companion.proxy.config.MemoryBudget;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.relay.netty.DirectMemoryBudgetValidator;

import static net.logstash.logback.argument.StructuredArguments.kv;

/**
 * Story 4.1 T3 (checkpoint 10): the startup/config-resolved log line (FR-OBS-2). On the Spring Boot
 * ready event &mdash; after the context refresh (every bean, the AD-30 self-check, and the
 * SmartLifecycle starts, the metrics endpoint included) and before the process serves traffic
 * &mdash; ONE INFO JSON line summarizes the RESOLVED configuration: the role&times;mode cell, the
 * proxy's own listener, the metrics port, the routing-table {@code system_id}s (the bounded metrics
 * label universe, so an operator scraping sees the table reflected), the TLS protocol policy, and
 * the AD-30 memory budget with its inputs.
 *
 * <p><b>No secrets, by construction:</b> every field is drawn from non-secret config structure.
 * Secret material is file paths under AD-18 (never logged); the trust-store password, the OIDC
 * client secret, and (never on this tier at all) bind passwords are structurally out of reach &mdash;
 * nothing here reads a value-bearing secret field. {@code system_id}s are identity, not secret
 * (AD-14), and are exactly what the routing summary exists to show.
 *
 * <p>Fires once per successful boot; a context that fails before ready logs nothing here (the
 * fail-fast refusal is the boot's own output). On {@code ApplicationReadyEvent} rather than a
 * lifecycle/bean-init hook so "started" means STARTED &mdash; everything above is verified live.
 */
@Slf4j
@RequiredArgsConstructor
@Component
public final class StartupSummaryLogger {

    private final ProxyCompanionProperties properties;
    private final RoutingTable routingTable;

    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        ProxyCompanionProperties.Memory memory = properties.memory();
        List<StructuredArgument> fields = new ArrayList<>(12);
        fields.add(kv("event", "startup_summary"));
        fields.add(kv("role", properties.forward() != null ? "forward" : "reverse"));
        fields.add(kv("mode", mode()));
        fields.add(kv("smpp_bind_host", properties.bind().host()));
        fields.add(kv("smpp_bind_port", properties.bind().port()));
        if (properties.metrics() != null) {
            fields.add(kv("metrics_port", properties.metrics().port())); // absent node = endpoint down: omitted, truthful
        }
        fields.add(kv("routing_system_ids", routingTable.systemIds().stream().sorted().toList()));
        fields.add(kv("tls_protocols", Objects.requireNonNullElse(properties.tls().protocols(), List.of())));
        // The SAME derivation the AD-30 startup check used (MemoryBudget is the one source; RELAY-026 discipline).
        fields.add(kv("memory_budget_bytes", MemoryBudget.compute(
                memory.maxInboundDepth(), memory.concurrentPairs(), memory.safetyFactor())));
        // Step-04 review (finding #15): the CEILING the self-check compared that budget against —
        // machine-derived and non-secret (the explicit -XX:MaxDirectMemorySize value, else -Xmx), so
        // an operator reading the budget line can see the whole comparison without re-deriving the
        // JVM side. DirectMemoryBudgetValidator is the one source (the same RELAY-026 discipline).
        fields.add(kv("direct_memory_ceiling_bytes",
                DirectMemoryBudgetValidator.liveDirectMemoryCeiling()));
        fields.add(kv("max_inbound_depth", memory.maxInboundDepth()));
        fields.add(kv("concurrent_pairs", memory.concurrentPairs()));
        fields.add(kv("safety_factor", memory.safetyFactor()));
        log.info("proxy companion started — resolved configuration summary",
                (Object[]) fields.toArray(new StructuredArgument[0]));
    }

    /** The selected mode leaf: a/c on forward (B is structurally forbidden), a/b/c on reverse. */
    private String mode() {
        ProxyCompanionProperties.@Nullable Forward forward = properties.forward();
        if (forward != null) {
            return forward.modeA() != null ? "a" : "c";
        }
        ProxyCompanionProperties.@Nullable Reverse reverse = properties.reverse();
        if (reverse == null) {
            // Unreachable post-validation (AD-17: exactly one role branch) — a wiring bug, not a config state.
            throw new IllegalStateException("no companion.<role> branch (AD-17) — a wiring bug");
        }
        if (reverse.modeA() != null) {
            return "a";
        }
        if (reverse.modeB() != null) {
            return "b";
        }
        return "c";
    }
}
