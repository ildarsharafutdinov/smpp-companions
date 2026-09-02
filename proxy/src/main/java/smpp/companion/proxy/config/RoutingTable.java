package smpp.companion.proxy.config;

import java.util.HashMap;
import java.util.Map;

import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

/**
 * The AD-29 runtime routing table (Story 3.3, [B] topology): the FORWARD cell's {@code system_id}
 * allow-list, resolved once at construction into a {@code system_id → entry} lookup. Immutable after
 * startup (AD-8: "config and the routing table are immutable after startup validation"). Duplicate
 * {@code system_id}s and an empty table are refused at bind time by
 * {@link CompanionConfigValidator}; this component only indexes what already validated.
 *
 * <p>Keyed per {@code system_id} — NEVER per connection and never per {@code message_id} (REL-4 /
 * AD-9): N concurrent sessions under one {@code system_id} each resolve the SAME single target
 * (AD-29 1:1; the routing entry is the forward's dial target — AD-29 as-built under [B]). The
 * REVERSE cells carry no routing table (a {@code null} forward branch indexes nothing); their
 * every bind routes to the single configured SMSC endpoint, which is why the reverse arm of the
 * interceptor never consults this bean.
 *
 * <p>Lives in {@code config} because the spine's package ownership pins the routing table there
 * ("config &mdash; @ConfigurationProperties model, fail-fast validation, role&times;mode matrix,
 * routing table").
 */
@Component
public final class RoutingTable {

    private final Map<String, ProxyCompanionProperties.RoutingEntry> entries;

    /** The validated properties; exactly one role&times;mode branch is populated (AD-17 compact ctor). */
    public RoutingTable(ProxyCompanionProperties properties) {
        ProxyCompanionProperties.@Nullable Forward forward = properties.forward();
        Map<String, ProxyCompanionProperties.RoutingEntry> indexed = new HashMap<>();
        if (forward != null) {
            for (ProxyCompanionProperties.RoutingEntry entry : forwardRouting(forward)) {
                indexed.put(entry.systemId(), entry); // duplicates refused by the validator upstream
            }
        }
        this.entries = indexed;
    }

    private static java.util.List<ProxyCompanionProperties.RoutingEntry> forwardRouting(
            ProxyCompanionProperties.Forward forward) {
        if (forward.modeA() != null) {
            return forward.modeA().routing();
        }
        if (forward.modeC() != null) {
            return forward.modeC().routing();
        }
        throw new IllegalStateException("no companion.forward.<mode> branch (AD-17) — a wiring bug, not a config state");
    }

    /**
     * The single egress target for a permitted {@code system_id}, or {@code null} on a routing miss
     * (AD-11: no default route — the caller must deny fail-closed).
     *
     * @param systemId the bind's {@code system_id} verbatim (AD-14); non-null.
     */
    public ProxyCompanionProperties.@Nullable RoutingEntry route(String systemId) {
        return entries.get(systemId);
    }

    /**
     * The bounded label universe (AD-19 / Story 4.1 T3): every routing-table {@code system_id} &mdash;
     * the ONLY values a {@code system_id}-labeled metrics series may ever draw from (pre-registered
     * at startup by the production observer; ids outside this set hit unlabeled counters, never a
     * new series &mdash; a burst of distinct unknown ids cannot grow the series count). Empty by
     * construction on reverse cells (no forward branch &rarr; nothing indexed), which is exactly why
     * the reverse arm's labeled set is empty.
     */
    public java.util.Set<String> systemIds() {
        return java.util.Set.copyOf(entries.keySet());
    }
}
