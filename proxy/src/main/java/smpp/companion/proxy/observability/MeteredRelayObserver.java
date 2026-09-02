package smpp.companion.proxy.observability;

import java.util.LinkedHashMap;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Counter;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;

import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;

import static net.logstash.logback.argument.StructuredArguments.kv;

/**
 * Story 4.1 T3 (checkpoint 8): the PRODUCTION {@link RelayObserver} &mdash; the Micrometer
 * implementation that displaces {@link NoopRelayObserver} via {@link Primary @Primary} (deterministic
 * under component scanning; {@code @ConditionalOnMissingBean} is bean-order-sensitive &mdash; the
 * Design Note). The noop file stays {@code final @Component} and remains the fallback in minimal test
 * contexts that never component-scan this package; the interface is UNCHANGED (the shape test pins
 * it), so the relay's fire sites wire against the same port as before.
 *
 * <p><b>Cardinality bounded by construction (AD-19 / PRIV-1).</b> Every series is created at
 * CONSTRUCTION from closed sets, and no fire path can create another:
 * <ul>
 *   <li>{@link #PDU_COUNTER}{@code {direction}} &mdash; the closed 2-value {@link Direction} enum,
 *       both pre-registered (post-couple PDU count, AD-27);</li>
 *   <li>{@link #BIND_ACCEPT_COUNTER}{@code {system_id}} &mdash; pre-registered ONLY for
 *       {@link RoutingTable#systemIds()} (the bounded label universe). An accept whose id is
 *       outside the table (every reverse cell &mdash; the table is empty there by construction)
 *       increments {@link #UNKNOWN_ID_COUNTER} instead: NO series is created. The {@link SystemId}
 *       is for structured logging only, exactly as the seam javadoc reserves it;</li>
 *   <li>{@link #BIND_REJECT_COUNTER} &mdash; unlabeled (the verdict type is log-only: AD-33 collapses
 *       both {@code Deny*} permits to one wire status, and a {@code verdict} label would fan the
 *       same closed 3-value set for no operator value); rejects with off-table ids ALSO increment
 *       {@link #UNKNOWN_ID_COUNTER}, so the cardinality-attack row (a burst of distinct unknown ids
 *       lands on rejects on the reverse arm) grows counters, never series;</li>
 *   <li>{@link #CLOSE_COUNTER}{@code {direction, reason}} &mdash; the full 2&times;16
 *       {@link Direction}&times;{@link CloseReason} grid pre-registered (the closed enum is the whole
 *       label domain);</li>
 *   <li>NO {@code command_id} label, NO channel-id label, NO free-form {@code system_id} &mdash;
 *       ever (the seam carries none of them, and this impl derives none).</li>
 * </ul>
 *
 * <p><b>The JSON lines (FR-OBS-2).</b> Bind accept/reject each log ONE INFO object-line (event,
 * {@code system_id}, outcome / verdict type + the AD-33 synthesized wire status) via logstash
 * {@code StructuredArguments} &mdash; fields ride the T1 {@code LogstashEncoder}; the plain-console
 * test logback renders the same arguments as {@code key=value} pairs. High-frequency triggers
 * ({@code onFramedPdu}, {@code onConnectionClosed}) log NOTHING (metrics only) &mdash; a per-PDU log
 * line would be exactly the flood the privacy contract keeps out of default-level logs.
 *
 * <p><b>Never throws.</b> Every trigger body is catch-guarded ({@code Throwable} &rarr; one bounded
 * WARN, relay path continues): an observer must never be able to break the data plane from inside.
 * Post-construction this is belt-and-braces by design &mdash; all series already exist, so increments
 * cannot hit registration paths &mdash; but the guard also absorbs any future drift (e.g. a logging
 * regression). The fire-site isolation (Story 4.1 T4) additionally protects the relay from ANY
 * throwing implementation, not only this one.
 */
@Slf4j
@Primary
@Component
public final class MeteredRelayObserver implements RelayObserver {

    /** Post-couple framed-PDU count per leg ({@code relay_pdus_total{direction}}). */
    static final String PDU_COUNTER = "relay.pdus";

    /** Bind-accept count per routing-table {@code system_id} ({@code relay_binds_accepted_total}). */
    static final String BIND_ACCEPT_COUNTER = "relay.binds.accepted";

    /** Unlabeled verifier-deny count ({@code relay_binds_rejected_total}). */
    static final String BIND_REJECT_COUNTER = "relay.binds.rejected";

    /** Unlabeled count of bind events whose id is outside the routing table ({@code relay_binds_unknown_total}). */
    static final String UNKNOWN_ID_COUNTER = "relay.binds.unknown";

    /** Leg-close count per {@code direction}/{@code reason} ({@code relay_connections_closed_total}). */
    static final String CLOSE_COUNTER = "relay.connections.closed";

    static final String SYSTEM_ID_TAG = "system_id";
    static final String DIRECTION_TAG = "direction";
    static final String REASON_TAG = "reason";

    /**
     * The wire {@code command_status} the relay's AD-33 collapse synthesizes for EVERY proxy-side
     * denial: {@code ESME_RBINDFAIL} 0x0000000D (SMPP 3.4 &sect;5.1.3). Mirrored as the literal here
     * because {@code relay.BindInterceptor}'s constant is package-private and observability must
     * not depend on {@code relay/}; the test tier pins this literal INDEPENDENTLY of both constants
     * (the same anti-drift discipline {@code BindInterceptor} itself uses). The reject fires before
     * the wire effect, but the status is deterministic per AD-33 (both {@code Deny*} permits
     * collapse to it), so the observer can state it.
     */
    static final String AD_33_SYNTHESIZED_BIND_RESP_STATUS = "0x0000000D";

    /**
     * PDU counters indexed by {@link Direction#ordinal()} — fully populated at construction (both
     * values), so every fire is a plain array hit; no map lookup, no nullable edge.
     */
    private final Counter[] pdusByDirection;

    private final Map<String, Counter> acceptsBySystemId;

    /**
     * Close counters indexed by {@code [Direction.ordinal()][CloseReason.ordinal()]} — the full
     * 2&times;16 grid populated at construction (the closed enums ARE the label domain).
     */
    private final Counter[][] closesByDirection;

    private final Counter rejectedTotal;
    private final Counter unknownSystemIdTotal;

    /**
     * Pre-registers the ENTIRE series surface (the cardinality bound): both PDU directions, one
     * accept series per routing-table id, the full close grid, and the two unlabeled counters.
     * Fail-fast by construction &mdash; a registry/filter problem throws HERE, at startup, never on
     * a relay path.
     *
     * @param registry the one shared registry (AD-27: one counter source &mdash; {@code ObservabilityConfig})
     * @param routingTable the cell's table; empty on reverse cells (the labeled set is empty by construction)
     */
    public MeteredRelayObserver(PrometheusMeterRegistry registry, RoutingTable routingTable) {
        Counter[] pdus = new Counter[Direction.values().length];
        for (Direction direction : Direction.values()) {
            pdus[direction.ordinal()] = Counter.builder(PDU_COUNTER)
                    .description("Framed PDUs relayed across a coupled pair, per leg (the PDU count; "
                            + "no PDU type or content crosses the seam, AD-27).")
                    .tag(DIRECTION_TAG, direction.name())
                    .register(registry);
        }
        this.pdusByDirection = pdus;

        Map<String, Counter> accepts = new LinkedHashMap<>();
        for (String systemId : routingTable.systemIds()) {
            accepts.put(systemId, Counter.builder(BIND_ACCEPT_COUNTER)
                    .description("Binds whose AD-25 ROK couple completed, labeled ONLY with "
                            + "routing-table system_ids (pre-registered at startup; off-table ids "
                            + "increment " + UNKNOWN_ID_COUNTER + " instead, AD-19).")
                    .tag(SYSTEM_ID_TAG, systemId)
                    .register(registry));
        }
        this.acceptsBySystemId = Map.copyOf(accepts);

        Counter[][] closes = new Counter[Direction.values().length][CloseReason.values().length];
        for (Direction direction : Direction.values()) {
            for (CloseReason reason : CloseReason.values()) {
                closes[direction.ordinal()][reason.ordinal()] = Counter.builder(CLOSE_COUNTER)
                        .description("Legs closed, by leg and close path (the closed CloseReason "
                                + "enum is the whole label domain, AD-19/AD-27).")
                        .tag(DIRECTION_TAG, direction.name())
                        .tag(REASON_TAG, reason.name())
                        .register(registry);
            }
        }
        this.closesByDirection = closes;

        this.rejectedTotal = Counter.builder(BIND_REJECT_COUNTER)
                .description("Binds denied by a returned Deny* verdict (unlabeled by design; the "
                        + "verdict type is log-only, AD-19/AD-33).")
                .register(registry);
        this.unknownSystemIdTotal = Counter.builder(UNKNOWN_ID_COUNTER)
                .description("Bind events whose system_id is outside the routing table (unlabeled "
                        + "by design; a burst of distinct unknown ids must grow this counter, never "
                        + "the series count, AD-19).")
                .register(registry);
    }

    @Override
    public void onFramedPdu(Direction direction) {
        try {
            pdusByDirection[direction.ordinal()].increment();
        } catch (Throwable t) {
            log.warn("the production observer swallowed its own failure (onFramedPdu) — "
                    + "the relay path continues", t);
        }
    }

    @Override
    public void onBindAccept(SystemId systemId) {
        try {
            String id = systemId.asString();
            Counter known = acceptsBySystemId.get(id);
            if (known != null) {
                known.increment();
            } else {
                // Off-table id (every reverse cell): the unlabeled counter takes it — NEVER a new series.
                unknownSystemIdTotal.increment();
            }
            log.info("bind accepted (AD-25 ROK couple)", kv("event", "bind_accept"),
                    kv("system_id", id), kv("outcome", "coupled"));
        } catch (Throwable t) {
            log.warn("the production observer swallowed its own failure (onBindAccept) — "
                    + "the relay path continues", t);
        }
    }

    @Override
    public void onBindReject(SystemId systemId, Verdict verdict) {
        try {
            String id = systemId.asString();
            rejectedTotal.increment();
            if (!acceptsBySystemId.containsKey(id)) {
                unknownSystemIdTotal.increment(); // same bound on the reject arm (the attack lands here)
            }
            log.info("bind rejected (AD-33 generic bind failure synthesized)", kv("event", "bind_reject"),
                    kv("system_id", id), kv("verdict", verdict.getClass().getSimpleName()),
                    kv("bind_resp_command_status", AD_33_SYNTHESIZED_BIND_RESP_STATUS));
        } catch (Throwable t) {
            log.warn("the production observer swallowed its own failure (onBindReject) — "
                    + "the relay path continues", t);
        }
    }

    @Override
    public void onConnectionClosed(Direction direction, CloseReason reason) {
        try {
            closesByDirection[direction.ordinal()][reason.ordinal()].increment();
        } catch (Throwable t) {
            log.warn("the production observer swallowed its own failure (onConnectionClosed) — "
                    + "close accounting degrades, never the close itself", t);
        }
    }
}
