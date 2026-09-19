package smpp.companion.proxy.observability;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Timer;
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
 *   <li>{@link #BIND_ADJUDICATION_TIMER} &mdash; the Story 8.1 T2 bind-adjudication-latency
 *       histogram, UNLABELED by design (bucket series multiply per label value: a verdict-class label
 *       would be a forbidden new dimension and {@code system_id} would multiply &times; the routing
 *       table, AD-19); one record per completed adjudication, buckets anchored to PERF-3 so the warm
 *       p99 (~250 ms), the cold bound (&le;2 s), and the 4 s adjudication deadline each fall strictly
 *       between adjacent edges;</li>
 *   <li>{@link #PDU_TRANSIT_TIMER}{@code {direction}} &mdash; the Story 8.1 T2 per-PDU relay-transit
 *       histogram, labeled ONLY with the closed 2-value {@link Direction} set (both series
 *       pre-registered like the counters), sub-ms&rarr;s buckets so the sub-ms PERF-4 budget is
 *       visible below 1 ms; one record per relayed PDU;</li>
 *   <li>NO {@code command_id} label, NO channel-id label, NO free-form {@code system_id} &mdash;
 *       ever (the seam carries none of them, and this impl derives none).</li>
 * </ul>
 *
 * <p><b>The JSON lines (FR-OBS-2).</b> Bind accept/reject each log ONE INFO object-line (event,
 * {@code system_id}, outcome / verdict type + the AD-33 synthesized wire status) via logstash
 * {@code StructuredArguments} &mdash; fields ride the T1 {@code LogstashEncoder}; the plain-console
 * test logback renders the same arguments as {@code key=value} pairs. High-frequency triggers
 * ({@code onFramedPdu}, {@code onConnectionClosed}) log NOTHING (metrics only) &mdash; a per-PDU log
 * line would be exactly the flood the privacy contract keeps out of default-level logs; the two
 * Story 8.1 T2 timing triggers ({@code onBindAdjudication}, carrying the same per-bind cadence as
 * the reject line whose verdict it precedes, and the per-PDU transit) are likewise metrics-only
 * &mdash; the audit found no FR-OBS-1 log-event row for a latency figure.
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

    /**
     * Bind-adjudication latency histogram ({@code relay_binds_adjudication_seconds_{bucket,sum,count}}),
     * UNLABELED &mdash; Story 8.1 T2 closing audit gap G1 (the spine-Deferred histogram item; owner
     * decision 2026-09-19, Open Question 1 = B).
     */
    static final String BIND_ADJUDICATION_TIMER = "relay.binds.adjudication";

    /**
     * Per-PDU relay-transit histogram ({@code relay_pdus_transit_seconds_{bucket,sum,count}{direction}}),
     * labeled with the closed {@link Direction} set only &mdash; Story 8.1 T2 closing audit gap G2.
     */
    static final String PDU_TRANSIT_TIMER = "relay.pdus.transit";

    /**
     * The adjudication-latency bucket edges, anchored to PERF-3 and spanning ~[50 ms &hellip; 8 s] so the
     * warm p99 (~250 ms), the cold bound (&le;2 s), and the {@code adjudication-deadline} default (4 s)
     * each fall STRICTLY between adjacent edges (the story's Design Note): 250 ms &isin; (100 ms, 500 ms],
     * 2 s &isin; (1 s, 2.5 s], 4 s &isin; (2.5 s, 5 s]. Exact edges are implementation-owned and recorded
     * where addendum A2 points (the addendum note + the runbook rows &mdash; Story 8.1 Tasks 4/5).
     */
    static final Duration[] BIND_ADJUDICATION_BUCKETS = {
            Duration.ofMillis(50), Duration.ofMillis(100), Duration.ofMillis(500),
            Duration.ofSeconds(1), Duration.ofMillis(2500), Duration.ofSeconds(5), Duration.ofSeconds(8)};

    /**
     * The relay-transit bucket edges, spanning sub-ms&rarr;s so the sub-ms PERF-4 per-PDU budget is
     * visible below 1 ms (two edges under it: 100 &micro;s and 500 &micro;s, plus the 1 ms edge itself).
     */
    static final Duration[] PDU_TRANSIT_BUCKETS = {
            Duration.ofNanos(100_000), Duration.ofNanos(500_000),
            Duration.ofMillis(1), Duration.ofMillis(5), Duration.ofMillis(10),
            Duration.ofMillis(50), Duration.ofMillis(100), Duration.ofMillis(500), Duration.ofSeconds(1)};

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
     * The adjudication-latency histogram &mdash; ONE unlabeled {@link Timer} pre-registered at
     * construction (Story 8.1 T2); every record is a plain field hit, no registration path.
     */
    private final Timer bindAdjudicationLatency;

    /**
     * Transit histograms indexed by {@link Direction#ordinal()} &mdash; both directions
     * pre-registered at construction (Story 8.1 T2), the same closed-set pattern as
     * {@link #pdusByDirection}.
     */
    private final Timer[] transitByDirection;

    /**
     * Pre-registers the ENTIRE series surface (the cardinality bound): both PDU directions, one
     * accept series per routing-table id, the full close grid, the two unlabeled counters, and the
     * two Story 8.1 T2 latency histograms (unlabeled adjudication + both transit directions).
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

        // Story 8.1 T2: the two ratified latency histograms (audit gaps G1/G2), pre-registered here
        // like every other series — the AD-19 construction-time cardinality mechanism, unchanged.
        this.bindAdjudicationLatency = Timer.builder(BIND_ADJUDICATION_TIMER)
                .description("Bind adjudication latency: verifier hand-off → verdict settle, one "
                        + "record per COMPLETED adjudication (Allow, Deny*, exceptional, and "
                        + "cancel-aborted settles alike; routing-miss/gate denials never adjudicated "
                        + "so never record). Unlabeled by design — bucket series multiply per label "
                        + "value and every candidate label is a forbidden dimension (AD-19). Buckets "
                        + "anchored to PERF-3: warm p99 ~250 ms, cold ≤2 s, the 4 s "
                        + "adjudication-deadline each fall strictly between edges over ~[50 ms … 8 s].")
                .serviceLevelObjectives(BIND_ADJUDICATION_BUCKETS)
                .register(registry);

        Timer[] transit = new Timer[Direction.values().length];
        for (Direction direction : Direction.values()) {
            transit[direction.ordinal()] = Timer.builder(PDU_TRANSIT_TIMER)
                    .description("Per-PDU relay transit: framed-PDU arrival at the relay seam → "
                            + "forward onto the peer leg, one record per relayed (post-couple) PDU, "
                            + "per direction (the closed 2-value set is the whole label domain, "
                            + "AD-19). Buckets span sub-ms→s so the sub-ms PERF-4 per-PDU budget is "
                            + "visible below 1 ms.")
                    .tag(DIRECTION_TAG, direction.name())
                    .serviceLevelObjectives(PDU_TRANSIT_BUCKETS)
                    .register(registry);
        }
        this.transitByDirection = transit;
    }

    @Override
    public void onFramedPdu(Direction direction, Duration transit) {
        try {
            pdusByDirection[direction.ordinal()].increment();
            transitByDirection[direction.ordinal()].record(transit);
        } catch (Throwable t) {
            log.warn("the production observer swallowed its own failure (onFramedPdu) — "
                    + "the relay path continues", t);
        }
    }

    @Override
    public void onBindAdjudication(Duration latency) {
        try {
            bindAdjudicationLatency.record(latency);
        } catch (Throwable t) {
            log.warn("the production observer swallowed its own failure (onBindAdjudication) — "
                    + "the verdict path continues", t);
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
