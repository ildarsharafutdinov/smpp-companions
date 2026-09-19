package smpp.companion.proxy.observability;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.Timer;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.netty.util.AsciiString;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 4.1 T3 (checkpoint 19): PRIV-1 proof for the production observer — the cardinality-attack
 * row of the I/O matrix. A burst of binds with DISTINCT unknown {@code system_id}s must grow the
 * UNLABELED counters and add ZERO series; the {@code system_id} label domain is exactly the routing
 * table (AC1: pre-registered from {alpha, beta}, so every labeled series draws only from it).
 *
 * <p>DIRECT construction (no context boot): the observer's whole contract surface is the registry +
 * the table, so the unit tier pins it without a Spring context. The full-app displacement
 * ({@code @Primary} wiring) is covered by every yml/builder boot constructing the bean.
 *
 * <p>RED-on-neuter: replace any unlabeled fallback with a labeled increment (or drop the
 * pre-registration), and the series-count / label-domain assertions below fail.
 *
 * <p><b>Story 8.1 T3 (2026-09-19):</b> the meter-count pin is 41 now &mdash; the three T2 timers
 * (the unlabeled adjudication-latency histogram + both transit directions) pre-register at
 * construction like every other series. The T3 rows pin the recording semantics: once per
 * completed adjudication (unlabeled), once per relayed PDU per direction, the pinned bucket edges
 * over the bounded scrape grid, and the cardinality-attack row fires the two timing triggers
 * through the burst (still zero new series &mdash; neither trigger carries a {@code system_id}).
 */
@Tag("unit")
@Tag("observability")
@Tag("p1")
@DisplayName("MeteredRelayObserver — cardinality bounded by construction (PRIV-1 / AC1)")
class MeteredRelayObserverTest {

    private static final Pattern SYSTEM_ID_LABEL = Pattern.compile("system_id=\"([^\"]+)\"");

    @Test
    @DisplayName("cardinality attack: a burst of distinct unknown ids grows counters, never series")
    void burstOfUnknownSystemIdsAddsNoSeries() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        MeteredRelayObserver observer = new MeteredRelayObserver(registry, new RoutingTable(alphaBetaTable()));

        assertThat(registry.get(MeteredRelayObserver.BIND_ACCEPT_COUNTER).tag("system_id", "alpha")
                .counter().count())
                .as("the labeled accept series are PRE-registered at startup (the table IS the label universe)")
                .isZero();
        assertThat(registry.get(MeteredRelayObserver.BIND_ACCEPT_COUNTER).tag("system_id", "beta")
                .counter().count()).isZero();

        int seriesBeforeBurst = registry.getMeters().size();
        for (int i = 0; i < 50; i++) {
            // The attack lands on BOTH triggers (on the reverse arm every reject carries an arbitrary
            // id; accepts of off-table ids are the same hazard), each with a DISTINCT unknown id.
            String attacker = "attacker" + i;
            observer.onBindReject(systemId(attacker),
                    i % 2 == 0 ? new Verdict.DenyInvalid() : new Verdict.DenyIndeterminate());
            observer.onBindAccept(systemId(attacker));
            // Story 8.1 T3: the two timing triggers fire through the attack too — neither carries a
            // system_id (unlabeled / direction-only), so the burst must not move the series count.
            observer.onBindAdjudication(Duration.ofMillis(1));
            observer.onFramedPdu(i % 2 == 0 ? Direction.INGRESS : Direction.EGRESS, Duration.ofNanos(1));
        }
        assertThat(registry.getMeters())
                .as("PRIV-1: 50 distinct unknown ids added ZERO series — cardinality is bounded by "
                        + "construction (AD-19)")
                .hasSize(seriesBeforeBurst);
        assertThat(registry.get(MeteredRelayObserver.BIND_ADJUDICATION_TIMER).timer().count())
                .as("all 50 adjudication fires landed on the histogram — never on a new series")
                .isEqualTo(50L);
        assertThat(registry.get(MeteredRelayObserver.UNKNOWN_ID_COUNTER).counter().count())
                .as("both burst arms hit the unlabeled unknown-id counter")
                .isEqualTo(100.0);
        assertThat(registry.get(MeteredRelayObserver.BIND_REJECT_COUNTER).counter().count())
                .as("every verifier deny hits the unlabeled reject counter")
                .isEqualTo(50.0);

        // A KNOWN id increments its pre-registered series — still no growth.
        observer.onBindAccept(systemId("alpha"));
        assertThat(registry.get(MeteredRelayObserver.BIND_ACCEPT_COUNTER).tag("system_id", "alpha")
                .counter().count()).isEqualTo(1.0);
        assertThat(registry.getMeters()).hasSize(seriesBeforeBurst);

        // The scrape-level view (what an operator's Prometheus actually fans out): every
        // system_id-labeled series draws ONLY from {alpha, beta} — AC1 verbatim.
        Set<String> labeledValues = new HashSet<>();
        Matcher matcher = SYSTEM_ID_LABEL.matcher(registry.scrape());
        while (matcher.find()) {
            labeledValues.add(matcher.group(1));
        }
        assertThat(labeledValues)
                .as("the scrape's whole system_id label domain is the routing table")
                .containsExactlyInAnyOrder("alpha", "beta");
    }

    @Test
    @DisplayName("pinned counters: PDU/close/accept series pre-registered over the closed sets and counting")
    void pinnedCountersPreRegisteredAndCounting() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        MeteredRelayObserver observer = new MeteredRelayObserver(registry, new RoutingTable(alphaBetaTable()));

        // The FULL 2×16 close grid exists at startup — including values that never fire today
        // (the T4 reason-hoist will make BIND_REJECTED/EGRESS_CONNECT_FAILED real).
        assertThat(registry.get(MeteredRelayObserver.CLOSE_COUNTER)
                .tag("direction", "INGRESS").tag("reason", "SHUTDOWN_DRAIN").counter().count())
                .as("the close grid is fully pre-registered (the closed enum is the whole label domain)")
                .isZero();
        assertThat(registry.get(MeteredRelayObserver.PDU_COUNTER).tag("direction", "EGRESS")
                .counter().count()).isZero();
        // Story 8.1 T2/T3: BOTH histograms pre-register at construction — unlabeled adjudication +
        // both transit directions — so no fire path can ever hit a registration path.
        assertThat(registry.get(MeteredRelayObserver.BIND_ADJUDICATION_TIMER).timer().count())
                .as("the adjudication histogram exists at startup, at zero")
                .isZero();
        assertThat(registry.get(MeteredRelayObserver.PDU_TRANSIT_TIMER).tag("direction", "INGRESS")
                .timer().count()).isZero();
        assertThat(registry.get(MeteredRelayObserver.PDU_TRANSIT_TIMER).tag("direction", "EGRESS")
                .timer().count()).isZero();

        observer.onFramedPdu(Direction.INGRESS, Duration.ofNanos(150_000));
        observer.onFramedPdu(Direction.INGRESS, Duration.ofNanos(150_000));
        observer.onFramedPdu(Direction.EGRESS, Duration.ofMillis(2));
        observer.onConnectionClosed(Direction.EGRESS, CloseReason.PEER_RST);

        assertThat(registry.get(MeteredRelayObserver.PDU_COUNTER).tag("direction", "INGRESS")
                .counter().count()).isEqualTo(2.0);
        assertThat(registry.get(MeteredRelayObserver.PDU_COUNTER).tag("direction", "EGRESS")
                .counter().count()).isEqualTo(1.0);
        assertThat(registry.get(MeteredRelayObserver.PDU_TRANSIT_TIMER).tag("direction", "INGRESS")
                .timer().count())
                .as("the transit histogram records beside the PDU counter — once per relayed PDU")
                .isEqualTo(2L);
        assertThat(registry.get(MeteredRelayObserver.PDU_TRANSIT_TIMER).tag("direction", "EGRESS")
                .timer().count()).isEqualTo(1L);
        assertThat(registry.get(MeteredRelayObserver.CLOSE_COUNTER)
                .tag("direction", "EGRESS").tag("reason", "PEER_RST").counter().count()).isEqualTo(1.0);

        // The whole registry surface, pinned: 2 PDU + 2 accept + 32 close + reject + unknown + the
        // 3 Story 8.1 T2 timers (unlabeled adjudication + both transit directions) — no hidden
        // series exists anywhere on the observer.
        assertThat(registry.getMeters()).hasSize(41);

        // The mirrored AD-33 wire status, pinned as the LITERAL — the same anti-drift discipline
        // BindInterceptor's own tests apply to the relay-side constant (that one is package-private
        // int 0x0000000D; this mirror is its string twin — each side pinned independently, so a
        // drift in EITHER constant fails a test on its own tier).
        assertThat(MeteredRelayObserver.AD_33_SYNTHESIZED_BIND_RESP_STATUS)
                .as("the reject line's bind_resp_command_status mirrors relay's AD-33 collapse")
                .isEqualTo("0x0000000D");
    }

    @Test
    @DisplayName("Story 8.1 T3: the adjudication histogram records once per fire, UNLABELED — "
            + "count/sum on the scrape, above-edge values still one record")
    void adjudicationHistogramRecordsOncePerFireUnlabeled() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        MeteredRelayObserver observer = new MeteredRelayObserver(registry, new RoutingTable(alphaBetaTable()));

        observer.onBindAdjudication(Duration.ofMillis(120));
        observer.onBindAdjudication(Duration.ofMillis(230));
        observer.onBindAdjudication(Duration.ofSeconds(9)); // above the top edge — still exactly one record

        Timer histogram = registry.get(MeteredRelayObserver.BIND_ADJUDICATION_TIMER).timer();
        assertThat(histogram.count())
                .as("one record per completed adjudication — three fires, three records")
                .isEqualTo(3L);
        assertThat(histogram.totalTime(TimeUnit.MILLISECONDS))
                .as("the sum carries every fire's full duration (the overflow bucket steals nothing)")
                .isEqualTo(120.0 + 230.0 + 9000.0);
        assertThat(histogram.getId().getTags())
                .as("UNLABELED by design — no verdict, no system_id, no other dimension (AD-19)")
                .isEmpty();

        String scrape = registry.scrape();
        assertThat(sampleValue(scrape, "relay_binds_adjudication_seconds_count"))
                .as("the operator-visible _count row — one per record")
                .isEqualTo(3.0);
        assertThat(sampleValue(scrape, "relay_binds_adjudication_seconds_sum"))
                .as("the scrape renders the sum in the timer's base unit (seconds)")
                .isEqualTo((120.0 + 230.0 + 9000.0) / 1000.0);
    }

    @Test
    @DisplayName("Story 8.1 T3: the transit histogram records once per relayed PDU, PER DIRECTION — "
            + "both series pre-registered, counts and sums per leg, every transit series labeled")
    void transitHistogramRecordsOncePerRelayedPduPerDirection() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        MeteredRelayObserver observer = new MeteredRelayObserver(registry, new RoutingTable(alphaBetaTable()));

        observer.onFramedPdu(Direction.INGRESS, Duration.ofNanos(150_000));
        observer.onFramedPdu(Direction.INGRESS, Duration.ofNanos(250_000));
        observer.onFramedPdu(Direction.EGRESS, Duration.ofMillis(2));

        Timer ingress = registry.get(MeteredRelayObserver.PDU_TRANSIT_TIMER)
                .tag("direction", "INGRESS").timer();
        assertThat(ingress.count())
                .as("one record per relayed PDU on the INGRESS leg")
                .isEqualTo(2L);
        assertThat(ingress.totalTime(TimeUnit.NANOSECONDS)).isEqualTo(150_000.0 + 250_000.0);
        Timer egress = registry.get(MeteredRelayObserver.PDU_TRANSIT_TIMER)
                .tag("direction", "EGRESS").timer();
        assertThat(egress.count()).isEqualTo(1L);
        assertThat(egress.totalTime(TimeUnit.MILLISECONDS)).isEqualTo(2.0);

        String scrape = registry.scrape();
        assertThat(labeledSampleValue(scrape, "relay_pdus_transit_seconds_count", "INGRESS"))
                .isEqualTo(2.0);
        assertThat(labeledSampleValue(scrape, "relay_pdus_transit_seconds_count", "EGRESS"))
                .isEqualTo(1.0);
        assertThat(scrape.lines()
                .filter(line -> !line.startsWith("#"))
                .filter(line -> line.startsWith("relay_pdus_transit"))
                .filter(line -> !line.contains("direction=\"")))
                .as("EVERY transit series carries the direction label — the closed 2-value set is "
                        + "the whole label domain, no unlabeled strays")
                .isEmpty();
    }

    @Test
    @DisplayName("Story 8.1 T3: bucket edges PINNED and the scrape grid BOUNDED — PERF-3 anchors "
            + "strictly between adjudication edges, sub-ms PERF-4 visible under 1 ms, recording "
            + "creates no series")
    void bucketEdgesPinnedAndScrapeGridBounded() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        MeteredRelayObserver observer = new MeteredRelayObserver(registry, new RoutingTable(alphaBetaTable()));

        // The pinned edges (implementation-owned; addendum A2 + the runbook rows document them —
        // Story 8.1 Tasks 4/5). containsExactly pins values AND order — change any edge and this fails.
        assertThat(MeteredRelayObserver.BIND_ADJUDICATION_BUCKETS)
                .containsExactly(Duration.ofMillis(50), Duration.ofMillis(100), Duration.ofMillis(500),
                        Duration.ofSeconds(1), Duration.ofMillis(2500), Duration.ofSeconds(5),
                        Duration.ofSeconds(8));
        assertThat(MeteredRelayObserver.PDU_TRANSIT_BUCKETS)
                .containsExactly(Duration.ofNanos(100_000), Duration.ofNanos(500_000),
                        Duration.ofMillis(1), Duration.ofMillis(5), Duration.ofMillis(10),
                        Duration.ofMillis(50), Duration.ofMillis(100), Duration.ofMillis(500),
                        Duration.ofSeconds(1));

        // PERF-3 anchors: each falls STRICTLY between adjacent adjudication edges (the Design Note).
        assertThat(strictlyBetweenEdges(MeteredRelayObserver.BIND_ADJUDICATION_BUCKETS, Duration.ofMillis(250)))
                .as("warm p99 ~250 ms falls inside (100 ms, 500 ms]").isTrue();
        assertThat(strictlyBetweenEdges(MeteredRelayObserver.BIND_ADJUDICATION_BUCKETS, Duration.ofSeconds(2)))
                .as("cold ≤2 s falls inside (1 s, 2.5 s]").isTrue();
        assertThat(strictlyBetweenEdges(MeteredRelayObserver.BIND_ADJUDICATION_BUCKETS, Duration.ofSeconds(4)))
                .as("the 4 s adjudication-deadline default falls inside (2.5 s, 5 s]").isTrue();
        // PERF-4: two edges strictly below 1 ms — the sub-ms budget is visible under the 1 ms edge.
        int subMsEdges = 0;
        for (Duration edge : MeteredRelayObserver.PDU_TRANSIT_BUCKETS) {
            if (edge.compareTo(Duration.ofMillis(1)) < 0) {
                subMsEdges++;
            }
        }
        assertThat(subMsEdges)
                .as("two edges strictly below 1 ms (100 µs and 500 µs) make PERF-4's sub-ms budget "
                        + "visible below the 1 ms edge")
                .isEqualTo(2);

        // The grid is BOUNDED: recording (incl. an above-top-edge overflow) changes only values.
        String before = registry.scrape();
        observer.onBindAdjudication(Duration.ofMillis(120));
        observer.onFramedPdu(Direction.INGRESS, Duration.ofNanos(150_000));
        observer.onFramedPdu(Direction.EGRESS, Duration.ofSeconds(9)); // over the top edge → the +Inf bucket
        String after = registry.scrape();

        assertThat(bucketEdges(after, "relay_binds_adjudication_seconds_bucket", null))
                .as("the adjudication grid: the 8 pinned edges + the +Inf overflow, unlabeled — "
                        + "nothing else can ever appear")
                .containsExactly(0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 8.0, Double.POSITIVE_INFINITY);
        for (Direction direction : Direction.values()) {
            assertThat(bucketEdges(after, "relay_pdus_transit_seconds_bucket", direction.name()))
                    .as("the transit grid for %s: the 9 pinned edges + +Inf", direction)
                    .containsExactly(1.0E-4, 5.0E-4, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0,
                            Double.POSITIVE_INFINITY);
        }
        assertThat(scrapeSeriesShape(after))
                .as("recording moved VALUES only — the series/bucket shape before vs after is "
                        + "identical (no runtime bucket or series creation)")
                .isEqualTo(scrapeSeriesShape(before));
    }

    // --- scrape-parsing helpers (the operator's view: what /metrics actually renders) -------

    private static final Pattern LE_LABEL = Pattern.compile("le=\"([^\"]+)\"");

    /**
     * The {@code le} edges of one histogram's bucket rows, in scrape order &mdash; filtered to one
     * direction for the transit grid, unlabeled-only for the adjudication grid ({@code null}).
     */
    private static List<Double> bucketEdges(String scrape, String series, @Nullable String direction) {
        return scrape.lines()
                .filter(line -> !line.startsWith("#"))
                .filter(line -> line.startsWith(series))
                .filter(line -> direction == null || line.contains("direction=\"" + direction + "\""))
                .map(line -> {
                    Matcher matcher = LE_LABEL.matcher(line);
                    assertThat(matcher.find()).as("a bucket row carries le: " + line).isTrue();
                    String le = matcher.group(1);
                    // Prometheus renders the overflow edge as +Inf; Java parses "Infinity".
                    return "+Inf".equals(le) ? Double.POSITIVE_INFINITY : Double.parseDouble(le);
                })
                .toList();
    }

    /** The sample value of one UNLABELED series row ({@code name value}). */
    private static double sampleValue(String scrape, String series) {
        return scrape.lines()
                .filter(line -> !line.startsWith("#"))
                .filter(line -> line.startsWith(series)
                        && (line.length() == series.length() || line.charAt(series.length()) == ' '))
                .findFirst()
                .map(line -> Double.parseDouble(line.substring(line.lastIndexOf(' ') + 1)))
                .orElseThrow(() -> new AssertionError("no sample row for " + series + " in the scrape"));
    }

    /** The sample value of one direction-labeled series row, skipping the per-bucket {@code le} rows. */
    private static double labeledSampleValue(String scrape, String series, String direction) {
        return scrape.lines()
                .filter(line -> !line.startsWith("#"))
                .filter(line -> line.startsWith(series))
                .filter(line -> line.contains("direction=\"" + direction + "\""))
                .filter(line -> !line.contains("le="))
                .findFirst()
                .map(line -> Double.parseDouble(line.substring(line.lastIndexOf(' ') + 1)))
                .orElseThrow(() -> new AssertionError(
                        "no sample row for " + series + "{direction=" + direction + "} in the scrape"));
    }

    /**
     * The scrape with live sample values stripped ({@code # HELP/# TYPE} verbatim, samples reduced to
     * series + labels, sorted) &mdash; two scrapes of a registry whose fires create no series have
     * identical shapes (the {@code MetricsEndpointTest.scrapeShape} idiom, local to this bare
     * registry where no JVM binder can move anything).
     */
    private static List<String> scrapeSeriesShape(String scrape) {
        return scrape.lines()
                .map(line -> {
                    if (line.startsWith("#")) {
                        return line;
                    }
                    int value = line.lastIndexOf(' ');
                    return value > 0 ? line.substring(0, value) : line;
                })
                .sorted()
                .toList();
    }

    /** True iff the anchor falls strictly between two adjacent edges over (lower, upper]. */
    private static boolean strictlyBetweenEdges(Duration[] buckets, Duration anchor) {
        for (int i = 0; i < buckets.length; i++) {
            Duration lower = i == 0 ? Duration.ZERO : buckets[i - 1];
            if (anchor.compareTo(lower) > 0 && anchor.compareTo(buckets[i]) <= 0) {
                return true;
            }
        }
        return false;
    }

    // --- fixtures ---------------------------------------------------------------------------

    private static SystemId systemId(String value) {
        return new SystemId(new AsciiString(value));
    }

    /**
     * The AC1 table: forward.mode-a with routing {alpha, beta} (minimal legal values — the observer
     * reads only the routing ids; direct record construction is the RopcBindCredentialVerifierTest
     * fixture idiom).
     */
    private static ProxyCompanionProperties alphaBetaTable() {
        return new ProxyCompanionProperties(
                new ProxyCompanionProperties.Bind(2775, "127.0.0.1", Duration.ofSeconds(4), Duration.ofSeconds(30)),
                new ProxyCompanionProperties.Memory(1, 1, 1.0,
                        ProxyCompanionProperties.Memory.BudgetCheck.FAIL),
                new ProxyCompanionProperties.Tls(List.of("TLSv1.3"), List.of(), List.of()),
                new ProxyCompanionProperties.Forward(
                        new ProxyCompanionProperties.ForwardModeA(
                                new ProxyCompanionProperties.TrustStore("/unused-by-observer", null),
                                List.of(new ProxyCompanionProperties.RoutingEntry(
                                                "alpha", "reverse.internal", 2776, null),
                                        new ProxyCompanionProperties.RoutingEntry(
                                                "beta", "reverse2.internal", 2776, null))),
                        null, null),
                null, null,
                new ProxyCompanionProperties.Shutdown(RelayTestFixtures.DEFAULT_DRAIN_TIMEOUT));
    }
}
