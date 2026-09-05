package smpp.companion.proxy.observability;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import io.netty.util.AsciiString;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;

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
        }
        assertThat(registry.getMeters())
                .as("PRIV-1: 50 distinct unknown ids added ZERO series — cardinality is bounded by "
                        + "construction (AD-19)")
                .hasSize(seriesBeforeBurst);
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

        observer.onFramedPdu(Direction.INGRESS);
        observer.onFramedPdu(Direction.INGRESS);
        observer.onFramedPdu(Direction.EGRESS);
        observer.onConnectionClosed(Direction.EGRESS, CloseReason.PEER_RST);

        assertThat(registry.get(MeteredRelayObserver.PDU_COUNTER).tag("direction", "INGRESS")
                .counter().count()).isEqualTo(2.0);
        assertThat(registry.get(MeteredRelayObserver.PDU_COUNTER).tag("direction", "EGRESS")
                .counter().count()).isEqualTo(1.0);
        assertThat(registry.get(MeteredRelayObserver.CLOSE_COUNTER)
                .tag("direction", "EGRESS").tag("reason", "PEER_RST").counter().count()).isEqualTo(1.0);

        // The whole registry surface, pinned: 2 PDU + 2 accept + 32 close + reject + unknown —
        // no hidden series exists anywhere on the observer.
        assertThat(registry.getMeters()).hasSize(38);

        // The mirrored AD-33 wire status, pinned as the LITERAL — the same anti-drift discipline
        // BindInterceptor's own tests apply to the relay-side constant (that one is package-private
        // int 0x0000000D; this mirror is its string twin — each side pinned independently, so a
        // drift in EITHER constant fails a test on its own tier).
        assertThat(MeteredRelayObserver.AD_33_SYNTHESIZED_BIND_RESP_STATUS)
                .as("the reject line's bind_resp_command_status mirrors relay's AD-33 collapse")
                .isEqualTo("0x0000000D");
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
                new ProxyCompanionProperties.Bind(2775, "127.0.0.1", Duration.ofSeconds(4)),
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
                new ProxyCompanionProperties.Shutdown(Duration.ofSeconds(10)));
    }
}
