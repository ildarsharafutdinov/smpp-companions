package smpp.companion.proxy.observability;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.config.RoutingTable;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Story 4.1 step-04 review (finding #5): the startup line's role/mode resolution is verified for
 * EVERY cell, not just the forward-A boot the FR-OBS-2 suite drives. Direct construction is the
 * unit-tier idiom (the {@code MeteredRelayObserverTest} fixture pattern): the logger's whole
 * contract surface is the properties record + the routing table, and the JSON line is captured by
 * the shared {@link ObservabilityPairHarness} production appender &mdash; so each cell below
 * asserts on the SHIPPED encoder's actual output, not a hand-parsed message string.
 *
 * <p>Minimal property values (paths need not exist &mdash; the summary reads only the
 * role/mode/bind/metrics/tls/routing/memory structure, never a file). RED-on-neuter: a mode()
 * branch flip or a dropped role/mode field turns exactly its cell red.
 */
@Tag("unit")
@Tag("observability")
@Tag("p1")
@DisplayName("StartupSummaryLogger — role/mode resolution per AD-17 cell (FR-OBS-2)")
class StartupSummaryLoggerTest extends ObservabilityPairHarness {

    @Test
    @DisplayName("every non-forward-A cell resolves its role and mode onto the startup JSON line")
    void everyCellResolvesRoleAndMode() {
        armProductionJsonAppender();
        try {
            assertCell(forwardCProperties(), "forward", "c");
            assertCell(reverseAProperties(), "reverse", "a");
            assertCell(reverseBProperties(), "reverse", "b");
            assertCell(reverseCProperties(), "reverse", "c");
        } finally {
            restoreTestLogging();
        }
    }

    /** One boot's summary for one cell: reset the capture, fire the logger, assert role + mode. */
    private void assertCell(ProxyCompanionProperties properties, String role, String mode) {
        sink.reset();
        new StartupSummaryLogger(properties, new RoutingTable(properties)).onReady();
        Map<String, Object> line = lineByEvent(capturedJsonLines(), "startup_summary");
        assertThat(line.get("role")).as("role of %s/%s", role, mode).isEqualTo(role);
        assertThat(line.get("mode")).as("mode of %s/%s", role, mode).isEqualTo(mode);
    }

    // --- minimal per-cell property records (structure only — no file is read at summary time) ---

    private static ProxyCompanionProperties forwardCProperties() {
        return new ProxyCompanionProperties(
                bind(), memory(), tls(),
                new ProxyCompanionProperties.Forward(
                        null,
                        new ProxyCompanionProperties.ForwardModeC(
                                new ProxyCompanionProperties.ClientCert("/unused.crt", "/unused.key"),
                                new ProxyCompanionProperties.TrustStore("/unused.p12", null),
                                List.of(new ProxyCompanionProperties.RoutingEntry(
                                        "alpha", "reverse.internal", 2776, null))),
                        null),
                null, null,
                shutdown());
    }

    private static ProxyCompanionProperties reverseAProperties() {
        return new ProxyCompanionProperties(
                bind(), memory(), tls(), null,
                new ProxyCompanionProperties.Reverse(
                        new ProxyCompanionProperties.ReverseModeA(
                                new ProxyCompanionProperties.Smsc("smsc.carrier.example", 2775),
                                new ProxyCompanionProperties.ServerCert("/unused.crt", "/unused.key"),
                                oidc()),
                        null, null),
                null,
                shutdown());
    }

    private static ProxyCompanionProperties reverseBProperties() {
        return new ProxyCompanionProperties(
                bind(), memory(), tls(), null,
                new ProxyCompanionProperties.Reverse(
                        null,
                        new ProxyCompanionProperties.ReverseModeB(
                                new ProxyCompanionProperties.Smsc("smsc.carrier.example", 2775),
                                true, // ack present — the logger reads structure only
                                oidc()),
                        null),
                null,
                shutdown());
    }

    private static ProxyCompanionProperties reverseCProperties() {
        return new ProxyCompanionProperties(
                bind(), memory(), tls(), null,
                new ProxyCompanionProperties.Reverse(
                        null, null,
                        new ProxyCompanionProperties.ReverseModeC(
                                new ProxyCompanionProperties.Smsc("smsc.carrier.example", 2775),
                                new ProxyCompanionProperties.ServerCert("/unused.crt", "/unused.key"),
                                new ProxyCompanionProperties.TrustStore("/unused.p12", null),
                                oidc())),
                null,
                shutdown());
    }

    private static ProxyCompanionProperties.Bind bind() {
        return new ProxyCompanionProperties.Bind(2775, "127.0.0.1", Duration.ofSeconds(4));
    }

    private static ProxyCompanionProperties.Memory memory() {
        return new ProxyCompanionProperties.Memory(1, 1, 1.0,
                ProxyCompanionProperties.Memory.BudgetCheck.FAIL);
    }

    private static ProxyCompanionProperties.Tls tls() {
        return new ProxyCompanionProperties.Tls(List.of("TLSv1.3"), List.of(), List.of());
    }

    private static ProxyCompanionProperties.Shutdown shutdown() {
        return new ProxyCompanionProperties.Shutdown(Duration.ofSeconds(10));
    }

    private static ProxyCompanionProperties.Oidc oidc() {
        return new ProxyCompanionProperties.Oidc(
                URI.create("https://idp.example.com/realms/smpp-companions"),
                "smpp-client", "/unused-secret",
                new ProxyCompanionProperties.TrustStore("/unused-idp.p12", null),
                Duration.ofSeconds(4), 64);
    }
}
