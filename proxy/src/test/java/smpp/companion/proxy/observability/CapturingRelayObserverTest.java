package smpp.companion.proxy.observability;

import java.time.Duration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Smoke-proofs {@link CapturingRelayObserver} records every trigger &mdash; so T7 / T8 / T9 relay tests
 * can trust their capturing fake before they wire it into a racing pipeline. Bites if a capture path is
 * broken (RED-on-neuter for the test infra itself). Re-pinned in-step for the Story 8.1 T2 seam
 * change (the transit carry + the fifth trigger).
 */
@Tag("unit")
@Tag("relay")
@DisplayName("CapturingRelayObserver — records all 5 triggers (relay-test infrastructure)")
class CapturingRelayObserverTest {

    @Test
    @DisplayName("firing all 5 triggers records each, and clear() resets")
    void recordsAllTriggersThenClears() {
        var captor = new CapturingRelayObserver();
        var systemId = new SystemId(io.netty.util.AsciiString.of("legacy1"));

        captor.onFramedPdu(Direction.INGRESS, Duration.ofNanos(250_000));
        captor.onBindAdjudication(Duration.ofMillis(120));
        captor.onBindAccept(systemId);
        captor.onBindReject(systemId, new Verdict.DenyInvalid());
        captor.onConnectionClosed(Direction.INGRESS, CloseReason.PEER_RST);

        assertThat(captor.framedPdus()).containsExactly(Direction.INGRESS);
        assertThat(captor.framedPduEvents())
                .singleElement()
                .satisfies(f -> {
                    assertThat(f.direction()).isEqualTo(Direction.INGRESS);
                    assertThat(f.transit()).isEqualTo(Duration.ofNanos(250_000));
                });
        assertThat(captor.bindAdjudications()).containsExactly(Duration.ofMillis(120));
        assertThat(captor.bindAccepts()).containsExactly(systemId);
        assertThat(captor.bindRejects())
                .singleElement()
                .satisfies(r -> {
                    assertThat(r.systemId()).isEqualTo(systemId);
                    assertThat(r.verdict()).isEqualTo(new Verdict.DenyInvalid());
                });
        assertThat(captor.connectionCloses())
                .singleElement()
                .satisfies(c -> {
                    assertThat(c.direction()).isEqualTo(Direction.INGRESS);
                    assertThat(c.reason()).isEqualTo(CloseReason.PEER_RST);
                });

        captor.clear();
        assertThat(captor.framedPdus()).isEmpty();
        assertThat(captor.framedPduEvents()).isEmpty();
        assertThat(captor.bindAdjudications()).isEmpty();
        assertThat(captor.bindAccepts()).isEmpty();
        assertThat(captor.bindRejects()).isEmpty();
        assertThat(captor.connectionCloses()).isEmpty();
    }
}
