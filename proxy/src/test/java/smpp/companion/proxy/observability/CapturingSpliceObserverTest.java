package smpp.companion.proxy.observability;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Smoke-proofs {@link CapturingSpliceObserver} records every trigger &mdash; so T7 / T8 / T9 relay tests
 * can trust their capturing fake before they wire it into a racing pipeline. Bites if a capture path is
 * broken (RED-on-neuter for the test infra itself).
 */
@Tag("unit")
@Tag("relay")
@DisplayName("CapturingSpliceObserver — records all 4 triggers (relay-test infrastructure)")
class CapturingSpliceObserverTest {

    @Test
    @DisplayName("firing all 4 triggers records each, and clear() resets")
    void recordsAllTriggersThenClears() {
        var captor = new CapturingSpliceObserver();
        var systemId = new SystemId(io.netty.util.AsciiString.of("legacy1"));

        captor.onFramedPdu(Direction.INGRESS);
        captor.onBindAccept(systemId);
        captor.onBindReject(systemId, new Verdict.DenyInvalid());
        captor.onConnectionClosed(Direction.INGRESS, CloseReason.PEER_RST);

        assertThat(captor.framedPdus()).containsExactly(Direction.INGRESS);
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
        assertThat(captor.bindAccepts()).isEmpty();
        assertThat(captor.bindRejects()).isEmpty();
        assertThat(captor.connectionCloses()).isEmpty();
    }
}
