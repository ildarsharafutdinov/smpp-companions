package smpp.companion.proxy.observability;

import java.time.Duration;

import org.springframework.stereotype.Component;

import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;

/**
 * The seeded default {@link RelayObserver} (AD-27): every trigger is a no-op. A Spring
 * {@link Component @Component} so it is the injectable default bean the relay wires against; Epic 4
 * swapped in the production Micrometer {@code /metrics} impl behind the interface (the Story 8.1 T2
 * timing triggers ride the same swap). Carries no state and starts no work &mdash; it exists so
 * {@code relay/} has a zero-overhead observer to call before the real observability body lands.
 * Mirrors the {@code AlwaysAllowBindCredentialVerifier} stand-in pattern.
 */
@Component
public final class NoopRelayObserver implements RelayObserver {

    @Override
    public void onFramedPdu(Direction direction, Duration transit) {
        // noop — seeded default; the production impl swaps in behind the seam.
    }

    @Override
    public void onBindAdjudication(Duration latency) {
        // noop — seeded default; the production impl swaps in behind the seam.
    }

    @Override
    public void onBindAccept(SystemId systemId) {
        // noop — seeded default; the production impl swaps in behind the seam.
    }

    @Override
    public void onBindReject(SystemId systemId, Verdict verdict) {
        // noop — seeded default; the production impl swaps in behind the seam.
    }

    @Override
    public void onConnectionClosed(Direction direction, CloseReason reason) {
        // noop — seeded default; the production impl swaps in behind the seam.
    }
}
