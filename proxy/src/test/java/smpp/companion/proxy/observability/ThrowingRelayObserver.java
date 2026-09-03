package smpp.companion.proxy.observability;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;

/**
 * Story 4.1 T4 (checkpoint 20) &mdash; the THROWING {@link RelayObserver} double for the fire-site
 * hardening proof: records every trigger (the {@link CapturingRelayObserver} contract) and THEN
 * throws from each ARMED method, so {@code ThrowingObserverHardeningTest} can assert BOTH halves of
 * the seam contract at once: the relay invariants hold (the fire sites' throw isolation swallowed
 * the throw &mdash; frame forwarded, deny synthesized, teardown complete, close exactly-once) AND each
 * throw produced exactly one bounded WARN. The seeded {@link NoopRelayObserver} can never throw and
 * the production {@code MeteredRelayObserver} self-guards &mdash; this double stands in for ANY future
 * implementation that does neither, which is exactly what fire-site (not impl-site) isolation
 * protects.
 *
 * <p><b>Not for production:</b> lives in {@code proxy/src/test}. Thread-safe the same way its
 * capturing twin is (lock-free queues &mdash; the relay's teardown/couple paths race, AD-25); the
 * throw is an {@link IllegalStateException} stand-in for any implementation failure.
 */
public final class ThrowingRelayObserver implements RelayObserver {

    /** The four seam methods &mdash; arming constants, one per fire site under test. */
    public enum Trigger {
        FRAMED_PDU, BIND_ACCEPT, BIND_REJECT, CONNECTION_CLOSED
    }

    /** A captured {@link RelayObserver#onBindReject(SystemId, Verdict)} event. */
    public record BindReject(SystemId systemId, Verdict verdict) { }

    /** A captured {@link RelayObserver#onConnectionClosed(Direction, CloseReason)} event. */
    public record ConnectionClose(Direction direction, CloseReason reason) { }

    private final Set<Trigger> armed;
    private final ConcurrentLinkedQueue<Direction> framedPdus = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<SystemId> bindAccepts = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<BindReject> bindRejects = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<ConnectionClose> connectionCloses = new ConcurrentLinkedQueue<>();

    /**
     * @param armed the methods that throw AFTER recording their trigger; every other method records
     *              only (the unarmed twin of {@link CapturingRelayObserver}).
     */
    public ThrowingRelayObserver(Set<Trigger> armed) {
        this.armed = Set.copyOf(armed);
    }

    @Override
    public void onFramedPdu(Direction direction) {
        framedPdus.add(direction);
        throwIfArmed(Trigger.FRAMED_PDU);
    }

    @Override
    public void onBindAccept(SystemId systemId) {
        bindAccepts.add(systemId);
        throwIfArmed(Trigger.BIND_ACCEPT);
    }

    @Override
    public void onBindReject(SystemId systemId, Verdict verdict) {
        bindRejects.add(new BindReject(systemId, verdict));
        throwIfArmed(Trigger.BIND_REJECT);
    }

    @Override
    public void onConnectionClosed(Direction direction, CloseReason reason) {
        connectionCloses.add(new ConnectionClose(direction, reason));
        throwIfArmed(Trigger.CONNECTION_CLOSED);
    }

    /** Legs that fired {@link RelayObserver#onFramedPdu(Direction)}, in arrival order. */
    public List<Direction> framedPdus() {
        return List.copyOf(framedPdus);
    }

    /** Identities that fired {@link RelayObserver#onBindAccept(SystemId)} (at the AD-25 ROK couple). */
    public List<SystemId> bindAccepts() {
        return List.copyOf(bindAccepts);
    }

    /** Reject events &mdash; {@link SystemId} + {@link Verdict} pairs (AD-33). */
    public List<BindReject> bindRejects() {
        return List.copyOf(bindRejects);
    }

    /** Close events &mdash; leg + {@link CloseReason}; assert exactly-once per channel (AC5). */
    public List<ConnectionClose> connectionCloses() {
        return List.copyOf(connectionCloses);
    }

    private void throwIfArmed(Trigger trigger) {
        if (armed.contains(trigger)) {
            throw new IllegalStateException("observer boom: " + trigger);
        }
    }
}
