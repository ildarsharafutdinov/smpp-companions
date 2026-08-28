package smpp.companion.proxy.observability;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;

/**
 * A thread-safe capturing {@link RelayObserver} for the relay tests &mdash; T7 {@code BindInterceptor},
 * the T8 per-leg relay handlers ({@code RelayIngressHandler}/{@code RelayEgressHandler} since the
 * Story 3.4 T5 split), and the T9 in-JVM mock consume this. Records every trigger in concurrent
 * structures so a test can AssertJ-assert the AC5 pinned contracts: {@link #bindAccepts()} fires at the
 * AD-25 ROK couple, {@link #connectionCloses()} fires exactly-once per channel, {@link #framedPdus()} is the
 * PDU count (one fire per framed PDU), and the A-1 affinity smoke asserts zero DLR cross-bleed against
 * per-channel captures.
 *
 * <p><b>Not for production:</b> lives in {@code proxy/src/test}; the production default bean is
 * {@link NoopRelayObserver}. Concurrency-safe because the relay's teardown / couple paths race (AD-25): the
 * capturing queues are lock-free. Snapshot accessors return immutable {@link List} copies so assertions are
 * stable once the test has observed quiescence (the relay test owns the await/latch that precedes a
 * snapshot).
 */
public final class CapturingRelayObserver implements RelayObserver {

    /** A captured {@link RelayObserver#onBindReject(SystemId, Verdict)} event. */
    public record BindReject(SystemId systemId, Verdict verdict) { }

    /** A captured {@link RelayObserver#onConnectionClosed(Direction, CloseReason)} event. */
    public record ConnectionClose(Direction direction, CloseReason reason) { }

    private final ConcurrentLinkedQueue<Direction> framedPdus = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<SystemId> bindAccepts = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<BindReject> bindRejects = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<ConnectionClose> connectionCloses = new ConcurrentLinkedQueue<>();

    @Override
    public void onFramedPdu(Direction direction) {
        framedPdus.add(direction);
    }

    @Override
    public void onBindAccept(SystemId systemId) {
        bindAccepts.add(systemId);
    }

    @Override
    public void onBindReject(SystemId systemId, Verdict verdict) {
        bindRejects.add(new BindReject(systemId, verdict));
    }

    @Override
    public void onConnectionClosed(Direction direction, CloseReason reason) {
        connectionCloses.add(new ConnectionClose(direction, reason));
    }

    /** Legs that fired {@link RelayObserver#onFramedPdu(Direction)}, in arrival order (PDU count = size). */
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

    /** Drain every queue &mdash; handy between sub-scenarios of one test method. */
    public void clear() {
        framedPdus.clear();
        bindAccepts.clear();
        bindRejects.clear();
        connectionCloses.clear();
    }
}
