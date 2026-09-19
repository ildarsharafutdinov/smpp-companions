package smpp.companion.proxy.observability;

import java.time.Duration;

import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;

/**
 * The observability seam the relay fires against a coupled ingress&harr;egress pair (AD-27). Story 2.2
 * AUTHORS this interface (2.1 scoped it OUT); {@link NoopRelayObserver} is the seeded default bean, and
 * Epic 4 swapped in the production Micrometer {@code /metrics} impl behind this interface.
 *
 * <p><b>No PDU type, no content.</b> The triggers carry only a {@link Direction}, a {@link Duration}
 * (timing scalars, Story 8.1 T2), a {@link SystemId} (at the bind handshake only), a {@link Verdict}
 * (on reject only), or a {@link CloseReason}. No {@code command_id}, no {@code ChannelId}, no PDU body
 * crosses this seam &mdash; the AD-19 cardinality bound (no high-cardinality label) and AD-27 (the
 * codec never emits metrics) both hold. The {@link SystemId} a production impl receives is for
 * structured logging only, <b>not</b> a metrics label (reverse.mode-b has no routing table, so the
 * labeled set is empty by construction). PDU <i>count</i> is observed by counting
 * {@link #onFramedPdu(Direction, Duration)} fires (one per relayed, post-couple framed PDU); the seam
 * carries no byte-volume signal.
 *
 * <p><b>Pinned triggers (AC5):</b>
 * <ul>
 *   <li>{@link #onBindAccept(SystemId)} fires exactly at the AD-25 ROK couple (NOT at the verdict &mdash; the
 *       verdict precedes the egress bind; the couple ratifies the SMSC's ROK);</li>
 *   <li>{@link #onConnectionClosed(Direction, CloseReason)} fires exactly-once per channel (CAS-guarded at
 *       the {@code channelInactive} teardown site; the violation handler only stashes the reason and never
 *       calls this directly).</li>
 * </ul>
 *
 * <p><b>Story 8.1 T2 (2026-09-19) &mdash; the ratified Q1=B seam change, landed as an explicit dated
 * contract change</b> (owner decision 2026-09-19; the story's Spec Change Log carries the entry, and
 * {@code RelayObserverShapeTest} was re-pinned in-step): {@code onFramedPdu(Direction)} became
 * {@link #onFramedPdu(Direction, Duration)} (the per-PDU relay transit duration, stamped at framed-PDU
 * arrival and recorded at the egress forward &mdash; one call per relayed PDU, no label beyond
 * {@code direction}), and the fifth trigger {@link #onBindAdjudication(Duration)} landed for the bind
 * adjudication latency histogram (unlabeled). Neither duration is content, neither adds a label
 * dimension, and both fire sites stay throw-isolated; the four pre-existing trigger contracts are
 * otherwise unchanged.
 */
public interface RelayObserver {

    /**
     * A framed PDU crossed a leg of a <b>coupled</b> pair &mdash; <b>post-couple only</b> (the Story 4.1 T4
     * javadoc truth: the single fire site is the opaque relay's forward in {@code
     * CoupledRelayHandler.relayFramedPdu}; the pre-couple bind-handshake plane &mdash; the AD-14
     * original-frame dial and the verbatim {@code bind_*_resp} propagation &mdash; never fires it).
     * Carries no type or body &mdash; opaque framing is the AD-2 invariant. PDU count = the number of
     * these fires; this never inspects content.
     *
     * <p><b>Story 8.1 T2 (Q1=B):</b> the trigger now carries the PDU's <b>transit duration</b> &mdash;
     * stamped at the framed PDU's arrival at the relay seam and computed at its forward onto the peer
     * leg (the single fire site), never double-stamped inside relay internals. A production impl
     * records it into the per-direction relay-transit histogram; the value is a timing scalar, not
     * content, and adds no label beyond {@code direction}.
     *
     * @param direction the leg the PDU crossed; non-null.
     * @param transit   the framed PDU's relay transit (arrival at the relay seam &rarr; forward onto
     *                  the peer leg); non-null, monotonic-clock measured.
     */
    void onFramedPdu(Direction direction, Duration transit);

    /**
     * A bind adjudication <b>completed</b> &mdash; the verifier future settled (Story 8.1 T2, the bind
     * latency histogram's trigger). Fires exactly once per completed adjudication, at the settle point
     * ({@code BindInterceptor.onVerdict}'s first acts), for EVERY completion alike: {@code Allow},
     * either {@code Deny*}, an exceptional future, and a teardown/cancel-aborted exchange whose pin
     * settles per the port's no-op-if-done contract. Never fires for adjudications that never
     * settled (the synchronous verifier blow-up and null-return arms denied before a future existed),
     * and never for non-verdict denials (routing miss, the new-adjudication gate &mdash; no adjudication
     * started). Unlabeled by contract: the latency depends on neither the identity nor the outcome,
     * and a verdict or {@code system_id} label would fan a dimension AD-19 refuses.
     *
     * @param latency the adjudication duration (verifier hand-off &rarr; verdict settle, monotonic
     *                clock); non-null.
     */
    void onBindAdjudication(Duration latency);

    /**
     * A bind handshake completed &mdash; the AD-25 couple flag set on a decoded ROK {@code bind_*_resp}.
     * Fires exactly at the couple, NOT at the {@link Verdict} (the verdict precedes the egress bind; the
     * couple ratifies the SMSC's ROK).
     *
     * @param systemId the identity forwarded end-to-end (AD-14); non-null. For structured logging only, not a
     *                 metrics label (AD-19).
     */
    void onBindAccept(SystemId systemId);

    /**
     * A bind was denied &mdash; the {@link smpp.companion.proxy.security.BindCredentialVerifier} returned a
     * {@code Deny*} and the relay collapsed it to one generic bind-failure code (AD-33). The {@link Verdict}
     * distinction (invalid vs indeterminate) is informative only; both deny.
     *
     * @param systemId the identity whose bind was rejected; non-null. For structured logging only, not a
     *                 metrics label (AD-19).
     * @param verdict  the denial verdict; non-null.
     */
    void onBindReject(SystemId systemId, Verdict verdict);

    /**
     * A leg of the coupled pair closed. Fires exactly-once per channel (AC5 / AD-27) at the
     * {@code channelInactive} teardown site; the violation handler only stashes the reason and never calls
     * this directly.
     *
     * @param direction the leg that closed; non-null.
     * @param reason    the close path; non-null.
     */
    void onConnectionClosed(Direction direction, CloseReason reason);
}
