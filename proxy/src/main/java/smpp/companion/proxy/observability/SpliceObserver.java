package smpp.companion.proxy.observability;

import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;

/**
 * The observability seam the relay fires against a coupled ingress&harr;egress pair (AD-27). Story 2.2
 * AUTHORS this interface (2.1 scoped it OUT); {@link NoopSpliceObserver} is the seeded default bean, and
 * Epic 4 swaps in the production Micrometer {@code /metrics} impl behind this UNCHANGED interface.
 *
 * <p><b>No PDU type, no content.</b> The triggers carry only a {@link Direction}, a {@link SystemId} (at
 * the bind handshake only), a {@link Verdict} (on reject only), or a {@link CloseReason}. No {@code
 * command_id}, no {@code ChannelId}, no PDU body crosses this seam &mdash; the AD-19 cardinality bound (no
 * high-cardinality label) and AD-27 (the codec never emits metrics) both hold. The {@link SystemId} a
 * production impl receives is for structured logging only, <b>not</b> a metrics label (reverse.mode-b has
 * no routing table, so the labeled set is empty by construction). PDU <i>count</i> is observed by counting
 * {@link #onFramedPdu(Direction)} fires (one per framed PDU); the seam carries no byte-volume signal.
 *
 * <p><b>Pinned triggers (AC5):</b>
 * <ul>
 *   <li>{@link #onBindAccept(SystemId)} fires exactly at the AD-25 ROK flip (NOT at the verdict &mdash; the
 *       verdict precedes the egress bind; the flip ratifies the SMSC's ROK);</li>
 *   <li>{@link #onConnectionClosed(Direction, CloseReason)} fires exactly-once per channel (CAS-guarded at
 *       the {@code channelInactive} teardown site; the violation handler only stashes the reason and never
 *       calls this directly).</li>
 * </ul>
 */
public interface SpliceObserver {

    /**
     * A framed PDU crossed a leg (pre- or post-couple). Carries no type or body &mdash; opaque framing is the
     * AD-2 invariant. PDU count = the number of these fires; this never inspects content.
     *
     * @param direction the leg the PDU crossed; non-null.
     */
    void onFramedPdu(Direction direction);

    /**
     * A bind handshake completed &mdash; the AD-25 splice flag flipped on a decoded ROK {@code bind_*_resp}.
     * Fires exactly at the flip, NOT at the {@link Verdict} (the verdict precedes the egress bind; the flip
     * ratifies the SMSC's ROK).
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
