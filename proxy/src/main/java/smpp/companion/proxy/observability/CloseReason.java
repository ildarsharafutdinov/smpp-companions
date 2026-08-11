package smpp.companion.proxy.observability;

/**
 * The exhaustive set of paths that close a coupled ingress&harr;egress pair (AD-27 / gate-fix
 * {@code .memlog.md:96}). Exactly sixteen values &mdash; this is a <b>closed set over the spine's close
 * paths</b>: every {@link SpliceObserver#onConnectionClosed(Direction, CloseReason)} trigger carries one
 * of these, and the violation handler that stashes a reason (AC5) may choose only from this list. Epic 4's
 * production {@code SpliceObserver} maps each value to a metrics / structured-log outcome; adding or
 * removing a value here is a contract change the {@code observability/} shape test bites on (AC9 standing
 * gate AI-1).
 *
 * <p><b>Exhaustive over the spine's close paths:</b>
 * <ul>
 *   <li>Peer-driven: {@link #PEER_HALF_CLOSE}, {@link #PEER_RST}.</li>
 *   <li>Egress-establishment: {@link #EGRESS_CONNECT_FAILED}.</li>
 *   <li>Framer / codec (AD-30 floor &amp; ceiling / decode): {@link #OVERSIZED_FRAME},
 *       {@link #UNDERSIZED_FRAME}, {@link #DECODE_ERROR}.</li>
 *   <li>Pre-couple policy (AD-32 uniform bare-close): {@link #UNKNOWN_COMMAND_ID},
 *       {@link #PRE_COUPLE_NON_BIND_PDU}, {@link #GENERIC_NACK_PRE_BIND}.</li>
 *   <li>Bind handshake (AD-25 flip / AD-33 collapse): {@link #CLEAN_UNBIND_HANDSHAKE},
 *       {@link #BIND_REJECTED}, {@link #BIND_FAILED_NON_ROK}.</li>
 *   <li>TLS (Epic 3 &mdash; present now so the closed set is stable across the story boundary, fired only
 *       once TLS lands): {@link #INGRESS_TLS_HANDSHAKE_FAILED}, {@link #EGRESS_TLS_HANDSHAKE_FAILED}.</li>
 *   <li>Lifecycle: {@link #SHUTDOWN_DRAIN}.</li>
 *   <li>Bounded catch-all: {@link #OTHER}.</li>
 * </ul>
 */
public enum CloseReason {
    /** The peer (legacy client or SMSC) half-closed its leg (FIN); teardown propagates post-couple (REL-1). */
    PEER_HALF_CLOSE,
    /** The peer sent an abrupt RST mid-splice; both legs tear down and the teardown is observed (RELAY-010). */
    PEER_RST,
    /** The egress connection to the SMSC could not be established; the ingress tears down too (RELAY-006). */
    EGRESS_CONNECT_FAILED,
    /** A frame exceeded {@code SmppFrame.MAX_COMMAND_LENGTH} (the AD-30 framer ceiling). */
    OVERSIZED_FRAME,
    /** A frame was shorter than {@code SmppFrame.MIN_COMMAND_LENGTH} (the AD-30 framer floor). */
    UNDERSIZED_FRAME,
    /** A framed PDU failed to decode (e.g. a header-only {@code bind_resp} with no NUL terminator, CODEC-021). */
    DECODE_ERROR,
    /** A pre-couple PDU carried a {@code command_id} outside the bind family and the known set (AD-32). */
    UNKNOWN_COMMAND_ID,
    /** A pre-couple non-bind PDU hit the AD-32 uniform bare-close (no {@code _resp} synthesis). */
    PRE_COUPLE_NON_BIND_PDU,
    /** A clean {@code unbind} / {@code unbind_resp} handshake completed post-couple. */
    CLEAN_UNBIND_HANDSHAKE,
    /** The SMSC sent a {@code generic_nack} pre-couple; forwarded verbatim then torn down (AD-32 case 4). */
    GENERIC_NACK_PRE_BIND,
    /** The {@code BindCredentialVerifier} returned a {@code Deny*} verdict (AD-33 collapsed bind-failure). */
    BIND_REJECTED,
    /** The SMSC returned a non-ROK {@code bind_*_resp}; no splice flips, teardown (RELAY-001). */
    BIND_FAILED_NON_ROK,
    /** The ingress TLS handshake failed (Epic 3; present so the closed set is stable across the boundary). */
    INGRESS_TLS_HANDSHAKE_FAILED,
    /** The egress TLS handshake failed (Epic 3; present so the closed set is stable across the boundary). */
    EGRESS_TLS_HANDSHAKE_FAILED,
    /** The {@code SmartLifecycle} drain on proxy shutdown closed the pair (full AD-22 body is Epic 4). */
    SHUTDOWN_DRAIN,
    /** A close path not covered by any of the above &mdash; the bounded catch-all (never a silent drop). */
    OTHER
}
