package smpp.companion.proxy.observability;

/**
 * The exhaustive set of paths that close a coupled ingress&harr;egress pair (AD-27 / gate-fix
 * {@code .memlog.md:96}). Exactly sixteen values &mdash; this is a <b>closed set over the spine's close
 * paths</b>: every {@link RelayObserver#onConnectionClosed(Direction, CloseReason)} trigger carries one
 * of these, and the violation handler that stashes a reason (AC5) may choose only from this list. Epic 4's
 * production {@code RelayObserver} maps each value to a metrics / structured-log outcome; adding or
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
 *   <li>Bind handshake (AD-25 couple / AD-33 collapse): {@link #CLEAN_UNBIND_HANDSHAKE},
 *       {@link #BIND_REJECTED}, {@link #BIND_FAILED_NON_ROK}.</li>
 *   <li>TLS (Epic 3 &mdash; present now so the closed set is stable across the story boundary, fired only
 *       once TLS lands): {@link #INGRESS_TLS_HANDSHAKE_FAILED}, {@link #EGRESS_TLS_HANDSHAKE_FAILED}.</li>
 *   <li>Lifecycle: {@link #SHUTDOWN_DRAIN}.</li>
 *   <li>Bounded catch-all: {@link #OTHER}.</li>
 * </ul>
 *
 * <p><b>Firing semantics (documented by the Story 4.1 T4 hoist):</b> <b>nine</b> of the sixteen values
 * fire today, stashed by the relay's classification/teardown arms or the deny-path reason hoist
 * ({@code BindInterceptor.denyAndTeardown}):
 * <ul>
 *   <li>Via the shared classification/stash arms: {@link #PEER_HALF_CLOSE} (also the unstashed coupled
 *       default), {@link #PEER_RST}, {@link #DECODE_ERROR} (including the framer's over/undersized
 *       rejects, which surface as {@code DecoderException}), and {@link #OTHER} (the catch-all and the
 *       unstashed pre-couple default).</li>
 *   <li>Via the AD-32 pre-couple policy arms: {@link #PRE_COUPLE_NON_BIND_PDU},
 *       {@link #GENERIC_NACK_PRE_BIND}, {@link #BIND_FAILED_NON_ROK}.</li>
 *   <li>{@link #BIND_REJECTED} &mdash; <b>since the T4 hoist</b>: every proxy-side AD-33 denial (a returned
 *       {@code Deny*} verdict, the fail-closed verifier-failure/null arms, and the RELAY-004 retry-bind
 *       guard) stashes it before the deny teardown.</li>
 *   <li>{@link #EGRESS_CONNECT_FAILED} &mdash; <b>since the T4 hoist</b>: every egress-establishment
 *       failure (a refused/failed connect, SMSC death before the {@code bind_resp}, and the egress-leg
 *       pre-answer violations).</li>
 * </ul>
 * The remaining <b>seven are reserved</b> (kept for closed-set stability, never silently removed): the
 * framer floor/ceiling pair ({@link #OVERSIZED_FRAME}, {@link #UNDERSIZED_FRAME} &mdash; their rejects
 * currently classify as {@link #DECODE_ERROR}); {@link #UNKNOWN_COMMAND_ID} (the codec is structural
 * &mdash; no known-set gate exists pre-couple, so a non-bind PDU closes as
 * {@link #PRE_COUPLE_NON_BIND_PDU}); {@link #CLEAN_UNBIND_HANDSHAKE} (post-couple {@code unbind} relays
 * opaquely; no unbind FSM exists); the TLS pair ({@link #INGRESS_TLS_HANDSHAKE_FAILED},
 * {@link #EGRESS_TLS_HANDSHAKE_FAILED} &mdash; handshake failures currently classify generically as
 * {@link #PEER_RST}/{@link #DECODE_ERROR}); and {@link #SHUTDOWN_DRAIN} (the AD-22 drain body is story
 * 4.2). A dedicated classification for any reserved value is a taxonomy change, not a contract change
 * &mdash; the value set itself is what the shape test pins.
 */
public enum CloseReason {
    /** The peer (legacy client or SMSC) half-closed its leg (FIN); teardown propagates post-couple (REL-1). */
    PEER_HALF_CLOSE,
    /** The peer sent an abrupt RST mid-relay; both legs tear down and the teardown is observed (RELAY-010). */
    PEER_RST,
    /**
     * The egress connection to the SMSC could not be established; the ingress tears down too (RELAY-006).
     * Fires since the Story 4.1 T4 hoist &mdash; for a refused/failed connect AND every pre-answer egress
     * death or violation (the {@code EgressLeg} collapse arms); all indistinguishable on the wire by
     * design (AD-33), all the same taxonomy value.
     */
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
    /**
     * The {@code BindCredentialVerifier} returned a {@code Deny*} verdict (AD-33 collapsed bind-failure).
     * Fires since the Story 4.1 T4 hoist &mdash; stashed by the deny teardown for every proxy-side AD-33
     * denial: {@code Deny*} verdicts, the fail-closed verifier-failure/null arms, and the RELAY-004
     * retry-bind guard.
     */
    BIND_REJECTED,
    /** The SMSC returned a non-ROK {@code bind_*_resp}; the pair never couples, teardown (RELAY-001). */
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
