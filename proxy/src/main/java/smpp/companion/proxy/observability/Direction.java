package smpp.companion.proxy.observability;

/**
 * The leg of a coupled ingress&harr;egress pair a {@link RelayObserver} event is observed on (AD-27).
 * {@link #INGRESS} = the legacy-client-facing channel; {@link #EGRESS} = the SMSC-facing channel. Two
 * values only &mdash; the spine's per-PDU / per-byte / close triggers fire per-direction, and the
 * {@link RelayObserver} seam carries no channel or identity label (AD-19 cardinality bound).
 */
public enum Direction {
    /** The legacy-client-facing leg of the coupled pair. */
    INGRESS,
    /** The SMSC-facing leg of the coupled pair. */
    EGRESS
}
