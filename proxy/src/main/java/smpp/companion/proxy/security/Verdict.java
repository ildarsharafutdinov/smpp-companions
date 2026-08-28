package smpp.companion.proxy.security;

/**
 * The closed adjudication result returned across the {@link BindCredentialVerifier} port (AD-12). Sealed over
 * exactly three payload-less permits — <b>no {@link Throwable}, no free-form reason string, no Nimbus type
 * crosses the port</b>. The ROPC adapter absorbs the "why"; the port carries only the verdict.
 *
 * <p>{@link Allow} = credentials verified (the bind may splice / relay). {@link DenyInvalid} = credentials
 * definitively invalid (e.g. an IdP 4xx). {@link DenyIndeterminate} = the verdict could not be reached
 * (timeout, network error, 5xx, a non-JWT token response &mdash; the JWT-only policy, Story 3.4 T1/T2,
 * 2026-08-27) &mdash; fail-closed per AD-11 (DENY on indeterminate).
 * The distinction between the two DENY permits is informative; <b>both deny</b>. Adding a permit breaks the
 * port's sealed contract (Story 2.1 AC8 ratifies this exact set as "immutable henceforth").
 *
 * <p>The permits are nested records so the closed hierarchy is owned by this file: no external subtype can
 * extend it, and each permit carries zero components (no reason payload leaks across the port).
 */
public sealed interface Verdict permits Verdict.Allow, Verdict.DenyInvalid, Verdict.DenyIndeterminate {

    /** Credentials verified — the bind may be spliced / relayed (AD-12). The token verdict is discarded. */
    record Allow() implements Verdict { }

    /** Credentials definitively invalid (e.g. an IdP 4xx) — DENY (AD-11). */
    record DenyInvalid() implements Verdict { }

    /** Verdict indeterminate (timeout / network error / 5xx / non-JWT token response) — fail-closed DENY (AD-11). */
    record DenyIndeterminate() implements Verdict { }
}
