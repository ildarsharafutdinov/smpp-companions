package smpp.companion.proxy.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import smpp.companion.proxy.config.ProxyCompanionProperties;

/**
 * Story 3.2 T7 (AC1) — the security-side wiring: exactly ONE {@link BindCredentialVerifier} bean per
 * AD-17 cell, selected structurally by the populated {@code companion.<role>.<mode>} branch. Per the
 * AD-12 amendment of 2026-08-18 (which inverts the story's original AC1 direction): every
 * <b>reverse</b> cell adjudicates — it wires the {@link RopcBindCredentialVerifier} (the reverse
 * role is the sole enforcement point before the SMSC), constructed fail-closed over the T2 provider
 * link ({@link IdpSslContextFactory}'s TLS posture + the token endpoint derived from
 * {@code provider-url} + the AD-18 client-secret load; the 3.2-T2 startup discovery probe was
 * removed by Story 3.4 T9, 2026-08-29 — no provider wire call at boot); <b>forward</b> cells are
 * trusted-side relays that carry no OIDC material — they wire the
 * {@link AlwaysAllowBindCredentialVerifier} stand-in.
 *
 * <p>{@link AlwaysAllowBindCredentialVerifier} lost its unconditional {@code @Component} for this:
 * a self-annotated stand-in would put TWO verifier beans in every reverse context. The
 * {@link AdjudicationLifecycle} rides along in every cell (inert where the verifier is the
 * stand-in), owning the AD-22 stop window below the relay acceptor's phase.
 *
 * <p>No bean here touches {@code relay/} — the acceptor and interceptor keep injecting the
 * UNCHANGED port type; only the selected implementation changes per cell (AC8-immutable port,
 * wired never re-authored).
 */
@Configuration
public class VerifierWiringConfig {

    /**
     * The cell's single {@link BindCredentialVerifier}. The reverse branch's presence IS the
     * selector (the AD-17 compact ctor guarantees exactly one populated role&times;mode leaf), so
     * the selection cannot drift from the config model. The adapter bean's inferred
     * {@code close()} destroy method is deliberate — the {@link AdjudicationLifecycle} stop runs
     * the drain first (phase-ordered), and the destroy call is the idempotent backstop for a boot
     * that fails before the lifecycle ever starts (the {@code RelayNettyConfig} pattern).
     */
    @Bean
    public BindCredentialVerifier bindCredentialVerifier(ProxyCompanionProperties properties,
            IdpSslContextFactory tlsFactory) {
        if (properties.reverse() != null) {
            return new RopcBindCredentialVerifier(tlsFactory);
        }
        return new AlwaysAllowBindCredentialVerifier();
    }

    /**
     * The adjudicator's lifecycle bean (AD-22): stops BELOW the relay acceptor's phase, so the
     * acceptor (no new binds) closes before the adjudicator denies its in-flight adjudications. On
     * forward cells (the stand-in verifier) its stop is a pure flag flip.
     */
    @Bean
    public AdjudicationLifecycle adjudicationLifecycle(BindCredentialVerifier bindCredentialVerifier) {
        return new AdjudicationLifecycle(bindCredentialVerifier);
    }
}
