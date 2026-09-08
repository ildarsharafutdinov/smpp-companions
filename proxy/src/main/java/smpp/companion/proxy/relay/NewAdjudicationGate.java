package smpp.companion.proxy.relay;

import org.springframework.stereotype.Component;

/**
 * Story 4.3 T4 (OBS-017; AD-22 step 1) &mdash; the new-adjudication gate: the shared, injectable flag
 * that carries &ldquo;the acceptor stopped&rdquo; from {@code RelayServerLifecycle.stop()}
 * ({@code relay/netty} &mdash; the acceptor's {@code SmartLifecycle}) to {@code BindInterceptor.onRequest}
 * ({@code relay} &mdash; the per-channel handshake gate), two beans that otherwise share no state (the
 * acceptor's own {@code running} flag is private and lifecycle-scoped). {@code RelayServerLifecycle#stop()}
 * {@link #arm()}s it AT the acceptor close &mdash; BEFORE the close future completes, so a bind racing
 * the close window on an already-established socket is already denied. From that point every NEW bind
 * on an established socket fail-closed-DENIES: the AD-33 generic {@code bind_resp} + close, with NO
 * verifier contact and NO registry entry (OBS-017's two observables &mdash; the consumer sits BEFORE
 * {@code manager.register}, which is what keeps the second one true). New <b>connects</b> are refused
 * by the closed listener itself; the gate is only for the established sockets the close cannot reach.
 *
 * <p><b>Scope fence:</b> the gate denies only NEW adjudications (the first-bind arm). In-flight
 * adjudications are 4.2's deny window ({@code AdjudicationLifecycle}, phase-ordered strictly after
 * the acceptor's stop); POST-COUPLE relaying is untouched &mdash; the 4.3 drain body requires
 * established pairs to keep relaying until the deadline. One-way by design: nothing re-opens it
 * (runtime config is immutable, AD-18 &mdash; a re-open is a new process); re-arming is an idempotent
 * no-op, which is what makes the Spring re-stop and the group bean's destroy-method backstop safe.
 *
 * <p><b>Bean:</b> a singleton {@link Component @Component} (the {@code ConnectionRegistry} house
 * pattern): ONE instance must reach BOTH the acceptor lifecycle (the armer) and the
 * {@code RelayIngressInitializer} graph (the consumer's wiring), which component scan guarantees.
 * Holds one volatile boolean &mdash; {@code new NewAdjudicationGate()} is the test seam (unarmed =
 * admits new binds).
 */
@Component
public final class NewAdjudicationGate {

    private volatile boolean armed;

    /**
     * Arms the gate: from this call, no new adjudication may start. Called by
     * {@code RelayServerLifecycle.stop()} at the acceptor close (AD-22 step 1 &mdash; &ldquo;no new
     * binds&rdquo;). One-way and idempotent; safe from any thread (the Spring shutdown thread arms it
     * while the still-live relay event loop reads it &mdash; the volatile write orders the flag before
     * the acceptor close the same stop performs).
     */
    public void arm() {
        armed = true;
    }

    /**
     * @return {@code false} while the acceptor is up (new binds adjudicate normally); {@code true} once
     *         the acceptor's stop armed the gate &mdash; the first-bind arm must then fail-closed-DENY
     *         without verifier contact and without registering an entry (OBS-017).
     */
    public boolean armed() {
        return armed;
    }
}
