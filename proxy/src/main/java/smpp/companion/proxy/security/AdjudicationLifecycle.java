package smpp.companion.proxy.security;

import org.springframework.context.SmartLifecycle;

import java.util.Objects;

import smpp.companion.proxy.bootstrap.ProxyCompanionLifecycle;

/**
 * Story 3.2 T7 (AC1) — the adjudicator's {@link SmartLifecycle}; the deny window re-phased by
 * Story 4.2 T1 (AD-22 pt. 1). On reverse cells (the verifier is the
 * {@link RopcBindCredentialVerifier}) {@link #stop()} runs the adapter's AD-22 stop body: DENY
 * in-flight (step 2 — {@code deny()}: {@code shutdownNow()}, every cancelled adjudication settles
 * {@code DenyIndeterminate}, Story 3.2 AC5), then RELEASE (steps 4/5 — {@code release()}: the
 * bounded VT await, the shared provider client, the client secret; the 3.2-era
 * key-cache-refresh-before-client-close step died with local JWT verification, Story 3.4 T2,
 * 2026-08-27). The halves are SPLIT and each idempotent on the adapter since 4.2 T1; this stop
 * runs them FUSED ({@code close()} = deny &rarr; release) until the 4.2 T3 coordinator owns
 * release-await at the app phase — then this bean runs the deny alone (on a still-live relay loop:
 * T2 moves the loop quiesce out of the acceptor's stop), and the bean destroy path keeps the fused
 * backstop. On forward cells (the always-allow stand-in) there is nothing to stop and the stop is
 * a pure flag flip.
 *
 * <p>Phase discipline (the 5-step spine, ARCHITECTURE-SPINE AD-22 amended 2026-08-27):
 * {@link #ADJUDICATION_PHASE} sits strictly BELOW the SMPP acceptor's
 * {@code RelayServerLifecycle.RELAY_ACCEPTOR_PHASE} — Spring stops higher phases first, so the
 * acceptor (no new binds) stops BEFORE the deny fires — and strictly ABOVE the metrics endpoint's
 * scrape-late window ({@code MetricsEndpointLifecycle.METRICS_ENDPOINT_PHASE}): the deny runs
 * while the endpoint still scrapes, so an operator's final scrape sees the denied binds' counters.
 *
 * <p>Idempotent by the running flag (the {@code RelayServerLifecycle} house pattern); the adapter's
 * own deny/release halves are idempotent too, so the Spring destroy-method backstop on a boot that
 * failed before the lifecycle started (or re-firing after the stop already ran) cannot double-drain
 * harmfully.
 */
public final class AdjudicationLifecycle implements SmartLifecycle {

    /**
     * The deny window's stop-order phase (re-phased by Story 4.2 T1): strictly below the relay
     * acceptor's {@code RELAY_ACCEPTOR_PHASE} (the acceptor stops first — AD-22 step 1, no new
     * binds) and strictly above the metrics endpoint's scrape-late window
     * ({@code METRICS_ENDPOINT_PHASE} — the final scrape still sees the deny), i.e. the slot the
     * 5-step spine reserves for AD-22 step 2 between the acceptor and the app phases.
     */
    public static final int ADJUDICATION_PHASE = ProxyCompanionLifecycle.APP_PHASE + 750;

    private final BindCredentialVerifier verifier;
    private volatile boolean running;

    public AdjudicationLifecycle(BindCredentialVerifier verifier) {
        this.verifier = Objects.requireNonNull(verifier, "verifier");
    }

    @Override
    public void start() {
        running = true;
    }

    @Override
    public void stop(Runnable callback) {
        try {
            stop();
        } finally {
            // MUST invoke — releases the shutdown latch within the per-phase graceful window
            // (mirrors ProxyCompanionLifecycle / RelayServerLifecycle).
            callback.run();
        }
    }

    @Override
    public void stop() {
        if (!running) {
            return; // never started or already stopped — idempotent
        }
        running = false;
        if (verifier instanceof RopcBindCredentialVerifier adapter) {
            // The AD-22 stop body lives in the adapter (it owns the pool, the shared client and
            // the client secret): fused deny → release until the 4.2 T3 coordinator re-homes the
            // release half to the app phase. Both halves are idempotent on their own — the Spring
            // destroy call (the adapter bean's inferred close()) is the never-started-lifecycle
            // backstop and a no-op after this stop.
            adapter.close();
        }
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    @Override
    public int getPhase() {
        return ADJUDICATION_PHASE;
    }
}
