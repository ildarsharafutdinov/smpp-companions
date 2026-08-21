package smpp.companion.proxy.security;

import org.springframework.context.SmartLifecycle;

import java.util.Objects;

import smpp.companion.proxy.bootstrap.ProxyCompanionLifecycle;

/**
 * Story 3.2 T7 (AC1) — the adjudicator's {@link SmartLifecycle}: owns the AD-22 stop window for the
 * cell's {@link BindCredentialVerifier}. On reverse cells (the verifier is the
 * {@link RopcBindCredentialVerifier}) {@link #stop()} runs the adapter's full AD-22 body — deny
 * in-flight ({@code shutdownNow()} + bounded drain) then the JWKS-refresh-before-client-close
 * ordering; on forward cells (the always-allow stand-in) there is nothing to stop and the stop is a
 * pure flag flip. Phase discipline: {@link #getPhase()} sits strictly BELOW
 * {@code RelayServerLifecycle.RELAY_ACCEPTOR_PHASE} — Spring stops higher phases first, so the SMPP
 * acceptor (no new binds) stops BEFORE the adjudicator drains (AD-22 step order).
 *
 * <p>Idempotent by the running flag (the {@code RelayServerLifecycle} house pattern); the adapter's
 * own close is idempotent too, so the Spring destroy-method backstop on a boot that failed before
 * the lifecycle started cannot double-drain harmfully.
 */
public final class AdjudicationLifecycle implements SmartLifecycle {

    /** The app-level slot — strictly below the relay acceptor's phase (see class javadoc). */
    public static final int ADJUDICATION_PHASE = ProxyCompanionLifecycle.APP_PHASE;

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
            // The AD-22 body lives in the adapter (it owns the pool, the JWKS refresh, the shared
            // client and the client secret): deny in-flight with a bounded drain, then the
            // refresh-before-client-close ordering. Idempotent on its own — the Spring destroy
            // call is the never-started-lifecycle backstop.
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
