package smpp.companion.proxy.bootstrap;

import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

/**
 * Framework-only {@link SmartLifecycle} stub (AC8). Records start/stop transitions so the boot +
 * SIGTERM-equivalent smoke tests can assert the lifecycle is driven by Spring. The AD-22
 * phase-ordered 7-step shutdown BODY lands in Epic 4; here we mount only the framework: a bean that
 * starts on context refresh and stops (invoking the callback) on {@link org.springframework.context.event.ContextClosedEvent}.
 */
@Component
public class ProxyCompanionLifecycle implements SmartLifecycle {

    /**
     * Explicit app-level phase (Story 2.2 T6 — the deferred-work 2nd-SmartLifecycle ordering item):
     * this bean coordinates the app-level shutdown window (the AD-22 7-step drain body lands here in
     * Epic 4), so the relay's data-plane acceptor must stop BEFORE it (Spring stops higher phases
     * first) — {@code RelayServerLifecycle.RELAY_ACCEPTOR_PHASE} is deliberately {@code APP_PHASE + 1000}.
     * The previous implicit default ({@code Integer.MAX_VALUE}) stopped this stub FIRST — undefined
     * against any second lifecycle; now both ends of the contract are named and pinned.
     */
    public static final int APP_PHASE = 0;

    private volatile boolean running = false;

    @Override
    public void start() {
        this.running = true;
    }

    @Override
    public void stop(Runnable callback) {
        try {
            stop();
        } finally {
            // MUST invoke — releases the shutdown latch within the per-phase graceful-shutdown window.
            callback.run();
        }
    }

    @Override
    public void stop() {
        this.running = false;
    }

    @Override
    public boolean isRunning() {
        return this.running;
    }

    @Override
    public int getPhase() {
        return APP_PHASE;
    }
}
