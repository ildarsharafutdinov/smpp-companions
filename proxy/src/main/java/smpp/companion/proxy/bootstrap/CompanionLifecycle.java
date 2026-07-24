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
public class CompanionLifecycle implements SmartLifecycle {

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
}
