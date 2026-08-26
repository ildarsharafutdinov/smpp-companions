package smpp.companion.proxy.tls;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.netty.util.concurrent.DefaultThreadFactory;

/**
 * Story 3.3 — the AD-28(1)/AD-4 TLS wiring substrate: the ONE hand-managed fixed <b>platform</b>-thread
 * pool that executes {@code SslHandler} delegated handshake tasks for BOTH relay legs (the reverse
 * listener's inbound handshakes and the forward's per-session dials). Not virtual threads
 * (SSLEngine delegated tasks are CPU-bound and may pin carriers — AD-28), not a Spring
 * {@code ThreadPoolTaskExecutor} (hand-managed by rule), shared ingress+egress.
 *
 * <p><b>Bounded queue, abort-on-saturation (AD-4):</b> the queue is
 * {@link #DELEGATED_TASK_QUEUE_CAPACITY} deep with {@link ThreadPoolExecutor.AbortPolicy} — a
 * saturated pool throws {@link java.util.concurrent.RejectedExecutionException} out of
 * {@code SslHandler.executeDelegatedTask}, which lands in {@code exceptionCaught} and fails the
 * handshake/connection: deny the connection (AD-11), never {@code CallerRunsPolicy} (that would run
 * handshake crypto ON the event loop), never unbounded queueing. Verified against the Netty
 * 4.2.16.Final sources ({@code SslHandler.executeDelegatedTask} rethrows REE).
 *
 * <p>Pool sizing: {@code max(2, availableProcessors)} fixed threads — handshake-crypto sized to the
 * box, one pool for the whole process (every cell's TLS rides it). Sizing is deliberately NOT
 * configurable (no knob creep); it is an implementation constant of the AD-28 posture.
 *
 * <p>{@code destroyMethod = "shutdownNow"}: the drain need not linger (Epic 4's AD-22 ordering owns
 * the graceful window; an in-flight handshake task at shutdown is fail-closed by the channel close).
 */
@Configuration
public class TlsWiringConfig {

    /** The bounded delegated-task queue depth (per AD-4: bounded, never unbounded). */
    static final int DELEGATED_TASK_QUEUE_CAPACITY = 256;

    /**
     * The shared bounded delegating-task executor (AD-28(1)). Hand-built (not
     * {@code Executors.newFixedThreadPool}) because the JDK factory's queue is UNBOUNDED — the exact
     * posture AD-4 forbids.
     */
    @Bean(destroyMethod = "shutdownNow")
    public ExecutorService tlsDelegatedTaskExecutor() {
        int threads = Math.max(2, Runtime.getRuntime().availableProcessors());
        return new ThreadPoolExecutor(
                threads, threads, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(DELEGATED_TASK_QUEUE_CAPACITY),
                new DefaultThreadFactory("companion-tls"),
                new ThreadPoolExecutor.AbortPolicy());
    }
}
