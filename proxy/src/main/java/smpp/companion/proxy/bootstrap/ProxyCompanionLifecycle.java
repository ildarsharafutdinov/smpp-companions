package smpp.companion.proxy.bootstrap;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.jspecify.annotations.Nullable;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import io.netty.channel.EventLoopGroup;

import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.security.RopcBindCredentialVerifier;

/**
 * The app-level {@link SmartLifecycle} — since Story 4.2 T3 the <b>AD-22 shutdown coordinator</b>:
 * the bean that walks the 5-step spine's remaining steps (ARCHITECTURE-SPINE.md:196-199, amended
 * 2026-08-27) once every higher phase has stopped. Spring stops descending, so by the time
 * {@link #stop()} runs the acceptor is closed ({@code RELAY_ACCEPTOR_PHASE} — step 1: no new binds,
 * the shared loop deliberately still live), the in-flight adjudications are denied
 * ({@code ADJUDICATION_PHASE} — step 2: {@code shutdownNow()} fired on the still-live loop, so every
 * cancelled continuation executes and no fail-closed {@code bind_resp} strands — the residue AD-22
 * exists to kill), and the metrics endpoint's final scrape window is done
 * ({@code METRICS_ENDPOINT_PHASE}). The walk, in spine order:
 * <ol start="2">
 * <li><b>deny</b> — the adapter's {@code deny()} re-fired. Normally a no-op (the adjudication phase
 * above already denied); it stands as the walk's own fail-closed backstop so the coordinator can
 * never release an undenied pool, whatever happened above it.</li>
 * <li><b>drain</b> — the EMPTY step-3 seam ({@link #drainRelayedConnections()}): deliberately a
 * no-op in this story — story 4.3 fills the body (registry enumeration + mutation fence, the
 * {@code companion.shutdown.drain-timeout} deadline, {@code SHUTDOWN_DRAIN} force-close, the
 * new-adjudication gate). Until then established splices are torn down at the quiesce, and no
 * sequencing line moves twice across the two stories.</li>
 * <li><b>release-await</b> — the adapter's {@code release()}: the bounded VT-pool await (every
 * in-flight adjudication settles {@code DenyIndeterminate} — fail-closed, AD-11), then the ONE
 * shared provider client closes and the client secret zeroizes (AD-10).</li>
 * <li><b>quiesce</b> — the shared relay loop dies HERE, last, with an EXPLICIT short quiet period
 * ({@link #SHUTDOWN_QUIET_PERIOD_MS}/{@link #SHUTDOWN_TIMEOUT_MS}, the
 * {@code MetricsEndpointLifecycle} pattern — never Netty's 2s default, whose per-close cost the
 * deferred-work ledger carried until this bean), awaited so the app phase completes with the loop
 * threads provably gone.</li>
 * </ol>
 *
 * <p><b>Bounded exit.</b> The walk's worst case is release's await ({@code oidc.timeout + 1s} over
 * the DOCUMENTED [2s, 5s] operator window, PERF-3 — a contract the config layer deliberately does
 * NOT validate, so the bound holds for in-window values only) plus the 2s quiesce cap — inside the
 * per-phase ceiling {@code spring.lifecycle.timeout-per-shutdown-phase: 30s} (application.yml). No
 * new config keys in this story (the drain deadline key is 4.3's).
 *
 * <p><b>Idempotent end-to-end.</b> The running flag makes a second {@code stop()} a no-op (the
 * house pattern), the adapter's deny/release halves are independently once-guarded, and Netty's
 * quiesce is idempotent — so the bean-destroy backstops that fire after the coordinator (the group
 * bean's {@code destroyMethod="shutdownGracefully"} in {@code RelayNettyConfig}, the adapter bean's
 * inferred fused {@code close()}) are no-ops, never a double-free or a hang; those same destroy
 * backstops are what clean up a boot that failed before any lifecycle started.
 *
 * <p>Mounted in Story 2.2 (AC8) as the framework stub; the coordinator body landed with Story 4.2
 * T3 — the boot + SIGTERM-equivalent smoke tests still drive it through Spring's
 * {@link org.springframework.context.event.ContextClosedEvent} &rarr; {@code SmartLifecycle.stop}.
 */
@Component
public class ProxyCompanionLifecycle implements SmartLifecycle {

    /**
     * Explicit app-level phase (Story 2.2 T6 — the deferred-work 2nd-SmartLifecycle ordering item):
     * this bean is the shutdown COORDINATOR (the AD-22 walk since Story 4.2 T3), so every other
     * lifecycle must stop BEFORE it (Spring stops higher phases first) — the relay's data-plane
     * acceptor sits at {@code RelayServerLifecycle.RELAY_ACCEPTOR_PHASE = APP_PHASE + 1000}, the
     * deny window at {@code AdjudicationLifecycle.ADJUDICATION_PHASE = APP_PHASE + 750}, the metrics
     * scrape-late window at {@code MetricsEndpointLifecycle.METRICS_ENDPOINT_PHASE = APP_PHASE + 500}.
     * The previous implicit default ({@code Integer.MAX_VALUE}) stopped this bean FIRST — undefined
     * against any second lifecycle; both ends of the contract are named and pinned.
     */
    public static final int APP_PHASE = 0;

    /**
     * The loop-quiesce quiet period — explicitly short (the {@code MetricsEndpointLifecycle}
     * pattern): the walk is over, the pool is joined, and the only work left on the loop is the
     * continuations' final writes — never Netty's 2s default.
     */
    private static final long SHUTDOWN_QUIET_PERIOD_MS = 100;

    /** The quiesce cap — the per-phase ceiling is 30s; 2s bounds this step's worst case. */
    private static final long SHUTDOWN_TIMEOUT_MS = 2_000;

    private final @Nullable RopcBindCredentialVerifier adapter;   // null on forward cells (the stand-in)
    private final EventLoopGroup relayEventLoopGroup;

    private volatile boolean running = false;

    /**
     * @param verifier            the cell's single {@link BindCredentialVerifier} bean — the ROPC
     *                            adapter on reverse cells (its deny/release halves are the walk's
     *                            steps 2 and 4), the always-allow stand-in on forward cells (every
     *                            adapter step below then no-ops)
     * @param relayEventLoopGroup the ONE shared relay event loop bean (AD-1/AD-2) — the loop whose
     *                            quiesce is the walk's final step
     */
    public ProxyCompanionLifecycle(BindCredentialVerifier verifier, EventLoopGroup relayEventLoopGroup) {
        Objects.requireNonNull(verifier, "verifier");
        Objects.requireNonNull(relayEventLoopGroup, "relayEventLoopGroup");
        this.adapter = verifier instanceof RopcBindCredentialVerifier ropc ? ropc : null;
        this.relayEventLoopGroup = relayEventLoopGroup;
    }

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
        if (!running) {
            return; // never started or already stopped — idempotent (the house pattern)
        }
        running = false;
        // The AD-22 walk (steps 2-5; step 1, the acceptor close, ran at RELAY_ACCEPTOR_PHASE before
        // this phase began). The quiesce sits in FINALLY: a throwing step must never strand the
        // shared loop's non-daemon threads past the phase window (the MetricsEndpointLifecycle
        // stop discipline) — and the adapter's destroy backstop picks up whatever half was skipped.
        try {
            if (adapter != null) {
                adapter.deny();   // step 2: deny in-flight — idempotent re-fire (normally a no-op: the adjudication phase above already denied); the fail-closed backstop that the pool can never be released undenied
            }
            drainRelayedConnections();   // step 3: the EMPTY seam — story 4.3
            if (adapter != null) {
                adapter.release();   // step 4: release-await — bounded VT await, provider client close, secret zeroize
            }
        } finally {
            relayEventLoopGroup.shutdownGracefully(SHUTDOWN_QUIET_PERIOD_MS, SHUTDOWN_TIMEOUT_MS,
                    TimeUnit.MILLISECONDS)
                    .syncUninterruptibly();   // step 5: quiesce the shared loop — explicit short quiet period, awaited
        }
    }

    /**
     * AD-22 step 3 — the connection-drain seam. DELIBERATELY EMPTY in Story 4.2: no registry
     * enumeration, no drain deadline, no force-close, no new-adjudication gate — that body is story
     * 4.3's whole scope, and it lands HERE without any other sequencing line moving. The walk still
     * crosses the step (the 5-step spine is walked whole, seam included); until 4.3 fills it,
     * established splices are torn down at the quiesce — the documented 4.2 contract.
     */
    private void drainRelayedConnections() {
        // no-op — filled by story 4.3 (the drain body).
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
