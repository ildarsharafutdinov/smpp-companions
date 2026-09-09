package smpp.companion.proxy.bootstrap;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import lombok.extern.slf4j.Slf4j;

import org.jspecify.annotations.Nullable;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import io.netty.channel.EventLoopGroup;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.relay.ConnectionRegistry;
import smpp.companion.proxy.relay.RelayStateManager;
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
 * <li><b>drain</b> — the step-3 BODY ({@link #drainRelayedConnections()}, since Story 4.3 T5):
 * check the registry (an empty registry is the instant no-op, never a deadline sleep); otherwise
 * poll {@code registry.size() == 0}
 * against the {@code companion.shutdown.drain-timeout} deadline on the injectable {@link Clock}
 * (in-flight writes flush, peers half-close — post-couple relaying kept running through step 1's
 * gate); at the deadline the remainder is force-closed through the manager's drain teardown
 * ({@link RelayStateManager#forceCloseForDrain()} — {@code SHUTDOWN_DRAIN} stashed on both legs,
 * OBS-020) with ONE bounded WARN naming the count.</li>
 * <li><b>release-await</b> — the adapter's {@code release()}: the bounded VT-pool await (every
 * in-flight adjudication settles {@code DenyIndeterminate} — fail-closed, AD-11), then the ONE
 * shared provider client closes and the client secret zeroizes (AD-10).</li>
 * <li><b>quiesce</b> — the shared relay loop dies HERE, last, with an EXPLICIT short quiet period
 * ({@link #SHUTDOWN_QUIET_PERIOD_MS}/{@link #SHUTDOWN_TIMEOUT_MS}, the
 * {@code MetricsEndpointLifecycle} pattern — never Netty's 2s default, whose per-close cost the
 * deferred-work ledger carried until this bean), then — since Story 4.4 T5 — a BOUNDED termination
 * await ({@link #QUIESCE_AWAIT_BOUND_MS}): the graceful future caps the GRACEFUL period, never
 * thread death, so a loop task wedged in a handler would stall the old uninterruptible wait on it
 * past every ceiling. The bound trades the loop-thread join away, never the exit — ONE
 * WARN-and-proceed, fail-closed in OUTCOME (shutdown proceeds); the group bean's
 * {@code destroyMethod="shutdownGracefully"} backstop still guarantees loop death at full-app
 * close.</li>
 * </ol>
 *
 * <p><b>Bounded exit.</b> The walk's worst case is the drain deadline
 * ({@code companion.shutdown.drain-timeout}, default 10s — STRICTLY below the per-phase ceiling by
 * the documented operator contract, not a validated relation) plus release's await
 * ({@code oidc.timeout + 1s} over the [2s, 5s] PERF-3 window — a window the config layer VALIDATES
 * since Story 4.4 T5, so an out-of-window value refuses startup instead of stretching this bound)
 * plus the 3s quiesce outer bound ({@link #QUIESCE_AWAIT_BOUND_MS} — the 2s graceful cap plus 1s
 * thread-death slack) — at the defaults that is 10s + 6s + 3s, inside the per-phase ceiling
 * {@code spring.lifecycle.timeout-per-shutdown-phase: 30s} (application.yml); a peer that never
 * half-closes is force-closed AT the deadline (OBS-020), and a wedged loop task is bounded past
 * the same way (WARN-and-proceed at the quiesce bound) — nothing can hang the walk.
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
@Slf4j
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

    /**
     * The quiesce termination-await outer bound (Story 4.4 T5, the 4.2-ledger quiesce-bound item):
     * {@code shutdownGracefully}'s returned future caps the GRACEFUL period
     * ({@link #SHUTDOWN_TIMEOUT_MS}) only, never THREAD death — the old uninterruptible wait on it
     * could stall the shutdown thread past every ceiling on a loop task wedged inside a handler.
     * The bound is the graceful cap (2s) plus ~1s thread-death slack — release()'s budget-plus-1s
     * precedent ({@code RopcBindCredentialVerifier.release()}'s defensive await arm) — and on expiry
     * the walk WARNs once and PROCEEDS (fail-closed in outcome, not fail-fast): the group bean's
     * {@code destroyMethod="shutdownGracefully"} backstop still guarantees loop death at full-app
     * close. A named constant, not a config key — shutdown physics like the two it composes with
     * (the story adds no new keys beyond T4's pre-couple-idle-timeout).
     */
    private static final long QUIESCE_AWAIT_BOUND_MS = 3_000;

    /**
     * The drain-poll cadence (Story 4.3 T5): the registry has no completion hook, so the drain body
     * polls {@code size() == 0} — 50ms is fine-grained enough that the force-close lands within one
     * interval of the configured deadline and cheap enough for a shutdown thread (a single
     * {@code ConcurrentHashMap#size()} summation per tick — baseCount plus CounterCells, never a
     * volatile read, but uncontended on the shutdown thread).
     */
    private static final long DRAIN_POLL_INTERVAL_MS = 50;

    private final @Nullable RopcBindCredentialVerifier adapter;   // null on forward cells (the stand-in)
    private final EventLoopGroup relayEventLoopGroup;
    private final ConnectionRegistry registry;
    private final RelayStateManager manager;
    private final ProxyCompanionProperties.Shutdown shutdown;
    private final Clock clock;

    private volatile boolean running = false;

    /**
     * @param verifier            the cell's single {@link BindCredentialVerifier} bean — the ROPC
     *                            adapter on reverse cells (its deny/release halves are the walk's
     *                            steps 2 and 4), the always-allow stand-in on forward cells (every
     *                            adapter step below then no-ops)
     * @param relayEventLoopGroup the ONE shared relay event loop bean (AD-1/AD-2) — the loop whose
     *                            quiesce is the walk's final step
     * @param registry            the pair-storage bean — the drain body's READ surface only
     *                            ({@code size()} here; the deadline force-close's {@code snapshot()}
     *                            enumeration runs manager-side, and every mutation stays behind the
     *                            manager — the Story 4.3 mutation fence)
     * @param manager             the pair-lifecycle state manager — the drain deadline's force-close
     *                            runs through it ({@code forceCloseForDrain()}, Story 4.3 T5)
     * @param shutdown            the {@code companion.shutdown.*} drain inputs (the Clock-injectable
     *                            {@code drain-timeout} deadline, Story 4.3 T3)
     * @param clock               the deadline's time source (the repo's FIRST {@link Clock} bean,
     *                            {@code ShutdownWiringConfig} — injectable so the OBS-020 force-close
     *                            is testable with a mutable clock, never a wall-clock wait)
     */
    public ProxyCompanionLifecycle(BindCredentialVerifier verifier, EventLoopGroup relayEventLoopGroup,
            ConnectionRegistry registry, RelayStateManager manager,
            ProxyCompanionProperties.Shutdown shutdown, Clock clock) {
        Objects.requireNonNull(verifier, "verifier");
        Objects.requireNonNull(relayEventLoopGroup, "relayEventLoopGroup");
        Objects.requireNonNull(registry, "registry");
        Objects.requireNonNull(manager, "manager");
        Objects.requireNonNull(shutdown, "shutdown");
        Objects.requireNonNull(clock, "clock");
        this.adapter = verifier instanceof RopcBindCredentialVerifier ropc ? ropc : null;
        this.relayEventLoopGroup = relayEventLoopGroup;
        this.registry = registry;
        this.manager = manager;
        this.shutdown = shutdown;
        this.clock = clock;
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
        // this phase began). The quiesce sits in FINALLY: a throwing step must still terminate the
        // shared loop (the MetricsEndpointLifecycle stop discipline) — and since 4.4 T5 the await is
        // BOUNDED, so neither a throwing step nor a wedged loop task can stall the walk past the
        // outer bound; the adapter's destroy backstop picks up whatever half was skipped.
        try {
            if (adapter != null) {
                adapter.deny();   // step 2: deny in-flight — idempotent re-fire (normally a no-op: the adjudication phase above already denied); the fail-closed backstop that the pool can never be released undenied
            }
            drainRelayedConnections();   // step 3: the drain body — poll to the deadline, force-close the remainder (4.3 T5)
            if (adapter != null) {
                adapter.release();   // step 4: release-await — bounded VT await, provider client close, secret zeroize
            }
        } finally {
            // Step 5: quiesce the shared loop — explicit short quiet period, then the BOUNDED
            // termination await (4.4 T5). The graceful future is issued but NEVER waited on
            // uninterruptibly: it caps the graceful period, not thread death, so a loop task
            // wedged in a handler would stall that wait indefinitely. On expiry ONE WARN and
            // PROCEED (fail-closed in outcome — the walk returns; the group bean's destroyMethod
            // backstop still guarantees loop death at full-app close). A PRE-SET interrupt (the
            // drain's fail-closed break restores Spring's flag mid-walk) must not degrade this
            // join the way it does release()'s — the 4.3 interrupted-walk row pins the group
            // terminated at stop() return — so the flag is saved/cleared around the await and
            // restored after; a FRESH interrupt during the await takes the second WARN arm.
            relayEventLoopGroup.shutdownGracefully(SHUTDOWN_QUIET_PERIOD_MS, SHUTDOWN_TIMEOUT_MS,
                    TimeUnit.MILLISECONDS);
            boolean presetInterrupt = Thread.interrupted();
            try {
                if (!relayEventLoopGroup.awaitTermination(QUIESCE_AWAIT_BOUND_MS, TimeUnit.MILLISECONDS)) {
                    log.warn("the shared relay loop did not terminate within {}ms — proceeding with the "
                            + "shutdown (a wedged loop task cannot stall it past this bound; the group "
                            + "bean's destroyMethod shutdownGracefully backstop still guarantees loop "
                            + "death at full-app close; AD-22 fail-closed in outcome)", QUIESCE_AWAIT_BOUND_MS);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.warn("the relay loop quiesce await was interrupted — proceeding with the shutdown "
                        + "(the destroy backstop still guarantees loop death; AD-22 fail-closed in outcome)");
            } finally {
                if (presetInterrupt) {
                    Thread.currentThread().interrupt();   // preserve Spring's flag across the walk's tail
                }
            }
        }
    }

    /**
     * AD-22 step 3 — the connection drain (the body landed with Story 4.3 T5; the 4.2 seam it filled
     * was deliberately empty). Poll, not callbacks: the registry exposes no completion hook, so
     * {@code size() == 0} IS the completion signal its javadoc names. Three phases:
     * <ol>
     * <li><b>Empty registry &rarr; instant no-op.</b> The {@link ConnectionRegistry#size()} emptiness
     * read short-circuits BEFORE any deadline arithmetic or sleeping — the idle-walk bounds
     * (&lt;1.5s / &lt;5s) never pay for a drain window there is nothing to wait on.</li>
     * <li><b>Drain to the deadline.</b> Poll {@code registry.size()} against the
     * {@code drain-timeout} deadline on the injected {@link Clock} — while the budget lasts,
     * in-flight writes flush and peers half-close on the still-live loop (each peer FIN tears its
     * own pair down via {@code channelInactive}, so the count drops without this thread touching a
     * channel). An interrupt breaks the poll fail-closed (flag restored, force-close below, walk
     * continues — never a hang holding a stopped process hostage). The restored flag also flips
     * step 4's bounded {@code awaitTermination} to its interrupted arm while any VT is still
     * unwinding ({@code RopcBindCredentialVerifier.release()} logs one WARN and proceeds straight
     * to the hard close; an already-terminated pool returns true before ever observing the flag) —
     * the VT join is traded away, never the exit bound.</li>
     * <li><b>Deadline &rarr; bulk force-close.</b> Whatever remains is force-closed in bulk through
     * {@link RelayStateManager#forceCloseForDrain()} ({@code SHUTDOWN_DRAIN} stashed on both legs of
     * every won pair, both legs closed — OBS-020: no half-flushed PDU, a peer that never half-closes
     * cannot hang the exit), followed by ONE bounded WARN naming the force-closed count (a backlog
     * larger than the window drains force-closed in bulk; the walk still returns inside the 30s
     * per-phase ceiling).</li>
     * </ol>
     * The deadline is CLOCK-INJECTABLE by construction (RELAY-022 / OBS-020 blind-spot 5): no
     * wall-clock wait is ever required to prove the force-close — a mutable {@link Clock} advances
     * straight past the budget.
     */
    private void drainRelayedConnections() {
        if (registry.size() == 0) {
            return; // empty registry: the instant no-op walk — the deadline is never even computed
        }
        Instant deadline = clock.instant().plus(shutdown.drainTimeout());
        while (registry.size() > 0 && clock.instant().isBefore(deadline)) {
            try {
                Thread.sleep(DRAIN_POLL_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); // preserve the status for the caller (Spring)
                break; // fail-closed: stop waiting, force-close below, keep the walk moving
            }
        }
        int forceClosed = manager.forceCloseForDrain();
        if (forceClosed > 0) {
            log.warn("shutdown drain deadline ({}) expired — force-closed {} live pair(s) as SHUTDOWN_DRAIN "
                    + "(OBS-020: a peer that never half-closes can never hang the exit)",
                    shutdown.drainTimeout(), forceClosed);
        }
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
