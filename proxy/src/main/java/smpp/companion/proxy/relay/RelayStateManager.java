package smpp.companion.proxy.relay;

import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import io.netty.channel.Channel;
import io.netty.channel.ChannelId;

import smpp.companion.proxy.security.Password;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.VerdictRequest;

/**
 * The relay's single pair-lifecycle state manager (Story 3.4 T6; the T3 owner checkpoint 2026-08-28
 * ratified this exact shape &mdash; single manager, sealed decisions, all three absorptions): the transition
 * POLICY <b>over</b> {@link ConnectionRegistry}'s storage (AD-8's named home stays the storage; there is no
 * second state copy &mdash; AD-32). One bean for BOTH role arms (the pair lifecycle
 * {@code registered/adjudicating} &rarr; {@code egress-attached} &rarr; {@code awaiting-bind_resp} &rarr;
 * {@code coupled} &rarr; {@code tearing-down} is role-agnostic; the forward/reverse split lives entirely in
 * {@code BindInterceptor}'s control plane).
 *
 * <ul>
 * <li><b>Sealed decisions, never null checks (the T3 mechanics):</b> {@link #beginTeardown(Channel)} returns
 * {@link Teardown.Won Won(entry)} or {@link Teardown.Lost Lost} and performs the absorbed hygiene
 * ({@code cancelHttp()} + zeroize) <b>before</b> returning {@code Won} &mdash; the remove+mark &rarr;
 * cancel+wipe half of the AD-32 ordering is single-sited HERE, structurally un-gettable-wrong. Every
 * pre-T6 teardown site re-implemented that ordering &mdash; {@code BindInterceptor}'s four arms
 * ({@code denyAndTeardown} / {@code teardownForPreCoupleViolation} / {@code channelInactive} /
 * {@code exceptionCaught}, each pairing {@code beginTeardown} with its own
 * {@code cancelAndWipePending}) and the relay base's {@code teardownPair}/{@code channelInactive}/
 * {@code exceptionCaught}; they now consume the decision and run only their leg-specific tails
 * (closes, the AD-33 deny write, the reason stash).
 * <li><b>Zeroize ownership (the caller being the manager):</b> the in-flight password's wipe runs in THIS
 * class &mdash; at teardown (the hygiene above) and at {@link #settleAdjudication(ConnectionEntry)} (the
 * verdict continuation's first act, every completion path, idempotent per RELAY-005). The interceptor's
 * own explicit wipes of never-adjudicated secrets (a synchronous verifier blow-up / a null
 * {@code VerdictRequest}) stay interceptor-side: those secrets were never stored on the entry.
 * <li><b>The AD-25 couple is NOT manager-routable (the T3 hard constraint, AC6):</b> this surface has no
 * couple method at all &mdash; {@link ConnectionEntry#couple()} stays entry state with its single production
 * caller {@code RelayEgressHandler} (structural-by-type, pinned by {@code RelayCoupleSiteArchitectureTest}).
 * <li><b>Thread-bounding unchanged:</b> event-loop-confined policy like the handlers; the verdict
 * continuation hop (the interceptor's {@code eventLoop().execute}) is the one off-loop entry, and every
 * manager method it then calls runs on the pair's loop; no executor exists here (AD-28).
 * <li><b>The hot path (AC8):</b> a coupled PDU stays flag-read + forward &mdash; {@link #entryFor(Channel)}
 * is the same cached-attribute read the registry always served; no transition method, no policy
 * consultation, no new virtual dispatch sits on the per-PDU path.
 * </ul>
 *
 * <p><b>Bean:</b> a singleton {@link Component @Component} wrapping the {@link ConnectionRegistry} bean;
 * {@code BindInterceptor}, both per-leg relay handlers (via their {@code CoupledRelayHandler} base), and the
 * two pipeline initializers inject this one bean. Holds no state of its own, so
 * {@code new RelayStateManager(new ConnectionRegistry())} is the test seam.
 */
@Component
public final class RelayStateManager {

    private final ConnectionRegistry registry;

    public RelayStateManager(ConnectionRegistry registry) {
        this.registry = registry;
    }

    /**
     * Optimistically register a new pair at bind arrival (RELAY-006) &mdash; the registration path also
     * carries the in-flight assert the T6 absorption moved here from {@code BindInterceptor.adjudicate}:
     * registration runs ONLY on the first-bind arm (no live pair on this channel), because every path that
     * ends a pair removes its entry and clears BOTH legs' attributes in {@link #beginTeardown(Channel)}.
     * Reaching here with a live pair is a path bug, not a race. (The pre-T6 form additionally asserted the
     * interceptor's own pending-adjudication handles were clean; those handles now live ON the entry &mdash;
     * a fresh entry is clean by construction, and the teardown wipe is single-sited below, which is what
     * makes that half structural.) assert (not throw): Gradle test workers run with {@code -ea} so CI
     * bites; a production JVM without {@code -ea} pays nothing on the bind path.
     *
     * @param ingress  the legacy-client-facing leg; non-null.
     * @param systemId the identity forwarded end-to-end (AD-14); non-null.
     * @return the new entry (also cached on the ingress attribute).
     */
    public ConnectionEntry register(Channel ingress, SystemId systemId) {
        assert registry.entryFor(ingress) == null
                : "register reached with a live pair on this channel — a teardown arm skipped the entry removal";
        return registry.register(ingress, systemId);
    }

    /**
     * The registered &rarr; adjudicating transition (T6 absorption (a)): store the in-flight adjudication's
     * cancellation handle and password ON the pair, where the teardown hygiene and the settle wipe find
     * them. Called by the interceptor right after a non-null {@code VerdictRequest} returns from
     * {@code verify} (on the ingress event loop).
     */
    public void beginAdjudication(ConnectionEntry entry, VerdictRequest pendingVerdict, Password pendingPassword) {
        entry.beginAdjudication(pendingVerdict, pendingPassword);
    }

    /**
     * The adjudication settled (the verdict continuation's first act, whatever the outcome &mdash;
     * Allow/Deny/exceptional, and on the losing-race no-op path alike): drop the cancellation handle (a
     * later teardown must not cancel a settled adjudication) and zeroize the password. NO
     * {@code cancelHttp()} here &mdash; the adjudication is done; cancelling the wire call is teardown-only
     * hygiene.
     */
    public void settleAdjudication(ConnectionEntry entry) {
        entry.clearPendingVerdict();
        wipePassword(entry);
    }

    /**
     * Attach the SMSC-facing leg once it connects (the egress-attached transition; no-op if the pair already
     * tore down during the egress handshake &mdash; RELAY-006's no-orphan arm).
     */
    public void attachEgress(ChannelId ingressId, Channel egress) {
        registry.attachEgress(ingressId, egress);
    }

    /**
     * O(1) entry lookup from either leg (the cached-attribute read; no map probe). Returns {@code null} once
     * teardown has cleared the attribute, so a racing callback observes "absent" and no-ops (AC3). This is
     * the hot-path flag-read &mdash; a pure storage read, never a policy consultation (AC8).
     */
    public @Nullable ConnectionEntry entryFor(Channel channel) {
        return registry.entryFor(channel);
    }

    /**
     * Begin teardown of the pair reachable from this leg &mdash; THE one AD-32 ordering: remove + mark
     * tearing-down BEFORE close (the registry's CAS-once race, RELAY-005), then the absorbed hygiene
     * ({@code cancelHttp()} on a still-pending adjudication + zeroize of a still-pending password), and only
     * then the sealed decision. A {@link Teardown.Lost Lost} caller MUST no-op (a concurrent teardown owns
     * the closes); a {@link Teardown.Won Won} caller owns only its leg-specific tails (closes, the AD-33
     * deny write, the reason stash) &mdash; the ordering below is already complete when it acts.
     *
     * @param channel either leg of the pair; non-null.
     * @return {@code Won(entry)} iff THIS call won the race (the entry is removed, marked, and hygienic), or
     *         {@code Lost} if the pair is unknown here or teardown already began.
     */
    public Teardown beginTeardown(Channel channel) {
        ConnectionEntry won = registry.beginTeardown(channel); // remove + mark tearing-down BEFORE close
        if (won == null) {
            return new Teardown.Lost();
        }
        cancelAndWipe(won); // the absorbed hygiene BEFORE the Won return — the single-sited ordering half
        return new Teardown.Won(won);
    }

    /** Teardown hygiene: abort a still-pending ROPC (AD-12/AD-32) and drop the handle. */
    private static void cancelPendingVerdict(ConnectionEntry entry) {
        VerdictRequest inFlight = entry.pendingVerdict();
        if (inFlight != null) {
            inFlight.cancelHttp();
            entry.clearPendingVerdict();
        }
    }

    /** Teardown/settle hygiene: the caller-owned zeroize (the caller being THIS manager, T3) + drop the handle. */
    private static void wipePassword(ConnectionEntry entry) {
        Password password = entry.pendingPassword();
        if (password != null) {
            password.zeroize();
            entry.clearPendingPassword();
        }
    }

    private static void cancelAndWipe(ConnectionEntry entry) {
        cancelPendingVerdict(entry);
        wipePassword(entry);
    }

    /**
     * The sealed teardown decision (the T3 mechanics: beginTeardown returns Won(entry) or Lost). The
     * permits are nested records so the closed hierarchy is owned by this file (the {@code Verdict} idiom):
     * {@link Won} carries the hygienic entry for the caller's tails; {@link Lost} carries nothing &mdash;
     * its whole contract is "no-op".
     */
    public sealed interface Teardown {

        /**
         * This call won the teardown race: the entry is removed from the registry, marked tearing-down, and
         * hygienic ({@code cancelHttp} + zeroize already ran). The caller now owns ONLY its leg-specific
         * tails (closes, the AD-33 deny write, the reason stash) acting on {@link #entry()}.
         */
        record Won(ConnectionEntry entry) implements Teardown {
        }

        /** A concurrent teardown owns the pair &mdash; the caller MUST no-op (RELAY-005, AD-32 Q1). */
        record Lost() implements Teardown {
        }
    }
}
