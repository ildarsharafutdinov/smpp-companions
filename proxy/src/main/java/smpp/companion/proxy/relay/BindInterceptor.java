package smpp.companion.proxy.relay;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.util.concurrent.ScheduledFuture;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;

import smpp.companion.codec.bind.SmppBindPdu;
import smpp.companion.codec.bind.SmppBindRequest;
import smpp.companion.codec.bind.SmppBindResponse;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrame;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.observability.CloseReason;
import smpp.companion.proxy.observability.RelayObserver;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayEgressInitializer;
import smpp.companion.proxy.security.BindCredential;
import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.security.Password;
import smpp.companion.proxy.security.RequestContext;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.security.VerdictRequest;
import smpp.companion.proxy.tls.SmppLegTlsFactory;

/**
 * The bind-handshake interceptor (AC2; AD-7/AD-12/AD-14/AD-15/AD-25/AD-27/AD-33) — the control-plane half
 * of the relay's pre-couple window. One PER-CHANNEL instance sits on the ingress pipeline after the codec
 * prefix ({@code SmppFrameDecoder → SmppCodec → BindInterceptor}); its nested {@link EgressLeg} rides the
 * per-bind egress channel. It owns exactly the bind family and nothing else:
 *
 * <ul>
 * <li><b>Routing (AC2; AD-29) — the Story 3.3 ROLE-SPLIT:</b> the <b>reverse</b> arm (modes a/b/c)
 * has NO routing table by design: every decoded {@link SmppBindRequest} routes to the single
 * configured {@code companion.reverse.mode-<mode>.smsc}. The <b>forward</b> arm ([B] topology: it
 * dials the reverse per SMPP session) routes per {@code system_id} through the injected
 * {@link RoutingTable}: a <b>miss is the AD-33 collapse</b> (header-only deny + close, log-only —
 * never {@code onBindReject}, which fires ONLY for returned {@link Verdict}s, AD-27) and precedes
 * adjudication; a hit proceeds to the (AlwaysAllow-wired) verdict and the per-session egress dial.
 * <li><b>Adjudication (AD-12/AD-15):</b> {@code new BindCredential(new SystemId(req.systemId()), new
 * Password(req.password()))} handed to the injected {@link BindCredentialVerifier} inside a
 * {@link ScopedValue}-bound {@link RequestContext} (AD-5 — never {@code ThreadLocal}). The relay never
 * blocks the event loop and never spawns a virtual thread (AD-28 — the verifier's own executor owns that);
 * the verdict continuation is chained via {@link CompletableFuture#whenComplete} and hopped back onto the
 * ingress event loop.
 * <li><b>AD-33 denial collapse (Q2 ratified here):</b> every PROXY-side denial — verifier {@code Deny*},
 * a verifier failure, and egress-establishment failures that produce no SMSC response PDU (connect-fail,
 * SMSC death pre-{@code bind_resp}) — answers with ONE generic {@code command_status}:
 * {@code ESME_RBINDFAIL 0x0000000D} (SMPP 3.4 §5.1.3 "Bind Failed"; verified against
 * {@code docs/SMPP_v3_4_Issue1_2.pdf}). It is §5.1.3's literal generic bind-failure code, carries no
 * credential-validity information (unlike the adjacent {@code RINVPASWD}/{@code RINVSYSID}), reads
 * definitive rather than retry-worthy (unlike {@code ESME_RSYSERR}'s "System Error"), and is IDENTICAL
 * across both arms so a prober cannot distinguish verifier-reject from unreachable-SMSC. The deny
 * {@code bind_*_resp} is the ONE PDU the relay ever builds: a header-only 16-octet construct written
 * directly ({@link SmppFrame#HEADER_LENGTH} — no {@code SmppBindEncoder} re-serialization, AD-32).
 * SMSC-originated response PDUs are forwarded VERBATIM ({@link EgressLeg}) — NOT collapsed (AD-32 case 4).
 * <li><b>AD-14 identity-preserved forward:</b> on {@code Allow} the ORIGINAL frame
 * ({@link SmppBindRequest#originalFrame()}) is forwarded to the SMSC byte-exact — never re-encoded, never
 * remapped; ownership transfers to the egress write (that transfer IS the release).
 * <li><b>AD-25 forwarder split:</b> {@link EgressLeg} (this class's egress arm) forwards the SMSC's decoded
 * {@code bind_*_resp} to the legacy client; the T8 {@code RelayEgressHandler} observes the same decoded PDU
 * read-only to couple and never forwards it. {@code EgressLeg} is appended by the per-bind connect assembly
 * (before any read is armed — {@code AUTO_READ=false} guarantees no PDU can precede it) and does NOT
 * propagate decoded bind PDUs downstream: it is the bind-family's last consumer and owns the frame release,
 * a contract that stays stable when T8 inserts its handler earlier in the pipeline.
 * <li><b>Caller-owned zeroize (the open 2.1 review finding):</b> the relay — not {@code AlwaysAllow} — owns
 * {@link Password#zeroize()}. Since the Story 3.4 T6 absorption the in-flight handles live ON the
 * {@link ConnectionEntry} and the wipe's owner is the {@code RelayStateManager} (T3: "the caller being the
 * manager"): the wipe runs when the adjudication SETTLES ({@code manager.settleAdjudication} — the
 * continuation's first act: Allow/Deny/exceptional) and at every TEARDOWN (retry-bind, ingress/egress
 * death, violation — {@code manager.beginTeardown}'s hygiene) — NOT at {@code verify()}-return, because the
 * Epic-3 ROPC adapter reads the secret asynchronously while its future is pending. The wipe can never
 * corrupt the AD-14 forward: {@code SmppBytes} copies each C-octet field out of the frame, so the
 * password's backing array is not the frame's memory. Idempotent (RELAY-005 double-zeroize safe). This
 * class's two explicit wipes cover only the never-adjudicated secrets of the synchronous-blow-up and
 * null-return arms (nothing was stored on the entry for them to wipe).
 * <li><b>RELAY-004 (retry-bind):</b> a second bind while the handshake is in flight is deterministically
 * rejected — the AD-33 generic deny answering the RETRY's sequence, {@code cancelHttp()} on the in-flight
 * adjudication, teardown of both legs; no second pair, no registry corruption. The "in flight" predicate is
 * the registry entry itself (AD-32: "the entry's state, not a separate boolean") — fully so since T6 put
 * the adjudication handles on the entry.
 * <li><b>F1 — client-sent {@code bind_*_resp} (Story 4.4 T2):</b> a decoded bind RESPONSE on the ingress
 * leg is a direction violation (a bind response is SMSC-side; a sane ESME never sends one): in BOTH
 * pre-couple windows (no bind sent yet, or one in flight/awaiting its answer) the frame is released, an
 * existing pair tears down through {@code manager.beginTeardown} ({@code cancelHttp()} + zeroize ride
 * inside), the {@link CloseReason#PRE_COUPLE_NON_BIND_PDU} reason is stashed, and the legs bare-close —
 * NO response PDU, NEVER a forward (a forwarded pre-flip ROK would couple the pair without SMSC consent —
 * the forged-ROK window stays sealed). Not a returned {@code Verdict} → no {@code onBindReject} (AD-27).
 * Post-couple the decoded PDU passes through to T8's opaque relay exactly like a stray re-bind (AD-2's
 * every-PDU doctrine).
 * <li><b>F14 — the adjudication-deadline arm (Story 4.4 T3):</b> {@code adjudicate} arms a per-channel
 * deny timer on the INGRESS event loop at the configured {@code companion.bind.adjudication-deadline}
 * (the same budget {@code RequestContext.deadline} carries — one number) via the {@link ChannelTimer}
 * seam. A verifier future that never settles can no longer pin the registry entry, the original bind
 * frame, and the legacy client's socket past that deadline: at fire the task re-checks the entry
 * (absent / tearing-down / coupled &rarr; no-op — the AD-25 re-check idiom) and otherwise routes
 * {@link CloseReason#BIND_REJECTED} through the ONE teardown path ({@code denyAndTeardown} &rarr;
 * {@code manager.beginTeardown}: the {@code cancelHttp()} + zeroize hygiene rides inside, and the
 * aborted exchange's pin settles {@code DenyIndeterminate} per the port's no-op-if-done contract —
 * the relay never authors a second completion). The timer fabricates NO {@link Verdict}, so
 * {@code onBindReject} NEVER fires for a deadline deny (AD-27: verifier-returned Verdicts only; the
 * deadline deny is log-distinguishable, enum-identical {@code BIND_REJECTED}). Cancelled at settle
 * ({@code onVerdict}, both arms) and at every interceptor teardown arm — but convergence, not
 * cancellation, is the correctness argument: a stale fire re-checks and no-ops.
 * <li><b>F13 residue — the pre-couple idle watchdog (Story 4.4 T4):</b> {@code channelActive} arms a
 * second per-channel task at {@code companion.bind.pre-couple-idle-timeout} (default {@code 30s}) on
 * the SAME {@link ChannelTimer} seam. An accepted socket that never reaches COUPLE — never binds,
 * or a silent SMSC after the forward — is bare-closed at the window's end ({@code beginTeardown} +
 * the {@link CloseReason#PRE_COUPLE_NON_BIND_PDU} stash, NO response PDU: {@code onPreCoupleIdle}
 * is the F1 arm's exact shape), which is what makes the
 * {@code ConnectionCapHandler}'s closeFuture-riding slot release REACHABLE for never-binding
 * sockets. Bounds connect→couple ONLY: cancelled at the couple (the egress answer arm) and at every
 * teardown arm, and a fire that finds the entry coupled NO-OPS — a COUPLED pair idling indefinitely
 * is NEVER reaped (PERF-2's headline population). Like the deadline arm it fabricates no
 * {@link Verdict} → no {@code onBindReject}; the WARN log distinguishes the idle cause, the enum
 * value does not.
 * <li><b>The new-adjudication gate (Story 4.3 T4; OBS-017):</b> once the acceptor's stop armed the
 * injected {@link NewAdjudicationGate}, this handler's FIRST-BIND arm (an established socket with no
 * entry) fail-closed-DENIES before anything else — frame release + the AD-33 deny + close, the
 * routing-miss arm's shape (no pair exists to tear down): no verifier contact, no registry entry —
 * the check sits BEFORE {@code manager.register}, which is what keeps OBS-017's no-entry observable
 * true. Not a returned {@link Verdict} → no {@code onBindReject} (AD-27). Post-couple relaying is
 * untouched — the AD-22 drain body needs established pairs relaying until the deadline; in-flight
 * adjudications are 4.2's deny window ({@code AdjudicationLifecycle}), phase-ordered after the
 * acceptor stop that arms the gate.
 * </ul>
 *
 * <p><b>Teardown ordering (AD-32/AC3 discipline):</b> since Story 3.4 T6 the ordering is SINGLE-SITED in
 * {@code RelayStateManager.beginTeardown} — remove + mark tearing-down BEFORE close, then
 * {@code cancelHttp()} + zeroize — which then hands back the sealed {@code Won(entry) | Lost} decision;
 * this class's teardown arms consume the decision and run only their tails (the deny write +
 * {@link ChannelFutureListener#CLOSE} ("bind_resp error, then close" — walkthrough §5), the egress close).
 * A losing racer (the {@code Lost} arm) no-ops — never a {@code bind_resp} on a connection being torn
 * down. The verdict continuation re-checks the entry (absent or tearing-down → no-op — the AD-25 race-free
 * re-check). Post-couple behavior is T8's plane: once {@code entry.coupled()}, decoded bind PDUs are
 * passed through untouched, and the general teardown site / exactly-once {@code onConnectionClosed} live
 * there.
 *
 * <p><b>RELAY logging rule (T3):</b> logs/observes {@link SystemId} only — never
 * {@code SmppBindRequest}/{@code Password}/{@code BindCredential} objects nor the raw password
 * {@code AsciiString}.
 */
@Slf4j
@SuppressWarnings("FutureReturnValueIgnored") // reason: read()/close()/writeAndFlush() on the relay's own
// channels are fire-and-forget control operations — a failed close/write merely means the channel was
// already closing (the desired end state), and Netty itself releases a buffer whose write fails; the
// deny path's write DOES carry a CLOSE listener (the one completion we act on).
public final class BindInterceptor extends SimpleChannelInboundHandler<SmppBindPdu> {

    /**
     * AD-33 Q2 (ratified at T7): the ONE generic bind-failure {@code command_status} every proxy-side
     * denial collapses to — {@code ESME_RBINDFAIL} 0x0000000D, SMPP 3.4 §5.1.3 "Bind Failed" (verified
     * against the repo's spec PDF). Pinned in tests as the LITERAL 0x0000000D, independent of this constant.
     */
    static final int AD_33_GENERIC_BIND_FAILURE_STATUS = 0x0000000D;

    /**
     * The per-bind {@link RequestContext} handle (AD-5) — bound around each {@code verify} call.
     */
    private static final ScopedValue<RequestContext> REQUEST_CONTEXT = ScopedValue.newInstance();

    /** The production egress connect: the assembled {@link Bootstrap} against the configured target. */
    private static final EgressConnector DEFAULT_CONNECTOR = (bootstrap, host, port) -> bootstrap.connect(host, port);

    /**
     * The production per-channel timer (Story 4.4 T3, F14): the ingress event loop's own scheduler —
     * AD-2's mechanism for every relay-side timeout (a per-channel scheduled task on the loop that owns
     * the handshake, never an {@code IdleStateHandler} install). Package-private so the same-package
     * test fixtures that do not drive the deadline inject the REAL production arm rather than a
     * hand-copied lambda.
     */
    static final ChannelTimer DEFAULT_TIMER =
            (channel, delayMillis, task) -> channel.eventLoop().schedule(task, delayMillis, TimeUnit.MILLISECONDS);

    private final BindCredentialVerifier verifier;
    private final RelayStateManager manager;
    /** Story 4.3 T4 (OBS-017): the shared new-adjudication gate — fail-closed-DENY the first-bind arm once armed. */
    private final NewAdjudicationGate gate;
    private final RelayObserver observer;
    private final RelayEgressInitializer egressInitializer;
    private final RelayChannelOptions channelOptions;
    private final EgressConnector connector;
    private final RoutingTable routingTable;
    private final SmppLegTlsFactory tlsFactory;
    /** The role arm: {@code true} on the forward cells ([B]: dial-out per session, routing-gated). */
    private final boolean forwardRole;
    /** The REVERSE cells' single egress target (every mode leaf carries one); null on forward cells. */
    private final ProxyCompanionProperties.@Nullable Smsc smsc;
    /**
     * The configured adjudication budget ({@code companion.bind.adjudication-deadline}, default {@code 4s}
     * in application.yml — owner FIXME 2026-08-15, formerly the hardcoded 30s constant): each bind's
     * {@code RequestContext.deadline} is {@code now + this}, and since Story 4.4 T3 (F14) the SAME
     * budget arms the per-channel deadline timer below — one number for the whole pre-couple auth
     * window. Positive by the {@code Bind} record's fail-fast guard (AD-17).
     */
    private final Duration adjudicationDeadline;
    /**
     * The pre-couple idle window ({@code companion.bind.pre-couple-idle-timeout}, default {@code 30s}
     * in application.yml — Story 4.4 T4, the F13 residue): bounds connect→couple ONLY. Deliberately a
     * SECOND knob beside {@link #adjudicationDeadline} (the F10/F14 one-number reuse does not apply):
     * slot-reclaim cadence is an ops concern distinct from the PERF-3 auth budget. Positive by the
     * {@code Bind} record's fail-fast guard (AD-17).
     */
    private final Duration preCoupleIdleTimeout;
    /** Story 4.4 T3 (F14): the per-channel schedule seam — production arms on the ingress event loop. */
    private final ChannelTimer timer;
    /**
     * The in-flight adjudication's deadline timer handle (Story 4.4 T3, F14) — channel-scoped instance
     * state (this handler is per-channel, and every arm/cancel site below runs on the ingress event
     * loop — the same confinement the handlers follow). NOT entry state by design: the T6-absorption
     * doctrine keeps the VERDICT handles on the {@link ConnectionEntry} because the manager's hygiene
     * must reach them from any teardown caller, while the timer is this interceptor's own arm and only
     * this interceptor can cancel it. Null when no adjudication is pending; cleared at fire, settle,
     * and every teardown arm (a stale fire re-checks the entry and no-ops regardless).
     */
    private @Nullable ScheduledFuture<?> pendingDeadlineTimer;
    /**
     * The in-flight adjudication's latency ARM (Story 8.1 T2, audit gap G1) — the monotonic stamp
     * taken where {@link #pendingDeadlineTimer} is armed ({@code adjudicate}'s verify hand-off; the
     * Design Note's "{@code ChannelTimer} arm" hook point), consumed exactly once at the SETTLE
     * ({@code onVerdict} — the "cancel" half of the same pair) by {@link #recordAdjudicationLatency}.
     * Same channel-scoped confinement doctrine as the deadline handle above: interceptor state, not
     * entry state — only this interceptor arms and settles it, always on the ingress event loop. Null
     * when no adjudication is pending (the synchronous-blow-up and null-return arms denied before a
     * future existed — nothing was ever armed, so nothing ever records).
     */
    private @Nullable Long pendingAdjudicationStartNanos;
    /**
     * The pre-couple idle watchdog's handle (Story 4.4 T4, F13 residue) — same channel-scoped
     * confinement rationale as {@link #pendingDeadlineTimer} above. Unlike the deadline handle it
     * spans the WHOLE connect→couple window (armed at {@code channelActive}, NOT at adjudicate): it
     * is cancelled at the couple (the egress answer arm — a coupled idle pair is NEVER reaped,
     * PERF-2) and at every teardown arm; a fire on an absent/tearing-down/coupled entry no-ops.
     */
    private @Nullable ScheduledFuture<?> pendingIdleWatchdog;

    // The in-flight adjudication handles (cancelHttp target + wipe target) moved ONTO the ConnectionEntry
    // by the Story 3.4 T6 absorption — this class's own pendingVerdict/pendingPassword fields died with it;
    // see RelayStateManager.beginAdjudication / settleAdjudication / beginTeardown. The deadline TIMER
    // handle (Story 4.4 T3) is the one deliberate exception: channel-scoped interceptor state (above).

    /**
     * Production constructor (used by {@code RelayIngressInitializer} per accepted channel): the
     * injected beans + the role resolved structurally from the populated branch (Story 3.3: the
     * reverse arm targets the cell's single {@code smsc}; the forward arm routes per
     * {@code system_id} and dials TLS per routing entry). The {@code gate} is the SAME singleton bean
     * {@code RelayServerLifecycle} arms at the acceptor close (Story 4.3 T4, OBS-017) — component scan
     * guarantees the sharing.
     */
    public BindInterceptor(BindCredentialVerifier verifier, RelayStateManager manager, RelayObserver observer,
                           ProxyCompanionProperties properties, RelayEgressInitializer egressInitializer,
                           RelayChannelOptions channelOptions, RoutingTable routingTable,
                           SmppLegTlsFactory tlsFactory, NewAdjudicationGate gate) {
        this(verifier, manager, observer, properties, egressInitializer, channelOptions, routingTable,
                tlsFactory, gate, DEFAULT_CONNECTOR, DEFAULT_TIMER);
    }

    /**
     * Full constructor (package-private): adds the {@link EgressConnector} seam — RELAY-006's sanctioned
     * "injected failing ChannelFuture" — so tests can drive the connect-fail arm deterministically and pin
     * the egress-bootstrap wiring without a live socket.
     */
    BindInterceptor(BindCredentialVerifier verifier, RelayStateManager manager, RelayObserver observer,
                    ProxyCompanionProperties properties, RelayEgressInitializer egressInitializer,
                    RelayChannelOptions channelOptions, RoutingTable routingTable,
                    SmppLegTlsFactory tlsFactory, NewAdjudicationGate gate, EgressConnector connector) {
        this(verifier, manager, observer, properties, egressInitializer, channelOptions, routingTable,
                tlsFactory, gate, connector, DEFAULT_TIMER);
    }

    /**
     * Test constructor (package-private): adds the {@link ChannelTimer} seam (Story 4.4 T3, F14) on top of
     * the {@link EgressConnector} one — the deadline rows capture the scheduled task and fire it manually
     * (the deterministic-seam idiom: no real wall-clock waits, no {@code Clock} injection into
     * {@code RequestContext}/verifier surfaces — 4.3's standing reservation).
     */
    BindInterceptor(BindCredentialVerifier verifier, RelayStateManager manager, RelayObserver observer,
                    ProxyCompanionProperties properties, RelayEgressInitializer egressInitializer,
                    RelayChannelOptions channelOptions, RoutingTable routingTable,
                    SmppLegTlsFactory tlsFactory, NewAdjudicationGate gate, EgressConnector connector,
                    ChannelTimer timer) {
        this.verifier = verifier;
        this.manager = manager;
        this.gate = gate;
        this.observer = observer;
        this.egressInitializer = egressInitializer;
        this.channelOptions = channelOptions;
        this.routingTable = routingTable;
        this.tlsFactory = tlsFactory;
        this.connector = connector;
        this.timer = timer;
        ProxyCompanionProperties.@Nullable Forward forward = properties.forward();
        ProxyCompanionProperties.@Nullable Reverse reverse = properties.reverse();
        if (forward != null) {
            this.forwardRole = true;
            this.smsc = null; // forward dials the ROUTING target ([B]); no single SMSC exists (SEC-097)
        } else if (reverse != null) {
            this.forwardRole = false;
            this.smsc = reverseSmsc(reverse);
        } else {
            // Unreachable post-validation (AD-17 compact ctor) — a wiring bug, not a data-plane condition.
            throw new IllegalStateException(
                    "BindInterceptor requires a companion.<role> branch (AD-17 single-cell selection)");
        }
        this.adjudicationDeadline = properties.bind().adjudicationDeadline();
        this.preCoupleIdleTimeout = properties.bind().preCoupleIdleTimeout();
    }

    /** The reverse cells' single SMSC target (every mode leaf carries one, @NotNull-validated). */
    private static ProxyCompanionProperties.Smsc reverseSmsc(ProxyCompanionProperties.Reverse reverse) {
        if (reverse.modeA() != null) {
            return reverse.modeA().smsc();
        }
        if (reverse.modeB() != null) {
            return reverse.modeB().smsc();
        }
        if (reverse.modeC() != null) {
            return reverse.modeC().smsc();
        }
        throw new IllegalStateException("no companion.reverse.<mode> branch (AD-17) — refusing to start.");
    }

    /** The per-bind egress connect seam ({@link Bootstrap} → {@link ChannelFuture}); see the package ctor. */
    interface EgressConnector {
        ChannelFuture connect(Bootstrap bootstrap, String host, int port);
    }

    /**
     * The per-channel scheduled-task seam (Story 4.4 T3, F14): one {@code schedule} of a task on the
     * channel's owning event loop after a delay, returning the cancellable handle. Production is
     * {@link #DEFAULT_TIMER} — {@code channel.eventLoop().schedule(...)}, the AD-2 mechanism (a
     * per-channel scheduled task on the loop that owns the handshake; NEVER an {@code IdleStateHandler}
     * install, never live pipeline surgery). Tests capture the task and fire it manually — the
     * deterministic-seam idiom, no real wall-clock waits. Package-private like {@link EgressConnector}:
     * the only injection point is the test constructor; the surface never leaves {@code relay/}.
     */
    @FunctionalInterface
    interface ChannelTimer {
        ScheduledFuture<?> schedule(Channel channel, long delayMillis, Runnable task);
    }

    // ---------------------------------------------------------------- ingress leg

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        ctx.fireChannelActive();
        ctx.read(); // arm the initial read — under AUTO_READ=false nothing arrives until demanded (AC4)
        // Story 4.4 T4 (F13 residue): arm the pre-couple idle watchdog — the connect→couple window's
        // outer bound. Armed at ACTIVE (not at the first bind) so the never-binding socket — zero
        // PDUs, no registry entry — is inside the window too: that socket holds a concurrent-pairs
        // cap slot until this task closes it (the ConnectionCapHandler's release rides the closeFuture
        // exactly once). Cancelled at the couple and at every teardown arm; a fire re-checks and
        // no-ops on anything already coupled (PERF-2: coupled idle pairs are never reaped).
        pendingIdleWatchdog = timer.schedule(ctx.channel(), preCoupleIdleTimeout.toMillis(),
                () -> onPreCoupleIdle(ctx.channel()));
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, SmppBindPdu msg) {
        if (msg instanceof SmppBindRequest req) {
            onRequest(ctx, req);
        } else {
            // A bind RESPONSE from the legacy client — a direction violation ({@link SmppBindPdu} is
            // sealed, so this is provably an {@link SmppBindResponse}): F1 (Story 4.4 T2) bare-closes it,
            // never a silent drop.
            onResponse(ctx, (SmppBindResponse) msg);
        }
    }

    private void onRequest(ChannelHandlerContext ctx, SmppBindRequest req) {
        Channel channel = ctx.channel();
        ConnectionEntry entry = manager.entryFor(channel);
        if (entry == null) {
            if (gate.armed()) {
                // Story 4.3 T4 (OBS-017): the acceptor stopped — a NEW adjudication may not start.
                // Fail-closed deny in the routing-miss arm's exact shape (no pair exists to tear down,
                // so no manager beginTeardown): release the frame, the AD-33 generic deny answering
                // this bind, close. The gate sits BEFORE register — no registry entry ever appears —
                // and the verifier is never contacted (the bind never becomes an adjudication).
                // LOG-ONLY beyond the wire deny: not a returned Verdict → no onBindReject (AD-27); the
                // system_id alone is observed (the RELAY logging rule), bounded by the live-socket
                // count (each denied socket closes). Post-couple PDUs never reach this arm — the
                // drain body (4.3 T5) needs established pairs relaying until the deadline.
                log.warn("bind after acceptor stop — fail-closed deny, no adjudication started (OBS-017): {}",
                        req.systemId());
                req.originalFrame().release();
                writeBindFailureAndClose(channel, req.commandId(), req.sequenceNumber());
                return;
            }
            if (forwardRole && routingTable.route(req.systemId().toString()) == null) {
                // AD-29/AD-11 routing miss on the forward arm: NO pair is ever created (no registry
                // entry, no adjudication — the miss precedes both), the AD-33 generic deny answers
                // this bind, and the connection closes. LOG-ONLY (no observer fire: a routing miss is
                // not a returned Verdict, AD-27; no metrics exist pre-Epic 4). The log observes the
                // system_id ALONE (the RELAY logging rule).
                log.warn("routing miss: system_id not in the routing table — AD-33 deny (AD-29/AD-11): {}",
                        req.systemId());
                req.originalFrame().release();
                writeBindFailureAndClose(channel, req.commandId(), req.sequenceNumber());
                return;
            }
            // First bind on this connection: optimistically register the pair (RELAY-006 — the entry exists
            // before the egress connects), then adjudicate.
            entry = manager.register(channel, new SystemId(req.systemId()));
            adjudicate(channel, entry, req);
        } else if (entry.coupled()) {
            // Post-couple (T8 coupled on the decoded ROK bind_resp): every PDU is T8's opaque relay. A
            // bind-family PDU still DECODES — SmppCodec is structural, so "dormant post-couple" (AD-2)
            // means downstream handlers IGNORE the decode, not that it stops — which is why this arm
            // receives a decoded SmppBindRequest rather than a raw frame: channelRead0 only ever sees
            // SmppBindPdu, and the only request-shaped PDU a legacy client can send is a bind. The
            // pass-through itself is a pure fireChannelRead of the DECODED record (not refcounted —
            // SimpleChannelInboundHandler's auto-release of it is a no-op): the interceptor neither
            // releases nor forwards anything here; T8's RelayIngressHandler sits AFTER this handler on the
            // ingress pipeline and owns the frame there (it forwards req.originalFrame() as relayed bytes
            // or releases them per its relay lifecycle).
            ctx.fireChannelRead(req);
            return;
        } else {
            // RELAY-004: a bind handshake is already in flight on this connection (the entry exists, not
            // coupled). Deterministic reject: the AD-33 generic deny answering the RETRY's sequence +
            // teardown of the pair (cancel the in-flight adjudication; no second egress pair). The deny
            // carries BIND_REJECTED (the T4 hoist) — a proxy-side rejection, not an egress failure.
            req.originalFrame().release();
            denyAndTeardown(channel, req.commandId(), req.sequenceNumber(), CloseReason.BIND_REJECTED);
            return;
        }
        ctx.read(); // keep the pre-couple read armed (the retry-bind must be readable; T8 owns the general gate)
    }

    /**
     * The F1 arm (Story 4.4 T2): a decoded {@code bind_*_resp} on the INGRESS leg — a bind response is an
     * SMSC-side PDU, so one from the legacy client is a direction violation in EVERY pre-couple window.
     * Fail-closed with the AD-32 uniform bare-close ({@code RelayIngressHandler.readPreCouple}'s exact
     * shape): release the frame, tear the pair (if one exists) down through
     * {@code manager.beginTeardown} — the {@code cancelHttp()} + zeroize hygiene rides inside — stash
     * {@link CloseReason#PRE_COUPLE_NON_BIND_PDU}, close the legs. NO response PDU is synthesized and the
     * PDU is NEVER forwarded: a forwarded pre-flip ROK would couple the pair without SMSC consent (the
     * forged-ROK window stays sealed). In the never-bound window no registry entry exists — the stash +
     * close is the whole effect (nothing to tear down, nothing to cancel). Not a returned
     * {@code Verdict} → no {@code onBindReject} (AD-27). Post-couple the decoded PDU passes through
     * untouched to T8's opaque relay exactly like a stray re-bind (AD-2's every-PDU doctrine — the
     * interceptor is dormant there).
     */
    private void onResponse(ChannelHandlerContext ctx, SmppBindResponse resp) {
        Channel channel = ctx.channel();
        ConnectionEntry entry = manager.entryFor(channel);
        if (entry != null && entry.coupled()) {
            // Post-couple (T8's plane — the request arm's exact idiom): a pure fireChannelRead of the
            // DECODED record (not refcounted — the auto-release of it is a no-op); the downstream relay
            // handler forwards resp.originalFrame() as relayed bytes, so the interceptor neither
            // releases nor forwards anything here.
            ctx.fireChannelRead(resp);
            return;
        }
        resp.originalFrame().release();
        if (entry == null) {
            // The never-bound window (F1 row 1): no bind was ever sent — no pair exists, close only.
            CoupledRelayHandler.stash(channel, CloseReason.PRE_COUPLE_NON_BIND_PDU);
            channel.close();
            return;
        }
        // Mid-adjudication / awaiting-bind_resp (F1 row 2): the manager's single-sited ordering
        // (remove + mark BEFORE close → cancelHttp + zeroize) runs INSIDE beginTeardown; this arm then
        // owns only its tails — the reason stash + the closes. A losing racer no-ops (RELAY-005).
        cancelPendingDeadlineTimer(); // the in-flight adjudication's F14 arm dies with the pair (4.4 T3)
        cancelPendingIdleWatchdog(); // ... and so does the T4 window bound — the pair is closing NOW
        if (manager.beginTeardown(channel) instanceof RelayStateManager.Teardown.Won(ConnectionEntry won)) {
            CoupledRelayHandler.stash(channel, CloseReason.PRE_COUPLE_NON_BIND_PDU);
            Channel egress = won.egress();
            if (egress != null) {
                egress.close();
            }
            channel.close(); // the bare close — the whole wire effect of AD-32 case 3
        }
    }

    /** Runs the verifier inside the {@link ScopedValue}-bound {@link RequestContext} and chains the continuation. */
    private void adjudicate(Channel channel, ConnectionEntry entry, SmppBindRequest req) {
        // Invariant (owner FIXME 2026-08-15; the assert moved to the registration path by the Story 3.4 T6
        // absorption): adjudicate runs ONLY on the first-bind arm (a fresh entry), and the in-flight
        // handles are ENTRY state now — a fresh entry is clean by construction and the teardown wipe is
        // single-sited in RelayStateManager.beginTeardown, so the pre-T6 "reached with an in-flight
        // adjudication" path bug is structurally unreachable. manager.register's assert carries the
        // surviving first-bind-arm guard (no live pair on the channel).

        BindCredential cred = new BindCredential(new SystemId(req.systemId()), new Password(req.password()));
        RequestContext context = new RequestContext(
                cred.systemId(), channel.id(), Instant.now().plus(adjudicationDeadline));
        VerdictRequest verdictRequest;
        try {
            // Non-blocking proof (owner FIXME 2026-08-15): this call only HANDS OFF the credential —
            // the "await" of VerdictRequest.future() is the whenComplete chain below, never a
            // thread-blocking join/get on the event loop. Mechanically pinned two ways in
            // BindInterceptorTest: the class-level @Timeout turns a blocking-verifier regression into a
            // test FAILURE (not a hang), and RELAY-004 writes a SECOND PDU through the same pipeline
            // while verdict #1 is still latched — the pipeline provably stays live. A verifier that
            // blocks INSIDE verify() violates the port contract (the implementation's own executor owns
            // the async, AD-28) — unenforceable from the relay, which is exactly why the port returns a
            // future rather than a value.
            verdictRequest = ScopedValue.where(REQUEST_CONTEXT, context)
                    .call(() -> verifier.verify(cred, REQUEST_CONTEXT));
        } catch (Exception e) {
            // The verifier blew up synchronously — fail-closed (AD-11): same generic deny, no onBindReject
            // (an exception is not a returned Verdict — AD-27). No pendingVerdict/pendingPassword is
            // stored on the entry on this arm (nothing was returned to track), so the manager's
            // beginTeardown hygiene inside denyAndTeardown finds nothing — correct — and the explicit
            // zeroize below is this arm's single wipe of the never-adjudicated secret. The deny carries
            // BIND_REJECTED (the T4 hoist): a proxy-side fail-closed rejection.
            req.originalFrame().release();
            denyAndTeardown(channel, req.commandId(), req.sequenceNumber(), CloseReason.BIND_REJECTED);
            cred.password().zeroize();
            return;
        }
        if (verdictRequest == null) {
            // A null VerdictRequest violates the port's never-null contract (BindCredentialVerifier) —
            // treat it exactly like a synchronous verifier blow-up above (AD-11 fail-closed): same generic
            // deny, no onBindReject (null is not a returned Verdict, AD-27), and the single explicit
            // zeroize is this arm's wipe of the never-adjudicated secret. Without this arm the future()
            // dereference below would NPE OUTSIDE the try — the pair still tears down via exceptionCaught,
            // but the original frame's pooled buffer leaks (review F12, 2026-08-17). BIND_REJECTED (the
            // T4 hoist): same proxy-side fail-closed class as the synchronous blow-up above.
            req.originalFrame().release();
            denyAndTeardown(channel, req.commandId(), req.sequenceNumber(), CloseReason.BIND_REJECTED);
            cred.password().zeroize();
            return;
        }
        // The in-flight handles are ENTRY state now (T6 absorption (a)): the store goes through the manager,
        // where the teardown hygiene and the settle wipe below find them.
        manager.beginAdjudication(entry, verdictRequest, cred.password());
        // Story 8.1 T2: the adjudication-latency ARM — taken at the same hook point the F14 deadline
        // timer arms on (the verify hand-off), consumed once at the settle in onVerdict. Duration =
        // now − arm (the Design Note's formula); the fire is THROW-ISOLATED there like every observer
        // trigger, so the timing hook can never throw into the verdict path.
        pendingAdjudicationStartNanos = System.nanoTime();
        // Story 4.4 T3 (F14): arm the adjudication deadline on the ingress event loop — the SAME budget
        // the RequestContext above carried (one number, {@code companion.bind.adjudication-deadline}). A
        // verifier future that never settles can no longer pin the entry, the original bind frame, and
        // the legacy socket past it: the task below re-checks and routes the fail-closed deny through
        // the ONE teardown path. Cancelled at settle and at every interceptor teardown arm — but a
        // missed cancellation is converged away by the task's own re-check, never corrupted by it.
        // Arming AFTER beginAdjudication: the timer belongs to the in-flight-verdict window exactly (the
        // synchronous-blow-up and null-return arms above denied without ever pending).
        pendingDeadlineTimer = timer.schedule(channel, adjudicationDeadline.toMillis(),
                () -> onAdjudicationDeadline(channel, entry, req.commandId(), req.sequenceNumber()));
        verdictRequest.future().whenComplete((verdict, error) ->
                // Hop the continuation onto the ingress event loop — it touches registry/pipeline state the
                // loop owns. (EmbeddedChannel runs this inline; a real loop schedules it.)
                channel.eventLoop().execute(() -> onVerdict(channel, entry, req, verdict, error)));
    }

    /**
     * The verdict continuation (on the ingress event loop). Settles the entry's adjudication first —
     * {@code manager.settleAdjudication} drops the cancellation handle and performs the caller-owned
     * zeroize on EVERY completion path (Allow/Deny/exceptional, and the losing-race no-op alike;
     * idempotent per RELAY-005) — cancels the pending deadline timer (both arms below: the verdict
     * landed inside the budget, the arm is spent), and records the adjudication latency (Story 8.1
     * T2: {@link #recordAdjudicationLatency()} — exactly once per completed adjudication, BEFORE the
     * race-free re-check so a concurrently-torn-down pair's settled future still counts); every path
     * releases or transfers the original frame.
     */
    private void onVerdict(Channel channel, ConnectionEntry entry, SmppBindRequest req,
                           @Nullable Verdict verdict, @Nullable Throwable error) {
        manager.settleAdjudication(entry);
        cancelPendingDeadlineTimer();
        recordAdjudicationLatency(); // Story 8.1 T2: the settle — one histogram record per COMPLETED adjudication
        // AD-25 race-free re-check: a concurrent teardown (retry-bind, leg death, AD-32 case 3, the F14
        // deadline arm below) owns the close — this callback must no-op (no egress, no deny, no observer
        // trigger).
        if (manager.entryFor(channel) != entry || entry.tearingDown()) {
            req.originalFrame().release();
            return;
        }
        if (error == null && verdict instanceof Verdict.Allow) {
            // Takes ownership of the original frame on EVERY internal path (forward, or release on
            // connect-fail / torn-down-during-connect).
            openEgressAndForward(channel, entry, req);
        } else {
            // Deny* verdict, an exceptional future (error != null — fail-closed, AD-11), or a
            // defensively-null verdict: all collapse to the same generic deny. onBindReject fires
            // ONLY for an actual returned Verdict (AD-27) — never for error/absence (which carry no
            // Verdict to report). Story 4.1 T4: the fire is THROW-ISOLATED at the site (a throwing
            // observer degrades the reject count/log line, never the frame release, the deny
            // synthesis, or the teardown below), and the deny teardown carries BIND_REJECTED (the
            // close-reason hoist — the close counter sees the real reason, not the OTHER default).
            if (error == null && verdict != null) {
                CoupledRelayHandler.fireGuarded("onBindReject",
                        () -> observer.onBindReject(entry.systemId(), verdict)); // the decision, before the wire effect
            }
            req.originalFrame().release();
            denyAndTeardown(channel, req.commandId(), req.sequenceNumber(), CloseReason.BIND_REJECTED);
        }
    }

    // ---------------------------------------------------------------- F14: the adjudication-deadline arm

    /**
     * The F14 deadline task (Story 4.4 T3), fired on the ingress event loop at
     * {@code companion.bind.adjudication-deadline} after the arm in {@code adjudicate}. Re-checks FIRST
     * — the entry may since have settled (the verdict landed: {@code onVerdict} cancelled the timer, but
     * a fire racing that cancellation on the loop is serialized after it, and a missed cancellation must
     * still converge), begun tearing down (retry-bind, leg death, F1, the shutdown drain), or coupled
     * (the SMSC's ROK answered) — a stale fire MUST no-op (the AD-25 re-check idiom; the sealed
     * {@code Won/Lost} race picks exactly one teardown winner). Otherwise the fail-closed deny:
     * {@link CloseReason#BIND_REJECTED} through the one shared path, whose {@code manager.beginTeardown}
     * hygiene cancels the still-pending verdict ({@code cancelHttp()} settles the pin
     * {@code DenyIndeterminate} per the port's no-op-if-done contract — the relay never authors a second
     * completion of the verifier's future) and zeroizes the password. NO {@link Verdict} is fabricated:
     * {@code onBindReject} NEVER fires for a timer deny (AD-27 — observer contract; the deadline deny is
     * log-distinguishable, enum-identical).
     */
    private void onAdjudicationDeadline(Channel channel, ConnectionEntry entry,
                                        int requestCommandId, int sequenceNumber) {
        pendingDeadlineTimer = null; // fired — there is no handle left to cancel
        if (manager.entryFor(channel) != entry || entry.tearingDown() || entry.coupled()) {
            return; // settled / tearing-down / coupled — a stale fire no-ops (convergence, not cancellation)
        }
        log.warn("adjudication deadline elapsed without a verdict — fail-closed deny (F14): {}",
                entry.systemId());
        denyAndTeardown(channel, requestCommandId, sequenceNumber, CloseReason.BIND_REJECTED);
    }

    /**
     * Deadline-arm hygiene (Story 4.4 T3): drop the pending timer's handle and cancel the task. Called
     * at settle ({@code onVerdict}) and at every interceptor teardown arm — a pair that is going down
     * must not have the deadline fire into it. Best-effort by design: a racing fire re-checks the entry
     * and no-ops, and cancelling an already-fired/completed future is a harmless no-op.
     */
    private void cancelPendingDeadlineTimer() {
        ScheduledFuture<?> pending = pendingDeadlineTimer;
        pendingDeadlineTimer = null;
        if (pending != null) {
            pending.cancel(false);
        }
    }

    /**
     * The adjudication-latency SETTLE (Story 8.1 T2, audit gap G1 — the bind histogram's recording
     * site): fires {@link RelayObserver#onBindAdjudication(Duration)} with {@code now − arm} for the
     * arm taken beside the deadline timer in {@code adjudicate}, then clears it — exactly one record
     * per COMPLETED adjudication, this method being the single settle funnel (every settled verifier
     * future hops here; deadline/teardown-aborted exchanges included, because their {@code cancelHttp()}
     * settles the pin per the port's no-op-if-done contract). Never fires for the never-armed arms
     * (synchronous verifier blow-up, null {@code VerdictRequest} — no future ever existed) or the
     * non-verdict denials (routing miss, the new-adjudication gate — no adjudication ever started).
     * THROW-ISOLATED at the site via {@code fireGuarded} and cleared BEFORE the fire, so a throwing
     * observer can neither eat the verdict path below nor double-record on any re-entry.
     */
    private void recordAdjudicationLatency() {
        Long arm = pendingAdjudicationStartNanos;
        if (arm == null) {
            return; // nothing armed — no adjudication was pending (see the field's javadoc)
        }
        pendingAdjudicationStartNanos = null; // exactly-once: spent before the fire, throw or not
        Duration latency = Duration.ofNanos(System.nanoTime() - arm);
        CoupledRelayHandler.fireGuarded("onBindAdjudication", () -> observer.onBindAdjudication(latency));
    }

    // ---------------------------------------------------------------- F13 residue: the pre-couple idle watchdog

    /**
     * The pre-couple idle watchdog task (Story 4.4 T4), fired on the ingress event loop at
     * {@code companion.bind.pre-couple-idle-timeout} after the arm in {@code channelActive}. The
     * connection did not reach couple inside the window — either extreme: a socket that never sent
     * its bind (no registry entry exists), or a pair still walking the handshake (mid-adjudication,
     * dialing, or awaiting a silent SMSC's {@code bind_resp} — the R32 sub-window RELAY-021 does not
     * bound). Re-checks FIRST exactly like the F14 arm: a coupled entry NO-OPS (PERF-2 — a coupled
     * pair idling indefinitely is the legitimate steady state and is NEVER reaped; the couple also
     * cancelled the task, so this is only the missed-cancellation convergence), a tearing-down entry
     * no-ops (a teardown owns the close), and a fire racing the socket's own close finds the entry
     * absent and the channel inactive — nobody left to close. Otherwise the fail-closed bare close in
     * the F1 arm's exact shape ({@code manager.beginTeardown} — the {@code cancelHttp()} + zeroize
     * hygiene rides inside — then the reason stash + the closes): NO response PDU is synthesized and
     * no {@link Verdict} is fabricated → never {@code onBindReject} (AD-27; the idle close is
     * log-distinguishable, enum-identical {@link CloseReason#PRE_COUPLE_NON_BIND_PDU}).
     */
    private void onPreCoupleIdle(Channel channel) {
        pendingIdleWatchdog = null; // fired — there is no handle left to cancel
        ConnectionEntry entry = manager.entryFor(channel);
        if (entry != null && (entry.tearingDown() || entry.coupled())) {
            return; // tearing-down: a teardown owns the close; coupled: NEVER reaped (PERF-2)
        }
        if (entry == null) {
            if (!channel.isActive()) {
                return; // a stale fire racing the socket's own close — nobody left to close
            }
            log.warn("pre-couple idle timeout elapsed with no bind — closing the never-binding socket "
                    + "(companion.bind.pre-couple-idle-timeout): {}", channel);
            CoupledRelayHandler.stash(channel, CloseReason.PRE_COUPLE_NON_BIND_PDU);
            channel.close();
            return;
        }
        log.warn("pre-couple idle timeout elapsed before couple — closing the pair "
                + "(companion.bind.pre-couple-idle-timeout): {}", entry.systemId());
        cancelPendingDeadlineTimer(); // the in-flight adjudication's F14 arm dies with the pair (4.4 T3)
        if (manager.beginTeardown(channel) instanceof RelayStateManager.Teardown.Won(ConnectionEntry won)) {
            CoupledRelayHandler.stash(channel, CloseReason.PRE_COUPLE_NON_BIND_PDU);
            Channel egress = won.egress();
            if (egress != null) {
                egress.close();
            }
            channel.close(); // the bare close — the whole wire effect, no response PDU
        }
    }

    /**
     * Watchdog hygiene (Story 4.4 T4): drop the pending watchdog's handle and cancel the task.
     * Called at the COUPLE (the egress answer arm — the pre-couple window is over; a coupled pair
     * idling for hours must NEVER be reaped, PERF-2) and at every interceptor teardown arm. NOT at
     * verdict settle: the Allow verdict only moves the pair into the egress dial, which is still
     * pre-couple (the watchdog must bound the silent-SMSC await). Best-effort like the deadline arm:
     * a racing fire re-checks and no-ops.
     */
    private void cancelPendingIdleWatchdog() {
        ScheduledFuture<?> pending = pendingIdleWatchdog;
        pendingIdleWatchdog = null;
        if (pending != null) {
            pending.cancel(false);
        }
    }

    // ---------------------------------------------------------------- the AD-33 collapse + teardown

    /**
     * The shared denial path: the manager's single-sited teardown ordering (remove + mark BEFORE close,
     * then {@code cancelHttp} + zeroize — all inside {@code manager.beginTeardown}), then — iff this caller
     * won the race — the Story 4.1 T4 close-reason hoist ({@link CoupledRelayHandler#stash} of the
     * caller's {@link CloseReason}: the deny-path close is OBSERVED with the real reason, not the
     * pre-couple OTHER default — a WINNER's tail, so a losing racer never overwrites the concurrent
     * winner's own reason), the header-only AD-33 deny answering the given request identifiers, followed
     * by close ("bind_resp error, then close"). A losing racer no-ops: never a {@code bind_resp} on a
     * connection being torn down (AD-32 Q1 invariant).
     *
     * @param reason the taxonomy value stashed for the exactly-once close fire —
     *               {@link CloseReason#BIND_REJECTED} for the proxy-side adjudication denials (verifier
     *               {@code Deny*}, the fail-closed verifier-failure arms, the RELAY-004 retry guard),
     *               {@link CloseReason#EGRESS_CONNECT_FAILED} for the egress-establishment failures.
     *               Observability-only: both arms collapse to the SAME wire deny by design (AD-33).
     */
    private void denyAndTeardown(Channel ingress, int requestCommandId, int sequenceNumber, CloseReason reason) {
        cancelPendingDeadlineTimer(); // the pair is going down — the F14 arm must not fire into it (4.4 T3)
        cancelPendingIdleWatchdog(); // ... and neither may the T4 window bound (4.4 T4)
        RelayStateManager.Teardown outcome = manager.beginTeardown(ingress);
        if (!(outcome instanceof RelayStateManager.Teardown.Won(ConnectionEntry won))) {
            return; // a concurrent teardown owns the close
        }
        CoupledRelayHandler.stash(ingress, reason); // T4 hoist: the close counter sees the real reason
        writeBindFailureAndClose(ingress, requestCommandId, sequenceNumber);
        Channel egress = won.egress();
        if (egress != null) {
            egress.close();
        }
    }

    /**
     * The AD-33 wire effect: the header-only deny answering the given request identifiers, then
     * close ("bind_resp error, then close"). Shared by the teardown-race winner and the
     * routing-miss arm (which has NO pair to tear down).
     */
    private static void writeBindFailureAndClose(Channel ingress, int requestCommandId, int sequenceNumber) {
        ingress.writeAndFlush(synthesizeBindFailure(ingress.alloc(), requestCommandId, sequenceNumber))
                .addListener(ChannelFutureListener.CLOSE);
    }

    /**
     * The ONE PDU the relay builds (AD-33): a header-only {@code bind_*_resp} — 16 octets written directly
     * ({@link SmppFrame#HEADER_LENGTH}; never re-serialized via {@code SmppBindEncoder}). The response id
     * comes from the codec's own constants ({@link SmppCommandIds} — AD-27: the bind-family set is
     * consumed, never redefined).
     */
    private static ByteBuf synthesizeBindFailure(ByteBufAllocator alloc, int requestCommandId, int sequenceNumber) {
        int responseId = switch (requestCommandId) {
            case SmppCommandIds.BIND_RECEIVER -> SmppCommandIds.BIND_RECEIVER_RESP;
            case SmppCommandIds.BIND_TRANSMITTER -> SmppCommandIds.BIND_TRANSMITTER_RESP;
            case SmppCommandIds.BIND_TRANSCEIVER -> SmppCommandIds.BIND_TRANSCEIVER_RESP;
            default -> throw new IllegalArgumentException(
                    "not a bind-family request command_id: 0x" + Integer.toHexString(requestCommandId));
        };
        return alloc.buffer(SmppFrame.HEADER_LENGTH, SmppFrame.HEADER_LENGTH)
                .writeInt(SmppFrame.HEADER_LENGTH)
                .writeInt(responseId)
                .writeInt(AD_33_GENERIC_BIND_FAILURE_STATUS)
                .writeInt(sequenceNumber);
    }

    // ---------------------------------------------------------------- the Allow path: egress + AD-14 forward

    /**
     * Assembles the per-bind egress connection (HexDumpProxy-style: the ingress channel's event loop is the
     * group, so both legs run on one thread — AD-2), wires the T6 substrate, and forwards the ORIGINAL bind
     * frame verbatim on connect success. Takes ownership of {@code req.originalFrame()} on every path.
     *
     * <p><b>Story 3.3 role-split:</b> the REVERSE arm dials the cell's single configured SMSC target with
     * the shared PLAINTEXT egress initializer (the SMSC leg is trusted in every mode — AD-12 amended);
     * the FORWARD arm dials the bind's ROUTING target with a per-bind TLS-carrying egress initializer
     * (client {@link io.netty.handler.ssl.SslHandler} per {@code tlsContextId}, [B] topology).
     */
    private void openEgressAndForward(Channel ingress, ConnectionEntry entry, SmppBindRequest req) {
        final String targetHost;
        final int targetPort;
        final io.netty.channel.ChannelHandler childInitializer;
        if (forwardRole) {
            ProxyCompanionProperties.RoutingEntry route = routingTable.route(req.systemId().toString());
            if (route == null) {
                // Unreachable (immutable post-startup table; the miss was denied pre-adjudication) —
                // fail closed with the same collapse rather than dialing anything.
                req.originalFrame().release();
                writeBindFailureAndClose(ingress, req.commandId(), req.sequenceNumber());
                return;
            }
            targetHost = route.host();
            targetPort = route.port();
            childInitializer = new RelayEgressInitializer(manager, observer,
                    ch -> tlsFactory.newEgressSslHandler(ch.alloc(), route));
        } else {
            ProxyCompanionProperties.Smsc target = smsc;
            if (target == null) {
                // Unreachable post-validation (every reverse mode leaf carries a @NotNull smsc) — a
                // role-resolution bug; fail closed rather than dialing anything.
                throw new IllegalStateException("reverse arm without an SMSC target — a role-resolution bug");
            }
            targetHost = target.host();
            targetPort = target.port();
            childInitializer = egressInitializer;
        }
        Bootstrap bootstrap = new Bootstrap()
                .group(ingress.eventLoop())
                .channel(NioSocketChannel.class)
                .handler(childInitializer); // the T6 codec prefix (+ the T8 slot documented there)
        channelOptions.applyToEgress(bootstrap);
        connector.connect(bootstrap, targetHost, targetPort).addListener((ChannelFutureListener) future -> {
            if (!future.isSuccess()) {
                // Egress-establishment failure: no SMSC response PDU will ever arrive — collapse to the SAME
                // generic deny (a prober cannot distinguish verifier-reject from unreachable-SMSC). NOT a
                // Verdict → no onBindReject (AD-27). EGRESS_CONNECT_FAILED (the T4 hoist): this is the
                // taxonomy value's namesake arm.
                req.originalFrame().release();
                denyAndTeardown(ingress, req.commandId(), req.sequenceNumber(),
                        CloseReason.EGRESS_CONNECT_FAILED);
                return;
            }
            Channel egress = future.channel();
            if (manager.entryFor(ingress) != entry || entry.tearingDown()) {
                // The pair tore down while connecting — nothing to attach to; kill the egress, release.
                req.originalFrame().release();
                egress.close();
                return;
            }
            manager.attachEgress(entry.ingressId(), egress);
            // The bind-family forwarder rides after the codec prefix. Appended here — before ANY read is
            // armed (AUTO_READ=false) — so no PDU can precede it; not the AD-2 "live pipeline surgery"
            // (which forbids remove() on a live channel). T6 absorption (b): the leg carries the ENTRY ref
            // (its answered state derives from the entry — no shadow bit on the handler).
            egress.pipeline().addLast(new EgressLeg(ingress, entry, req.commandId(), req.sequenceNumber()));
            egress.writeAndFlush(req.originalFrame()); // AD-14: verbatim; the write takes the release
            egress.read(); // arm the bind_resp read (AUTO_READ=false)
        });
    }

    // ---------------------------------------------------------------- ingress teardown window

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        Channel channel = ctx.channel();
        ConnectionEntry entry = manager.entryFor(channel);
        if (entry == null || entry.coupled()) {
            ctx.fireChannelInactive(); // nothing in flight, or T8's plane owns the post-couple teardown
            return;
        }
        // The legacy client vanished mid-handshake: teardown with NO deny (nobody left to answer — AD-32's
        // no-bind_resp-on-a-torn-down-connection invariant), the manager's cancel + wipe hygiene, close the
        // egress leg. The pending deadline timer dies with the pair (4.4 T3): nobody is left to answer its
        // deny either — and a racing fire would only find the entry absent and no-op. The idle watchdog
        // dies with it (4.4 T4): the socket it would have closed IS the socket that just went away.
        cancelPendingDeadlineTimer();
        cancelPendingIdleWatchdog();
        if (manager.beginTeardown(channel) instanceof RelayStateManager.Teardown.Won(ConnectionEntry won)) {
            Channel egress = won.egress();
            if (egress != null) {
                egress.close();
            }
        }
        ctx.fireChannelInactive();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        // Fail-closed containment: whatever broke, tear the handshake down. No response synthesis (a
        // mid-handshake violation is AD-32's no-_resp posture); the decoder layer's own rejects close the
        // channel and land in channelInactive.
        Channel channel = ctx.channel();
        ConnectionEntry entry = manager.entryFor(channel);
        if (entry != null && entry.coupled()) {
            // Post-couple: T8's plane — propagate so the relay handler stashes the CloseReason
            // (DECODE_ERROR / PEER_RST) and performs the pair teardown; it owns the close.
            ctx.fireExceptionCaught(cause);
            return;
        }
        if (entry != null) {
            cancelPendingDeadlineTimer(); // containment kills the F14 arm with the pair (4.4 T3)
            cancelPendingIdleWatchdog(); // ... and the T4 window bound (4.4 T4)
            if (manager.beginTeardown(channel) instanceof RelayStateManager.Teardown.Won(ConnectionEntry won)) {
                Channel egress = won.egress();
                if (egress != null) {
                    egress.close();
                }
            }
        }
        ctx.close();
    }

    // ---------------------------------------------------------------- the egress arm (AD-25 forwarder split)

    /**
     * The egress-side arm of the bind handshake (AD-25: {@code BindInterceptor} forwards the
     * {@code bind_*_resp}; the {@code RelayEgressHandler} only observes it). One per-pair instance, appended to
     * the egress pipeline by the connect assembly after the codec prefix. Forwards the SMSC's decoded
     * {@code bind_*_resp} VERBATIM to the legacy client — ROK and non-ROK alike (RELAY-002c: the SMSC is
     * the sole credential authority; its actual response is ground truth and is never collapsed, never
     * re-encoded) — by transferring {@link SmppBindResponse#originalFrame()} into the ingress write.
     * Consumes the decoded PDU (no downstream propagate): it is the bind family's last consumer, and the
     * T8 couple unit observes the same PDU from its earlier pipeline position.
     *
     * <p><b>The answered state is ENTRY state (T6 absorption (b)):</b> this leg's pre-T6 shadow bit
     * ({@code answered}) died — every bind answer transitioned the {@link ConnectionEntry} upstream
     * (the ROK couple in {@code RelayEgressHandler} on one arm, BEFORE this forwarder runs; the
     * non-ROK/nack teardown on the other, AFTER the verbatim forward — AD-32 case 4), so
     * {@link ConnectionEntry#answered()} derives the awaiting-bind_resp &rarr; answered transition with
     * zero shadow bits outside the entry; the derivation holds because this forwarder consults it only
     * at channelInactive/exceptionCaught, after the egress close the teardown already performed. The leg
     * holds the entry ref from its construction site.
     *
     * <p>If the SMSC leg dies BEFORE answering (close/RST/unbind — no response PDU), the bind can never
     * complete: collapse to the AD-33 generic deny so the legacy socket never hangs. After the answer, the
     * leg's lifecycle is T8's (post-bind_resp teardown propagates downstream).
     */
    @RequiredArgsConstructor // owner FIXME 2026-08-15: Lombok for the final-field ctor (house style)
    private final class EgressLeg extends SimpleChannelInboundHandler<SmppBindPdu> {

        private final Channel ingress;
        private final ConnectionEntry entry;
        private final int requestCommandId;
        private final int sequenceNumber;

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, SmppBindPdu msg) {
            if (msg instanceof SmppBindResponse response) {
                // Verbatim both directions of the status bit — RELAY-002c (NOT collapsed); ownership of the
                // frame transfers to the ingress write (that transfer is the release). No answered bit to
                // set: the upstream RelayEgressHandler already transitioned the entry (couple on ROK,
                // teardown on anything else) before this forwarder ran.
                //
                // The bind is ANSWERED — the pre-couple window is over (coupled on the ROK arm, or the
                // non-ROK teardown is imminent): the idle watchdog dies HERE (Story 4.4 T4). Cancelling
                // at the couple is the PERF-2 contract's active half — a coupled pair idling for hours
                // is the legitimate steady state and must NEVER be reaped (the fire-time coupled
                // re-check is the missed-cancellation backstop).
                cancelPendingIdleWatchdog();
                ingress.writeAndFlush(response.originalFrame());
            } else {
                // A bind REQUEST from the SMSC is a direction violation mid-handshake: no response PDU will
                // answer our bind — fail closed via the AD-33 collapse.
                msg.originalFrame().release();
                collapse(ctx);
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            if (!entry.answered()) {
                // SMSC death pre-bind_resp (RST/half-close/unbind): egress-establishment failure — same
                // AD-33 generic deny as a refused connect (the arms are indistinguishable by design),
                // and (the T4 hoist) the SAME close reason: EGRESS_CONNECT_FAILED.
                denyAndTeardown(ingress, requestCommandId, sequenceNumber, CloseReason.EGRESS_CONNECT_FAILED);
            }
            ctx.fireChannelInactive(); // T8's post-answer teardown observation continues downstream
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            if (!entry.answered()) {
                collapse(ctx);
            } else {
                ctx.close();
            }
        }

        private void collapse(ChannelHandlerContext ctx) {
            // Pre-answer egress violation (a bind REQUEST from the SMSC, a decode/pipeline break):
            // no SMSC response PDU will answer our bind — an egress-establishment failure for taxonomy
            // purposes (EGRESS_CONNECT_FAILED, the T4 hoist), collapsed to the AD-33 deny.
            denyAndTeardown(ingress, requestCommandId, sequenceNumber, CloseReason.EGRESS_CONNECT_FAILED);
            ctx.close();
        }
    }
}
