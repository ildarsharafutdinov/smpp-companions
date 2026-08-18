package smpp.companion.proxy.relay;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.nio.NioSocketChannel;

import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;

import smpp.companion.codec.bind.SmppBindPdu;
import smpp.companion.codec.bind.SmppBindRequest;
import smpp.companion.codec.bind.SmppBindResponse;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrame;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.observability.SpliceObserver;
import smpp.companion.proxy.relay.netty.RelayChannelOptions;
import smpp.companion.proxy.relay.netty.RelayEgressInitializer;
import smpp.companion.proxy.security.BindCredential;
import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.security.Password;
import smpp.companion.proxy.security.RequestContext;
import smpp.companion.proxy.security.SystemId;
import smpp.companion.proxy.security.Verdict;
import smpp.companion.proxy.security.VerdictRequest;

/**
 * The bind-handshake interceptor (AC2; AD-7/AD-12/AD-14/AD-15/AD-25/AD-27/AD-33) — the control-plane half
 * of the relay's pre-couple window. One PER-CHANNEL instance sits on the ingress pipeline after the codec
 * prefix ({@code SmppFrameDecoder → SmppCodec → BindInterceptor}); its nested {@link EgressLeg} rides the
 * per-bind egress channel. It owns exactly the bind family and nothing else:
 *
 * <ul>
 * <li><b>Routing (AC2, no allow-list):</b> EVERY decoded {@link SmppBindRequest} routes to the single
 * configured egress {@code companion.reverse.mode-b.smsc}. AD-29's {@code system_id} allow-list is the
 * FORWARD-role contract and is deliberately absent here — reverse.mode-b has no routing table by design.
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
 * {@code bind_*_resp} to the legacy client; the T8 {@code RelayHandler} observes the same decoded PDU
 * read-only to flip and never forwards it. {@code EgressLeg} is appended by the per-bind connect assembly
 * (before any read is armed — {@code AUTO_READ=false} guarantees no PDU can precede it) and does NOT
 * propagate decoded bind PDUs downstream: it is the bind-family's last consumer and owns the frame release,
 * a contract that stays stable when T8 inserts its handler earlier in the pipeline.
 * <li><b>Caller-owned zeroize (the open 2.1 review finding):</b> the relay — not {@code AlwaysAllow} — owns
 * {@link Password#zeroize()}. The wipe runs when the adjudication SETTLES (the continuation's
 * {@code finally}: Allow/Deny/exceptional) and at every TEARDOWN (retry-bind, ingress/egress death,
 * violation) — NOT at {@code verify()}-return, because the Epic-3 ROPC adapter reads the secret
 * asynchronously while its future is pending. The wipe can never corrupt the AD-14 forward:
 * {@code SmppBytes} copies each C-octet field out of the frame, so the password's backing array is not the
 * frame's memory. Idempotent (RELAY-005 double-zeroize safe).
 * <li><b>RELAY-004 (retry-bind):</b> a second bind while the handshake is in flight is deterministically
 * rejected — the AD-33 generic deny answering the RETRY's sequence, {@code cancelHttp()} on the in-flight
 * adjudication, teardown of both legs; no second pair, no registry corruption. The "in flight" predicate is
 * the registry entry itself (AD-32: "the entry's state, not a separate boolean").
 * </ul>
 *
 * <p><b>Teardown ordering (AD-32/AC3 discipline):</b> {@code registry.beginTeardown} (remove + mark
 * tearing-down) BEFORE close, then {@code cancelHttp()} + zeroize, then the deny write +
 * {@link ChannelFutureListener#CLOSE} ("bind_resp error, then close" — walkthrough §5). A losing racer
 * ({@code beginTeardown} returned {@code null}) no-ops — never a {@code bind_resp} on a connection being
 * torn down. The verdict continuation re-checks the entry (absent or tearing-down → no-op — the AD-25
 * race-free re-check). Post-flip behavior is T8's plane: once {@code entry.spliced()}, decoded bind PDUs
 * are passed through untouched, and the general teardown site / exactly-once {@code onConnectionClosed}
 * live there.
 *
 * <p><b>RELAY logging rule (T3):</b> logs/observes {@link SystemId} only — never
 * {@code SmppBindRequest}/{@code Password}/{@code BindCredential} objects nor the raw password
 * {@code AsciiString}.
 */
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

    private final BindCredentialVerifier verifier;
    private final ConnectionRegistry registry;
    private final SpliceObserver observer;
    private final RelayEgressInitializer egressInitializer;
    private final RelayChannelOptions channelOptions;
    private final EgressConnector connector;
    private final ProxyCompanionProperties.Smsc smsc;
    /**
     * The configured adjudication budget ({@code companion.bind.adjudication-deadline}, default {@code 4s}
     * in application.yml — owner FIXME 2026-08-15, formerly the hardcoded 30s constant): each bind's
     * {@code RequestContext.deadline} is {@code now + this}. Positive by the {@code Bind} record's
     * fail-fast guard (AD-17).
     */
    private final Duration adjudicationDeadline;

    /** The in-flight adjudication handle ({@code cancelHttp} target) while the verdict is pending. */
    private volatile @Nullable VerdictRequest pendingVerdict;
    /** The in-flight bind's password (the wipe target when teardown precedes the verdict). */
    private volatile @Nullable Password pendingPassword;

    /**
     * Production constructor (used by {@code RelayIngressInitializer} per accepted channel): the injected
     * beans + the single configured egress target resolved from {@code companion.reverse.mode-b.smsc}.
     */
    public BindInterceptor(BindCredentialVerifier verifier, ConnectionRegistry registry, SpliceObserver observer,
                           ProxyCompanionProperties properties, RelayEgressInitializer egressInitializer,
                           RelayChannelOptions channelOptions) {
        this(verifier, registry, observer, properties, egressInitializer, channelOptions, DEFAULT_CONNECTOR);
    }

    /**
     * Full constructor (package-private): adds the {@link EgressConnector} seam — RELAY-006's sanctioned
     * "injected failing ChannelFuture" — so tests can drive the connect-fail arm deterministically and pin
     * the egress-bootstrap wiring without a live socket.
     */
    BindInterceptor(BindCredentialVerifier verifier, ConnectionRegistry registry, SpliceObserver observer,
                    ProxyCompanionProperties properties, RelayEgressInitializer egressInitializer,
                    RelayChannelOptions channelOptions, EgressConnector connector) {
        ProxyCompanionProperties.@Nullable Reverse reverse = properties.reverse();
        if (reverse == null || reverse.modeB() == null) {
            // The acceptor is mode-b-scoped (RelayServerLifecycle): an interceptor outside that cell is a
            // wiring bug, not a data-plane condition — fail fast at construction.
            throw new IllegalStateException(
                    "BindInterceptor requires companion.reverse.mode-b.smsc (the relay acceptor is mode-b-scoped)");
        }
        this.verifier = verifier;
        this.registry = registry;
        this.observer = observer;
        this.egressInitializer = egressInitializer;
        this.channelOptions = channelOptions;
        this.connector = connector;
        this.smsc = reverse.modeB().smsc();
        this.adjudicationDeadline = properties.bind().adjudicationDeadline();
    }

    /** The per-bind egress connect seam ({@link Bootstrap} → {@link ChannelFuture}); see the package ctor. */
    interface EgressConnector {
        ChannelFuture connect(Bootstrap bootstrap, String host, int port);
    }

    // ---------------------------------------------------------------- ingress leg

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        ctx.fireChannelActive();
        ctx.read(); // arm the initial read — under AUTO_READ=false nothing arrives until demanded (AC4)
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, SmppBindPdu msg) {
        if (msg instanceof SmppBindRequest req) {
            onRequest(ctx, req);
        } else {
            // A bind RESPONSE from the legacy client is a direction violation — release its frame and drop
            // it silently (fail-closed, no response). Cannot come from a sane ESME.
            msg.originalFrame().release();
        }
    }

    private void onRequest(ChannelHandlerContext ctx, SmppBindRequest req) {
        Channel channel = ctx.channel();
        ConnectionEntry entry = registry.entryFor(channel);
        if (entry == null) {
            // First bind on this connection: optimistically register the pair (RELAY-006 — the entry exists
            // before the egress connects), then adjudicate.
            entry = registry.register(channel, new SystemId(req.systemId()));
            adjudicate(channel, entry, req);
        } else if (entry.spliced()) {
            // Post-flip (T8 flipped on the decoded ROK bind_resp): every PDU is T8's opaque splice. A
            // bind-family PDU still DECODES — SmppCodec is structural, so "dormant post-couple" (AD-2)
            // means downstream handlers IGNORE the decode, not that it stops — which is why this arm
            // receives a decoded SmppBindRequest rather than a raw frame: channelRead0 only ever sees
            // SmppBindPdu, and the only request-shaped PDU a legacy client can send is a bind. The
            // pass-through itself is a pure fireChannelRead of the DECODED record (not refcounted —
            // SimpleChannelInboundHandler's auto-release of it is a no-op): the interceptor neither
            // releases nor forwards anything here; T8's RelayHandler sits AFTER this handler on the
            // ingress pipeline and owns the frame there (it forwards req.originalFrame() as splice bytes
            // or releases them per its splice lifecycle).
            ctx.fireChannelRead(req);
            return;
        } else {
            // RELAY-004: a bind handshake is already in flight on this connection (the entry exists, not
            // spliced). Deterministic reject: the AD-33 generic deny answering the RETRY's sequence +
            // teardown of the pair (cancel the in-flight adjudication; no second egress pair).
            req.originalFrame().release();
            denyAndTeardown(channel, req.commandId(), req.sequenceNumber());
            return;
        }
        ctx.read(); // keep the pre-couple read armed (the retry-bind must be readable; T8 owns the general gate)
    }

    /** Runs the verifier inside the {@link ScopedValue}-bound {@link RequestContext} and chains the continuation. */
    private void adjudicate(Channel channel, ConnectionEntry entry, SmppBindRequest req) {
        // Invariant (owner FIXME 2026-08-15): adjudicate runs ONLY on the first-bind arm (no entry), and
        // every path that clears the entry also clears the pending handles on THIS event loop — the
        // retry/deny teardown arms call cancelAndWipePending(), the continuation nulls them first. Both
        // fields are written only from the ingress event loop, so reaching here with one set means a
        // path bug, not a race. assert (not throw): Gradle test workers run with -ea so CI bites; a
        // production JVM without -ea pays nothing on the bind hot path.
        assert pendingVerdict == null && pendingPassword == null
                : "adjudicate reached with an in-flight adjudication — a teardown arm skipped cancelAndWipePending";

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
            // stored on this arm (nothing was returned to track), so denyAndTeardown's
            // cancelAndWipePending finds nothing — correct — and the explicit zeroize below is this
            // arm's single wipe of the never-adjudicated secret.
            req.originalFrame().release();
            denyAndTeardown(channel, req.commandId(), req.sequenceNumber());
            cred.password().zeroize();
            return;
        }
        if (verdictRequest == null) {
            // A null VerdictRequest violates the port's never-null contract (BindCredentialVerifier) —
            // treat it exactly like a synchronous verifier blow-up above (AD-11 fail-closed): same generic
            // deny, no onBindReject (null is not a returned Verdict, AD-27), and the single explicit
            // zeroize is this arm's wipe of the never-adjudicated secret. Without this arm the future()
            // dereference below would NPE OUTSIDE the try — the pair still tears down via exceptionCaught,
            // but the original frame's pooled buffer leaks (review F12, 2026-08-17).
            req.originalFrame().release();
            denyAndTeardown(channel, req.commandId(), req.sequenceNumber());
            cred.password().zeroize();
            return;
        }
        pendingVerdict = verdictRequest;
        pendingPassword = cred.password();
        verdictRequest.future().whenComplete((verdict, error) ->
                // Hop the continuation onto the ingress event loop — it touches registry/pipeline state the
                // loop owns. (EmbeddedChannel runs this inline; a real loop schedules it.)
                channel.eventLoop().execute(() -> onVerdict(channel, entry, req, cred, verdict, error)));
    }

    /**
     * The verdict continuation (on the ingress event loop). Unconditionally settles the pending handles;
     * every path releases or transfers the original frame, and the {@code finally} performs the
     * caller-owned zeroize (Allow/Deny/exceptional alike).
     */
    private void onVerdict(Channel channel, ConnectionEntry entry, SmppBindRequest req, BindCredential cred,
                           @Nullable Verdict verdict, @Nullable Throwable error) {
        try {
            pendingVerdict = null; // settled — a later teardown cannot cancel a settled adjudication
            // AD-25 race-free re-check: a concurrent teardown (retry-bind, leg death, AD-32 case 3) owns the
            // close — this callback must no-op (no egress, no deny, no observer trigger).
            if (registry.entryFor(channel) != entry || entry.tearingDown()) {
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
                // Verdict to report).
                if (error == null && verdict != null) {
                    observer.onBindReject(entry.systemId(), verdict); // the decision, before the wire effect
                }
                req.originalFrame().release();
                denyAndTeardown(channel, req.commandId(), req.sequenceNumber());
            }
        } finally {
            cred.password().zeroize(); // caller-owned wipe on every completion path (idempotent — RELAY-005)
            pendingPassword = null;
        }
    }

    // ---------------------------------------------------------------- the AD-33 collapse + teardown

    /**
     * The shared denial path: teardown (remove + mark BEFORE close), cancel the in-flight adjudication,
     * wipe the password, then — iff this caller won the teardown race — the header-only AD-33 deny
     * answering the given request identifiers, followed by close ("bind_resp error, then close").
     * A losing racer no-ops: never a {@code bind_resp} on a connection being torn down (AD-32 Q1 invariant).
     */
    private void denyAndTeardown(Channel ingress, int requestCommandId, int sequenceNumber) {
        ConnectionEntry won = registry.beginTeardown(ingress); // remove + mark tearing-down BEFORE close
        cancelAndWipePending();
        if (won == null) {
            return; // a concurrent teardown owns the close
        }
        ingress.writeAndFlush(synthesizeBindFailure(ingress.alloc(), requestCommandId, sequenceNumber))
                .addListener(ChannelFutureListener.CLOSE);
        Channel egress = won.egress();
        if (egress != null) {
            egress.close();
        }
    }

    /** Teardown-side hygiene: abort the in-flight ROPC (AD-12/AD-32) and wipe the pending password. */
    private void cancelAndWipePending() {
        VerdictRequest inFlight = pendingVerdict;
        if (inFlight != null) {
            inFlight.cancelHttp();
            pendingVerdict = null;
        }
        Password password = pendingPassword;
        if (password != null) {
            password.zeroize();
            pendingPassword = null;
        }
    }

    /**
     * The T8 {@code RelayHandler}'s AD-32 case-3 arm: a pre-couple non-bind violation on the ingress leg
     * bare-closes the pair. The interceptor owns this teardown because the pending-adjudication handles
     * ({@code cancelHttp} + zeroize) live HERE — the ordering is the pinned AC3/AD-32 sequence:
     * {@code beginTeardown} (remove + mark tearing-down BEFORE close) → {@code cancelHttp()} +
     * {@code zeroize()} → close. Uniformly emits NOTHING on the wire — no {@code bind_resp}, no synthetic
     * {@code _resp} (AD-32 case 3 / RELAY-002; a losing racer no-ops per RELAY-005).
     *
     * @param ingress the violating legacy-client leg; non-null.
     */
    void teardownForPreCoupleViolation(Channel ingress) {
        ConnectionEntry won = registry.beginTeardown(ingress); // remove + mark tearing-down BEFORE close
        cancelAndWipePending();
        if (won == null) {
            return; // a concurrent teardown owns the closes
        }
        Channel egress = won.egress();
        if (egress != null) {
            egress.close();
        }
        ingress.close(); // the bare close — the whole wire effect of AD-32 case 3
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
     */
    private void openEgressAndForward(Channel ingress, ConnectionEntry entry, SmppBindRequest req) {
        Bootstrap bootstrap = new Bootstrap()
                .group(ingress.eventLoop())
                .channel(NioSocketChannel.class)
                .handler(egressInitializer); // the T6 codec prefix (+ the T8 slot documented there)
        channelOptions.applyToEgress(bootstrap);
        connector.connect(bootstrap, smsc.host(), smsc.port()).addListener((ChannelFutureListener) future -> {
            if (!future.isSuccess()) {
                // Egress-establishment failure: no SMSC response PDU will ever arrive — collapse to the SAME
                // generic deny (a prober cannot distinguish verifier-reject from unreachable-SMSC). NOT a
                // Verdict → no onBindReject (AD-27).
                req.originalFrame().release();
                denyAndTeardown(ingress, req.commandId(), req.sequenceNumber());
                return;
            }
            Channel egress = future.channel();
            if (registry.entryFor(ingress) != entry || entry.tearingDown()) {
                // The pair tore down while connecting — nothing to attach to; kill the egress, release.
                req.originalFrame().release();
                egress.close();
                return;
            }
            registry.attachEgress(entry.ingressId(), egress);
            // The bind-family forwarder rides after the codec prefix. Appended here — before ANY read is
            // armed (AUTO_READ=false) — so no PDU can precede it; not the AD-2 "live pipeline surgery"
            // (which forbids remove() on a live channel).
            egress.pipeline().addLast(new EgressLeg(ingress, req.commandId(), req.sequenceNumber()));
            egress.writeAndFlush(req.originalFrame()); // AD-14: verbatim; the write takes the release
            egress.read(); // arm the bind_resp read (AUTO_READ=false)
        });
    }

    // ---------------------------------------------------------------- ingress teardown window

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        Channel channel = ctx.channel();
        ConnectionEntry entry = registry.entryFor(channel);
        if (entry == null || entry.spliced()) {
            ctx.fireChannelInactive(); // nothing in flight, or T8's plane owns the post-flip teardown
            return;
        }
        // The legacy client vanished mid-handshake: teardown with NO deny (nobody left to answer — AD-32's
        // no-bind_resp-on-a-torn-down-connection invariant), cancel + wipe, close the egress leg.
        ConnectionEntry won = registry.beginTeardown(channel);
        cancelAndWipePending();
        if (won != null) {
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
        ConnectionEntry entry = registry.entryFor(channel);
        if (entry != null && entry.spliced()) {
            // Post-flip: T8's plane — propagate so the RelayHandler stashes the CloseReason
            // (DECODE_ERROR / PEER_RST) and performs the pair teardown; it owns the close.
            ctx.fireExceptionCaught(cause);
            return;
        }
        if (entry != null) {
            ConnectionEntry won = registry.beginTeardown(channel);
            cancelAndWipePending();
            if (won != null) {
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
     * {@code bind_*_resp}; the {@code RelayHandler} only observes it). One per-pair instance, appended to
     * the egress pipeline by the connect assembly after the codec prefix. Forwards the SMSC's decoded
     * {@code bind_*_resp} VERBATIM to the legacy client — ROK and non-ROK alike (RELAY-002c: the SMSC is
     * the sole credential authority; its actual response is ground truth and is never collapsed, never
     * re-encoded) — by transferring {@link SmppBindResponse#originalFrame()} into the ingress write.
     * Consumes the decoded PDU (no downstream propagate): it is the bind family's last consumer, and the
     * T8 flipper observes the same PDU from its earlier pipeline position.
     *
     * <p>If the SMSC leg dies BEFORE answering (close/RST/unbind — no response PDU), the bind can never
     * complete: collapse to the AD-33 generic deny so the legacy socket never hangs. After the answer, the
     * leg's lifecycle is T8's (post-bind_resp teardown propagates downstream).
     */
    @RequiredArgsConstructor // owner FIXME 2026-08-15: Lombok for the three-final-field ctor (house style)
    private final class EgressLeg extends SimpleChannelInboundHandler<SmppBindPdu> {

        private final Channel ingress;
        private final int requestCommandId;
        private final int sequenceNumber;
        private volatile boolean answered;

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, SmppBindPdu msg) {
            if (msg instanceof SmppBindResponse response) {
                answered = true;
                // Verbatim both directions of the status bit — RELAY-002c (NOT collapsed); ownership of the
                // frame transfers to the ingress write (that transfer is the release).
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
            if (!answered) {
                // SMSC death pre-bind_resp (RST/half-close/unbind): egress-establishment failure — same
                // AD-33 generic deny as a refused connect (the arms are indistinguishable by design).
                denyAndTeardown(ingress, requestCommandId, sequenceNumber);
            }
            ctx.fireChannelInactive(); // T8's post-answer teardown observation continues downstream
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            if (!answered) {
                collapse(ctx);
            } else {
                ctx.close();
            }
        }

        private void collapse(ChannelHandlerContext ctx) {
            denyAndTeardown(ingress, requestCommandId, sequenceNumber);
            ctx.close();
        }
    }
}
