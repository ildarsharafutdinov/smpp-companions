package smpp.companion.proxy.relay;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.DecoderException;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;

import smpp.companion.codec.bind.SmppBindPdu;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.proxy.observability.CloseReason;
import smpp.companion.proxy.observability.Direction;
import smpp.companion.proxy.observability.RelayObserver;

/**
 * The shared post-couple component of the two per-leg data-plane relay handlers (AC3/AC7/AC8;
 * AD-2/AD-3/AD-27/AD-32) — the Story 3.4 T5 direction-split base (D3, owner checkpoint 2026-08-28):
 * {@link RelayIngressHandler} and {@link RelayEgressHandler} extend this class, one instance per LEG.
 * The base owns everything the two legs do IDENTICALLY:
 *
 * <ul>
 * <li><b>The single read prelude:</b> the AD-25 race-free re-check (an absent or tearing-down entry
 * &rarr; consume the frame and fail-closed close the stray leg — no couple, no forward) and the
 * {@link ConnectionEntry#coupled()} branch — post-couple, EVERY PDU (a stray bind-family decode
 * included; {@code SmppCodec} is structural, so "dormant post-couple" means the relay forwards
 * {@link SmppBindPdu#originalFrame()}) is handed to {@link #relayFramedPdu} as opaque framed bytes.
 * The pre-couple window is the SUBCLASS's: {@link #readPreCouple(ChannelHandlerContext, ConnectionEntry,
 * Object)} is the one leg-specific hook (pre-couple is the bind-handshake plane, never the per-PDU
 * hot path — AC8: zero virtual dispatch per relayed PDU).
 * <li><b>The post-couple opaque relay (AD-2/AD-3, REL-1):</b> byte-exact forwarding to the peer leg,
 * one fire of {@link RelayObserver#onFramedPdu(Direction)} per relayed PDU. NO live pipeline surgery:
 * the coupling is the couple flag's one write, not a {@code pipeline.remove()}. Backpressure is the
 * AD-2 substrate: the write-completion listener re-arms the source leg's read only while the peer
 * stays writable, and {@link #channelWritabilityChanged} performs the explicit low-water re-arm (the
 * peer's outbound buffer drained below one max frame) — the emergent per-channel inbound bound of
 * AD-30. Story 4.1 T4 hardened this plane's observer seam: the PDU-count fire is THROW-ISOLATED at
 * the site ({@link #fireGuarded} — a throwing observer degrades the count, never the forward), and
 * the relayed body is TRACE-logged ({@link #PDU_BODIES}, off by default; bind-family bodies
 * redacted — the password cannot cross at any level).
 * <li><b>The shared teardown + exactly-once close telemetry (AD-27/AD-32):</b> the race-free
 * {@link #teardownPair} ordering (stash on BOTH legs, then the manager's single-sited
 * {@code beginTeardown} — remove + mark tearing-down + the cancel/wipe hygiene BEFORE close — then
 * close peer + self; a losing racer no-ops, RELAY-005; the decision is the sealed
 * {@code RelayStateManager.Teardown} since Story 3.4 T6), the
 * post-couple halves of {@link #channelInactive} (RELAY-008/010) and {@link #exceptionCaught}
 * (DecoderException &rarr; {@link CloseReason#DECODE_ERROR}; IOException &rarr; {@link CloseReason#PEER_RST}),
 * and {@link #fireClosedExactlyOnce} — {@link RelayObserver#onConnectionClosed} fires ONLY at the
 * {@code channelInactive} site, CAS-guarded per channel and (Story 4.1 T4) THROW-ISOLATED — a
 * throwing observer degrades close accounting, never the close itself; every other path merely
 * STASHES a {@link CloseReason}. An unstashed close defaults to {@link CloseReason#PEER_HALF_CLOSE}
 * for a coupled pair (the RELAY-008 contract) and {@link CloseReason#OTHER} for a pre-couple leg.
 * <li><b>The {@code CLOSE_REASON}/{@code CLOSE_FIRED} channel-attribute keys</b> — hoisted here from
 * the pre-split handler-private namespace (Story 3.4 T5 resolves D5: both per-leg classes share the
 * base's keys; runtime-only attributes, no wire effect — the reason SEMANTICS stay Epic-4).
 * </ul>
 *
 * <p><b>The ONE residual direction conditional (T9-sanctioned):</b> {@link #peerOf(ConnectionEntry,
 * Channel)} — the base field-compare ternary over the {@code direction} field (a base FIELD set via
 * the protected ctor, NOT an abstract method — AC8). No other {@code Direction} branch exists in the
 * split: pre-couple direction behavior lives in the subclass TYPES (AD-25's couple in exactly one of
 * them — structural-by-TYPE, AC6).
 *
 * <p><b>RELAY logging rule (T3):</b> this handler observes {@code SystemId} only — never a
 * {@code SmppBindRequest}/{@code Password}/{@code BindCredential} object, never a password
 * {@code AsciiString} (it touches no credential at all; the zeroize lives in {@code RelayStateManager}'s
 * teardown/settle hygiene — Story 3.4 T6).
 */
@SuppressWarnings("FutureReturnValueIgnored") // reason: close() on the relay's own channels is a
// fire-and-forget fail-closed control operation — a failed close merely means the channel was already
// closing (the desired end state); every write whose completion we ACT on carries a listener.
@Slf4j
public abstract class CoupledRelayHandler extends ChannelInboundHandlerAdapter {

    /** The {@link CloseReason} stash a violation/teardown path leaves for the {@code channelInactive} site. */
    protected static final AttributeKey<CloseReason> CLOSE_REASON =
            AttributeKey.valueOf(CoupledRelayHandler.class, "closeReason");

    /** The exactly-once guard for {@link RelayObserver#onConnectionClosed} (CAS per channel, AC5). */
    protected static final AttributeKey<AtomicBoolean> CLOSE_FIRED =
            AttributeKey.valueOf(CoupledRelayHandler.class, "closeFired");

    /**
     * The PDU-body TRACE logger (Story 4.1 T4 / FR-OBS-2 / PRIV-1) — a DEDICATED name,
     * {@code smpp.companion.proxy.relay.pdu}, so an operator enables exactly body logging via
     * {@code logging.level.smpp.companion.proxy.relay.pdu=TRACE} (standard {@code logging.level.*};
     * off by default) without opening any other relay logger. The ONE site that writes it is
     * {@link #relayFramedPdu} — post-couple only: the bind HANDSHAKE family bypasses the relay plane
     * (the AD-14 dial and the verbatim {@code bind_resp} forward), and the one residual password
     * carrier that can reach the site (a stray post-couple re-bind, relayed as its original frame)
     * is REDACTED there — so the bind password cannot cross at ANY level (the privacy contract).
     */
    private static final Logger PDU_BODIES = LoggerFactory.getLogger("smpp.companion.proxy.relay.pdu");

    /**
     * The pair-lifecycle state manager (Story 3.4 T6) — every transition routes through it;
     * {@code protected} for the one subclass transition need: the ingress leg's pre-couple violation
     * teardown ({@code RelayIngressHandler.readPreCouple}). The per-PDU hot path uses it ONLY as the
     * cached-attribute flag-read ({@link RelayStateManager#entryFor} — a pure storage read, AC8).
     */
    protected final RelayStateManager manager;
    /** The observability seam — {@code protected} for the one subclass trigger: {@code onBindAccept} at the couple. */
    protected final RelayObserver observer;
    private final Direction direction;

    /** @param direction the leg this instance serves — the only per-instance state beyond the shared beans. */
    protected CoupledRelayHandler(RelayStateManager manager, RelayObserver observer, Direction direction) {
        this.manager = manager;
        this.observer = observer;
        this.direction = direction;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        ctx.channel().attr(CLOSE_FIRED).setIfAbsent(new AtomicBoolean(false));
    }

    // ---------------------------------------------------------------- the single read path

    /**
     * The shared read prelude — final so no subclass can bypass it: the AD-25 race-free re-check, then
     * the post-couple opaque relay, then (pre-couple only) the subclass hook.
     */
    @Override
    public final void channelRead(ChannelHandlerContext ctx, Object msg) {
        Channel channel = ctx.channel();
        ConnectionEntry entry = manager.entryFor(channel);
        if (entry == null || entry.tearingDown()) {
            // AD-25 race-free re-check: this delivery is stale (the pair's teardown won before it
            // arrived) — consume the frame and fail-closed close the stray leg. No couple, no forward.
            releaseFrame(msg);
            channel.close();
            return;
        }
        if (entry.coupled()) {
            // Post-couple: EVERY PDU is opaque framed bytes (AD-2/AD-3) — including a stray bind-family
            // decode: the relay forwards the original frame, never the parsed record.
            relayFramedPdu(ctx, entry, msg instanceof SmppBindPdu pdu ? pdu.originalFrame() : (ByteBuf) msg);
            return;
        }
        readPreCouple(ctx, entry, msg);
    }

    /**
     * The one leg-specific hook: the pre-couple window (AD-32), where the two legs differ. The ingress
     * leg delegates its violations to the upstream {@code BindInterceptor} (the pending-adjudication
     * handles live there); the egress leg owns the AD-25 couple (the only {@code ConnectionEntry#couple()}
     * call site — structural-by-TYPE, AC6) and the case-4 {@code generic_nack} arm. Never called
     * post-couple (the prelude's {@code coupled()} branch owns that plane).
     *
     * @param entry the live, not-yet-coupled pair entry (re-checked by the prelude; non-null).
     */
    protected abstract void readPreCouple(ChannelHandlerContext ctx, ConnectionEntry entry, Object msg);

    // ---------------------------------------------------------------- the post-couple relay (AD-2/REL-1)

    /**
     * Forwards one framed PDU to the peer leg, byte-exact (the write takes the frame's ownership).
     * Write-completes-gates-read: the listener re-arms THIS leg's read only on success AND while the
     * peer is still writable — the low-water re-arm ({@link #channelWritabilityChanged}) owns the read
     * when the peer's outbound buffer was over the high mark, which is the AD-30 per-channel bound.
     */
    private void relayFramedPdu(ChannelHandlerContext ctx, ConnectionEntry entry, ByteBuf frame) {
        Channel self = ctx.channel();
        Channel peer = peerOf(entry, self);
        if (peer == null || !peer.isActive()) {
            frame.release(); // never forward to a dead pair (RELAY-009: nothing partial, nothing leaked)
            teardownPair(self, entry, CloseReason.OTHER);
            return;
        }
        // Story 4.1 T4: the PDU-count fire is THROW-ISOLATED at the site — a throwing observer
        // degrades the count, never the forward below.
        fireGuarded("onFramedPdu", () -> observer.onFramedPdu(direction)); // one fire per relayed PDU (AD-27)
        if (PDU_BODIES.isTraceEnabled()) {
            tracePduBody(direction, frame); // FR-OBS-2: bodies TRACE-only; bind-family redacted
        }
        peer.writeAndFlush(frame).addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                if (peer.isWritable()) {
                    ctx.read(); // the peer took the PDU — pull the next one from this leg (AD-2)
                }
                return;
            }
            // The peer died mid-write: Netty already released the frame; tear the pair down.
            ConnectionEntry current = manager.entryFor(self);
            if (current != null && !current.tearingDown()) {
                teardownPair(self, current, CloseReason.OTHER);
            }
        });
    }

    /**
     * The explicit low-water re-arm (AD-2/AD-30): this leg's OUTBOUND buffer drained below one max
     * frame — the producer leg whose reads the high-water trip gated may push again. Scoped to coupled
     * pairs: the bind-handshake read cadence belongs to the interceptor plane.
     */
    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
        Channel channel = ctx.channel();
        if (channel.isWritable()) {
            ConnectionEntry entry = manager.entryFor(channel);
            if (entry != null && entry.coupled()) {
                Channel peer = peerOf(entry, channel);
                if (peer != null) {
                    peer.read();
                }
            }
        }
        ctx.fireChannelWritabilityChanged();
    }

    // ---------------------------------------------------------------- teardown + observability

    /**
     * Race-free pair teardown (AC3/AD-32): stash the reason on BOTH legs, {@code beginTeardown} (remove
     * + mark tearing-down BEFORE close), then close the peer and this leg. A losing racer no-ops
     * (RELAY-005) — never a write on a pair someone else is tearing down.
     */
    protected void teardownPair(Channel self, ConnectionEntry entry, CloseReason reason) {
        stash(self, reason);
        Channel peer = peerOf(entry, self);
        if (peer != null) {
            stash(peer, reason);
        }
        if (!(manager.beginTeardown(self) instanceof RelayStateManager.Teardown.Won)) {
            return; // a concurrent teardown owns the closes
        }
        if (peer != null) {
            peer.close();
        }
        self.close();
    }

    /**
     * RELAY-008/010 — the post-couple plane: either leg going inactive tears the pair and closes the peer
     * (AD-8/REL-1). Pre-couple legs defer to the interceptor plane ({@code BindInterceptor}/{@code EgressLeg}
     * {@code channelInactive} own the handshake teardowns), then EVERY leg — coupled or not — fires its
     * exactly-once {@link RelayObserver#onConnectionClosed} here, at the one site that owns it.
     */
    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        Channel channel = ctx.channel();
        ConnectionEntry entry = manager.entryFor(channel);
        boolean coupled = entry != null && entry.coupled();
        if (entry != null && coupled) {
            if (manager.beginTeardown(channel) instanceof RelayStateManager.Teardown.Won) {
                Channel peer = peerOf(entry, channel);
                if (peer != null) {
                    stash(peer, CloseReason.PEER_HALF_CLOSE); // the propagation's cause
                    peer.close();
                }
            }
        }
        fireClosedExactlyOnce(channel, coupled);
        ctx.fireChannelInactive();
    }

    /**
     * Fail-closed observation of whatever broke this leg: classify, stash, tear the pair down IF the
     * pair had already coupled, close. Pre-couple the handshake planes own the consequence (the egress
     * leg's {@code EgressLeg} collapses the dead bind via AD-33 — the CODEC-021 header-only
     * {@code bind_resp} lands here as a {@link DecoderException}, {@code isOk()} never reached).
     */
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        Channel channel = ctx.channel();
        CloseReason reason = classify(cause);
        stash(channel, reason);
        ConnectionEntry entry = manager.entryFor(channel);
        if (entry != null && entry.coupled()) {
            if (manager.beginTeardown(channel) instanceof RelayStateManager.Teardown.Won) {
                Channel peer = peerOf(entry, channel);
                if (peer != null) {
                    stash(peer, reason);
                    peer.close();
                }
            }
        }
        ctx.close();
    }

    /** Fires the leg's close event exactly once (the CAS is the AC5 guard; only this site calls it). */
    private void fireClosedExactlyOnce(Channel channel, boolean coupled) {
        AtomicBoolean fired = channel.attr(CLOSE_FIRED).get();
        if (fired == null || !fired.compareAndSet(false, true)) {
            return;
        }
        CloseReason stashed = channel.attr(CLOSE_REASON).get();
        CloseReason reason = stashed != null ? stashed
                : coupled ? CloseReason.PEER_HALF_CLOSE : CloseReason.OTHER;
        // Story 4.1 T4: throw-isolated at the site — a throwing observer degrades close ACCOUNTING,
        // never the close itself (the CAS above is already spent, so exactly-once holds regardless).
        fireGuarded("onConnectionClosed", () -> observer.onConnectionClosed(direction, reason));
    }

    /**
     * Story 4.1 T4 throw isolation at the fire sites: runs ONE {@link RelayObserver} trigger and
     * swallows any {@link Throwable} it throws into a single bounded WARN — the relay path continues
     * (frame forwarded/released, deny synthesis and teardown proceed, close stays exactly-once). The
     * isolation lives at the FIRE SITE (the four sites in {@code relay/}), not inside an observer
     * implementation, so it protects ANY implementation — the belt-and-braces contract the production
     * observer additionally self-guards inside ({@code MeteredRelayObserver}). One WARN per swallowed
     * throw (the I/O matrix's "bounded" column): no rethrow, no flood. Package-private static: the
     * seam's single-sited mechanism, shared by the base's two sites and the two interceptor-plane
     * sites ({@code RelayEgressHandler.onBindAccept}, {@code BindInterceptor.onBindReject}).
     *
     * @param trigger the seam method's name — names the WARN line (diagnostics and WARN-count tests)
     * @param fire    the observer call, unexecuted until this method runs it
     */
    static void fireGuarded(String trigger, Runnable fire) {
        try {
            fire.run();
        } catch (Throwable t) {
            log.warn("RelayObserver.{} threw — bounded WARN, relay path continues (throw isolation)",
                    trigger, t);
        }
    }

    /**
     * The TRACE-gated body line (Story 4.1 T4 / FR-OBS-2): ONE line per RELAYED PDU — direction, the
     * framed length, the {@code command_id} read raw ({@code getInt(4)}, never a codec helper;
     * EMITTING the id is TRACE-gated by rule), and the frame's hex body. The bind family's body is
     * NEVER logged — a stray post-couple re-bind still carries the password, the RELAY logging
     * rule's one hard exception — the line is redacted to metadata only. Reads are non-destructive
     * ({@code hexDump} copies bytes; reader/writer indexes untouched), so the relayed frame is
     * unaffected. The framer guarantees &ge; 16 readable bytes, so the raw {@code command_id} read
     * cannot go out of bounds.
     */
    private static void tracePduBody(Direction direction, ByteBuf frame) {
        int commandId = frame.getInt(4); // the established raw-id idiom (RelayEgressHandler's nack check)
        if (SmppCommandIds.isBindFamily(commandId)) {
            PDU_BODIES.trace("relayed pdu: direction={} command_id=0x{} length={} body=<redacted: bind family>",
                    direction, Integer.toHexString(commandId), frame.readableBytes());
            return;
        }
        PDU_BODIES.trace("relayed pdu: direction={} command_id=0x{} length={} body=0x{}",
                direction, Integer.toHexString(commandId), frame.readableBytes(),
                ByteBufUtil.hexDump(frame));
    }

    private static CloseReason classify(Throwable cause) {
        if (cause instanceof DecoderException) {
            return CloseReason.DECODE_ERROR;
        }
        if (cause instanceof IOException) {
            return CloseReason.PEER_RST; // how a reset surfaces on a live NIO channel, pre-inactive
        }
        return CloseReason.OTHER;
    }

    /** Stashes the close reason for the {@code channelInactive} site (AD-27: never fires directly). */
    protected static void stash(Channel channel, CloseReason reason) {
        channel.attr(CLOSE_REASON).set(reason);
    }

    /** The other leg of the pair from this handler's perspective ({@code null} pre-attach). */
    private @Nullable Channel peerOf(ConnectionEntry entry, Channel self) {
        return direction == Direction.INGRESS ? entry.egress() : entry.ingress();
    }

    /** Releases a pipeline message: the framed {@link ByteBuf}, or a decoded PDU's retained original frame. */
    protected static void releaseFrame(Object msg) {
        if (msg instanceof SmppBindPdu pdu) {
            pdu.originalFrame().release();
        } else {
            ReferenceCountUtil.release(msg);
        }
    }
}
