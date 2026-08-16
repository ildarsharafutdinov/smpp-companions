package smpp.companion.proxy.relay;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.jspecify.annotations.Nullable;

import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.DecoderException;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;
import lombok.RequiredArgsConstructor;

import smpp.companion.codec.bind.SmppBindPdu;
import smpp.companion.codec.bind.SmppBindRequest;
import smpp.companion.codec.bind.SmppBindResponse;
import smpp.companion.proxy.observability.CloseReason;
import smpp.companion.proxy.observability.Direction;
import smpp.companion.proxy.observability.SpliceObserver;

/**
 * The data-plane relay handler (AC3/AC7; AD-2/AD-3/AD-25/AD-27/AD-32) — the second of the two per-channel
 * handlers, one instance per LEG ({@code Direction} is the only per-instance state beyond the shared
 * beans). The ingress pipeline is {@code framer → codec → BindInterceptor → RelayHandler}; the egress
 * pipeline is {@code framer → codec → RelayHandler} (then T7's per-pair {@code EgressLeg} bind-family
 * forwarder, appended by the connect assembly). It owns exactly four things:
 *
 * <ul>
 * <li><b>The AD-25 single flip (THE load-bearing invariant):</b> the splice flag is flipped by EXACTLY ONE
 * site — {@link #channelRead} on the <b>egress</b> leg (the {@code bind_*_resp} arrives from the SMSC on
 * the egress channel, which rides the ingress channel's event loop — AD-2 same-loop coupling, so the flip
 * runs "on the ingress event loop" as AC3/AD-25 word it) — upon the DECODED
 * {@link SmppBindResponse#isOk()} predicate: never a peeked {@code command_id}, never "any frame from
 * egress", never at the verdict. {@link SpliceObserver#onBindAccept} fires EXACTLY at the flip. A non-ROK
 * response does NOT flip: it is propagated first (the {@code EgressLeg} forwards it verbatim — AD-32 case
 * 4 / RELAY-002c) and THEN the pair tears down ({@link CloseReason#BIND_FAILED_NON_ROK}). The flip
 * re-checks the {@link ConnectionRegistry} entry (absent or tearing-down &rarr; consume + fail-closed
 * close, no flip — the AD-25 race-free re-check).
 * <li><b>The post-flip opaque splice (AD-2/AD-3, REL-1):</b> once {@link ConnectionEntry#spliced()},
 * EVERY PDU — {@code unbind} included, and a stray bind-family decode included ({@code SmppCodec} is
 * structural: "dormant post-couple" means downstream handlers ignore the decode, so the splice forwards
 * {@link SmppBindPdu#originalFrame()}) — is forwarded as the framed {@link ByteBuf} to the peer leg,
 * byte-exact, one fire of {@link SpliceObserver#onFramedPdu(Direction)} per spliced PDU. NO live
 * pipeline surgery: the coupling is the flag flip, not a {@code pipeline.remove()}. Backpressure is the
 * AD-2 substrate: the write-completion listener re-arms the source leg's read only while the peer stays
 * writable, and {@link #channelWritabilityChanged} performs the explicit low-water re-arm (the peer's
 * outbound buffer drained below one max frame) — the emergent per-channel inbound bound of AD-30.
 * <li><b>The AD-32 pre-couple uniform bare-close:</b> pre-flip, on EITHER leg, everything that is not
 * bind-family emits NO response and closes. On the ingress leg the teardown is delegated to the upstream
 * {@link BindInterceptor} ({@link BindInterceptor#teardownForPreCoupleViolation(Channel)}) because the
 * pending-adjudication handles ({@code cancelHttp} + zeroize) live there — preserving the pinned AC3
 * ordering (remove + mark BEFORE close → cancel + wipe → close). On the egress leg, closing is enough:
 * {@code EgressLeg.channelInactive} collapses the dead bind via AD-33. The ONE case-4 exception: an SMSC
 * {@code generic_nack} is the SMSC's own answer — forwarded VERBATIM to the legacy client first, then
 * teardown ({@link CloseReason#GENERIC_NACK_PRE_BIND}). The offending {@code command_id} is read only to
 * detect that one case ({@code getInt(4)}, no codec helper — AD-19) and is never emitted anywhere.
 * <li><b>The exactly-once close telemetry (AD-27):</b> {@link SpliceObserver#onConnectionClosed} fires
 * ONLY at the {@link #channelInactive} site, guarded by a CAS on the channel attribute; every other path
 * merely STASHES a {@link CloseReason} on the channel for {@code channelInactive} to read. An unstashed
 * close defaults to {@link CloseReason#PEER_HALF_CLOSE} for a spliced pair (the RELAY-008 contract — the
 * peer FINned) and {@link CloseReason#OTHER} for a pre-flip leg (the handshake's own planes closed it).
 * A peer teardown propagates its reason onto the leg it closes. {@link #exceptionCaught} classifies
 * {@link DecoderException} &rarr; {@link CloseReason#DECODE_ERROR} (the CODEC-021 header-only
 * {@code bind_resp} path — {@code isOk()} is never reached) and {@link IOException} &rarr;
 * {@link CloseReason#PEER_RST} (how a live NIO channel surfaces a reset, pre-inactive).
 * </ul>
 *
 * <p><b>RELAY logging rule (T3):</b> this handler observes {@code SystemId} only — never a
 * {@code SmppBindRequest}/{@code Password}/{@code BindCredential} object, never a password
 * {@code AsciiString} (it touches no credential at all; the zeroize lives in the interceptor's teardown).
 */
@SuppressWarnings("FutureReturnValueIgnored") // reason: close() on the relay's own channels is a
// fire-and-forget fail-closed control operation — a failed close merely means the channel was already
// closing (the desired end state); every write whose completion we ACT on carries a listener.
@RequiredArgsConstructor
public final class RelayHandler extends ChannelInboundHandlerAdapter {

    /** The {@link CloseReason} stash a violation/teardown path leaves for the {@code channelInactive} site. */
    private static final AttributeKey<CloseReason> CLOSE_REASON =
            AttributeKey.valueOf(RelayHandler.class, "closeReason");

    /** The exactly-once guard for {@link SpliceObserver#onConnectionClosed} (CAS per channel, AC5). */
    private static final AttributeKey<AtomicBoolean> CLOSE_FIRED =
            AttributeKey.valueOf(RelayHandler.class, "closeFired");

    /**
     * SMPP 3.4 §4.3 {@code generic_nack} — the ONE opaque {@code command_id} the pre-couple policy must
     * distinguish (AD-32 case 4: the SMSC's own answer is ground truth and is forwarded verbatim). Not
     * exported by {@code SmppCommandIds} because it is NOT bind-family (AD-27 declares it
     * opaque-spliced); this is a local classification constant, not a redefinition of the bind set.
     */
    private static final int GENERIC_NACK = 0x80000000;

    private final ConnectionRegistry registry;
    private final SpliceObserver observer;
    private final Direction direction;

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        ctx.channel().attr(CLOSE_FIRED).setIfAbsent(new AtomicBoolean(false));
    }

    // ---------------------------------------------------------------- the single read path

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        Channel channel = ctx.channel();
        ConnectionEntry entry = registry.entryFor(channel);
        if (entry == null || entry.tearingDown()) {
            // AD-25 race-free re-check: this delivery is stale (the pair's teardown won before it
            // arrived) — consume the frame and fail-closed close the stray leg. No flip, no forward.
            releaseFrame(msg);
            channel.close();
            return;
        }
        if (entry.spliced()) {
            // Post-flip: EVERY PDU is opaque framed bytes (AD-2/AD-3) — including a stray bind-family
            // decode: the splice forwards the original frame, never the parsed record.
            splice(ctx, entry, msg instanceof SmppBindPdu pdu ? pdu.originalFrame() : (ByteBuf) msg);
            return;
        }
        if (msg instanceof SmppBindResponse response) {
            if (response.isOk()) {
                // THE AD-25 flip — the only flipSpliced() call site in the relay. fire-and-arm order:
                // flip first (the state transition), observe exactly at the flip, then hand the decoded
                // PDU to the EgressLeg forwarder (the AD-25 split: RelayHandler never forwards it).
                if (entry.flipSpliced()) {
                    observer.onBindAccept(entry.systemId());
                    entry.ingress().read(); // arm the post-couple data plane on both legs (AUTO_READ=false)
                    channel.read();
                }
                ctx.fireChannelRead(response);
                return;
            }
            // Non-ROK: do NOT flip; tear down — but the SMSC's own answer reaches the legacy client
            // FIRST (AD-32 case 4 / RELAY-002c; fireChannelRead runs the EgressLeg forward synchronously
            // on this event loop, so the write is queued before the closes are).
            ctx.fireChannelRead(response);
            teardownPair(channel, entry, CloseReason.BIND_FAILED_NON_ROK);
            return;
        }
        if (msg instanceof SmppBindRequest) {
            // Pre-couple bind family is the cooperative set (AD-32): the interceptor plane owns it. On
            // the egress leg that is the EgressLeg (a bind REQUEST from the SMSC is a direction
            // violation it collapses); on the ingress leg the interceptor consumed it upstream, so this
            // arm is egress-only in practice — propagate, never consume bind-family here.
            ctx.fireChannelRead(msg);
            return;
        }
        ByteBuf frame = (ByteBuf) msg; // opaque non-bind — the codec's only other output shape
        if (direction == Direction.EGRESS && frame.getInt(4) == GENERIC_NACK) {
            // AD-32 case 4: the SMSC's own answer to the bind — ground truth, forwarded VERBATIM (no
            // flip, no collapse); the write takes the frame's ownership, then the pair tears down.
            entry.ingress().writeAndFlush(frame);
            teardownPair(channel, entry, CloseReason.GENERIC_NACK_PRE_BIND);
            return;
        }
        // RELAY-002 (ingress) / RELAY-003 (egress): the AD-32 uniform bare-close — no response, no
        // leak. The offending command_id is never read on the ingress path at all (non-bind is already
        // structural: the codec emitted it opaque because it is not bind-family) and never emitted.
        releaseFrame(frame);
        stash(channel, CloseReason.PRE_COUPLE_NON_BIND_PDU);
        if (direction == Direction.INGRESS) {
            BindInterceptor interceptor = channel.pipeline().get(BindInterceptor.class);
            if (interceptor != null) {
                interceptor.teardownForPreCoupleViolation(channel); // beginTeardown → cancel+wipe → close both
                return;
            }
            channel.close(); // defensive: no interceptor in this pipeline — bare close anyway
            return;
        }
        // Egress leg: closing here is the whole violation — EgressLeg.channelInactive sees the bind
        // died unanswered and collapses it to the AD-33 generic deny (R32 propagation, no leak).
        channel.close();
    }

    // ---------------------------------------------------------------- the post-flip splice (AD-2/REL-1)

    /**
     * Forwards one framed PDU to the peer leg, byte-exact (the write takes the frame's ownership).
     * Write-completes-gates-read: the listener re-arms THIS leg's read only on success AND while the
     * peer is still writable — the low-water re-arm ({@link #channelWritabilityChanged}) owns the read
     * when the peer's outbound buffer was over the high mark, which is the AD-30 per-channel bound.
     */
    private void splice(ChannelHandlerContext ctx, ConnectionEntry entry, ByteBuf frame) {
        Channel self = ctx.channel();
        Channel peer = peerOf(entry, self);
        if (peer == null || !peer.isActive()) {
            frame.release(); // never forward to a dead pair (RELAY-009: nothing partial, nothing leaked)
            teardownPair(self, entry, CloseReason.OTHER);
            return;
        }
        observer.onFramedPdu(direction); // one fire per spliced PDU — the PDU count (AD-27)
        peer.writeAndFlush(frame).addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                if (peer.isWritable()) {
                    ctx.read(); // the peer took the PDU — pull the next one from this leg (AD-2)
                }
                return;
            }
            // The peer died mid-write: Netty already released the frame; tear the pair down.
            ConnectionEntry current = registry.entryFor(self);
            if (current != null && !current.tearingDown()) {
                teardownPair(self, current, CloseReason.OTHER);
            }
        });
    }

    /**
     * The explicit low-water re-arm (AD-2/AD-30): this leg's OUTBOUND buffer drained below one max
     * frame — the producer leg whose reads the high-water trip gated may push again. Scoped to spliced
     * pairs: the bind-handshake read cadence belongs to the interceptor plane.
     */
    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
        Channel channel = ctx.channel();
        if (channel.isWritable()) {
            ConnectionEntry entry = registry.entryFor(channel);
            if (entry != null && entry.spliced()) {
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
    private void teardownPair(Channel self, ConnectionEntry entry, CloseReason reason) {
        stash(self, reason);
        Channel peer = peerOf(entry, self);
        if (peer != null) {
            stash(peer, reason);
        }
        ConnectionEntry won = registry.beginTeardown(self);
        if (won == null) {
            return; // a concurrent teardown owns the closes
        }
        if (peer != null) {
            peer.close();
        }
        self.close();
    }

    /**
     * RELAY-008/010 — the post-flip plane: either leg going inactive tears the pair and closes the peer
     * (AD-8/REL-1). Pre-flip legs defer to the interceptor plane ({@code BindInterceptor}/{@code EgressLeg}
     * {@code channelInactive} own the handshake teardowns), then EVERY leg — coupled or not — fires its
     * exactly-once {@link SpliceObserver#onConnectionClosed} here, at the one site that owns it.
     */
    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        Channel channel = ctx.channel();
        ConnectionEntry entry = registry.entryFor(channel);
        boolean spliced = entry != null && entry.spliced();
        if (entry != null && spliced) {
            ConnectionEntry won = registry.beginTeardown(channel);
            if (won != null) {
                Channel peer = peerOf(entry, channel);
                if (peer != null) {
                    stash(peer, CloseReason.PEER_HALF_CLOSE); // the propagation's cause
                    peer.close();
                }
            }
        }
        fireClosedExactlyOnce(channel, spliced);
        ctx.fireChannelInactive();
    }

    /**
     * Fail-closed observation of whatever broke this leg: classify, stash, tear the pair down IF the
     * splice had already flipped, close. Pre-flip the handshake planes own the consequence (the egress
     * leg's {@code EgressLeg} collapses the dead bind via AD-33 — the CODEC-021 header-only
     * {@code bind_resp} lands here as a {@link DecoderException}, {@code isOk()} never reached).
     */
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        Channel channel = ctx.channel();
        CloseReason reason = classify(cause);
        stash(channel, reason);
        ConnectionEntry entry = registry.entryFor(channel);
        if (entry != null && entry.spliced()) {
            ConnectionEntry won = registry.beginTeardown(channel);
            if (won != null) {
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
    private void fireClosedExactlyOnce(Channel channel, boolean spliced) {
        AtomicBoolean fired = channel.attr(CLOSE_FIRED).get();
        if (fired == null || !fired.compareAndSet(false, true)) {
            return;
        }
        CloseReason stashed = channel.attr(CLOSE_REASON).get();
        CloseReason reason = stashed != null ? stashed
                : spliced ? CloseReason.PEER_HALF_CLOSE : CloseReason.OTHER;
        observer.onConnectionClosed(direction, reason);
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

    private static void stash(Channel channel, CloseReason reason) {
        channel.attr(CLOSE_REASON).set(reason);
    }

    /** The other leg of the pair from this handler's perspective ({@code null} pre-attach). */
    private @Nullable Channel peerOf(ConnectionEntry entry, Channel self) {
        return direction == Direction.INGRESS ? entry.egress() : entry.ingress();
    }

    /** Releases a pipeline message: the framed {@link ByteBuf}, or a decoded PDU's retained original frame. */
    private static void releaseFrame(Object msg) {
        if (msg instanceof SmppBindPdu pdu) {
            pdu.originalFrame().release();
        } else {
            ReferenceCountUtil.release(msg);
        }
    }
}
