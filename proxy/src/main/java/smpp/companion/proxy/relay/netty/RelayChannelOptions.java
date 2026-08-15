package smpp.companion.proxy.relay.netty;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.ChannelOption;
import io.netty.channel.WriteBufferWaterMark;

import smpp.companion.codec.framer.SmppFrame;
import smpp.companion.proxy.config.ProxyCompanionProperties;

/**
 * The shared per-channel option substrate for BOTH relay legs (AC4; AD-2/AD-21/AD-30) — applied by
 * {@link RelayServerLifecycle} to the acceptor's child channels now, and by the T7 egress
 * {@code Bootstrap} to every per-bind SMSC connection. One component so both legs carry IDENTICAL
 * options (they are the same data plane): the AD-21 shared allocator, the AD-2
 * {@code AUTO_READ=false} demand-driven read, and the AD-30 explicit
 * {@link ChannelOption#WRITE_BUFFER_WATER_MARK}.
 *
 * <p><b>Watermark math (AD-30 &mdash; the per-channel bound, made real in bytes; direction matters).</b>
 * The watermark trips on the channel's OWN OUTBOUND write buffer ({@link WriteBufferWaterMark} is the
 * outbound writability signal, not an inbound cap). The low water mark is ONE max-sized frame
 * ({@link SmppFrame#MAX_COMMAND_LENGTH} — RELAY-026's single named value, never a literal): once a
 * leg's outbound buffer drains below a frame's worth of queued bytes, writability flips back and the
 * splice re-arms the peer leg's read &mdash; the "explicit low-water mark to re-arm read". The high
 * water mark bounds that outbound buffer at
 * {@code MAX_COMMAND_LENGTH × companion.memory.max-inbound-depth}; the PER-CHANNEL INBOUND bound is
 * emergent from it: T8's write-completes-gates-read (AD-2) arms the peer leg's reads only while this
 * leg stays writable, so at most {@code max-inbound-depth} max-sized framed PDUs are admitted into the
 * spliced pair before writability trips and reads stop. This ties
 * the per-channel byte bound to the SAME depth input the AD-30 budget formula multiplies by
 * ({@code MemoryBudget.compute}), so the per-channel bound, the watermark, and the direct-memory
 * budget cannot drift apart. The gating behavior itself lives in the T8 {@code RelayHandler} (reads
 * are armed on the ingress leg only once the egress pair is coupled), which is why the options land
 * here in T6 and the read-demand logic lands with the handlers.
 *
 * <p>Computation is long-multiplication clamped to {@code Integer.MAX_VALUE} — a pathological
 * {@code max-inbound-depth} (e.g. an operator probing {@code Integer.MAX_VALUE}) must not overflow the
 * int-typed {@link WriteBufferWaterMark} into a negative/garbage high mark. At such depths the AD-30
 * startup self-check governs the real bound; the watermark merely stops degrading.
 */
@Component
@RequiredArgsConstructor
public final class RelayChannelOptions {

    private final ProxyCompanionProperties properties;
    private final PooledByteBufAllocator allocator;

    /**
     * Applies the shared substrate to the acceptor (the ingress legs). The three data-plane options are
     * CHILD options — the server channel itself allocates nothing and reads only TCP accepts — plus ONE
     * server-socket option, {@code SO_REUSEADDR}, ingress-only: a crash with established binds leaves
     * TIME_WAIT/FIN_WAIT children on the port, and the restarted listener must bind over its own dead
     * connections' remnants instead of boot-looping on {@code BindException} until the kernel drains
     * (~60s). A LIVE listener on the port still fails the bind ({@code EADDRINUSE}) — the AD-17
     * fail-fast posture is preserved; only the dead remnants are bypassed.
     *
     * @param bootstrap the acceptor {@link ServerBootstrap} being assembled by
     *         {@link RelayServerLifecycle#start()}
     */
    public void applyToIngress(ServerBootstrap bootstrap) {
        bootstrap.option(ChannelOption.SO_REUSEADDR, true)
                .childOption(ChannelOption.ALLOCATOR, allocator)
                .childOption(ChannelOption.AUTO_READ, false)
                .childOption(ChannelOption.WRITE_BUFFER_WATER_MARK, writeBufferWaterMark());
    }

    /**
     * Applies the SAME substrate to a per-bind egress {@code Bootstrap} (the SMSC leg — T7 assembles
     * one per accepted bind, HexDumpProxy-style, with the ingress channel's event loop as its group).
     * Identical options on both legs is the point: ingress and egress are one spliced data plane.
     * NO {@code SO_REUSEADDR} here — that is acceptor-socket semantics (rebind over TIME_WAIT on a
     * listener); a connecting client socket has no use for it.
     *
     * @param bootstrap the egress {@link Bootstrap} being assembled for one bind's SMSC connection
     */
    public void applyToEgress(Bootstrap bootstrap) {
        bootstrap.option(ChannelOption.ALLOCATOR, allocator)
                .option(ChannelOption.AUTO_READ, false)
                .option(ChannelOption.WRITE_BUFFER_WATER_MARK, writeBufferWaterMark());
    }

    /**
     * Low = one max frame (re-arm threshold); high = {@code max-inbound-depth} max frames (the OUTBOUND
     * bound the T8 gate turns into the per-channel inbound ceiling). Computed as long, clamped to
     * {@code Integer.MAX_VALUE} (see class javadoc); {@code low == high} (a depth-1 minimal config) is
     * legal — the writability signal then trips and re-arms at the same byte count.
     */
    private WriteBufferWaterMark writeBufferWaterMark() {
        long high = (long) SmppFrame.MAX_COMMAND_LENGTH * properties.memory().maxInboundDepth();
        return new WriteBufferWaterMark(
                SmppFrame.MAX_COMMAND_LENGTH, (int) Math.min(Integer.MAX_VALUE, high));
    }
}
