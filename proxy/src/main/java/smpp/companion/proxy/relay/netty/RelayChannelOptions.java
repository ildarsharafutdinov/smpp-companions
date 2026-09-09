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
 * {@code Bootstrap} to every per-bind SMSC connection. One component so both legs carry the IDENTICAL
 * data-plane substrate (they are one coupled plane): the AD-21 shared allocator, the AD-2
 * {@code AUTO_READ=false} demand-driven read, and the AD-30 explicit
 * {@link ChannelOption#WRITE_BUFFER_WATER_MARK}. Two options are deliberately PER-LEG rather than
 * shared: the acceptor's {@code SO_REUSEADDR} (ingress-only listener semantics — see
 * {@link #applyToIngress}) and, since Story 4.4 T1 (F10), the egress dial's bound
 * {@link ChannelOption#CONNECT_TIMEOUT_MILLIS} (client-connect semantics — an accepted ingress
 * socket never dials; see {@link #connectTimeoutMillis()}).
 *
 * <p><b>Watermark math (AD-30 &mdash; the per-channel bound, made real in bytes; direction matters).</b>
 * The watermark trips on the channel's OWN OUTBOUND write buffer ({@link WriteBufferWaterMark} is the
 * outbound writability signal, not an inbound cap). The low water mark is ONE max-sized frame
 * ({@link SmppFrame#MAX_COMMAND_LENGTH} — RELAY-026's single named value, never a literal): once a
 * leg's outbound buffer drains below a frame's worth of queued bytes, writability flips back and the
 * relay re-arms the peer leg's read &mdash; the "explicit low-water mark to re-arm read". The high
 * water mark bounds that outbound buffer at
 * {@code MAX_COMMAND_LENGTH × companion.memory.max-inbound-depth}; the PER-CHANNEL INBOUND bound is
 * emergent from it: T8's write-completes-gates-read (AD-2) arms the peer leg's reads only while this
 * leg stays writable, so read demand stops once writability trips. The bound is steady-state, not
 * exact: a single read cycle may deliver several framed PDUs and one write may already be in flight
 * when writability trips, and {@code read()} under {@code AUTO_READ=false} is an idempotent
 * interest-arm (re-arms coalesce into the same armed state — they do not queue extra reads), so the
 * standing inbound bytes are bounded by the high water mark plus one read cycle's worth, not by
 * precisely {@code max-inbound-depth} frames. This ties
 * the per-channel byte bound to the SAME depth input the AD-30 budget formula multiplies by
 * ({@code MemoryBudget.compute}), so the per-channel bound, the watermark, and the direct-memory
 * budget cannot drift apart. The gating behavior itself lives in the T8 relay handlers ({@code CoupledRelayHandler}
 * base; reads
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
     * Identical data-plane options on both legs is the point: ingress and egress are one coupled data
     * plane. NO {@code SO_REUSEADDR} here — that is acceptor-socket semantics (rebind over TIME_WAIT on a
     * listener); a connecting client socket has no use for it. PLUS the one egress-ONLY option (the
     * mirror of that asymmetry): the dial bound {@link ChannelOption#CONNECT_TIMEOUT_MILLIS}, derived
     * from the adjudication deadline (Story 4.4 T1, F10 — see {@link #connectTimeoutMillis()}).
     *
     * @param bootstrap the egress {@link Bootstrap} being assembled for one bind's SMSC connection
     */
    public void applyToEgress(Bootstrap bootstrap) {
        bootstrap.option(ChannelOption.ALLOCATOR, allocator)
                .option(ChannelOption.AUTO_READ, false)
                .option(ChannelOption.WRITE_BUFFER_WATER_MARK, writeBufferWaterMark())
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeoutMillis());
    }

    /**
     * The egress dial bound (Story 4.4 T1, F10): {@code CONNECT_TIMEOUT_MILLIS} DERIVED from
     * {@code companion.bind.adjudication-deadline} — no second knob (the F13 one-number precedent:
     * the deadline IS the whole pre-couple auth budget, so the dial bound is the same number).
     * Without it a SYN-blackholing SMSC target hangs the legacy client's socket on Netty/OS's ~30s
     * default — ~7.5&times; PERF-3's configured fail-closed budget; with it the dial fails at
     * &le; the deadline and the existing connect-fail arm ({@code BindInterceptor}'s
     * {@code EGRESS_CONNECT_FAILED} deny) answers immediately, so the worst-case client answer is
     * deadline + &epsilon;.
     *
     * <p>Long math with both clamps (the {@link #writeBufferWaterMark()} idiom): {@code max(1, &hellip;)}
     * because the {@code Bind} record's positive guard admits SUB-millisecond durations whose
     * {@code toMillis()} floors to 0 — a 0ms bound is no bound; {@code min(Integer.MAX_VALUE, &hellip;)}
     * because the same guard admits pathologically large durations whose millis would wrap the
     * int-typed option negative.
     */
    private int connectTimeoutMillis() {
        long millis = properties.bind().adjudicationDeadline().toMillis();
        return (int) Math.min(Integer.MAX_VALUE, Math.max(1L, millis));
    }

    /**
     * Low = one max frame (re-arm threshold); high = {@code max-inbound-depth} max frames (the OUTBOUND
     * bound the T8 gate turns into the per-channel inbound bound's high mark — the realized inbound
     * bound is the high mark plus one read cycle; see the class javadoc). Computed as long, clamped to
     * {@code Integer.MAX_VALUE} (see class javadoc); {@code low == high} (a depth-1 minimal config) is
     * legal — the writability signal then trips and re-arms at the same byte count.
     */
    private WriteBufferWaterMark writeBufferWaterMark() {
        long high = (long) SmppFrame.MAX_COMMAND_LENGTH * properties.memory().maxInboundDepth();
        return new WriteBufferWaterMark(
                SmppFrame.MAX_COMMAND_LENGTH, (int) Math.min(Integer.MAX_VALUE, high));
    }
}
