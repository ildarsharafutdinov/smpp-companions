package smpp.companion.proxy.relay;

import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;

import smpp.companion.codec.bind.SmppBindRequest;
import smpp.companion.codec.bind.SmppBindResponse;
import smpp.companion.proxy.observability.CloseReason;
import smpp.companion.proxy.observability.Direction;
import smpp.companion.proxy.observability.RelayObserver;

/**
 * The SMSC-facing leg of the data-plane relay (AC6; AD-2/AD-25/AD-32) — the COUPLE UNIT of the
 * Story 3.4 T5 direction-split (D3, owner checkpoint 2026-08-28): the egress half of the split
 * pre-couple window over the shared {@link CoupledRelayHandler} base. It owns exactly the
 * pre-couple behavior that can ONLY exist on the leg the SMSC answers:
 *
 * <ul>
 * <li><b>THE AD-25 couple (THE load-bearing invariant — structural-by-TYPE, AC6):</b> the couple flag
 * is set by EXACTLY ONE site in production code — this class's pre-couple hook — upon the DECODED
 * {@link SmppBindResponse#isOk()} predicate: never a peeked {@code command_id}, never "any frame from
 * egress", never at the verdict. The {@code bind_*_resp} arrives from the SMSC on the egress channel,
 * which rides the ingress channel's event loop — AD-2 same-loop coupling, so the couple runs "on the
 * ingress event loop" as AC3/AD-25 word it. {@link RelayObserver#onBindAccept} fires EXACTLY at the
 * couple. The ingress class cannot express the couple: it has no bind-response arm at all, and
 * {@code RelayCoupleSiteArchitectureTest} pins that ONLY this class among main-source classes calls
 * {@link ConnectionEntry#couple()}.
 * <li><b>Non-ROK + case-4 answers (AD-32 cases 2/4, RELAY-001b/RELAY-002c):</b> a non-ROK response
 * does NOT couple: it is propagated first (the {@code EgressLeg} forwards it verbatim — AD-32 case 4)
 * and THEN the pair tears down ({@link CloseReason#BIND_FAILED_NON_ROK}); an SMSC
 * {@code generic_nack} is the SMSC's own answer — forwarded VERBATIM to the legacy client first, then
 * teardown ({@link CloseReason#GENERIC_NACK_PRE_BIND}). The offending {@code command_id} is read only
 * to detect that one case ({@code getInt(4)}, no codec helper — AD-19) and is never emitted anywhere;
 * the INGRESS leg never reads the id at all.
 * <li><b>The egress-leg uniform bare-close (RELAY-003):</b> any other pre-couple PDU emits NO response
 * and closes — closing here is the whole violation: the {@code EgressLeg} sees the bind died
 * unanswered and collapses it to the AD-33 generic deny. A bind REQUEST from the SMSC propagates to
 * the {@code EgressLeg} (the direction violation IT collapses) — bind-family is never consumed here.
 * </ul>
 */
@SuppressWarnings("FutureReturnValueIgnored") // reason: the case-4 verbatim write is fire-and-forget
// fail-closed — its failure merely means the ingress is already closing (the desired end state); the
// close paths carry the base's own rationale.
public final class RelayEgressHandler extends CoupledRelayHandler {

    /**
     * SMPP 3.4 §4.3 {@code generic_nack} — the ONE opaque {@code command_id} the pre-couple policy must
     * distinguish (AD-32 case 4: the SMSC's own answer is ground truth and is forwarded verbatim). Not
     * exported by {@code SmppCommandIds} because it is NOT bind-family (AD-27 declares it
     * opaque-relayed); this is a local classification constant, not a redefinition of the bind set.
     */
    private static final int GENERIC_NACK = 0x80000000;

    public RelayEgressHandler(ConnectionRegistry registry, RelayObserver observer) {
        super(registry, observer, Direction.EGRESS);
    }

    @Override
    protected void readPreCouple(ChannelHandlerContext ctx, ConnectionEntry entry, Object msg) {
        Channel channel = ctx.channel();
        if (msg instanceof SmppBindResponse response) {
            if (response.isOk()) {
                // THE AD-25 couple — the only couple() call site in production code (AC6
                // structural-by-type: the ingress class has no bind-response arm to carry it).
                // fire-and-arm order: couple first (the state transition), observe exactly at the
                // couple, then hand the decoded PDU to the EgressLeg forwarder (the AD-25 split: the
                // relay handler never forwards it).
                if (entry.couple()) {
                    observer.onBindAccept(entry.systemId());
                    entry.ingress().read(); // arm the post-couple data plane on both legs (AUTO_READ=false)
                    channel.read();
                }
                ctx.fireChannelRead(response);
                return;
            }
            // Non-ROK: do NOT couple; tear down — but the SMSC's own answer reaches the legacy client
            // FIRST (AD-32 case 4 / RELAY-002c; fireChannelRead runs the EgressLeg forward synchronously
            // on this event loop, so the write is queued before the closes are).
            ctx.fireChannelRead(response);
            teardownPair(channel, entry, CloseReason.BIND_FAILED_NON_ROK);
            return;
        }
        if (msg instanceof SmppBindRequest) {
            // Pre-couple bind family is the cooperative set (AD-32): the interceptor plane owns it. A
            // bind REQUEST from the SMSC is a direction violation the EgressLeg collapses — propagate,
            // never consume bind-family here.
            ctx.fireChannelRead(msg);
            return;
        }
        ByteBuf frame = (ByteBuf) msg; // opaque non-bind — the codec's only other output shape
        if (frame.getInt(4) == GENERIC_NACK) {
            // AD-32 case 4: the SMSC's own answer to the bind — ground truth, forwarded VERBATIM (no
            // couple, no collapse); the write takes the frame's ownership, then the pair tears down.
            entry.ingress().writeAndFlush(frame);
            teardownPair(channel, entry, CloseReason.GENERIC_NACK_PRE_BIND);
            return;
        }
        // RELAY-003: the egress-leg AD-32 uniform bare-close — no response, no leak. Closing here is
        // the whole violation: EgressLeg.channelInactive sees the bind died unanswered and collapses
        // it to the AD-33 generic deny (R32 propagation, no leak).
        releaseFrame(frame);
        stash(channel, CloseReason.PRE_COUPLE_NON_BIND_PDU);
        channel.close();
    }
}
