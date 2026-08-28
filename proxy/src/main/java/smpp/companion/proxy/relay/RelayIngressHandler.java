package smpp.companion.proxy.relay;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;

import smpp.companion.proxy.observability.CloseReason;
import smpp.companion.proxy.observability.Direction;
import smpp.companion.proxy.observability.RelayObserver;

/**
 * The legacy-client-facing leg of the data-plane relay (AC3; AD-2/AD-32) — the ingress half of the
 * Story 3.4 T5 direction-split (D3, owner checkpoint 2026-08-28) over the shared
 * {@link CoupledRelayHandler} base. Its pre-couple window is uniform by design:
 *
 * <ul>
 * <li><b>NO bind-response arm at all (AC6, the structural half):</b> the AD-25 couple lives in
 * {@link RelayEgressHandler} — this class cannot express it (no decoded-{@code bind_resp} branch
 * exists here to carry the {@code ConnectionEntry#couple()} call). A stray decoded
 * {@code bind_resp} on this leg is UNREACHABLE today (the upstream {@code BindInterceptor.channelRead0}
 * releases client-sent bind-responses silently) and fails CLOSED post-split: bare-close via the
 * delegation below — never couples, never a {@code ClassCastException} on the decoded record.
 * <li><b>RELAY-002 — the AD-32 case-3 bare-close via DELEGATION:</b> a pre-couple violation on this
 * leg tears down through the upstream {@code BindInterceptor}
 * ({@code BindInterceptor.teardownForPreCoupleViolation(Channel)}) because the pending-adjudication
 * handles ({@code cancelHttp} + zeroize) live there — preserving the pinned AC3 ordering (remove +
 * mark BEFORE close &rarr; cancel + wipe &rarr; close). Uniformly emits NOTHING on the wire — no
 * {@code bind_resp}, no synthetic {@code _resp}. With no interceptor in the pipeline (a wiring bug),
 * the bare close still happens — fail-closed either way.
 * </ul>
 *
 * <p>The offending {@code command_id} is NEVER read on this leg (non-bind is already structural: the
 * codec emitted the PDU opaque because it is not bind-family) and never emitted.
 */
@SuppressWarnings("FutureReturnValueIgnored") // reason: close() on the relay's own channels is a
// fire-and-forget fail-closed control operation — a failed close merely means the channel was already
// closing (the desired end state).
public final class RelayIngressHandler extends CoupledRelayHandler {

    public RelayIngressHandler(ConnectionRegistry registry, RelayObserver observer) {
        super(registry, observer, Direction.INGRESS);
    }

    @Override
    protected void readPreCouple(ChannelHandlerContext ctx, ConnectionEntry entry, Object msg) {
        Channel channel = ctx.channel();
        // RELAY-002: the AD-32 uniform bare-close — no response, no leak. Covers the opaque non-bind
        // PDU AND a stray bind-family decode (unreachable today; this class has no bind arm — see the
        // class javadoc): both are violations on this leg, both fail closed here.
        releaseFrame(msg);
        stash(channel, CloseReason.PRE_COUPLE_NON_BIND_PDU);
        BindInterceptor interceptor = channel.pipeline().get(BindInterceptor.class);
        if (interceptor != null) {
            interceptor.teardownForPreCoupleViolation(channel); // beginTeardown → cancel+wipe → close both
            return;
        }
        channel.close(); // defensive: no interceptor in this pipeline — bare close anyway
    }
}
