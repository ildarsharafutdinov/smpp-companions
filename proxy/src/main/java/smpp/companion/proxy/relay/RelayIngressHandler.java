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
 * teardown below — never couples, never a {@code ClassCastException} on the decoded record.
 * <li><b>RELAY-002 — the AD-32 case-3 bare-close, DIRECT to the state manager (Story 3.4 T6):</b> a
 * pre-couple violation on this leg tears down through {@code manager.beginTeardown} — the pre-T6
 * pipeline-lookup delegation to the upstream {@code BindInterceptor} DIED with the T6 absorption (the
 * pending-adjudication hygiene, {@code cancelHttp} + zeroize, is manager-side now, so this leg needs no
 * interceptor to tear a pair down correctly). The pinned AC3 ordering (remove + mark BEFORE close
 * &rarr; cancel + wipe &rarr; close) is the manager's single-sited sequence. Uniformly emits NOTHING on
 * the wire — no {@code bind_resp}, no synthetic {@code _resp}; a losing racer no-ops (RELAY-005).
 * </ul>
 *
 * <p>The offending {@code command_id} is NEVER read on this leg (non-bind is already structural: the
 * codec emitted the PDU opaque because it is not bind-family) and never emitted.
 */
@SuppressWarnings("FutureReturnValueIgnored") // reason: close() on the relay's own channels is a
// fire-and-forget fail-closed control operation — a failed close merely means the channel was already
// closing (the desired end state).
public final class RelayIngressHandler extends CoupledRelayHandler {

    public RelayIngressHandler(RelayStateManager manager, RelayObserver observer) {
        super(manager, observer, Direction.INGRESS);
    }

    @Override
    protected void readPreCouple(ChannelHandlerContext ctx, ConnectionEntry entry, Object msg) {
        Channel channel = ctx.channel();
        // RELAY-002: the AD-32 uniform bare-close — no response, no leak. Covers the opaque non-bind
        // PDU AND a stray bind-family decode (unreachable today; this class has no bind arm — see the
        // class javadoc): both are violations on this leg, both fail closed here.
        releaseFrame(msg);
        stash(channel, CloseReason.PRE_COUPLE_NON_BIND_PDU);
        // The manager's single-sited ordering (remove + mark → cancelHttp + zeroize) runs INSIDE
        // beginTeardown; this leg then owns only its tails — the egress close + the bare close.
        RelayStateManager.Teardown outcome = manager.beginTeardown(channel);
        if (!(outcome instanceof RelayStateManager.Teardown.Won(ConnectionEntry won))) {
            return; // a concurrent teardown owns the closes (RELAY-005)
        }
        Channel egress = won.egress();
        if (egress != null) {
            egress.close();
        }
        channel.close(); // the bare close — the whole wire effect of AD-32 case 3
    }
}
