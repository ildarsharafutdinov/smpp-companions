package smpp.companion.proxy.relay.netty;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.observability.Direction;
import smpp.companion.proxy.observability.SpliceObserver;
import smpp.companion.proxy.relay.ConnectionRegistry;
import smpp.companion.proxy.relay.RelayHandler;

/**
 * The egress (SMSC-facing) pipeline (AC4; AD-2/AD-3): one {@link SmppFrameDecoder} then one
 * {@link SmppCodec} then the egress {@link RelayHandler} per egress channel — the SAME codec prefix
 * as the ingress leg ({@link RelayIngressInitializer}), because both legs of a coupled pair are one
 * framed-PDU data plane: the framer must delimit PDUs arriving FROM the SMSC (its {@code bind_*_resp}
 * and every post-couple PDU) exactly as on the ingress leg. Per-channel INSTANCES (CODEC-014),
 * created fresh in {@code initChannel}; the {@link RelayHandler} is per-channel BY DESIGN — it
 * carries the leg's {@link Direction} and its exactly-once close marker.
 *
 * <p><b>Attachment point (owner decision 2026-08-15 — codec-only prefix in T6; T8 landed the
 * entry).</b> The full egress pipeline per AC4 is {@code SmppFrameDecoder → SmppCodec → RelayHandler}:
 * the T8 {@link RelayHandler} (the AD-25 flip reader + opaque splice toward the ingress leg) sits
 * after {@code SmppCodec}. T7's per-bind egress {@code Bootstrap} (HexDumpProxy-style, grouped on the
 * ingress channel's event loop, options from {@link RelayChannelOptions}) installs this initializer,
 * and its connect assembly appends the {@code BindInterceptor.EgressLeg} bind-family forwarder AFTER
 * the {@link RelayHandler} (the flipper propagates bind-family PDUs so the forwarder still sees them).
 * NO {@link SslHandler io.netty.handler.ssl.SslHandler} on this leg either — plaintext
 * ({@code reverse.mode-b}) is this story's slice; TLS is Epic 3.
 */
@Component
@RequiredArgsConstructor
public final class RelayEgressInitializer extends ChannelInitializer<Channel> {

    private final ConnectionRegistry registry;
    private final SpliceObserver observer;

    @Override
    protected void initChannel(Channel channel) {
        channel.pipeline()
                .addLast(new SmppFrameDecoder()) // per-channel instance (CODEC-014)
                .addLast(new SmppCodec())
                // T8 (landed): the AD-25 single flipper + AD-32 bare-close + opaque splice. The flip
                // itself runs HERE — the bind_resp arrives from the SMSC on this leg, which rides the
                // ingress channel's event loop (AD-2 same-loop coupling).
                .addLast(new RelayHandler(registry, observer, Direction.EGRESS));
    }
}
