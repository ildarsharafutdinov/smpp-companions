package smpp.companion.proxy.relay.netty;

import org.springframework.stereotype.Component;

import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.framer.SmppFrameDecoder;

/**
 * The egress (SMSC-facing) pipeline prefix (AC4; AD-2/AD-3): one {@link SmppFrameDecoder} then one
 * {@link SmppCodec} per egress channel — the SAME codec prefix as the ingress leg
 * ({@link RelayIngressInitializer}), because both legs of a coupled pair are one framed-PDU data
 * plane: the framer must delimit PDUs arriving FROM the SMSC (its {@code bind_*_resp} and every
 * post-couple PDU) exactly as on the ingress leg. Per-channel INSTANCES (CODEC-014), created fresh in
 * {@code initChannel}.
 *
 * <p><b>Attachment point (owner decision 2026-08-15 — codec-only prefix in T6).</b> The full egress
 * pipeline per AC4 is {@code SmppFrameDecoder → SmppCodec → RelayHandler}: T8 appends the egress-side
 * {@code RelayHandler} (the AD-25 flip reader + opaque splice toward the ingress leg) AFTER
 * {@code SmppCodec}. T7's per-bind egress {@code Bootstrap} (HexDumpProxy-style, grouped on the
 * ingress channel's event loop, options from {@link RelayChannelOptions}) installs this initializer.
 * NO {@code SslHandler} on this leg either — plaintext ({@code reverse.mode-b}) is this story's
 * slice; TLS is Epic 3.
 */
@Component
public final class RelayEgressInitializer extends ChannelInitializer<Channel> {

    @Override
    protected void initChannel(Channel channel) {
        channel.pipeline()
                .addLast(new SmppFrameDecoder()) // per-channel instance (CODEC-014)
                .addLast(new SmppCodec());
        // T8: .addLast(relayHandler) — egress-side flip reader + opaque splice toward the ingress leg.
    }
}
