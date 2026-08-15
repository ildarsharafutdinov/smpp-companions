package smpp.companion.proxy.relay.netty;

import org.springframework.stereotype.Component;

import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.framer.SmppFrameDecoder;

/**
 * The ingress (legacy-ESME-facing) pipeline prefix (AC4; AD-2/AD-3): one {@link SmppFrameDecoder}
 * then one {@link SmppCodec} per accepted channel. Per-channel INSTANCES for both (CODEC-014 — the
 * framer is stateful reassembly and the codec keeps no shared state, but per-channel isolation is the
 * pinned contract), created fresh in {@code initChannel}; never a shared/singleton handler here.
 *
 * <p><b>Attachment points (owner decision 2026-08-15 — codec-only prefix in T6; no placeholder
 * handler classes).</b> The full ingress pipeline per AC4 is
 * {@code SmppFrameDecoder → SmppCodec → BindInterceptor → RelayHandler}: T7 appends
 * {@code BindInterceptor} (bind-family verifier gating, AD-7/AD-25) AFTER {@code SmppCodec}, then T8
 * appends {@code RelayHandler} (the AD-25 single flipper + AD-32 bare-close + opaque splice) last.
 * The decoders stay active for the channel's whole life (AD-2 — {@code SmppFrameDecoder} frames both
 * pre- and post-couple; {@code SmppCodec} is dormant post-couple, never removed: no live pipeline
 * surgery). Options (allocator / {@code AUTO_READ=false} / watermark) are NOT set here — they are
 * acceptor child options owned by {@link RelayChannelOptions}. NO {@code SslHandler} on this leg —
 * plaintext to the mock SMSC is this story's slice; TLS is Epic 3.
 */
@Component
public final class RelayIngressInitializer extends ChannelInitializer<Channel> {

    @Override
    protected void initChannel(Channel channel) {
        channel.pipeline()
                .addLast(new SmppFrameDecoder()) // per-channel instance (CODEC-014)
                .addLast(new SmppCodec());
        // T7: .addLast(bindInterceptor) — bind-family gating + AD-33 collapse (AD-7/AD-25).
        // T8: .addLast(relayHandler) — AD-25 single flipper + AD-32 bare-close + opaque splice.
    }
}
