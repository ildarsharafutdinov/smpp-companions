package smpp.companion.proxy.relay.netty;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.observability.SpliceObserver;
import smpp.companion.proxy.relay.BindInterceptor;
import smpp.companion.proxy.relay.ConnectionRegistry;
import smpp.companion.proxy.security.BindCredentialVerifier;

/**
 * The ingress (legacy-ESME-facing) pipeline prefix (AC4; AD-2/AD-3): one {@link SmppFrameDecoder}
 * then one {@link SmppCodec} then one {@link BindInterceptor} per accepted channel. Per-channel
 * INSTANCES for all three (CODEC-014 — the framer is stateful reassembly and the codec keeps no shared
 * state, but per-channel isolation is the pinned contract; the interceptor is per-channel BY DESIGN —
 * it carries the connection's in-flight adjudication state), created fresh in {@code initChannel};
 * never a shared/singleton handler here.
 *
 * <p><b>Attachment points (owner decision 2026-08-15 — codec-only prefix in T6; no placeholder
 * handler classes).</b> The full ingress pipeline per AC4 is
 * {@code SmppFrameDecoder → SmppCodec → BindInterceptor → RelayHandler}: the T7 entry
 * {@link BindInterceptor} (bind-family verifier gating + AD-33 collapse, AD-7/AD-25) has LANDED;
 * T8 appends {@code RelayHandler} (the AD-25 single flipper + AD-32 bare-close + opaque splice) last.
 * The decoders stay active for the channel's whole life (AD-2 — {@code SmppFrameDecoder} frames both
 * pre- and post-couple; {@code SmppCodec} is dormant post-couple, never removed: no live pipeline
 * surgery). Options (allocator / {@code AUTO_READ=false} / watermark) are NOT set here — they are
 * acceptor child options owned by {@link RelayChannelOptions}. NO {@code SslHandler} on this leg —
 * plaintext to the mock SMSC is this story's slice; TLS is Epic 3.
 */
@Component
@RequiredArgsConstructor
public final class RelayIngressInitializer extends ChannelInitializer<Channel> {

    private final BindCredentialVerifier verifier;
    private final ConnectionRegistry registry;
    private final SpliceObserver observer;
    private final ProxyCompanionProperties properties;
    private final RelayEgressInitializer egressInitializer;
    private final RelayChannelOptions channelOptions;

    @Override
    protected void initChannel(Channel channel) {
        channel.pipeline()
                .addLast(new SmppFrameDecoder()) // per-channel instance (CODEC-014)
                .addLast(new SmppCodec())
                // T7 (landed): bind-family verifier gating + AD-33 collapse + the AD-14 forward
                // (AD-7/AD-25/AD-27/AD-33). Per-channel: holds the in-flight adjudication handles.
                .addLast(new BindInterceptor(verifier, registry, observer, properties, egressInitializer, channelOptions));
        // T8: .addLast(relayHandler) — AD-25 single flipper + AD-32 bare-close + opaque splice.
    }
}
