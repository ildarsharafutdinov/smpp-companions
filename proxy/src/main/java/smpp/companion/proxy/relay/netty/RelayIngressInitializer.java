package smpp.companion.proxy.relay.netty;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.config.RoutingTable;
import smpp.companion.proxy.observability.RelayObserver;
import smpp.companion.proxy.relay.BindInterceptor;
import smpp.companion.proxy.relay.RelayIngressHandler;
import smpp.companion.proxy.relay.RelayStateManager;
import smpp.companion.proxy.security.BindCredentialVerifier;
import smpp.companion.proxy.tls.SmppLegTlsFactory;

/**
 * The ingress (client-facing) pipeline prefix (AC4; AD-2/AD-3): one {@link SmppFrameDecoder}
 * then one {@link SmppCodec} then one {@link BindInterceptor} per accepted channel. Per-channel
 * INSTANCES for all three (CODEC-014 — the framer is stateful reassembly and the codec keeps no shared
 * state, but per-channel isolation is the pinned contract; the interceptor is per-channel BY DESIGN —
 * it carries the connection's in-flight adjudication state), created fresh in {@code initChannel};
 * never a shared/singleton handler here.
 *
 * <p><b>Attachment points (owner decision 2026-08-15 — codec-only prefix in T6; no placeholder
 * handler classes).</b> The full ingress pipeline per AC4 is
 * {@code SslHandler? → SmppFrameDecoder → SmppCodec → BindInterceptor → RelayIngressHandler}: the T7
 * entry {@link BindInterceptor} (bind-family verifier gating + AD-33 collapse, AD-7/AD-25) and the T8
 * entry {@link RelayIngressHandler} (the ingress leg of the T5 direction-split over
 * {@code CoupledRelayHandler}: the AD-32 bare-close through the state manager (Story 3.4 T6) + the
 * post-couple
 * opaque relay) have both LANDED; Story 3.3 ([B] topology) prepends the {@code SslHandler} <b>iff this cell's listener
 * is TLS</b> (reverse.mode-a/c — {@link SmppLegTlsFactory#listenerTls()}); the forward cells'
 * trusted leg and reverse.mode-b stay plaintext (AD-15/AD-12-amended — no TLS on the trusted legs).
 * The singleton initializer is per-CELL parametric through the injected factory bean (the TLS
 * decision is startup-static per cell, never per channel).
 *
 * <p>The decoders stay active for the channel's whole life (AD-2 — {@code SmppFrameDecoder} frames both
 * pre- and post-couple; {@code SmppCodec} is dormant post-couple, never removed: no live pipeline
 * surgery). Options (allocator / {@code AUTO_READ=false} / watermark) are NOT set here — they are
 * acceptor child options owned by {@link RelayChannelOptions}.
 */
@Component
@RequiredArgsConstructor
public final class RelayIngressInitializer extends ChannelInitializer<Channel> {

    private final BindCredentialVerifier verifier;
    private final RelayStateManager manager;
    private final RelayObserver observer;
    private final ProxyCompanionProperties properties;
    private final RelayEgressInitializer egressInitializer;
    private final RelayChannelOptions channelOptions;
    private final RoutingTable routingTable;
    private final SmppLegTlsFactory tlsFactory;

    @Override
    protected void initChannel(Channel channel) {
        if (tlsFactory.listenerTls()) {
            // Story 3.3 ([B]): the reverse's internet-leg TLS listener — the handler terminates the
            // handshake BEFORE any SMPP byte is framed (the spine's SslHandler-first pipeline order;
            // REQUIRE in Mode C refuses the cert-less peer at the TLS layer, below the codec).
            channel.pipeline().addFirst(tlsFactory.newIngressSslHandler(channel.alloc()));
        }
        channel.pipeline()
                .addLast(new SmppFrameDecoder()) // per-channel instance (CODEC-014)
                .addLast(new SmppCodec())
                // T7 (landed): bind-family verifier gating + AD-33 collapse + the AD-14 forward
                // (AD-7/AD-25/AD-27/AD-33). Per-channel instance; the in-flight adjudication
                // handles live on the ConnectionEntry via RelayStateManager (Story 3.4 T6).
                // Story 3.3: role-split — the FORWARD arm routes per system_id (AD-29) and dials TLS.
                .addLast(new BindInterceptor(
                        verifier, manager, observer, properties, egressInitializer, channelOptions,
                        routingTable, tlsFactory))
                // T8 (landed) / Story 3.4 T5 (split) + T6: the ingress relay leg (the couple itself
                // fires on the egress leg's RelayEgressHandler, which rides this channel's event
                // loop, AD-2) + the AD-32 pre-couple bare-close through the state manager + the
                // post-couple opaque relay.
                .addLast(new RelayIngressHandler(manager, observer));
    }
}
