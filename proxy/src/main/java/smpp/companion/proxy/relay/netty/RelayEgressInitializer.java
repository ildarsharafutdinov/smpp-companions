package smpp.companion.proxy.relay.netty;

import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.handler.ssl.SslHandler;

import smpp.companion.codec.bind.SmppCodec;
import smpp.companion.codec.framer.SmppFrameDecoder;
import smpp.companion.proxy.observability.RelayObserver;
import smpp.companion.proxy.relay.ConnectionRegistry;
import smpp.companion.proxy.relay.RelayEgressHandler;

/**
 * The egress (SMSC- or reverse-facing) pipeline (AC4; AD-2/AD-3): one {@link SmppFrameDecoder}
 * then one {@link SmppCodec} then the egress {@link RelayEgressHandler} per egress channel — the SAME
 * codec prefix as the ingress leg ({@link RelayIngressInitializer}), because both legs of a coupled
 * pair are one framed-PDU data plane: the framer must delimit PDUs arriving FROM the peer (its
 * {@code bind_*_resp} and every post-couple PDU) exactly as on the ingress leg. Per-channel
 * INSTANCES (CODEC-014), created fresh in {@code initChannel}; the {@link RelayEgressHandler} is
 * per-channel BY DESIGN — its {@code CoupledRelayHandler} base carries the leg's {@code Direction}
 * and its exactly-once close marker.
 *
 * <p><b>Attachment point (owner decision 2026-08-15 — codec-only prefix in T6; T8 landed the
 * entry).</b> The full egress pipeline per AC4 is
 * {@code SslHandler? → SmppFrameDecoder → SmppCodec → RelayEgressHandler}: the T8 relay entry (the
 * AD-25 single couple unit + opaque relay toward the ingress leg) sits after {@code SmppCodec}. The
 * per-bind egress {@code Bootstrap} (HexDumpProxy-style, grouped on the ingress channel's event
 * loop, options from {@link RelayChannelOptions}) installs this initializer, and its connect
 * assembly appends the {@code BindInterceptor.EgressLeg} bind-family forwarder AFTER the
 * {@link RelayEgressHandler} (the couple unit propagates bind-family PDUs so the forwarder still sees them).
 *
 * <p><b>Story 3.3 ([B] topology): the optional per-dial TLS seam.</b> The shared singleton (the
 * two-arg constructor — the REVERSE cells' plaintext SMSC dial, byte-identical to Story 2.2)
 * installs no {@link SslHandler}; the FORWARD cells' per-session internet-leg dial constructs a
 * per-bind initializer (the three-arg constructor) whose {@link TargetTls} seam prepends the
 * per-target client handler — FIRST in the pipeline, so the TLS handshake completes before the
 * framer sees any byte, and the ORIGINAL bind (AD-14) rides the TLS record layer untouched.
 */
@Component
public final class RelayEgressInitializer extends ChannelInitializer<Channel> {

    private final ConnectionRegistry registry;
    private final RelayObserver observer;
    private final @Nullable TargetTls targetTls;

    /**
     * The production singleton (the reverse cells' plaintext SMSC leg). {@code @Autowired} marks it
     * as Spring's choice among the two constructors (the three-arg one is a per-bind test/dial
     * constructor, never a bean).
     */
    @Autowired
    public RelayEgressInitializer(ConnectionRegistry registry, RelayObserver observer) {
        this(registry, observer, null);
    }

    /**
     * The per-dial TLS-carrying variant (the forward arm): {@link #initChannel} prepends the seam's
     * handler before the codec prefix. A {@code null} seam means the PLAINTEXT egress pipeline —
     * the same contract the {@code @Autowired} singleton carries (the reverse cells' SMSC dial);
     * the forward arm under [B] A/C always passes a live seam (it dials TLS per session).
     *
     * @param targetTls creates the per-connection client {@link SslHandler} (once per dial; the
     *        engine is per-connection state); {@code null} = no TLS on this egress leg.
     */
    public RelayEgressInitializer(ConnectionRegistry registry, RelayObserver observer, @Nullable TargetTls targetTls) {
        this.registry = registry;
        this.observer = observer;
        this.targetTls = targetTls;
    }

    /** The per-dial TLS seam: one {@link SslHandler} per egress channel (the engine is per-connection). */
    public interface TargetTls {

        /**
         * Creates the per-connection client handler (the engine is per-connection state — never shared).
         *
         * @param channel the freshly-connected egress channel (its allocator feeds the engine); non-null.
         * @return the client handler to prepend; the implementation must return a FRESH handler.
         */
        SslHandler newHandler(Channel channel);
    }

    @Override
    protected void initChannel(Channel channel) {
        TargetTls tls = targetTls;
        if (tls != null) {
            channel.pipeline().addFirst(tls.newHandler(channel));
        }
        channel.pipeline()
                .addLast(new SmppFrameDecoder()) // per-channel instance (CODEC-014)
                .addLast(new SmppCodec())
                // T8 (landed) / Story 3.4 T5 (split): the AD-25 single couple unit + AD-32 bare-close
                // + opaque relay. The couple itself runs HERE — the bind_resp arrives from the peer on
                // this leg, which rides the ingress channel's event loop (AD-2 same-loop coupling).
                .addLast(new RelayEgressHandler(registry, observer));
    }
}
