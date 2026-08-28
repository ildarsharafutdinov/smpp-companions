package smpp.companion.proxy.relay.netty;

import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.ChannelOption;
import io.netty.channel.WriteBufferWaterMark;

import smpp.companion.codec.framer.SmppFrame;
import smpp.companion.proxy.testsupport.RelayTestFixtures;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC4/AD-30 &mdash; the shared per-channel option substrate both relay legs carry. The watermark math
 * is the AD-30 per-channel inbound bound made real in bytes: low = ONE max frame (the explicit
 * low-water re-arm threshold), high = {@code max-inbound-depth} max frames &mdash; the SAME depth the
 * direct-memory budget multiplies by, so the per-channel bound and the JVM budget cannot drift.
 * Every assertion reads the options back off the REAL bootstrap config maps ({@code childOptions()} /
 * {@code options()}), so each is a direct pin: dropping a {@code childOption}/{@code option} line
 * removes the key from the map and goes RED (the T6 RED-on-neuter set).
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
class RelayChannelOptionsTest {

    @Test
    @DisplayName("ingress options: SO_REUSEADDR acceptor socket + child allocator/AUTO_READ=false/AD-30 watermark")
    void ingressChildOptionsCarryTheSharedSubstrate() {
        ServerBootstrap bootstrap = new ServerBootstrap();
        options(64).applyToIngress(bootstrap);

        // Restart hardening (review T6): the acceptor socket may rebind over its own dead connections'
        // TIME_WAIT/FIN_WAIT remnants — a crash with established binds must not boot-loop on BindException.
        // A LIVE listener on the port still fails the bind (EADDRINUSE): AD-17 fail-fast is preserved.
        assertThat(bootstrap.config().options().get(ChannelOption.SO_REUSEADDR))
                .as("acceptor socket: SO_REUSEADDR (crash-restart rebinding over TIME_WAIT)")
                .isEqualTo(true);

        Map<ChannelOption<?>, Object> childOptions = bootstrap.config().childOptions();
        // AD-21: the ONE shared pooled allocator (the Spring bean IS PooledByteBufAllocator.DEFAULT).
        assertThat(childOptions.get(ChannelOption.ALLOCATOR))
                .as("acceptor child channels draw from the shared pooled allocator (AD-21)")
                .isSameAs(PooledByteBufAllocator.DEFAULT);
        // AD-2: demand-driven reads — never AUTO_READ.
        assertThat(childOptions.get(ChannelOption.AUTO_READ))
                .as("AUTO_READ must be OFF on the ingress leg (AD-2 write-completes-gates-read)")
                .isEqualTo(false);
        // AD-30: explicit low-water re-arm + per-channel inbound ceiling (64 frames high).
        // (WriteBufferWaterMark has no equals — assert the low()/high() accessors.)
        WriteBufferWaterMark ingressMark = (WriteBufferWaterMark)
                childOptions.get(ChannelOption.WRITE_BUFFER_WATER_MARK);
        assertThat(ingressMark)
                .as("watermark: low = one max frame, high = max-inbound-depth max frames (AD-30)")
                .isNotNull();
        assertThat(ingressMark.low()).isEqualTo(SmppFrame.MAX_COMMAND_LENGTH);
        assertThat(ingressMark.high()).isEqualTo(SmppFrame.MAX_COMMAND_LENGTH * 64);
    }

    @Test
    @DisplayName("egress options: the IDENTICAL substrate (both legs are one data plane)")
    void egressBootstrapCarriesTheIdenticalSubstrate() {
        Bootstrap bootstrap = new Bootstrap();
        options(64).applyToEgress(bootstrap);

        Map<ChannelOption<?>, Object> channelOptions = bootstrap.config().options();
        assertThat(channelOptions.get(ChannelOption.ALLOCATOR))
                .as("the egress leg draws from the same shared pooled allocator (AD-21)")
                .isSameAs(PooledByteBufAllocator.DEFAULT);
        assertThat(channelOptions.get(ChannelOption.AUTO_READ))
                .as("AUTO_READ must be OFF on the egress leg too (AD-2)")
                .isEqualTo(false);
        WriteBufferWaterMark egressMark = (WriteBufferWaterMark)
                channelOptions.get(ChannelOption.WRITE_BUFFER_WATER_MARK);
        assertThat(egressMark)
                .as("both legs carry the SAME watermark — one coupled data plane")
                .isNotNull();
        assertThat(egressMark.low()).isEqualTo(SmppFrame.MAX_COMMAND_LENGTH);
        assertThat(egressMark.high()).isEqualTo(SmppFrame.MAX_COMMAND_LENGTH * 64);
        // The one ingress-only option stays absent here: SO_REUSEADDR is acceptor-socket semantics
        // (rebind over TIME_WAIT on a listener) — a connecting client socket has no use for it.
        assertThat(channelOptions.get(ChannelOption.SO_REUSEADDR))
                .as("SO_REUSEADDR never rides the egress client bootstrap")
                .isNull();
    }

    @Test
    @DisplayName("pathological max-inbound-depth clamps the high mark at Integer.MAX_VALUE (no int overflow)")
    void watermarkHighClampsAtIntegerMaxValueOnPathologicalDepth() {
        // depth = Integer.MAX_VALUE: the long product (~1.4e14) must clamp, not wrap — a wrapped
        // negative high mark would either throw in the WriteBufferWaterMark ctor or silently disable
        // the writability trip-wire (mutation: drop the clamp → this goes RED either way).
        Bootstrap bootstrap = new Bootstrap();
        options(Integer.MAX_VALUE).applyToEgress(bootstrap);

        WriteBufferWaterMark clamped = (WriteBufferWaterMark)
                bootstrap.config().options().get(ChannelOption.WRITE_BUFFER_WATER_MARK);
        assertThat(clamped).isNotNull();
        assertThat(clamped.low()).isEqualTo(SmppFrame.MAX_COMMAND_LENGTH);
        assertThat(clamped.high())
                .as("the long product (~1.4e14) clamps at Integer.MAX_VALUE — never a wrapped negative")
                .isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    @DisplayName("depth-1 minimal config yields legal low == high == one frame (the minimal test budget)")
    void depthOneMinimalConfigKeepsLegalEqualMarks() {
        // The minimal AD-30 test budget (1/1/1.0 — TestCompanionConfigs.common()) renders low == high;
        // WriteBufferWaterMark permits equality, so the minimal config must not reject the options.
        Bootstrap bootstrap = new Bootstrap();
        options(1).applyToEgress(bootstrap);

        WriteBufferWaterMark minimal = (WriteBufferWaterMark)
                bootstrap.config().options().get(ChannelOption.WRITE_BUFFER_WATER_MARK);
        assertThat(minimal).isNotNull();
        assertThat(minimal.low()).isEqualTo(SmppFrame.MAX_COMMAND_LENGTH);
        assertThat(minimal.high()).isEqualTo(SmppFrame.MAX_COMMAND_LENGTH);
    }

    /**
     * Builds the options component over the shared minimal mode-b fixture (the bind port is irrelevant
     * to the option maps — 2775 kept from the pre-consolidation copy).
     */
    private static RelayChannelOptions options(int maxInboundDepth) {
        return new RelayChannelOptions(
                RelayTestFixtures.modeBProperties(2775, maxInboundDepth), PooledByteBufAllocator.DEFAULT);
    }
}
