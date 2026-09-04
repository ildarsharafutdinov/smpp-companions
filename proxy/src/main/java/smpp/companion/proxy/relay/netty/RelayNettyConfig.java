package smpp.companion.proxy.relay.netty;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.util.concurrent.DefaultThreadFactory;

/**
 * Netty bootstrap beans for the stateless relay (AD-1/AD-2/AD-16). T5 mounts the allocator + the AD-30
 * self-check; T6 adds the {@code ServerBootstrap}/{@code Bootstrap} acceptor, the shared event loop,
 * and the ingress/egress pipelines wired to the beans defined here.
 *
 * <p>Spring-managed (not hand-built) so the lifecycle bean (T6) and the relay handlers (T7/T8) inject
 * these via DI, matching the {@code @Component}/{@code SmartLifecycle} conventions of
 * {@code AlwaysAllowBindCredentialVerifier} / {@code ProxyCompanionLifecycle}.
 */
@Configuration
public class RelayNettyConfig {

    /**
     * AD-21 &mdash; the ONE shared pooled allocator. Returning {@link PooledByteBufAllocator#DEFAULT}
     * makes the Spring-managed bean the canonical Netty singleton, so every channel (ingress + egress)
     * T6 wires via {@code ChannelOption.ALLOCATOR} draws pooled direct memory from a single arena set,
     * never a per-channel allocator. Pooled by construction, so this bean is the authoritative pooling
     * guarantee for the relay data plane &mdash; the {@code io.netty.allocator.type=pooled} system
     * property (read by Netty once at static init to pick {@code ByteBufAllocator.DEFAULT}) is redundant
     * for channels wired to this bean and is not set programmatically; setting it reliably would require
     * a JVM arg before any Netty class loads, which is a deploy concern (Epic 5), not a code concern.
     *
     * @return the shared {@link PooledByteBufAllocator#DEFAULT}
     *
     * <p>{@code destroyMethod = ""} because the bean IS the JVM-global {@code PooledByteBufAllocator.DEFAULT}
     * singleton — Spring must never destroy it. Netty 4.2 exposes no {@code close()}/{@code shutdown()}
     * today (so nothing is inferred), but pinning the intent guards a future Netty bump that could add one
     * and corrupt the shared singleton at context shutdown.
     */
    @Bean(destroyMethod = "")
    public PooledByteBufAllocator pooledByteBufAllocator() {
        return PooledByteBufAllocator.DEFAULT;
    }

    /**
     * AD-1/AD-2 &mdash; the ONE shared event loop group for both relay legs (the HexDumpProxy
     * pattern): the acceptor's boss/worker loops, and &mdash; from T7 &mdash; every per-bind egress
     * connection, which registers on its ingress channel's event loop so both legs of a coupled pair
     * run on one thread. Platform threads BY CONSTRUCTION ({@link DefaultThreadFactory} never creates
     * virtual threads) &mdash; virtual threads never carry the data-plane relay (AD-1); the
     * {@code companion-relay-...} name makes the relay's loops identifiable in thread dumps (and lets
     * the AD-1 platform-thread pin observe them). Size 0 = Netty's default (2 &times; cores).
     *
     * <p>The loop quiesce is NOT the acceptor's stop (Story 4.2 T2 &mdash;
     * {@link RelayServerLifecycle#stop()} closes the acceptor only; the loop must stay live across
     * the deny phase so the fail-closed continuations execute): the AD-22 shutdown coordinator at the
     * app phase ({@code ProxyCompanionLifecycle}, Story 4.2 T3) owns the quiesce &mdash; awaited,
     * explicit short quiet period. {@code destroyMethod = "shutdownGracefully"} is the backstop that
     * still guarantees the loop dies at full-app close (never-started cells never reach the
     * coordinator; a re-fire after the coordinator's quiesce is a no-op &mdash; both paths
     * idempotent). Not {@code destroyMethod = ""} as on the allocator &mdash; this bean OWNS its
     * group (created here, not a JVM-global singleton).
     *
     * <p>{@link MultiThreadIoEventLoopGroup} + {@link NioIoHandler#newFactory()} (NOT the deprecated
     * {@code NioEventLoopGroup}) is Netty 4.2's NIO idiom &mdash; the 4.2 IoHandle refactor deprecated
     * the old group class; the {@code NioServerSocketChannel} it serves is unchanged.
     */
    @Bean(destroyMethod = "shutdownGracefully")
    public EventLoopGroup relayEventLoopGroup() {
        return new MultiThreadIoEventLoopGroup(0, new DefaultThreadFactory("companion-relay"),
                NioIoHandler.newFactory());
    }
}
