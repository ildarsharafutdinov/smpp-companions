package smpp.companion.proxy.relay.netty;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.netty.buffer.PooledByteBufAllocator;

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
}
