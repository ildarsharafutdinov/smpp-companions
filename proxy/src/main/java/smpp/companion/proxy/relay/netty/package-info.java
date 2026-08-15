/**
 * Netty bootstrap infrastructure for the stateless relay: the ONE shared pooled
 * {@link io.netty.buffer.PooledByteBufAllocator} (AD-21) and the AD-30 live direct-memory startup
 * self-check. The {@code ServerBootstrap}/{@code Bootstrap} acceptor + pipelines (AD-1/AD-2/AD-16)
 * join this package in T6. Distinct sub-package of {@link smpp.companion.proxy.relay} so it carries
 * its own {@code @NullMarked} (AD-35 &mdash; nullness does not propagate to sub-packages).
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.proxy.relay.netty;

import org.jspecify.annotations.NullMarked;
