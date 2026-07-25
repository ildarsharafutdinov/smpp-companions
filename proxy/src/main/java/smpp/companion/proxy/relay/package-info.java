/**
 * Stateless SMPP transit relay — the inward consumer of the codec. Drives Netty directly (AD-16);
 * no WebFlux/Reactor. Body deferred to Epic 2.
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.proxy.relay;

import org.jspecify.annotations.NullMarked;
