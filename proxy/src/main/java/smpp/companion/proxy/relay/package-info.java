/**
 * Stateless SMPP transit relay — the inward consumer of the codec. Drives Netty directly (AD-16);
 * no WebFlux/Reactor. Body deferred to Epic 2.
 */
package smpp.companion.proxy.relay;
