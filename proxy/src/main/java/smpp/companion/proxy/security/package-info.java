/**
 * TLS modes + OIDC/ROPC adjudication. Uses only JDK {@code SSLEngine} + Nimbus (SEC-4, AD-13) — no
 * hand-rolled crypto/TLS/JWT. Body deferred to Epic 3.
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.proxy.security;

import org.jspecify.annotations.NullMarked;
