/**
 * {@code companion.*} configuration properties and fail-fast startup validation (AD-17). Story 1.1
 * ships the skeleton plus the single {@code companion.role} refuse-to-start smoke; the exhaustive
 * role×mode matrix (SEC-050..061/096/097) is Story 1.3.
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.proxy.config;

import org.jspecify.annotations.NullMarked;
