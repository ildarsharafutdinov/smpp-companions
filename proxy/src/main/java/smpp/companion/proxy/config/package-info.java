/**
 * {@code companion.*} configuration properties and fail-fast startup validation (AD-17). The
 * role&times;mode cell is encoded structurally in the property path
 * ({@code companion.<role>.<mode>.*}); exactly one branch must be populated at startup or the app
 * refuses to start. Each branch record declares only the fields its cell needs, so nullability
 * corresponds directly to optionality. SEC-050..061/096/097 + the SEC-052 Mode B posture are enforced
 * here (SEC-051 forward&times;B is structural &mdash; no forward.mode-b node exists).
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.proxy.config;

import org.jspecify.annotations.NullMarked;
