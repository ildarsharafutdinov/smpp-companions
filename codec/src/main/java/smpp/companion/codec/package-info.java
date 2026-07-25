/**
 * SMPP 3.4 codec — the PURE protocol layer.
 *
 * <p>This module is structurally PURE: it may depend only on {@code io.netty:*} and the JDK
 * standard library. It must NOT depend on {@code smpp.companion.proxy..}, Spring, Nimbus, or
 * Micrometer (AD-7, AD-27). The boundary is enforced mechanically from day one — before codec
 * code exists — by CODEC-039 (ArchUnit inward-only rule) and CODEC-040/041 (dep-allowlist +
 * positive control), so the inward-only seam can never silently drift.
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.codec;

import org.jspecify.annotations.NullMarked;
