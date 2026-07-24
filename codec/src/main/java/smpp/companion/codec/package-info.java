/**
 * SMPP 3.4 codec — the PURE protocol layer.
 *
 * <p>This module is structurally PURE: it may depend only on {@code io.netty:*} and the JDK
 * standard library. It must NOT depend on {@code smpp.companion.proxy..}, Spring, Nimbus, or
 * Micrometer (AD-7, AD-27). The boundary is enforced mechanically from day one — before codec
 * code exists — by CODEC-039 (ArchUnit inward-only rule) and CODEC-040/041 (dep-allowlist +
 * positive control), so the inward-only seam can never silently drift.
 */
package smpp.companion.codec;
