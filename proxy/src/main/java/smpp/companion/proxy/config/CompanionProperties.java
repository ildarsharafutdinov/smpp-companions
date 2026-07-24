package smpp.companion.proxy.config;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Bound from {@code companion.*}. Carries the documented key shapes (AD-17 seed) and the AD-34 TLS
 * protocol/cipher defaults. The exhaustive role&times;mode fail-fast matrix is Story 1.3; this story
 * ships the single {@code companion.role} refuse-to-start smoke (AC9): an absent role fails relaxed
 * binding via the compact-constructor guard below (invalid values fail enum conversion even earlier).
 */
@ConfigurationProperties("companion")
public record CompanionProperties(Role role, Tls tls) {

    /** Direction of the SMPP mapping. Absent or non-matching => the app refuses to start. */
    public enum Role { FORWARD, REVERSE }

    /**
     * Fail-fast guard (AC9 / AD-17): a missing {@code companion.role} leaves {@code role == null},
     * which fails the build of the context here. (An out-of-set string like {@code sideways} fails
     * enum conversion before this constructor ever runs — also non-zero exit.)
     */
    public CompanionProperties {
        if (role == null) {
            throw new IllegalArgumentException(
                "companion.role is required and must be one of [forward, reverse] — refusing to start (AD-17).");
        }
    }

    /** AD-34 pinned TLS defaults. Per-context intersection fail-fast is Story 1.3. */
    public record Tls(
        List<String> protocols,          // companion.tls.protocols
        List<String> tls12CipherSuites,  // companion.tls.tls12-cipher-suites (relaxed binding)
        List<String> tls13CipherSuites   // companion.tls.tls13-cipher-suites
    ) {
    }
}
