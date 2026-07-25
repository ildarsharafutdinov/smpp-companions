package smpp.companion.proxy.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Bound from {@code companion.*}. Carries the documented key shapes (AD-17 seed) and the AD-34 TLS
 * protocol/cipher defaults. The exhaustive role&times;mode fail-fast matrix is Story 1.3; this story
 * ships the single {@code companion.role} refuse-to-start smoke (AC9): an absent role is rejected by
 * Spring bean validation ({@code @NotNull} on {@code role}, fired because the record is
 * {@code @Validated}); an out-of-set value fails enum conversion at bind time. Both surface as a
 * non-zero startup exit.
 */
@ConfigurationProperties("companion")
@Validated
public record ProxyCompanionProperties(
        @NotNull(message = "companion.role is required and must be one of [forward, reverse] — refusing to start (AD-17).")
        Role role,
        @Valid Tls tls) {

    /** Direction of the SMPP mapping. Absent or non-matching => the app refuses to start. */
    public enum Role { FORWARD, REVERSE }

    /** AD-34 pinned TLS defaults. Per-context intersection fail-fast is Story 1.3. */
    public record Tls(
        List<String> protocols,          // companion.tls.protocols
        List<String> tls12CipherSuites,  // companion.tls.tls12-cipher-suites (relaxed binding)
        List<String> tls13CipherSuites   // companion.tls.tls13-cipher-suites
    ) {
    }
}
