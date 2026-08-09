package smpp.companion.proxy.security;

import io.netty.util.AsciiString;

import java.util.Objects;

/**
 * The SMPP {@code system_id} as a typed value (AD-12 / AD-14). <b>Not secret</b> — it is the ROPC username
 * and the identity forwarded end-to-end to the SMSC (no pooling / mapping / surrogate identity, AD-14).
 *
 * <p><b>Reinvention guardrail:</b> the codec (Story 1.2) already parses {@code system_id} into a Netty
 * {@link AsciiString}; this type wraps that SAME backing (no C-octet re-parse at the port). The relay seam is
 * {@code new SystemId(bindRequest.systemId())}. Enforces the SMPP 3.4 length bound: §3.2 caps
 * {@code system_id} at 16 octets and §3.1 counts the NUL terminator, so the value carries at most
 * {@value #MAX_LENGTH} value octets (the codec does not cap per-field length; this is the typed-boundary
 * fail-fast).
 *
 * @param value the {@code system_id} bytes EXCLUDING the wire NUL terminator the codec already stripped;
 *              non-null, &le; {@value #MAX_LENGTH} octets.
 */
public record SystemId(AsciiString value) {

    /** SMPP 3.4 §3.2 {@code system_id}: max 16 octets incl. the NUL terminator &rarr; 15 value octets. */
    public static final int MAX_LENGTH = 15;

    public SystemId {
        Objects.requireNonNull(value, "value");
        if (value.length() > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "system_id is " + value.length() + " octets; exceeds the SMPP 3.4 max of " + MAX_LENGTH
                            + " value octets (16 incl. NUL terminator)");
        }
    }
}
