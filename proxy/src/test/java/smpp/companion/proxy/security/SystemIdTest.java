package smpp.companion.proxy.security;

import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AC1 / AD-12 / AD-14: {@link SystemId} is the typed SMPP {@code system_id} carried across the port.
 *
 * <p><b>Reinvention guardrail:</b> the codec (Story 1.2) already parses {@code system_id} into a Netty
 * {@link AsciiString}; {@code SystemId} wraps that SAME backing (no C-octet re-parse at the port). The
 * relay seam will be {@code new SystemId(bindRequest.systemId())}. The SMPP 3.4 bound (§3.2 "system_id:
 * max 16 octets"; §3.1 the NUL terminator counts) &rarr; <b>max 15 value octets</b> — enforced here as the
 * typed-boundary fail-fast (the codec does not cap per-field length).
 *
 * <p>{@code SystemId} is the ROPC username / forwarded identity (AD-14) — it is NOT secret, so it needs no
 * defensive copy (unlike {@link BindCredential}'s password). RED-on-neuter (AC9): drop the length guard or
 * the null guard and this test goes RED.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AD-12 SystemId — AsciiString-backed SMPP system_id, ≤15 value octets")
class SystemIdTest {

    @Test
    @DisplayName("wraps the codec's AsciiString system_id verbatim (no re-parse)")
    void wrapsAsciiString() {
        AsciiString raw = new AsciiString("smsc-user-01");
        SystemId id = new SystemId(raw);
        // Same instance — the port wraps the codec's AsciiString without copying or re-parsing (reinvention guardrail).
        assertThat((CharSequence) id.value()).isSameAs(raw);
        // SystemId is NOT secret — toString exposes the identity (it is the forwarded/ROPC username, AD-14).
        assertThat(id.toString()).contains("smsc-user-01");
    }

    @Test
    @DisplayName("accepts an empty system_id (codec readAscii yields EMPTY_STRING) and the 15-octet max")
    void acceptsEmptyAndMaxLength() {
        assertThat((CharSequence) new SystemId(AsciiString.EMPTY_STRING).value()).isEqualTo(AsciiString.EMPTY_STRING);
        AsciiString fifteen = new AsciiString("123456789012345"); // exactly 15 value octets — the SMPP max
        assertThat((CharSequence) new SystemId(fifteen).value()).isEqualTo(fifteen);
    }

    @Test
    @DisplayName("rejects a system_id longer than 15 value octets (SMPP 3.4 §3.2 max-16-incl-NUL)")
    void rejectsOverlongSystemId() {
        AsciiString sixteen = new AsciiString("1234567890123456"); // 16 value octets + NUL = 17 > 16 — malformed
        assertThatThrownBy(() -> new SystemId(sixteen))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("system_id");
    }

    @Test
    @DisplayName("rejects a null system_id (AD-35 @NullMarked fail-fast)")
    void rejectsNull() {
        assertThatThrownBy(() -> new SystemId(null))
                .isInstanceOf(NullPointerException.class);
    }
}
