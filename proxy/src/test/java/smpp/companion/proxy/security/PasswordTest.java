package smpp.companion.proxy.security;

import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AC1 / AD-12: {@link Password} is the typed SMPP {@code password} — the ROPC secret — carried across the port.
 *
 * <p><b>Reinvention guardrail:</b> the codec (Story 1.2) already parses the password into a Netty
 * {@link AsciiString} (CODEC-024/PRIV-1 — the user-directed 2026-07-28 override for full type-uniformity across
 * every C-octet field); {@link Password} wraps that SAME backing (no C-octet re-parse, no copy at the port). The
 * relay seam will be {@code new Password(bindRequest.password())}. The SMPP 3.4 bound (§3.2 "password: max 9
 * octets"; §3.1 the NUL terminator counts; the codec strips it) &rarr; <b>max 8 value octets</b> — enforced here as
 * the typed-boundary fail-fast (the codec does not cap per-field length).
 *
 * <p>Unlike {@link SystemId} (the non-secret identity, AD-14), {@link Password} IS secret: it redacts its
 * {@code toString()} (the {@link AsciiString#toString()}-cache hazard, CODEC-024 P2 / AI-5) and its zeroization is
 * the holder's responsibility (AC5). RED-on-neuter (AC9): drop the length guard, the null guard, or the
 * {@code toString} redaction and a test below goes RED.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AD-12 Password — AsciiString-backed SMPP password, ≤8 value octets, secret")
class PasswordTest {

    @Test
    @DisplayName("wraps the codec's AsciiString password verbatim (no copy / no re-parse)")
    void wrapsAsciiString() {
        AsciiString raw = new AsciiString("s3cret");
        Password password = new Password(raw);
        // Same instance — the port wraps the codec's AsciiString without copying. Sharing the backing array is
        // load-bearing: the holder's single wipe covers this record's own copy (zeroization coverage).
        assertThat((CharSequence) password.value()).isSameAs(raw);
    }

    @Test
    @DisplayName("accepts an empty password (codec readAscii yields EMPTY_STRING) and the 8-octet max")
    void acceptsEmptyAndMaxLength() {
        assertThat((CharSequence) new Password(AsciiString.EMPTY_STRING).value()).isEqualTo(AsciiString.EMPTY_STRING);
        AsciiString eight = new AsciiString("12345678"); // exactly 8 value octets — the SMPP max
        assertThat((CharSequence) new Password(eight).value()).isEqualTo(eight);
    }

    @Test
    @DisplayName("rejects a password longer than 8 value octets (SMPP 3.4 §3.2 max-9-incl-NUL)")
    void rejectsOverlongPassword() {
        AsciiString nine = new AsciiString("123456789"); // 9 value octets + NUL = 10 > 9 — malformed
        assertThatThrownBy(() -> new Password(nine))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("password");
    }

    @Test
    @DisplayName("toString never renders the password (redacting override; AsciiString.toString() would cache+leak)")
    void toStringDoesNotLeakPassword() {
        // Digits are absent from the redacted form's vocabulary ("Password[***]"), so a digit password makes any
        // leak byte-visible: if the toString override were removed, the record's auto-toString would call
        // AsciiString.toString() (rendering the cleartext AND caching an immortal String the wipe cannot reach) and
        // this would fail (RED-on-neuter).
        AsciiString raw = new AsciiString("57013579");
        Password password = new Password(raw);
        String rendered = password.toString();
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            assertThat(rendered)
                    .as("toString must not render any password char (no String leak/cache)")
                    .doesNotContain(String.valueOf(c));
        }
        assertThat(rendered).contains("Password[***]");
        // AC5 hygiene discipline — wipe the backing array; safe because toString() was our redacting override.
        Arrays.fill(raw.array(), raw.arrayOffset(), raw.arrayOffset() + raw.length(), (byte) 0);
        raw.arrayChanged();
    }

    @Test
    @DisplayName("a single backing-array wipe covers the Password's own value (zeroization coverage)")
    void zeroizingBackingArrayWipesPasswordValue() {
        AsciiString raw = new AsciiString("s3cret");
        Password password = new Password(raw);
        AsciiString held = password.value();
        // The zeroization recipe the adapter runs (AC5 / AD-12):
        Arrays.fill(held.array(), held.arrayOffset(), held.arrayOffset() + held.length(), (byte) 0);
        held.arrayChanged();
        // Because Password shares the backing array (no copy), the Password's own value is now all-zero — the
        // internal-copy gap a char[]-clone-on-read design could not close.
        AsciiString after = password.value();
        byte[] arr = after.array();
        int off = after.arrayOffset();
        for (int i = 0; i < after.length(); i++) {
            assertThat(arr[off + i])
                    .as("Password's own value must be wiped by the holder's single wipe")
                    .isZero();
        }
    }

    @Test
    @DisplayName("rejects a null password (AD-35 @NullMarked fail-fast)")
    void rejectsNull() {
        assertThatThrownBy(() -> new Password(null))
                .isInstanceOf(NullPointerException.class);
    }
}
