package smpp.companion.proxy.security;

import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AC1 / AD-12: {@link BindCredential} composes the typed identity ({@link SystemId}) + the typed secret
 * ({@link Password}) — both immutable records (see {@link SystemIdTest} / {@link PasswordTest}). This test pins the
 * composition: the two component types, the {@code toString} redaction (the record's own self-contained
 * secret-hygiene guard — the primary secrecy boundary is {@link Password#toString()}, tested in {@link PasswordTest}),
 * and the null guards. RED-on-neuter (AC9): change a component type, drop the {@code toString} override, or remove a
 * null guard and a test below goes RED.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AD-12 BindCredential — composes SystemId + Password, no String leak")
class BindCredentialTest {

    private static BindCredential credential(AsciiString password) {
        return new BindCredential(new SystemId(new AsciiString("smsc-user")), new Password(password));
    }

    @Test
    @DisplayName("toString never renders the password (self-contained redaction; primary guard is Password.toString)")
    void toStringDoesNotLeakPassword() {
        // A digit password makes any leak byte-visible. If the override were removed, the record's auto-toString
        // would render `password=Password[***]` (Password redacts, so no digits) — but the explicit `password=***`
        // marker would be gone, so the contains(...) assertion fails (RED-on-neuter on the override's presence).
        AsciiString password = new AsciiString("57013579");
        BindCredential cred = credential(password);
        String rendered = cred.toString();
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            assertThat(rendered)
                    .as("toString must not render any password char (no String leak at the port boundary)")
                    .doesNotContain(String.valueOf(c));
        }
        assertThat(rendered).contains("password=***"); // explicit redaction marker — bites if the override is removed
    }

    @Test
    @DisplayName("password is the typed Password (not a raw char[]/String/AsciiString) on the record component")
    void passwordComponentIsPasswordType() {
        var components = BindCredential.class.getRecordComponents();
        var password = java.util.Arrays.stream(components)
                .filter(c -> c.getName().equals("password"))
                .findFirst().orElseThrow();
        assertThat(password.getType()).isEqualTo(Password.class);
    }

    @Test
    @DisplayName("rejects null password (AD-35 @NullMarked fail-fast)")
    void rejectsNullPassword() {
        assertThatThrownBy(() -> new BindCredential(new SystemId(new AsciiString("u")), null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("password");
    }

    @Test
    @DisplayName("rejects null systemId (AD-35 @NullMarked fail-fast)")
    void rejectsNullSystemId() {
        assertThatThrownBy(() -> new BindCredential(null, new Password(new AsciiString("pw"))))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("systemId");
    }
}
