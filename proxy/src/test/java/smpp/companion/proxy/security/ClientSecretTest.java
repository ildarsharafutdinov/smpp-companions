package smpp.companion.proxy.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The typed client-secret value (the {@link Password} pattern for the adapter's OWN secret material,
 * AD-10(3)/AD-18): load trims ASCII whitespace (secret files conventionally end with a newline — a
 * trailing {@code %0A} on the wire form would silently corrupt the credential), zeroize wipes the
 * backing array, and the record never renders the value. The load REFUSALS (missing file / blank
 * file) are pinned at the adapter level — {@code RopcBindCredentialVerifierTest
 * .constructorFailsFastOnBadConfig} drives {@link ClientSecret#load} through the real construction
 * path with the exact bad values bound.
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("ClientSecret — typed, trimmed-on-load, zeroizable client secret (AD-10(3)/AD-18)")
class ClientSecretTest {

    @Test
    @DisplayName("load trims leading/trailing ASCII whitespace (a trailing newline must not reach the wire form)")
    void loadTrimsAsciiWhitespace(@TempDir Path dir) throws Exception {
        Path file = Files.writeString(dir.resolve("secret"), "  smpp-confidential-secret \r\n");
        byte[] value = ClientSecret.load(file, "companion.reverse.mode-b.oidc.client-secret-path").value();
        assertThat(new String(value, StandardCharsets.US_ASCII))
                .as("the trimmed field copy is the secret — whitespace never reaches the form encoding")
                .isEqualTo("smpp-confidential-secret");
    }

    @Test
    @DisplayName("zeroize wipes the backing array (AD-10); idempotent")
    void zeroizeWipesBackingArray() {
        ClientSecret secret = new ClientSecret("s3cret".getBytes(StandardCharsets.US_ASCII));
        secret.zeroize();
        assertThat(secret.value()).as("zeroize must wipe every byte of the backing array")
                .containsOnly(0);
        secret.zeroize();   // idempotent — a second wipe is a no-op, not an exception
    }

    @Test
    @DisplayName("toString never renders the value (the Password toString contract)")
    void toStringNeverRendersTheValue() {
        ClientSecret secret = new ClientSecret("s3cret".getBytes(StandardCharsets.US_ASCII));
        assertThat(secret.toString())
                .as("the record must never render or invite expansion of the secret")
                .isEqualTo("ClientSecret[***]");
    }
}
