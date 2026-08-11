package smpp.companion.codec.bind;

import io.netty.buffer.Unpooled;
import io.netty.util.AsciiString;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import smpp.companion.codec.command.SmppCommandIds;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CODEC-024 P2 / AI-5: {@link SmppBindRequest#toString()} redacts the password. {@link SmppBindRequest} is a record,
 * so without an explicit override its auto-generated {@code toString} renders every component — calling
 * {@link AsciiString#toString()} on the password, which caches an immortal {@code String} the backing-array
 * zeroization wipe cannot reach (a plausible relay debug/error leak path). The override renders {@code password=***}
 * and omits the secret-bearing {@code originalFrame}. Mirrors {@code Password.toString()} /
 * {@code BindCredential.toString()}.
 *
 * <p>RED-on-neuter (AC9): drop the override and the record's auto-toString renders the digit password below, failing
 * {@code toStringRedactsPassword} — digits are absent from the redacted form's vocabulary ({@code ***}), so a leak is
 * byte-visible. The companion source-scan gate lives in {@code proxy} ({@code NoStringFromPasswordTest}).
 */
@Tag("unit")
@Tag("codec")
@Tag("p1")
@DisplayName("SmppBindRequest.toString - password redaction (CODEC-024 P2 / AI-5)")
class SmppBindRequestTest {

    @Test
    @DisplayName("toString redacts the password (golden string; auto-toString would leak it)")
    void toStringRedactsPassword() {
        // Digit-only password drawn from {5,6,7,8} — digits the redacted form NEVER renders (the golden below uses
        // only {0,1,2,3,4,9}: 0x9, sequenceNumber=42, ESME_001, 0x34, addrTon/addrNpi=0), so any leaked password
        // char is byte-visible without colliding with a legit numeric field. (Password[***] carries no digits at all,
        // so PasswordTest can use any; this richer toString renders digits, hence the restricted alphabet.)
        AsciiString secret = new AsciiString("56785678");
        SmppBindRequest req = new SmppBindRequest(
                SmppCommandIds.BIND_TRANSCEIVER, 0x00000000, 42,
                new AsciiString("ESME_001"), secret, new AsciiString("SMPP"),
                SmppCommandIds.INTERFACE_VERSION_3_4, (byte) 0, (byte) 0, new AsciiString(""),
                Unpooled.EMPTY_BUFFER);

        String rendered = req.toString();

        // Golden string pins the exact redacted form (commandId=0x9 is BIND_TRANSCEIVER; interfaceVersion=0x34 is 3.4;
        // originalFrame omitted — secret-bearing buffer; commandStatus omitted — always 0 on a request).
        assertThat(rendered).isEqualTo(
                "SmppBindRequest[commandId=0x9, sequenceNumber=42, systemId=ESME_001, password=***, "
                        + "systemType=SMPP, interfaceVersion=0x34, addrTon=0, addrNpi=0, addressRange=]");
        // No password char survives — RED-on-neuter: the auto-toString would render every digit.
        for (int i = 0; i < secret.length(); i++) {
            assertThat(rendered)
                    .as("toString must not render any password char (no String leak/cache)")
                    .doesNotContain(String.valueOf(secret.charAt(i)));
        }
    }
}
