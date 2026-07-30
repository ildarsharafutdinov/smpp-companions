package smpp.companion.codec.golden;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrame;

import java.net.URL;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CODEC-030 golden-vector corpus integrity (AC5). Owns ONLY the corpus's own integrity: it is non-empty,
 * every positive is a length-self-consistent bind-family PDU, and every negative tags a {@code CODEC-}
 * reject. The wire bytes are hand-authored from the SMPP 3.4 spec on disk ({@code docs/SMPP_v3_4_Issue1_2.pdf})
 * and loaded via {@link GoldenVectors} — no vector is ever produced by invoking the codec, so this stays an
 * oracle independent of the codec AND of jSMPP (R14/R33). The membership check uses the codec's
 * source-of-truth {@link SmppCommandIds#isBindFamily(int)} — checking membership is NOT invoking the codec
 * (no decode/encode runs). The field-by-field jSMMP cross-oracle (CODEC-031) and the negative biting-oracle
 * (CODEC-033) live in {@link BindConformanceTest}.
 */
@Tag("unit")
@Tag("codec")
@Tag("p2")
@DisplayName("Golden-vector corpus — CODEC-030 (AC5)")
class GoldenVectorCorpusTest {

    @Test
    @DisplayName("CODEC-030: corpus is non-empty (AC5)")
    void corpusIsNonEmpty() {
        assertThat(GoldenVectors.load())
                .as("AC5: the corpus must contain hand-authored bind-family + negative vectors")
                .isNotEmpty();
    }

    @Test
    @DisplayName("CODEC-030: every positive is a length-self-consistent bind-family PDU; every negative tags a CODEC- reject")
    void everyVectorMeetsCorpusInvariants() {
        List<GoldenVectors.Vector> vectors = GoldenVectors.load();
        assertThat(vectors).as("guarded by corpusIsNonEmpty").isNotEmpty();
        int positives = 0;
        int negatives = 0;
        for (GoldenVectors.Vector v : vectors) {
            if (v.negative()) {
                negatives++;
                assertThat(v.rejectTag())
                        .as("negative vector %s must tag its expected reject outcome", v.name())
                        .startsWith("CODEC-");
            } else {
                positives++;
                assertWellFormedBindPdu(v);
            }
        }
        assertThat(positives).as("corpus carries positive bind-family vectors").isGreaterThan(0);
        assertThat(negatives).as("corpus carries negative vectors").isGreaterThan(0);
    }

    @Test
    @DisplayName("CODEC-030: provenance-convention README is packaged as a resource (AC10 scaffold)")
    void provenanceConventionReadmeIsPackaged() {
        URL convention = getClass().getClassLoader().getResource("golden-vectors/README.md");
        assertThat(convention)
                .as("AC10: golden-vectors provenance-convention README must be packaged as a resource")
                .isNotNull();
    }

    /**
     * A positive vector must be a length-self-consistent bind-family PDU — authored from the spec, then
     * checked here against the codec's own source of truth (AD-27 {@code BIND_FAMILY}, AD-30 bounds).
     * Checking membership is not "invoking the codec": no decode/encode runs.
     */
    private static void assertWellFormedBindPdu(GoldenVectors.Vector v) {
        byte[] bytes = v.bytes();
        long declaredLength = unpackUnsigned(bytes, 0);
        assertThat(declaredLength)
                .as("positive vector %s: command_length (%d) must equal the hex byte count (%d)",
                        v.name(), declaredLength, bytes.length)
                .isEqualTo((long) bytes.length);
        assertThat(declaredLength)
                .as("positive vector %s: AD-30 bounds [%d, %d]",
                        v.name(), SmppFrame.MIN_COMMAND_LENGTH, SmppFrame.MAX_COMMAND_LENGTH)
                .isBetween((long) SmppFrame.MIN_COMMAND_LENGTH, (long) SmppFrame.MAX_COMMAND_LENGTH);
        int commandId = (int) unpackUnsigned(bytes, 4);
        assertThat(SmppCommandIds.isBindFamily(commandId))
                .as("positive vector %s: command_id 0x%08X must be a bind-family id (AD-27)", v.name(), commandId)
                .isTrue();
    }

    /** Reads 4 big-endian octets at {@code offset} as unsigned (SMPP header fields are unsigned BE). */
    private static long unpackUnsigned(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFFL) << 24
                | (bytes[offset + 1] & 0xFFL) << 16
                | (bytes[offset + 2] & 0xFFL) << 8
                | (bytes[offset + 3] & 0xFFL);
    }
}
