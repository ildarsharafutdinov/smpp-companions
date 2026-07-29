package smpp.companion.codec.golden;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import smpp.companion.codec.command.SmppCommandIds;
import smpp.companion.codec.framer.SmppFrame;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CODEC-030 golden-vector corpus (AC5). Every vector is hand-authored from the SMPP 3.4 spec on disk
 * ({@code docs/SMPP_v3_4_Issue1_2.pdf}) as a one-line text file whose first line is the provenance
 * header {@code # provenance: <§ref> ; raw-hex: <lowercase hex>}, with an optional
 * {@code ; reject: <CODEC-id reason>} on negative vectors. The {@code raw-hex} IS the wire bytes
 * (one source, diff-detectable); the loader decodes it via {@link HexFormat}. No vector is ever
 * produced by invoking the codec — neither {@code SmppCodec} nor {@code SmppBindEncoder} is referenced
 * here (R14/R33 independence). Positive vectors are asserted length-self-consistent
 * ({@code command_length} == hex byte count, AD-30 bounds, a bind-family {@code command_id}); negative
 * vectors carry their expected reject outcome. The field-by-field jSMPP cross-oracle (CODEC-031/033)
 * lands in T5; this test owns only the corpus's own integrity.
 */
@Tag("unit")
@Tag("codec")
@Tag("p2")
@DisplayName("Golden-vector corpus — CODEC-030 (AC5)")
class GoldenVectorCorpusTest {

    private static final String PROVENANCE_PREFIX = "# provenance:";
    private static final String RAW_HEX_MARKER = " ; raw-hex: ";
    private static final String REJECT_MARKER = " ; reject: ";
    private static final List<String> VECTOR_EXTENSIONS = List.of(".bin", ".smpp");
    private static final HexFormat HEX = HexFormat.of();

    @Test
    @DisplayName("CODEC-030: corpus is non-empty (AC5)")
    void corpusIsNonEmpty() {
        assertThat(listVectors())
                .as("AC5: the corpus must contain hand-authored bind-family + negative vectors")
                .isNotEmpty();
    }

    @Test
    @DisplayName("CODEC-030: every vector carries a well-formed provenance header with parseable lowercase raw-hex")
    void everyVectorCarriesAValidProvenanceHeader() throws Exception {
        List<Path> vectors = listVectors();
        assertThat(vectors).as("guarded by corpusIsNonEmpty").isNotEmpty();
        for (Path vector : vectors) {
            List<String> lines = Files.readAllLines(vector);
            assertThat(lines)
                    .as("golden vector %s must have a first line", vector)
                    .isNotEmpty();
            String header = lines.get(0);
            assertThat(header)
                    .as("golden vector %s must start with a provenance header", vector)
                    .startsWith(PROVENANCE_PREFIX);
            assertThat(header)
                    .as("golden vector %s must carry a raw-hex marker", vector)
                    .contains(RAW_HEX_MARKER);

            boolean negative = header.contains(REJECT_MARKER);
            if (negative) {
                String reject = header.substring(header.indexOf(REJECT_MARKER) + REJECT_MARKER.length()).trim();
                assertThat(reject)
                        .as("negative vector %s must tag its expected reject outcome", vector)
                        .isNotEmpty()
                        .startsWith("CODEC-");
            }

            int hexStart = header.indexOf(RAW_HEX_MARKER) + RAW_HEX_MARKER.length();
            int hexEnd = negative ? header.indexOf(REJECT_MARKER) : header.length();
            String hex = header.substring(hexStart, hexEnd).trim();
            assertThat(hex)
                    .as("raw-hex on %s must be non-empty", vector)
                    .isNotEmpty();
            assertThat(hex)
                    .as("raw-hex on %s must be lowercase (diff-stable)", vector)
                    .matches("[0-9a-f]*");
            assertThat(hex.length() % 2)
                    .as("raw-hex on %s must be whole octets", vector)
                    .isZero();

            byte[] bytes = HEX.parseHex(hex);
            if (!negative) {
                assertWellFormedBindPdu(vector, bytes);
            }
        }
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
    private static void assertWellFormedBindPdu(Path vector, byte[] bytes) {
        long declaredLength = unpackUnsigned(bytes, 0);
        assertThat(declaredLength)
                .as("positive vector %s: command_length (%d) must equal the hex byte count (%d)",
                        vector, declaredLength, bytes.length)
                .isEqualTo((long) bytes.length);
        assertThat(declaredLength)
                .as("positive vector %s: AD-30 bounds [%d, %d]",
                        vector, SmppFrame.MIN_COMMAND_LENGTH, SmppFrame.MAX_COMMAND_LENGTH)
                .isBetween((long) SmppFrame.MIN_COMMAND_LENGTH, (long) SmppFrame.MAX_COMMAND_LENGTH);
        int commandId = (int) unpackUnsigned(bytes, 4);
        assertThat(SmppCommandIds.isBindFamily(commandId))
                .as("positive vector %s: command_id 0x%08X must be a bind-family id (AD-27)", vector, commandId)
                .isTrue();
    }

    /** Reads 4 big-endian octets at {@code offset} as unsigned (SMPP header fields are unsigned BE). */
    private static long unpackUnsigned(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFFL) << 24
                | (bytes[offset + 1] & 0xFFL) << 16
                | (bytes[offset + 2] & 0xFFL) << 8
                | (bytes[offset + 3] & 0xFFL);
    }

    private List<Path> listVectors() {
        URL dir = getClass().getClassLoader().getResource("golden-vectors");
        if (dir == null) {
            return List.of(); // empty corpus — no packaged resource entry yet
        }
        try (Stream<Path> s = Files.walk(Paths.get(dir.toURI()), 1)) {
            return s.filter(Files::isRegularFile)
                    .filter(p -> VECTOR_EXTENSIONS.stream().anyMatch(ext ->
                            p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(ext)))
                    .sorted()
                    .toList();
        } catch (Exception e) {
            throw new IllegalStateException("failed to enumerate golden-vector corpus", e);
        }
    }
}
