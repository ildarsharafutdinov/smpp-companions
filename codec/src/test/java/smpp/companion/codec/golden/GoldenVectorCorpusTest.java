package smpp.companion.codec.golden;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CODEC-030 corpus scaffold. Establishes and enforces the provenance-header convention for every
 * golden vector present. The corpus is intentionally empty in Story 1.1 (the non-empty assertion
 * is authored in Story 1.2 once the framer / bind parser emit real wire bytes), so today this test
 * passes trivially — the boundary is locked, not claimed filled.
 */
@Tag("unit")
@Tag("codec")
@Tag("p2")
class GoldenVectorCorpusTest {

    private static final String PROVENANCE_HEADER_PREFIX = "# provenance:";
    private static final List<String> VECTOR_EXTENSIONS = List.of(".bin", ".smpp");

    @Test
    void everyPresentVectorCarriesAProvenanceHeader() throws Exception {
        for (Path vector : listVectors()) {
            List<String> lines = Files.readAllLines(vector);
            assertThat(lines)
                    .as("golden vector %s must start with a provenance header", vector)
                    .isNotEmpty()
                    .first()
                    .asString()
                    .startsWith(PROVENANCE_HEADER_PREFIX);
        }
    }

    /**
     * Story 1.1 ships an EMPTY corpus; the non-empty assertion (CODEC-030) lands in Story 1.2.
     */
    @Test
    void corpusScaffoldIsInPlace_nonEmptyAssertionDeferredToStory1_2() {
        // AC10 scaffold evidence: the golden-vectors directory + its provenance-header convention
        // (README.md) are packaged as a test resource. The non-empty + per-vector provenance content
        // assertion is CODEC-030 in Story 1.2 (cannot fire on an empty corpus today) — this is a real
        // assertion that the scaffold is present, not a no-op counted as green.
        long count = listVectors().size();
        System.out.println("[golden] corpus vector count (Story 1.1 scaffold, may be 0): " + count);
        URL convention = getClass().getClassLoader().getResource("golden-vectors/README.md");
        assertThat(convention)
                .as("AC10: golden-vectors provenance-convention README must be packaged as a resource")
                .isNotNull();
    }

    private List<Path> listVectors() {
        URL dir = getClass().getClassLoader().getResource("golden-vectors");
        if (dir == null) {
            return List.of(); // empty corpus — no packaged resource entry yet
        }
        try (Stream<Path> s = Files.walk(Paths.get(dir.toURI()), 1)) {
            return s.filter(Files::isRegularFile)
                    .filter(p -> VECTOR_EXTENSIONS.stream().anyMatch(ext ->
                            p.getFileName().toString().toLowerCase().endsWith(ext)))
                    .sorted()
                    .toList();
        } catch (Exception e) {
            throw new IllegalStateException("failed to enumerate golden-vector corpus", e);
        }
    }
}
