package smpp.companion.codec.golden;

import lombok.experimental.UtilityClass;
import smpp.companion.codec.command.SmppCommandIds;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

/**
 * Shared loader for the CODEC-030 golden-vector corpus (AC5). Every vector is a one-line text file whose
 * first line is the provenance header {@code # provenance: <§ref> ; raw-hex: <lowercase hex>} with an
 * optional {@code ; reject: <CODEC-id reason>} on negatives. This parser turns that header into a
 * {@link Vector}; the wire {@code bytes()} are the hand-authored form, decoded via {@link HexFormat} —
 * <b>no decode/encode of the codec-under-test runs here</b>, so the corpus stays an oracle independent of
 * the codec (R14/R33).
 *
 * <p>Package-private: consumed only by the codec's own tests — the corpus-integrity test
 * ({@link GoldenVectorCorpusTest}) and the T5 bind-family conformance tests ({@link BindConformanceTest}).
 *
 * <p><b>Reject-marker scoping (code-review patch 2026-07-29):</b> the {@code ; reject: } search is scoped
 * to AFTER the {@code raw-hex:} marker, so a {@code ; reject: } substring that happens to appear inside a
 * vector's {@code <§ref>} note cannot misclassify it or drive {@code substring} into a negative range. The
 * raw-hex is validated (lowercase, whole-octets, non-empty) at load time so a malformed vector fails fast
 * here rather than silently mid-assertion.
 *
 * <p>The {@link Vector} record stores the hex {@code String} (not a {@code byte[]}) so it stays array-free —
 * ErrorProne's {@code ArrayRecordComponent} runs on test compilation too.
 */
@UtilityClass
class GoldenVectors {

    private static final String PROVENANCE_PREFIX = "# provenance:";
    private static final String RAW_HEX_MARKER = " ; raw-hex: ";
    private static final String REJECT_MARKER = " ; reject: ";
    private static final List<String> VECTOR_EXTENSIONS = List.of(".bin", ".smpp");
    private static final HexFormat HEX = HexFormat.of();

    /**
     * One loaded golden vector. {@link #rawHex()} is the diff-stable source form; {@link #bytes()} parses it
     * on demand (test-only, tiny corpus). {@link #commandId()} / {@link #isResponse()} / {@link #rejectCode()}
     * are derived from the bytes / header so consumers never re-parse the header themselves.
     */
    record Vector(Path path, String name, String provenance, String rawHex, boolean negative, String rejectTag) {

        /** The hand-authored wire bytes parsed from {@link #rawHex()} (never codec-generated — R14/R33). */
        byte[] bytes() {
            return HEX.parseHex(rawHex);
        }

        /** The declared {@code command_id} (octets 4..7, unsigned big-endian) as the raw 32-bit pattern. */
        int commandId() {
            byte[] b = bytes();
            return ((b[4] & 0xFF) << 24) | ((b[5] & 0xFF) << 16) | ((b[6] & 0xFF) << 8) | (b[7] & 0xFF);
        }

        /** {@code true} iff this vector's {@code command_id} carries the SMPP response bit (bit 31). */
        boolean isResponse() {
            return SmppCommandIds.isResponse(commandId());
        }

        /** The leading {@code CODEC-NNN} tag on a negative's reject marker ("" for a positive vector). */
        String rejectCode() {
            if (rejectTag.isBlank()) {
                return "";
            }
            String t = rejectTag.trim();
            int sp = t.indexOf(' '); // the tag is "CODEC-NNN <reason>" — first token (no String.split, ErrorProne-clean)
            return sp < 0 ? t : t.substring(0, sp);
        }
    }

    /**
     * Loads and parses every vector in the {@code golden-vectors/} resource directory (sorted by name for
     * diff-stable ordering). Empty list if the directory is not packaged.
     */
    static List<Vector> load() {
        URL dir = GoldenVectors.class.getClassLoader().getResource("golden-vectors");
        if (dir == null) {
            return List.of(); // no packaged resource entry
        }
        try (Stream<Path> s = Files.walk(Paths.get(dir.toURI()), 1)) {
            return s.filter(Files::isRegularFile)
                    .filter(p -> {
                        String n = p.getFileName().toString().toLowerCase(Locale.ROOT);
                        return VECTOR_EXTENSIONS.stream().anyMatch(n::endsWith);
                    })
                    .sorted()
                    .map(GoldenVectors::parse)
                    .toList();
        } catch (Exception e) {
            throw new IllegalStateException("failed to enumerate golden-vector corpus", e);
        }
    }

    private static Vector parse(Path path) {
        List<String> lines;
        try {
            lines = Files.readAllLines(path);
        } catch (IOException e) {
            throw new IllegalStateException("failed to read golden vector " + path, e);
        }
        if (lines.isEmpty()) {
            throw new IllegalStateException("golden vector " + path + " has no provenance header line");
        }
        String header = lines.get(0);
        int hexMarker = header.indexOf(RAW_HEX_MARKER);
        if (!header.startsWith(PROVENANCE_PREFIX) || hexMarker < 0) {
            throw new IllegalStateException("golden vector " + path + " has a malformed provenance header: " + header);
        }
        String provenance = header.substring(0, hexMarker);
        int hexStart = hexMarker + RAW_HEX_MARKER.length();
        // SCOPED: a reject marker is recognized only AFTER the raw-hex (review patch 2026-07-29) — a
        // ' ; reject: ' substring inside the <§ref> note cannot set hexEnd < hexStart and throw here.
        int rejectIdx = header.indexOf(REJECT_MARKER, hexStart);
        boolean negative = rejectIdx >= 0;
        int hexEnd = negative ? rejectIdx : header.length();
        String rawHex = header.substring(hexStart, hexEnd).trim();
        String rejectTag = negative ? header.substring(rejectIdx + REJECT_MARKER.length()).trim() : "";
        if (rawHex.isEmpty() || !rawHex.matches("[0-9a-f]*") || rawHex.length() % 2 != 0) {
            throw new IllegalStateException("golden vector " + path + " has invalid raw-hex (need lowercase whole-octets): " + rawHex);
        }
        return new Vector(path, path.getFileName().toString(), provenance, rawHex, negative, rejectTag);
    }
}
