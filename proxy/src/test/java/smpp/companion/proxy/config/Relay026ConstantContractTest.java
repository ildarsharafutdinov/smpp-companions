package smpp.companion.proxy.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC5 / RELAY-026 &mdash; the codec max-command-length constant ({@code SmppFrame.MAX_COMMAND_LENGTH})
 * is the SINGLE named source for the AD-30 direct-memory formula. {@code max-frame} / {@code
 * max-command-length} are NOT config keys: they can only ever be the codec constant, so holding them
 * as configurable fields was redundant (the validator could only ever accept the constant). The
 * formula ({@link MemoryBudget}) references the constant directly. This is RELAY-026's purest form
 * &mdash; one named value, nothing to drift.
 *
 * <p>Guard: a source scan that proxy main has NO magic {@code 65536} literal (in any form: decimal,
 * {@code 0x10000}, {@code 65_536}) AND references {@code SmppFrame.MAX_COMMAND_LENGTH} in CODE (not
 * merely in javadoc). Comments are stripped before matching so a doc mention can never satisfy the
 * reference check and a literal in a comment is never a false offense. (Spec AC5 names "ArchUnit/AST";
 * a hardened source scan is the chosen lighter-weight mechanism &mdash; see Dev Record.) The codec-side
 * {@code MaxCommandLengthContractTest} pins the constant value; {@code MemoryBudgetTest} exercises the
 * formula against it. The live {@code ByteBufAllocatorMetric} startup self-check is deferred to Epic 2
 * (decision D1 &mdash; the shared allocator does not exist in 1.3).
 */
@Tag("integration")
@Tag("relay")
@Tag("p1")
class Relay026ConstantContractTest {

    // Decimal, hex (0x10000), and underscored (65_536) forms of the codec max, with an optional long suffix.
    private static final Pattern MAGIC_LITERAL =
            Pattern.compile("\\b65536[Ll]?\\b|\\b0x0*10000[Ll]?\\b|\\b65_536\\b");
    private static final Pattern NAMED_CONSTANT_REFERENCE = Pattern.compile("SmppFrame\\.MAX_COMMAND_LENGTH");
    // Strip block comments (incl. javadoc) then line comments, so only CODE is scanned. The (?<!:) lookbehind
    // keeps "https://" (and other "://") protocol tokens from being treated as a line-comment start.
    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern LINE_COMMENT = Pattern.compile("(?<!:)//[^\\n]*");

    @Test
    @DisplayName("static: proxy main CODE references SmppFrame.MAX_COMMAND_LENGTH and has no magic 65536 literal")
    void proxyMainReferencesTheNamedConstantAndHasNoMagicLiteral() throws IOException {
        // The CWD of :proxy:test is the proxy module dir, so src/main/java is the main source root.
        Path root = Path.of("src/main/java");
        assertThat(Files.exists(root))
                .as("proxy main source root must exist (test CWD = proxy module)").isTrue();
        List<String> magicLiteralOffenders = new ArrayList<>();
        int namedConstantReferences = 0;
        try (Stream<Path> walk = Files.walk(root)) {
            for (Path file : walk.filter(p -> p.toString().endsWith(".java")).toList()) {
                String code = stripComments(Files.readString(file));
                if (MAGIC_LITERAL.matcher(code).find()) {
                    magicLiteralOffenders.add(root.relativize(file).toString());
                }
                Matcher ref = NAMED_CONSTANT_REFERENCE.matcher(code);
                int perFile = 0;
                while (ref.find()) {
                    perFile++;
                }
                namedConstantReferences += perFile;
            }
        }
        assertThat(magicLiteralOffenders)
                .as("no 65536/0x10000/65_536 literal in proxy main CODE (reference SmppFrame.MAX_COMMAND_LENGTH instead)")
                .isEmpty();
        assertThat(namedConstantReferences)
                .as("proxy main CODE (not javadoc) must reference SmppFrame.MAX_COMMAND_LENGTH")
                .isGreaterThan(0);
    }

    private static String stripComments(String source) {
        return LINE_COMMENT.matcher(BLOCK_COMMENT.matcher(source).replaceAll(" ")).replaceAll(" ");
    }
}
