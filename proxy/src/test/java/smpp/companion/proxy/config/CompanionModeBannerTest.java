package smpp.companion.proxy.config;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import com.nimbusds.jose.util.JSONObjectUtils;

import smpp.companion.proxy.ProxyCompanionApplication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Story 5.1 T3 — the parked mode-banner stream decision, resolved: both mode warnings ride the
 * logback stream as ONE WARN JSON line (the shipped LogstashEncoder), never {@code System.err}
 * &mdash; the boot banners were the one non-JSON stream in a &ldquo;stdout is pure JSON-lines&rdquo;
 * deployment (FR-OBS-2), and the packaged {@code java -jar} shape puts every operator-facing line
 * where a log shipper expects it.
 *
 * <p><b>Boot-capture, not a bean unit test:</b> the row boots the REAL application (production
 * component scan, full cell config via {@link TestCompanionConfigs}) under
 * {@code --logging.config=classpath:logback-spring.xml} so the production JSON encoder is the one
 * under test (the {@code StructuredLogTest} full-boot idiom &mdash; the tier's plain
 * {@code logback-test.xml} masks the shipped shape). BOTH JVM streams are swapped into memory
 * before the boot, restored in {@code finally} however the row ends (the exception-safe house
 * rule &mdash; a failed row must not strand the swapped streams on later suites).
 *
 * <p>RED-on-neuter: revert either bean to {@code System.err.println} &rarr; the stdout arm goes
 * red (no WARN JSON line from the bean's logger) AND the stderr arm goes red (plain text on the
 * raw stream).
 */
@Tag("integration")
@Tag("deploy")
@Tag("p1")
@DisplayName("Mode banners — Story 5.1 T3: WARN JSON on the logback stream, stderr carries no plain text")
class CompanionModeBannerTest {

    @TempDir
    Path dir;

    @Test
    @DisplayName("reverse × B boot: the Mode B banner is ONE WARN JSON line on the logback stream; "
            + "stderr carries no plain text")
    void modeBBannerIsOneWarnJsonLineOnTheLogbackStreamAndStderrCarriesNoPlainText() {
        assertBannerRidesTheLogbackStream(
                TestCompanionConfigs.reverseB(dir),
                CompanionModeBWarning.class,
                CompanionModeBWarning.MODE_B_WARNING);
    }

    @Test
    @DisplayName("reverse × A boot: the Mode A banner is ONE WARN JSON line on the logback stream; "
            + "stderr carries no plain text")
    void modeABannerIsOneWarnJsonLineOnTheLogbackStreamAndStderrCarriesNoPlainText() {
        assertBannerRidesTheLogbackStream(
                TestCompanionConfigs.reverseA(dir),
                CompanionModeAWarning.class,
                CompanionModeAWarning.MODE_A_WARNING);
    }

    /**
     * Boots the cell with the PRODUCTION logback config and asserts the three T3 facts: stdout is
     * JSON-lines (every line one object), exactly one WARN line from the warning bean's logger
     * carries the whole banner text inside its {@code message} field (the starred block survives
     * the encoder as escaped newlines — one line, one object), and the raw stderr sink stays
     * empty (the pre-5.1 println split-stream is gone).
     */
    private void assertBannerRidesTheLogbackStream(
            TestCompanionConfigs cell, Class<?> warningBean, String bannerText) {
        // Swap BOTH streams BEFORE the boot so the whole window is captured — the appender binds at
        // logging re-init, and a stray System.err writer (the regression this row exists to catch)
        // resolves the sink at call time (the StructuredLogTest full-boot idiom, both arms).
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        System.setOut(new PrintStream(stdout, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(stderr, true, StandardCharsets.UTF_8));
        String capturedOut;
        String capturedErr;
        try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(ProxyCompanionApplication.class)
                .web(WebApplicationType.NONE)
                .run(withProductionLogbackConfig(cell.args()))) {
            assertThat(ctx.isActive())
                    .as("the fixture boot must succeed (the StructuredLogTest builder pattern)")
                    .isTrue();
        } finally {
            // Whatever throws mid-boot (or mid-assertion), the JVM-global streams go back first.
            System.setOut(originalOut);
            System.setErr(originalErr);
            capturedOut = stdout.toString(StandardCharsets.UTF_8);
            capturedErr = stderr.toString(StandardCharsets.UTF_8);
        }

        // (1) the logback stream: EVERY stdout line is one JSON object (strict parse — Nimbus
        // rejects plain text, so a println leak anywhere in the boot window fails here too).
        List<String> lines = capturedOut.lines().map(String::trim).filter(s -> !s.isEmpty()).toList();
        assertThat(lines).as("the booted app logged a non-empty stream").isNotEmpty();
        List<Map<String, Object>> parsed = parseEveryLine(lines);

        // (2) the banner: exactly ONE line from the warning bean's logger, at WARN, carrying the
        // WHOLE starred block in the message field (it fires once per successful @PostConstruct).
        List<Map<String, Object>> bannerLines = parsed.stream()
                .filter(line -> warningBean.getName().equals(line.get("logger_name")))
                .toList();
        assertThat(bannerLines)
                .as("exactly one banner line from %s", warningBean.getSimpleName())
                .hasSize(1);
        Map<String, Object> banner = bannerLines.get(0);
        assertThat(banner.get("level"))
                .as("the banner line is WARN-level (Story 5.1 T3)")
                .isEqualTo("WARN");
        assertThat(String.valueOf(banner.get("message")))
                .as("the whole banner text survived the encoder inside one JSON line")
                .contains(bannerText);

        // (3) stderr carries no plain text — the pre-5.1 println split-stream is gone (the AC's
        // second half, asserted directly on the raw sink).
        assertThat(capturedErr)
                .as("stderr carries no plain text (the banner never leaves the logback stream)")
                .isBlank();
    }

    /** Appends the production-logback arg (run args outrank the tier's logback-test.xml). */
    private static String[] withProductionLogbackConfig(String[] cellArgs) {
        String[] args = Arrays.copyOf(cellArgs, cellArgs.length + 1);
        args[cellArgs.length] = "--logging.config=classpath:logback-spring.xml";
        return args;
    }

    /**
     * Strict-parses every captured line as one JSON object (the {@code ObservabilityPairHarness}
     * idiom): Nimbus rejects plain text and trailing garbage, so the every-line-parses assertion
     * cannot pass vacuously.
     */
    private static List<Map<String, Object>> parseEveryLine(List<String> lines) {
        List<Map<String, Object>> parsed = new ArrayList<>(lines.size());
        for (String line : lines) {
            try {
                parsed.add(JSONObjectUtils.parse(line));
            } catch (ParseException e) {
                fail("stdout line is not one JSON object (FR-OBS-2): <" + line + ">", e);
            }
        }
        return parsed;
    }
}
