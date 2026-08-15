package smpp.companion.proxy.relay.netty;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AD-30 self-check &mdash; pure logic of {@link DirectMemoryBudgetValidator}. The comparison
 * ({@link DirectMemoryBudgetValidator#validate(long, long)}) and the size parser
 * ({@link DirectMemoryBudgetValidator#parseSize(String)}) are JVM/module-surface-free, so they are
 * unit-tested directly; the Spring-wired invocation + the live ceiling read are covered by
 * {@link DirectMemoryBudgetStartupCheckTest}. The {@code liveDirectMemoryCeiling()} smoke assertion
 * proves the ceiling read resolves a positive value on the running JVM.
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
class DirectMemoryBudgetValidatorTest {

    @Test
    @DisplayName("budget strictly above the ceiling throws DirectMemoryBudgetException")
    void budgetExceedingCeilingThrows() {
        assertThatThrownBy(() -> DirectMemoryBudgetValidator.validate(2_000L, 1_000L))
                .isInstanceOf(DirectMemoryBudgetException.class)
                .hasMessageContaining("AD-30")
                .hasMessageContaining("refusing to start")
                .hasMessageContaining("2000 bytes")
                .hasMessageContaining("1000 bytes");
    }

    @Test
    @DisplayName("budget equal to the ceiling is permitted (ceiling is inclusive)")
    void budgetEqualToCeilingPasses() {
        // Boundary: only strictly-greater trips. Equal must NOT throw (the relay may use up to the ceiling).
        assertThatCode(() -> DirectMemoryBudgetValidator.validate(1_000L, 1_000L))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("budget below the ceiling is permitted")
    void budgetBelowCeilingPasses() {
        assertThatCode(() -> DirectMemoryBudgetValidator.validate(999L, 1_000L))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("the exception carries the budget and ceiling that tripped it")
    void exceptionCarriesBudgetAndCeiling() {
        DirectMemoryBudgetException ex = new DirectMemoryBudgetException(2_000L, 1_000L);

        assertThat(ex.budget()).isEqualTo(2_000L);
        assertThat(ex.liveCeiling()).isEqualTo(1_000L);
    }

    @Test
    @DisplayName("liveDirectMemoryCeiling() reports a positive JVM direct-memory ceiling")
    void liveDirectMemoryCeilingIsPositive() {
        // Smoke-proves liveDirectMemoryCeiling() resolves a positive ceiling on the running JVM
        // (an explicit -XX:MaxDirectMemorySize if set, else Runtime.maxMemory()).
        assertThat(DirectMemoryBudgetValidator.liveDirectMemoryCeiling()).isPositive();
    }

    @Test
    @DisplayName("parseSize decodes k/m/g/t suffixes and bare bytes (case-insensitive, binary)")
    void parseSizeDecodesSuffixes() {
        assertThat(DirectMemoryBudgetValidator.parseSize("1073741824")).isEqualTo(1_073_741_824L);
        assertThat(DirectMemoryBudgetValidator.parseSize("1024k")).isEqualTo(1_024L * 1_024L);
        assertThat(DirectMemoryBudgetValidator.parseSize("256m")).isEqualTo(256L * 1_024L * 1_024L);
        assertThat(DirectMemoryBudgetValidator.parseSize("1g")).isEqualTo(1L * 1_024L * 1_024L * 1_024L);
        assertThat(DirectMemoryBudgetValidator.parseSize("1G")).isEqualTo(1L * 1_024L * 1_024L * 1_024L);
        assertThat(DirectMemoryBudgetValidator.parseSize(" 512m ")).isEqualTo(512L * 1_024L * 1_024L);
        // 't' is a VALID HotSpot size suffix (tebibytes) — rejecting it falsely refused a healthy
        // -XX:MaxDirectMemorySize=1t deployment on every cell (review round 2, fail-closed lens).
        assertThat(DirectMemoryBudgetValidator.parseSize("1t"))
                .isEqualTo(1L * 1_024L * 1_024L * 1_024L * 1_024L);
        assertThat(DirectMemoryBudgetValidator.parseSize("2T"))
                .isEqualTo(2L * 1_024L * 1_024L * 1_024L * 1_024L);
    }

    @Test
    @DisplayName("parseSize rejects blank, non-numeric, and overflowing values — naming the flag and token")
    void parseSizeRejectsInvalid() {
        assertThatThrownBy(() -> DirectMemoryBudgetValidator.parseSize(""))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> DirectMemoryBudgetValidator.parseSize("   "))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> DirectMemoryBudgetValidator.parseSize("abc"))
                .isInstanceOf(IllegalArgumentException.class)
                // The operator must see WHICH flag and WHAT value was rejected — not a bare
                // NumberFormatException ("For input string: \"abc\"") that names neither.
                .hasMessageContaining("-XX:MaxDirectMemorySize")
                .hasMessageContaining("abc");
        // Overflow guard: 9_999_999_999g ≈ 1.07e19 bytes > Long.MAX_VALUE, must not wrap silently.
        assertThatThrownBy(() -> DirectMemoryBudgetValidator.parseSize("9999999999g"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("the flag scan takes the LAST -XX:MaxDirectMemorySize occurrence (HotSpot last-wins)")
    void flagScanTakesLastOccurrence() {
        // HotSpot applies duplicate command-line flags last-wins; a first-match scan would under-report
        // the ceiling and falsely refuse a healthy deployment. Absent flag → null (caller falls back to
        // Runtime.maxMemory()).
        assertThat(DirectMemoryBudgetValidator.lastMaxDirectMemorySizeToken(java.util.List.of(
                        "-Xmx1g", "-XX:MaxDirectMemorySize=1g", "-XX:MaxDirectMemorySize=8g")))
                .isEqualTo("8g");
        assertThat(DirectMemoryBudgetValidator.lastMaxDirectMemorySizeToken(
                        java.util.List.of("-Xmx1g", "-XX:+UseZGC")))
                .isNull();
    }
}
