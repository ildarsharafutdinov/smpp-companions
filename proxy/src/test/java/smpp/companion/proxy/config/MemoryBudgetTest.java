package smpp.companion.proxy.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import smpp.companion.codec.framer.SmppFrame;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AC5 / AD-30: the {@code MaxDirectMemorySize} budget formula is pure and unit-testable. The
 * {@code max-frame} input is {@link SmppFrame#MAX_COMMAND_LENGTH}, used directly by
 * {@link MemoryBudget#compute} (RELAY-026 &mdash; the proxy-side constant reference is asserted in
 * {@code Relay026ConstantContractTest}).
 */
@Tag("unit")
@Tag("relay")
@Tag("p1")
@DisplayName("AD-30 direct-memory budget formula")
class MemoryBudgetTest {

    @Test
    @DisplayName("SmppFrame.MAX_COMMAND_LENGTH × max_inbound_depth × concurrent_pairs × safety_factor (shipped defaults)")
    void computeAppliesTheFormula() {
        // 65536 × 64 × 1024 × 1.5 = 6,442,450,944 bytes (the application.yml shipped tunable defaults).
        assertThat(MemoryBudget.compute(64, 1024, 1.5)).isEqualTo(6_442_450_944L);
    }

    @Test
    @DisplayName("safety factor 1.0 yields the exact product (no headroom)")
    void safetyFactorOneYieldsExactProduct() {
        assertThat(MemoryBudget.compute(32, 512, 1.0))
                .isEqualTo((long) SmppFrame.MAX_COMMAND_LENGTH * 32 * 512);
    }

    @Test
    @DisplayName("a fractional product is ceiled up to a whole byte count")
    void fractionalProductIsCeiled() {
        // 65536 × 1 × 1 × 1.1 = 72089.6 -> ceiled to 72090 (the codec constant × a non-integer factor).
        assertThat(MemoryBudget.compute(1, 1, 1.1)).isEqualTo(72090L);
    }

    @Test
    @DisplayName("a large but realistic envelope does not overflow long")
    void largeEnvelopeDoesNotOverflow() {
        // 65536 × 256 × 100000 × 1.5 = 2,516,582,400,000 (well within long; would overflow int).
        assertThat(MemoryBudget.compute(256, 100_000, 1.5)).isEqualTo(2_516_582_400_000L);
    }

    @Test
    @DisplayName("a non-finite or overflowing product throws (AD-30 guard for future callers)")
    void nonFiniteOrOverflowingProductThrows() {
        // The startup validator pre-checks finiteness for the bound path, but compute() is public and a
        // future Epic 2 caller may bypass it. Without this guard: NaN -> 0, Infinity/<huge> -> clamps to
        // Long.MAX_VALUE (a meaningless "no cap" budget). Each case must throw, not silently clamp.
        assertThatThrownBy(() -> MemoryBudget.compute(1, 1, Double.NaN))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> MemoryBudget.compute(1, 1, Double.POSITIVE_INFINITY))
                .isInstanceOf(IllegalArgumentException.class);
        // 65536 × 1 × 1 × 1e20 = 6.5e24 > Long.MAX_VALUE (~9.2e18): finite, but would clamp — must throw.
        assertThatThrownBy(() -> MemoryBudget.compute(1, 1, 1e20))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
