package smpp.companion.proxy.config;

import smpp.companion.codec.framer.SmppFrame;

/**
 * AD-30 direct-memory budget derivation (pure, unit-testable):
 * <pre>
 *   MaxDirectMemorySize = SmppFrame.MAX_COMMAND_LENGTH &times; maxInboundDepth &times; concurrentPairs &times; safetyFactor
 * </pre>
 * The {@code max-frame} input IS the codec constant ({@link SmppFrame#MAX_COMMAND_LENGTH}, RELAY-026)
 * &mdash; referenced directly here, not a parameter or a config key, so the codec max and the allocator
 * budget cannot drift. The live {@code ByteBufAllocatorMetric} self-check (live MaxDirectMemorySize
 * &ge; computed budget) lands in Epic 2 with the shared {@code PooledByteBufAllocator} (decision D1).
 */
public final class MemoryBudget {

    private MemoryBudget() {}

    /**
     * The AD-30 budget. Multiplication is performed in {@code double} to avoid {@code int} overflow
     * (the frame ceiling &times; maxInboundDepth &times; concurrentPairs easily exceeds Integer.MAX_VALUE)
     * and ceiled to a whole byte count.
     *
     * @param maxInboundDepth  the per-channel inbound queue depth (framed-PDU buffers)
     * @param concurrentPairs  the number of concurrent connection pairs
     * @param safetyFactor     the headroom multiplier (&ge; 1.0)
     * @return the derived direct-memory budget in bytes
     */
    public static long compute(int maxInboundDepth, int concurrentPairs, double safetyFactor) {
        double product = (double) SmppFrame.MAX_COMMAND_LENGTH * maxInboundDepth * concurrentPairs * safetyFactor;
        // The startup validator pre-checks finiteness for the bound path, but this method is public and a
        // future caller (Epic 2) may pass unvalidated inputs. Guard against the two silent failures:
        // a non-finite/negative product, and a finite product > Long.MAX_VALUE (whose (long) cast clamps to
        // Long.MAX_VALUE per JLS §5.1.3 — i.e. "no effective cap", defeating AD-30's purpose).
        if (!Double.isFinite(product) || product < 0 || product > Long.MAX_VALUE) {
            throw new IllegalArgumentException(
                    "AD-30 memory inputs produce an out-of-range budget (safety-factor=" + safetyFactor
                            + ", max-inbound-depth=" + maxInboundDepth + ", concurrent-pairs=" + concurrentPairs
                            + ") — refusing to start.");
        }
        return (long) Math.ceil(product);
    }
}
