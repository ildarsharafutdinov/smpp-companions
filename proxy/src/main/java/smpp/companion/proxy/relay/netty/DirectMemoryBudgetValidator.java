package smpp.companion.proxy.relay.netty;

import java.lang.management.ManagementFactory;
import java.util.List;

import org.jspecify.annotations.Nullable;

/**
 * AD-30 live direct-memory budget self-check (pure, unit-testable). Compares the AD-30 direct-memory
 * budget (the relay's worst-case off-heap PDU-buffer demand, derived by
 * {@link smpp.companion.proxy.config.MemoryBudget}) against the JVM's <em>live</em> direct-memory
 * ceiling, and fails fast (AD-17) if the budget exceeds it.
 *
 * <p><b>Live ceiling source.</b> The ceiling is read from the JVM's launch arguments <em>without</em>
 * touching any JDK-internal API: an explicit {@code -XX:MaxDirectMemorySize=<n>} is parsed if present
 * (the LAST occurrence when the flag repeats &mdash; HotSpot applies duplicate command-line flags
 * last-wins), otherwise the JVM's default direct-memory ceiling is {@link Runtime#maxMemory()} &mdash;
 * the {@code -Xmx} value HotSpot defaults {@code MaxDirectMemorySize} to when it is unset. Keeping the
 * proxy free of {@code jdk.internal.misc} means the production boot jar needs no {@code --add-exports}
 * and the self-check runs (rather than crashing with a module-access error) under {@code java -jar}
 * (AD-17). ({@link io.netty.buffer.ByteBufAllocatorMetric ByteBufAllocatorMetric} exposes only
 * {@code usedDirectMemory()} &mdash; current <em>usage</em>, not the ceiling &mdash; so it cannot serve
 * the check.)
 *
 * <p>The comparison ({@link #validate(long, long)}), the size parser ({@link #parseSize(String)}), and
 * the flag scan ({@link #lastMaxDirectMemorySizeToken(List)}) are pure statics so they are unit-testable
 * without the JVM surface; the live ceiling read ({@link #liveDirectMemoryCeiling()}) is isolated to one
 * call site. The Spring-wired invocation lives in {@link DirectMemoryBudgetStartupCheck}.
 */
public final class DirectMemoryBudgetValidator {

    private static final String FLAG_PREFIX = "-XX:MaxDirectMemorySize=";

    private DirectMemoryBudgetValidator() {}

    /**
     * The JVM's live direct-memory ceiling, in bytes.
     *
     * @return the explicit {@code -XX:MaxDirectMemorySize} value if set on the command line (the last
     *         occurrence when the flag repeats), otherwise {@link Runtime#maxMemory()} (the {@code -Xmx}
     *         value HotSpot defaults {@code MaxDirectMemorySize} to when unset). Always positive on a
     *         normally-launched JVM.
     */
    public static long liveDirectMemoryCeiling() {
        String token = lastMaxDirectMemorySizeToken(ManagementFactory.getRuntimeMXBean().getInputArguments());
        return token != null ? parseSize(token) : Runtime.getRuntime().maxMemory();
    }

    /**
     * The size token of the LAST {@code -XX:MaxDirectMemorySize=} occurrence in a JVM argument list —
     * HotSpot applies duplicate command-line flags last-wins, so the final occurrence is the live value;
     * taking the first would under-report the ceiling and falsely refuse a healthy deployment.
     * Package-private so the scan is unit-testable without a relaunched JVM.
     *
     * @param args the JVM input arguments (e.g. {@code ManagementFactory.getRuntimeMXBean().getInputArguments()})
     * @return the bare size token (e.g. {@code "512m"}), or {@code null} when the flag is absent
     */
    @Nullable
    static String lastMaxDirectMemorySizeToken(List<String> args) {
        String token = null;
        for (String arg : args) {
            if (arg.startsWith(FLAG_PREFIX)) {
                token = arg.substring(FLAG_PREFIX.length());
            }
        }
        return token;
    }

    /**
     * Parse a JVM memory-size token (as used by {@code -XX:MaxDirectMemorySize}) into bytes. Accepts an
     * optional {@code k}/{@code m}/{@code g}/{@code t} (case-insensitive, binary multiples) suffix —
     * exactly the suffixes HotSpot's size flags accept; a bare number is bytes. Package-private so the
     * pure parsing logic is unit-testable.
     *
     * @param token the size token, e.g. {@code "256m"}, {@code "1g"}, {@code "1t"}, {@code "1073741824"}
     * @return the size in bytes
     * @throws IllegalArgumentException if the token is blank, not a parseable size, or overflows a long
     *         (the message names {@code -XX:MaxDirectMemorySize} so an operator sees WHICH flag and WHAT
     *         value was rejected, not a bare {@code NumberFormatException})
     */
    static long parseSize(String token) {
        String s = token.strip();
        if (s.isEmpty()) {
            throw new IllegalArgumentException("blank -XX:MaxDirectMemorySize value");
        }
        char unit = Character.toLowerCase(s.charAt(s.length() - 1));
        long multiplier;
        String numberPart;
        if (unit == 'k') {
            multiplier = 1024L;
            numberPart = s.substring(0, s.length() - 1);
        } else if (unit == 'm') {
            multiplier = 1024L * 1024L;
            numberPart = s.substring(0, s.length() - 1);
        } else if (unit == 'g') {
            multiplier = 1024L * 1024L * 1024L;
            numberPart = s.substring(0, s.length() - 1);
        } else if (unit == 't') {
            multiplier = 1024L * 1024L * 1024L * 1024L;
            numberPart = s.substring(0, s.length() - 1);
        } else {
            multiplier = 1L;
            numberPart = s;
        }
        long n;
        try {
            n = Long.parseLong(numberPart.strip());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "-XX:MaxDirectMemorySize value is not a parseable size: \"" + token + "\"", e);
        }
        long bytes = n * multiplier;
        // Guard silent overflow (JLS §5.1.3): a product that wraps would under-report the ceiling,
        // defeating AD-30.
        if (n != 0L && bytes / n != multiplier) {
            throw new IllegalArgumentException("-XX:MaxDirectMemorySize value overflows a long: " + token);
        }
        return bytes;
    }

    /**
     * Fail-fast (AD-17/AD-30): throw {@link DirectMemoryBudgetException} iff the budget strictly exceeds
     * the live ceiling. A budget equal to the ceiling is permitted (the ceiling is inclusive &mdash; the
     * relay may use up to it).
     *
     * @param budget      the AD-30 budget ({@code MemoryBudget.compute(...)}), in bytes
     * @param liveCeiling the JVM's live direct-memory ceiling ({@link #liveDirectMemoryCeiling()}), in bytes
     * @throws DirectMemoryBudgetException if {@code budget > liveCeiling}
     */
    public static void validate(long budget, long liveCeiling) {
        if (budget > liveCeiling) {
            throw new DirectMemoryBudgetException(budget, liveCeiling);
        }
    }
}
