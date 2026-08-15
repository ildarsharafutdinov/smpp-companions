package smpp.companion.proxy.relay.netty;

/**
 * Fail-fast (AD-17) signal raised by the AD-30 live direct-memory startup self-check when the
 * computed direct-memory budget exceeds the JVM's live direct-memory ceiling. Thrown from a bean's
 * {@link org.springframework.beans.factory.InitializingBean#afterPropertiesSet()} during context
 * refresh &rarr; the refresh aborts &rarr; the process exits non-zero (AD-17).
 *
 * <p>Unchecked because it crosses the Spring lifecycle boundary (Spring wraps it in a
 * {@code BeanCreationException}); callers cannot meaningfully recover &mdash; under-provisioned
 * direct memory is a deployment defect, not a transient condition.
 */
public final class DirectMemoryBudgetException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final long budget;
    private final long liveCeiling;

    /**
     * @param budget      the AD-30 budget ({@code MemoryBudget.compute(...)}), in bytes
     * @param liveCeiling the JVM's live direct-memory ceiling (explicit {@code -XX:MaxDirectMemorySize}, or the {@code -Xmx} default), in bytes
     */
    public DirectMemoryBudgetException(long budget, long liveCeiling) {
        super("AD-30 direct-memory budget (" + describe(budget) + ") exceeds the JVM's live direct-memory "
                + "ceiling (" + describe(liveCeiling) + ") — refusing to start (AD-17/AD-30). Raise "
                + "-XX:MaxDirectMemorySize (or -Xmx, which it defaults to) or lower "
                + "companion.memory.{max-inbound-depth, concurrent-pairs, safety-factor}; only if the "
                + "over-budget posture is an explicitly accepted risk, opt in with "
                + "companion.memory.budget-check=warn.");
        this.budget = budget;
        this.liveCeiling = liveCeiling;
    }

    /** The AD-30 budget that tripped the check, in bytes. */
    public long budget() {
        return budget;
    }

    /** The JVM's live direct-memory ceiling the budget was compared against, in bytes. */
    public long liveCeiling() {
        return liveCeiling;
    }

    /**
     * Bytes plus, when the value is at least one mebibyte, a "/ N MiB" humanization. Sub-mebibyte values
     * report bytes only — integer-MiB division would render "0 MiB", which is meaningless to an operator
     * troubleshooting a startup failure (the precise byte count is always shown regardless).
     */
    private static String describe(long bytes) {
        long mib = bytes / (1024L * 1024L);
        return mib > 0L ? bytes + " bytes / " + mib + " MiB" : bytes + " bytes";
    }
}
