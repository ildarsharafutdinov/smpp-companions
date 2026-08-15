package smpp.companion.proxy.relay.netty;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;

import smpp.companion.proxy.config.MemoryBudget;
import smpp.companion.proxy.config.ProxyCompanionProperties;

/**
 * AD-30 live direct-memory startup self-check (retro AI-6 "with-relay"), wired for EVERY role&times;mode
 * cell: on context refresh, computes the AD-30 budget from the bound {@code companion.memory.*} inputs and
 * compares it against the JVM's live direct-memory ceiling. On over-budget, the
 * {@code companion.memory.budget-check} policy decides: {@code FAIL} (the default &mdash; shipped as
 * such in application.yml; any non-WARN value fails closed) throws {@link DirectMemoryBudgetException}
 * &rarr; refresh aborts &rarr; non-zero exit
 * (AD-17); {@code WARN} emits the loud accepted-risk banner (the Mode B pattern, AD-17/SEC-052 posture)
 * and boots. The check itself never skips &mdash; it always computes and compares; only the over-budget
 * severity is operator-tunable. Mounted as an {@link InitializingBean} so the check runs during refresh
 * (before {@code SmartLifecycle.start()}), failing the boot before any channel opens.
 *
 * <p><b>Unconditional scope.</b> The AD-30 budget is a property of the relay data plane, and every
 * role&times;mode cell relays (forward relays ESME&rarr;reverse, reverse relays to the SMSC/forward) &mdash;
 * and the AD-17 constructor guarantees every deployment has exactly one cell &mdash; so the check runs on
 * every boot; no per-cell widening is needed when Epic 3 wires the forward/mode-a/c relays. (Story 2.2 T5
 * had scoped it to {@code reverse.mode-b} only, the slice that story wired; made unconditional 2026-08-15
 * by operator decision &mdash; see the AD-30 amendment and the story Dev Notes.) The warn-mode banner is
 * emitted at check time, not post-refresh: the over-budget trip is real regardless of any later,
 * unrelated startup failure.
 *
 * <p>Stays in this package (not {@code config}) because it budgets the relay's shared allocator
 * (AD-21/AD-30); the Spring-wired invocation pattern (validated properties &rarr; pure statics in
 * {@link DirectMemoryBudgetValidator}) keeps the comparison unit-testable without the JVM surface.
 */
@Slf4j
@Component
public final class DirectMemoryBudgetStartupCheck implements InitializingBean {

    /**
     * The AD-30 loud over-budget accepted-risk banner for {@code budget-check=warn} (the Mode B banner
     * pattern — {@code CompanionModeBWarning.MODE_B_WARNING}: a starred block, logged at WARN so it is
     * unmissable in any log aggregation). One {@code {}} slot: the
     * {@link DirectMemoryBudgetException} message — the gate's own budget/ceiling/remediation text, so
     * the banner and the failure share one source of truth and cannot drift.
     */
    static final String OVER_BUDGET_WARNING = """
            ************************************************************
            * AD-30 DIRECT-MEMORY BUDGET EXCEEDS THE JVM CEILING.
            * ACCEPTED RISK — opted in via companion.memory.budget-check=warn.
            * Booting anyway; at full relay load, off-heap PDU-buffer
            * allocation can fail (OutOfDirectMemoryError).
            *
            * {}
            ************************************************************""";

    private final ProxyCompanionProperties properties;

    public DirectMemoryBudgetStartupCheck(ProxyCompanionProperties properties) {
        this.properties = properties;
    }

    @Override
    public void afterPropertiesSet() {
        var memory = properties.memory();
        long budget = MemoryBudget.compute(
                memory.maxInboundDepth(), memory.concurrentPairs(), memory.safetyFactor());
        long liveCeiling = DirectMemoryBudgetValidator.liveDirectMemoryCeiling();
        try {
            // validate() is the single comparison AND throw site (unit-tested): a no-op when
            // budget <= liveCeiling, throws iff budget > liveCeiling. No duplicated trip condition
            // here — the warn policy is applied to the gate's verdict, not a re-comparison.
            DirectMemoryBudgetValidator.validate(budget, liveCeiling);
        } catch (DirectMemoryBudgetException e) {
            if (memory.budgetCheck() == ProxyCompanionProperties.Memory.BudgetCheck.WARN) {
                // Over budget, and the operator explicitly accepted that risk: loud banner carrying
                // the gate's own message (budget, ceiling, remediation — one source of truth), then
                // boot. FAIL (the default — any non-WARN value, incl. a defensively-null yml-less
                // bind) rethrows below.
                log.warn(OVER_BUDGET_WARNING, e.getMessage());
            } else {
                throw e;
            }
        }
    }
}
