package smpp.companion.proxy.relay;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Story 3.4 T5 / AC6 — the AD-25 couple is STRUCTURAL-BY-TYPE (D3, owner checkpoint 2026-08-28): the
 * {@code RelayHandler} direction-split left exactly one production class able to perform the couple —
 * {@link RelayEgressHandler} (the egress leg is where the SMSC's decoded {@code bind_*_resp} arrives).
 * These rules pin it at the CALL-SITE level: among main-source classes, ONLY {@code RelayEgressHandler}
 * may call {@link ConnectionEntry#couple()}. The ingress class has no bind arm to carry the call, and
 * neither does the base ({@code CoupledRelayHandler}) — which is the point: a manager or handler that
 * gains couple access must fail here BEFORE it can become a second couple unit.
 *
 * <p><b>Why this analyzes main classes only</b> ({@code DO_NOT_INCLUDE_TESTS}): the test tier's
 * {@code ConnectionRegistryTest} pins the CAS-once semantics of {@code couple()} directly — those
 * direct calls are the sanctioned test-source exception the D3 resolution names. Scope and both rule
 * sides reference {@code class.getName()} so a rename refactors the rule with its subject (the
 * {@code ObservabilityLayerRulesTest} / {@code SecurityTlsSurfaceArchitectureTest} idiom).
 *
 * <p><b>The positive control</b> (the forbid rules must guard a live call site, not a vacuous one — the
 * {@code SecurityTlsSurfaceArchitectureTest} pattern): the second rule fails if the egress handler
 * stops calling {@code couple()} — e.g. a rename of the method or a move of the call site de-targets
 * BOTH rules, never silently greens the forbid.
 *
 * <p>RED-on-neuter (AI-1): move the {@code entry.couple()} call into the base or the ingress class (or
 * any other main class) and the forbid rule fails; rename {@code couple()} and the positive control
 * fails.
 */
@AnalyzeClasses(packages = "smpp.companion.proxy", importOptions = ImportOption.DoNotIncludeTests.class)
class RelayCoupleSiteArchitectureTest {

    /**
     * AC6: the couple call site is expressible in EXACTLY ONE main class — no other production type
     * (handler, base, or future manager) may call {@link ConnectionEntry#couple()}.
     */
    @ArchTest
    static final ArchRule coupleIsCallableOnlyFromTheEgressLegHandler =
            noClasses()
                    .that().resideInAPackage("..smpp.companion.proxy..")
                    .and().doNotHaveFullyQualifiedName(RelayEgressHandler.class.getName())
                    .should().callMethod(ConnectionEntry.class.getName(), "couple")
                    .because("the AD-25 couple is structural-by-type (AC6, Story 3.4 T5): only the egress leg "
                            + "sees the SMSC's decoded bind_*_resp, so only " + RelayEgressHandler.class.getSimpleName()
                            + " may perform the couple — a second caller (a manager, the shared base, the "
                            + "ingress class) is a second couple unit, exactly what AD-25 forbids. Test-source "
                            + "CAS pins (ConnectionRegistryTest) are excluded via DoNotIncludeTests per the "
                            + "D3 resolution.");

    /**
     * Positive control — the egress handler REALLY performs the couple, so the forbid rule above guards
     * a live call site (a rename of {@code couple()} or a move of the site de-targets both rules).
     */
    @ArchTest
    static final ArchRule egressLegHandlerPerformsTheCouple =
            classes()
                    .that().haveFullyQualifiedName(RelayEgressHandler.class.getName())
                    .should().callMethod(ConnectionEntry.class.getName(), "couple")
                    .because("the forbid rule must not be vacuously green — " + RelayEgressHandler.class.getSimpleName()
                            + " owning the couple is the asserted shape itself (the SecurityTlsSurfaceArchitectureTest "
                            + "positive-control pattern)");
}
