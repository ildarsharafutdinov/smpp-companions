package smpp.companion.proxy.relay;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaCall;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.core.domain.JavaCall.Predicates.target;
import static com.tngtech.archunit.core.domain.JavaClass.Predicates.equivalentTo;
import static com.tngtech.archunit.core.domain.properties.HasName.Predicates.name;
import static com.tngtech.archunit.core.domain.properties.HasOwner.Predicates.With.owner;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Story 4.3 T1 — the {@link ConnectionRegistry} MUTATION FENCE (the AD-22 drain groundwork): among
 * main-source classes, ONLY {@link RelayStateManager} may call the registry's mutators —
 * {@code register} / {@code attachEgress} / {@code beginTeardown} — at ANY arity. Every registry mutation
 * routes through the state manager so the AD-32 hygiene half ({@code cancelHttp()} + password zeroize
 * before the {@code Won} return) stays single-sited and cannot be bypassed by a handler or the drain body
 * reaching for the raw storage bean; the registry's ENTRY attribute sets/clears ride exactly these three
 * methods (the key is private), so fencing the methods fences the attribute writes too. Since Story 3.4
 * T6 this is a true invariant with zero offenders — the rule pins it structurally so the first future
 * direct injection of the registry (the AD-22 drain body deliberately READS it via
 * {@code snapshot()}/{@code size()} but must never mutate it) fails HERE, before it can fork the
 * teardown ordering.
 *
 * <p><b>Why this analyzes main classes only</b> ({@code DO_NOT_INCLUDE_TESTS}): the test tier drives the
 * registry directly everywhere — {@code ConnectionRegistryTest}'s CAS pins, the fixtures' harnesses — the
 * sanctioned test-source exception the {@code RelayCoupleSiteArchitectureTest} precedent names. Scope and
 * both rule sides reference the subject types ({@code class} tokens / {@code class.getName()}) so a rename
 * refactors the rule with its subject (the {@code ObservabilityLayerRulesTest} /
 * {@code SecurityTlsSurfaceArchitectureTest} idiom).
 *
 * <p><b>The positive control</b> (a forbid rule must guard live call sites, not vacuous ones — the
 * {@code SecurityTlsSurfaceArchitectureTest} pattern): the second rule fails if the state manager stops
 * driving ANY of the three mutators — e.g. a rename of a method or a move of a call site de-targets it,
 * never silently greens the forbid.
 *
 * <p><b>RED-on-neuter:</b> comment out the forbid rule's {@code RelayStateManager} exemption and the rule
 * fails on the manager's own sanctioned calls; call any of the three mutators on the registry from any
 * other main class (any arity) and the forbid rule fails on that class.
 */
@AnalyzeClasses(packages = "smpp.companion.proxy", importOptions = ImportOption.DoNotIncludeTests.class)
class ConnectionRegistryMutationFenceArchitectureTest {

    /**
     * ANY-ARITY call predicate: a method with this name owned by {@link ConnectionRegistry}. Arity-blind
     * by design (the 3.4 ledger fold applied at birth): an added overload slips nothing past the fence.
     */
    private static DescribedPredicate<JavaCall<?>> callOnRegistry(String methodName) {
        return target(owner(equivalentTo(ConnectionRegistry.class))).and(target(name(methodName)));
    }

    /**
     * The fence: no main class except the state manager may mutate the registry — every
     * {@code register} / {@code attachEgress} / {@code beginTeardown} call (and the ENTRY attribute
     * writes/clears those three methods carry) belongs to {@code RelayStateManager}.
     */
    @ArchTest
    static final ArchRule registryMutatorsAreCallableOnlyFromTheStateManager =
            noClasses()
                    .that().resideInAPackage("..smpp.companion.proxy..")
                    .and().doNotHaveFullyQualifiedName(RelayStateManager.class.getName())
                    .should().callMethodWhere(
                            callOnRegistry("register")
                                    .or(callOnRegistry("attachEgress"))
                                    .or(callOnRegistry("beginTeardown")))
                    .because("every ConnectionRegistry mutation — register, attachEgress, beginTeardown, and "
                            + "the ENTRY attribute writes/clears they carry — routes through the RelayStateManager "
                            + "(Story 3.4 T6: the cancelHttp + zeroize hygiene runs there, before the Won return), so "
                            + "a second caller forks the AD-32 teardown ordering exactly what the fence exists to "
                            + "deny. The AD-22 drain body (Story 4.3) reads the registry (snapshot/size) but must "
                            + "never mutate through it. Any arity: an added overload slips nothing (the 3.4 ledger "
                            + "fold). Test-source direct drives are excluded via DoNotIncludeTests per the "
                            + "RelayCoupleSiteArchitectureTest precedent.");

    /**
     * Positive control — the state manager REALLY drives all three mutators today, so the forbid rule
     * above guards live call sites (a rename of a mutator or a move of a call site de-targets this
     * control and fails here).
     */
    @ArchTest
    static final ArchRule stateManagerDrivesEveryRegistryMutator =
            classes()
                    .that().haveFullyQualifiedName(RelayStateManager.class.getName())
                    .should().callMethodWhere(callOnRegistry("register"))
                    .andShould().callMethodWhere(callOnRegistry("attachEgress"))
                    .andShould().callMethodWhere(callOnRegistry("beginTeardown"))
                    .because("the forbid rule must not be vacuously green — RelayStateManager owns the register "
                            + "(at bind arrival), attachEgress (at egress connect), and beginTeardown (on every "
                            + "teardown arm) call sites; if any of the three moves away or is renamed, the fence "
                            + "must fail loudly, not guard an empty surface (the SecurityTlsSurfaceArchitectureTest "
                            + "positive-control pattern).");
}
