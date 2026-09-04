package smpp.companion.proxy.observability;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC5 / AD-19 / AD-27 layer rule for the {@code observability} seam. The seeded contract types
 * ({@link RelayObserver}, {@link Direction}, {@link CloseReason}, {@link NoopRelayObserver}) are a pure
 * contract: a {@link Direction}, a {@link SystemId}, a {@link Verdict}, or a {@link CloseReason}
 * &mdash; <b>never a Netty type</b>. A {@code Channel}/{@code ChannelId}/{@code ByteBuf} member would smuggle
 * a high-cardinality label or a content handle across the seam, so the rule bites the moment one appears on a
 * contract type. Mirrors the {@code JmhIsolationArchitectureTest} ArchUnit idiom.
 *
 * <p>The rule is scoped by fully-qualified name to the four seeded main types (referenced via
 * {@code class.getName()} so a rename refactors both sides) &mdash; <b>not</b> the whole package &mdash; because
 * the package also holds test helpers ({@link CapturingRelayObserver}, the {@code *Test} classes) on the merged
 * test classpath, and those legitimately construct {@code AsciiString}s to build a {@link SystemId}. Mirrors
 * {@code JmhIsolationArchitectureTest}.
 *
 * <p>RED-on-neuter (AC9 / AI-1): add a Netty-typed member to any of the four contract types and this rule fails.
 *
 * <p><b>Story 4.1 T6 (checkpoint 23) &mdash; the companion rule:</b> the seam's IMPLEMENTATIONS are held to the
 * same ban. Every class implementing {@link RelayObserver} &mdash; the production
 * {@link MeteredRelayObserver}, the {@link NoopRelayObserver} seed, and any FUTURE impl &mdash; must stay
 * Netty-free: observers fire inside the relay's event-loop continuations (the four fire sites), so a Netty
 * dependency there puts data-plane machinery on the telemetry path and hands the impl the
 * {@code Channel}/{@code ByteBuf} the contract above already refuses (the {@code SystemId} javadoc reserves
 * {@code asString()} as exactly this escape hatch). Selection is BY TYPE ({@code implement(RelayObserver)}),
 * so a future impl is covered the moment it lands &mdash; and the metrics ENDPOINT is the one deliberate
 * exception on the other side of the boundary: {@link MetricsHttpHandler} (with
 * {@link MetricsEndpointLifecycle}) is this package's sanctioned Netty citizen (FR-OBS-1 needs a real HTTP
 * pipeline), exempted from the selection EXPLICITLY so the boundary is stated in code, not implied by
 * what the selection happens to skip. Test-tier fixtures ({@link CapturingRelayObserver},
 * {@link ThrowingRelayObserver}) pass unexempted today; a fixture that needs a {@link SystemId} should take
 * one as a parameter (as both do), not build one from an {@code AsciiString} &mdash; if a future fixture
 * must, exempt it by name and say why, the seeded rule's discipline.
 *
 * <p><b>Step-04 review (finding #11): the class import spans the WHOLE app</b>
 * ({@code smpp.companion.proxy}, the {@code NoRolledCryptoArchitectureTest} scope) &mdash; a
 * {@link RelayObserver} impl landed in any other package must not escape the ban. The seeded rule's
 * FQN-scoped selection is unaffected by the wider import (it still names its four types); the
 * implement()-based selection now evaluates every impl in the app, main or test.
 */
@AnalyzeClasses(packages = "smpp.companion.proxy")
class ObservabilityLayerRulesTest {

    @ArchTest
    static final ArchRule seededContractTypesMustNotDependOnNetty =
            noClasses()
                    .that().haveFullyQualifiedName(RelayObserver.class.getName())
                    .or().haveFullyQualifiedName(Direction.class.getName())
                    .or().haveFullyQualifiedName(CloseReason.class.getName())
                    .or().haveFullyQualifiedName(NoopRelayObserver.class.getName())
                    .should().dependOnClassesThat().resideInAPackage("io.netty..")
                    .because("the RelayObserver seam is a pure contract — no Netty type (Channel/ChannelId/"
                            + "ByteBuf) may appear on the interface or its seeded impl; that would smuggle a "
                            + "high-cardinality label or content across the seam (AD-19 / AD-27)");

    @ArchTest
    static final ArchRule observerImplementationsMustNotDependOnNetty =
            noClasses()
                    .that().implement(RelayObserver.class)
                    .and().doNotHaveFullyQualifiedName(MetricsHttpHandler.class.getName())
                    .should().dependOnClassesThat().resideInAPackage("io.netty..")
                    .because("observers never touch Netty — they fire inside the relay's event-loop "
                            + "continuations and must not see a Channel/ChannelId/ByteBuf (AD-19 / AD-27); "
                            + "the metrics endpoint handler is this package's one deliberate Netty citizen "
                            + "(FR-OBS-1: a real HTTP pipeline), explicitly exempted from the selection so "
                            + "the boundary — observers never, the endpoint does — is stated, not implied");

    /**
     * Vacuity guard (the Story 1.2 lesson — both rules above select from the imported classes, so an
     * import that saw NOTHING would pass them vacuously): the app-wide import the rules evaluate
     * must actually contain the policed classes — the contract types, the production observer, the
     * endpoint handler, and (the widened scope's point) classes OUTSIDE the observability package.
     */
    @Test
    @Tag("observability")
    @DisplayName("vacuity guard: the app-wide import sees the policed classes, in and out of the package")
    void theAppImportActuallySeesTheRulesTargets() {
        JavaClasses imported = new ClassFileImporter().importPackages("smpp.companion.proxy");
        List<String> names = imported.stream().map(JavaClass::getName).toList();
        assertThat(names)
                .as("the import behind both layer rules resolves the classes they police")
                .contains(RelayObserver.class.getName(),
                        NoopRelayObserver.class.getName(),
                        MeteredRelayObserver.class.getName(),
                        MetricsHttpHandler.class.getName(),
                        smpp.companion.proxy.relay.BindInterceptor.class.getName());
    }
}
