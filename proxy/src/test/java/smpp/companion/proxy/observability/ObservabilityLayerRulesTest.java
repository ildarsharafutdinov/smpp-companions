package smpp.companion.proxy.observability;

import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * AC5 / AD-19 / AD-27 layer rule for the {@code observability} seam. The seeded contract types
 * ({@link SpliceObserver}, {@link Direction}, {@link CloseReason}, {@link NoopSpliceObserver}) are a pure
 * contract: a {@link Direction}, a {@link SystemId}, a {@link Verdict}, or a {@link CloseReason}
 * &mdash; <b>never a Netty type</b>. A {@code Channel}/{@code ChannelId}/{@code ByteBuf} member would smuggle
 * a high-cardinality label or a content handle across the seam, so the rule bites the moment one appears on a
 * contract type. Mirrors the {@code JmhIsolationArchitectureTest} ArchUnit idiom.
 *
 * <p>The rule is scoped by fully-qualified name to the four seeded main types (referenced via
 * {@code class.getName()} so a rename refactors both sides) &mdash; <b>not</b> the whole package &mdash; because
 * the package also holds test helpers ({@link CapturingSpliceObserver}, the {@code *Test} classes) on the merged
 * test classpath, and those legitimately construct {@code AsciiString}s to build a {@link SystemId}. Mirrors
 * {@code JmhIsolationArchitectureTest}.
 *
 * <p>RED-on-neuter (AC9 / AI-1): add a Netty-typed member to any of the four contract types and this rule fails.
 */
@AnalyzeClasses(packages = "smpp.companion.proxy.observability")
class ObservabilityLayerRulesTest {

    @ArchTest
    static final ArchRule seededContractTypesMustNotDependOnNetty =
            noClasses()
                    .that().haveFullyQualifiedName(SpliceObserver.class.getName())
                    .or().haveFullyQualifiedName(Direction.class.getName())
                    .or().haveFullyQualifiedName(CloseReason.class.getName())
                    .or().haveFullyQualifiedName(NoopSpliceObserver.class.getName())
                    .should().dependOnClassesThat().resideInAPackage("io.netty..")
                    .because("the SpliceObserver seam is a pure contract — no Netty type (Channel/ChannelId/"
                            + "ByteBuf) may appear on the interface or its seeded impl; that would smuggle a "
                            + "high-cardinality label or content across the seam (AD-19 / AD-27)");
}
