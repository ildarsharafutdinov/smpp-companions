package smpp.companion.proxy.observability;

import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Story 4.1 step-04 review (finding #16) &mdash; the main-code JSON posture, pinned. The
 * logstash-logback-encoder dependency (Story 4.1 T1) put the FIRST Jackson on the proxy classpath
 * ({@code jackson-databind}, transitively &mdash; encoder-internal serialization only, per the build
 * file's note). Nothing else keeps hand-written code off it: the OBS-013 runtime-purity gate allows
 * the io.netty/net.logstash coordinates through, so a {@code com.fasterxml.jackson..} import in any
 * main or test class would silently spread a second JSON stack over the app that Nimbus
 * ({@code nimbus-jose-jwt}, the one sanctioned JSON library &mdash; see
 * {@code NoRolledCryptoArchitectureTest}) already owns.
 *
 * <p>Vacuously green today (no {@code smpp.companion..} class references Jackson) &mdash; a
 * future-regression guard, the {@code NoRolledCryptoArchitectureTest} third-party-stack pattern.
 * Deliberately NOT a purity-gate edit (the gate stays untouched): this is an architecture rule, not
 * a dependency-coordinates ban.
 */
@AnalyzeClasses(packages = "smpp.companion")
class NoJacksonArchitectureTest {

    @ArchTest
    static final ArchRule noSmppCompanionCodeMayDependOnJackson =
            noClasses()
                    .that().resideInAPackage("smpp.companion..")
                    .should().dependOnClassesThat().resideInAPackage("com.fasterxml.jackson..")
                    .because("Nimbus is the one JSON library for hand-written code (NoRolledCrypto's "
                            + "AD-12 posture); the logstash-logback-encoder's transitive "
                            + "jackson-databind is encoder-internal and must not leak into any class "
                            + "of the codec, proxy, or benchmark tiers");
}
