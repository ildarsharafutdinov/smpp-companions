package smpp.companion.proxy.security;

import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * SEC-090 (scaffold form, AC7): no hand-rolled crypto. Records the constraint that the security
 * layer must use only JDK {@code SSLEngine} + Nimbus for TLS/JWT (SEC-4, AD-13) — no reach into
 * JDK crypto internals ({@code sun.security..}). The {@code that()} set is empty today (no security
 * classes yet; body is Epic 3), so {@code allowEmptyShould(true)} keeps the rule green until it
 * becomes meaningful, at which point it is tightened.
 */
@AnalyzeClasses(packages = "smpp.companion.proxy")
class NoRolledCryptoArchitectureTest {

    @ArchTest
    static final ArchRule securityLayerMustNotReachJdkCryptoInternals =
        noClasses()
            .that().resideInAPackage("..smpp.companion.proxy.security..")
            .should().dependOnClassesThat().resideInAPackage("sun.security..")
            .allowEmptyShould(true); // scaffold — enforced once security/ lands (Epic 3)
}
