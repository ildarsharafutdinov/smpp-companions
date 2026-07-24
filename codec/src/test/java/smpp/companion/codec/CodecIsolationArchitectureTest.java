package smpp.companion.codec;

import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * CODEC-039: the codec module is structurally PURE — it must not depend on the proxy module
 * (inward-only seam, AD-7). Green today against the near-empty codec (package-info carries zero
 * class dependencies); becomes load-bearing once codec classes exist (Story 1.2).
 */
@AnalyzeClasses(packages = "smpp.companion")
class CodecIsolationArchitectureTest {

    @ArchTest
    static final ArchRule codecMustNotDependOnProxy =
        noClasses()
            .that().resideInAPackage("..smpp.companion.codec..")
            .should().dependOnClassesThat().resideInAPackage("..smpp.companion.proxy..");
}
