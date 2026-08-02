package smpp.companion.proxy;

import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Structural guard for the proxy {@code jmh} source set (AC8 / decision #3 hardening add #1). The JMH
 * benchmark classes live in {@code smpp.companion.jmh} (the {@code proxy/src/jmh} sourceSet); they target the
 * PURE codec (the inward seam, AD-7) and MUST NOT reach into the proxy's own internals (relay / security /
 * config / metrics). This one-line rule is the structural substitute for the module boundary the "separate
 * bench module" option would have provided — keeping benchmarks on the codec surface so a benchmark never
 * couples to not-yet-stable proxy wiring.
 *
 * <p>The benchmark classes are compiled by {@code compileJmhJava} (plain javac — no JMH bytecode-generator
 * ASM, which lives only in the opt-in {@code jmh} task) and placed on the test classpath, so this rule
 * analyzes the real compiled classes on every {@code :proxy:test}. Nightly-tier is preserved: a JMH breakage
 * cannot fail the PR build (AC8).
 */
@AnalyzeClasses(packages = "smpp.companion")
class JmhIsolationArchitectureTest {

    @ArchTest
    static final ArchRule jmhBenchmarksMustNotDependOnProxy =
            noClasses()
                    .that().resideInAPackage("..jmh..")
                    .should().dependOnClassesThat().resideInAPackage("..smpp.companion.proxy..");
}
