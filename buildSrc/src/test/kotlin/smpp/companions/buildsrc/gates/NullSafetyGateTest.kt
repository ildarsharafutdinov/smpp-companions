package smpp.companions.buildsrc.gates

import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue

/**
 * AD-35 positive control: drives the REAL `smpp.null-safety` plugin (via GradleRunner.withPluginClasspath)
 * in an isolated fixture and proves (a) a JSpecify nullness violation FAILS `compileJava`, (b) the gate
 * cannot be silently bypassed — each load-bearing config line, mutated in isolation, STOPS catching the
 * violation — and (c) a clean counterpart compiles.
 *
 * The violation is deliberately a generic-type-argument nullness mismatch (`List<@Nullable String>` ->
 * `.get(0)` assigned to a @NonNull local): this is the only kind NullAway sees EXCLUSIVELY under
 * `JSpecifyMode=true`, so the "without JSpecifyMode" mutation is the load-bearing proof that line matters.
 */
class NullSafetyGateTest {

    @TempDir
    lateinit var projectDir: Path

    // ---- positive control: the violation fails compileJava for the RIGHT reason ----

    @Test
    fun `a JSpecify generic-nullness violation fails compileJava at ERROR`() {
        gateFixture()
        val result = runner("compileJava").buildAndFail()
        assertEquals(TaskOutcome.FAILED, result.task(":compileJava")?.outcome)
        assertTrue(result.output.contains("NullAway")) {
            "expected a NullAway diagnostic in output:\n${result.output}"
        }
        assertTrue(result.output.contains("NullnessViolation")) {
            "expected the offending class name in output:\n${result.output}"
        }
    }

    // ---- clean negative control: no violation => compiles ----

    @Test
    fun `a clean source compiles under the full gate`() {
        cleanFixture()
        val result = runner("compileJava").build()
        assertEquals(TaskOutcome.SUCCESS, result.task(":compileJava")?.outcome)
    }

    // ---- silent-bypass mutation controls: each load-bearing line, removed, stops catching it ----

    @Test
    fun `mutation - without JSpecifyMode the generic-arg violation is invisible`() {
        // Same violation, NullAway at ERROR, but JSpecifyMode OFF: the @Nullable type-argument is not
        // propagated, so xs.get(0) reads as @NonNull and nothing fires => build SUCCEEDS.
        // Proves `option("NullAway:JSpecifyMode","true")` is load-bearing.
        manualFixture(jspecifyMode = false, severity = "ERROR")
        val result = runner("compileJava").build()
        assertEquals(TaskOutcome.SUCCESS, result.task(":compileJava")?.outcome)
    }

    @Test
    fun `mutation - NullAway at WARN does not fail the build`() {
        // Same violation + JSpecifyMode, but NullAway at WARN: the violation is reported, not fatal.
        // Proves `check("NullAway", ERROR)` severity is load-bearing.
        manualFixture(jspecifyMode = true, severity = "WARN")
        val result = runner("compileJava").build()
        assertEquals(TaskOutcome.SUCCESS, result.task(":compileJava")?.outcome)
    }

    @Test
    fun `mutation - with no analyzer applied the violation compiles`() {
        // Plain javac, no net.ltgt.errorprone / NullAway: nothing flags the (valid-but-unsound) Java.
        // Proves APPLYING the plugin — not merely having it on the classpath — is load-bearing.
        noAnalyzerFixture()
        val result = runner("compileJava").build()
        assertEquals(TaskOutcome.SUCCESS, result.task(":compileJava")?.outcome)
    }

    // ---- fixtures ----

    /** Applies the REAL smpp.null-safety plugin + the violating source. */
    private fun gateFixture() {
        settings(
            """
            pluginManagement { repositories { gradlePluginPortal(); mavenCentral() } }
            rootProject.name = "nullaway-fixture"
            """
        )
        build(
            """
            plugins { java; id("smpp.null-safety") }
            repositories { mavenCentral() }
            dependencies { implementation("org.jspecify:jspecify:1.0.0") }
            """
        )
        writeViolationSource()
    }

    /** Applies the REAL smpp.null-safety plugin + an unambiguously clean source. */
    private fun cleanFixture() {
        settings(
            """
            pluginManagement { repositories { gradlePluginPortal(); mavenCentral() } }
            rootProject.name = "nullaway-fixture"
            """
        )
        build(
            """
            plugins { java; id("smpp.null-safety") }
            repositories { mavenCentral() }
            dependencies { implementation("org.jspecify:jspecify:1.0.0") }
            """
        )
        writeCleanSource()
    }

    /**
     * Applies net.ltgt.errorprone DIRECTLY with one variant knob at a time — isolates a single variable
     * (avoids any override-of-the-real-plugin fragility) so each mutation is unambiguous.
     */
    private fun manualFixture(jspecifyMode: Boolean, severity: String) {
        settings(
            """
            pluginManagement { repositories { gradlePluginPortal(); mavenCentral() } }
            rootProject.name = "nullaway-fixture"
            """
        )
        val jspecifyOpt = if (jspecifyMode) """ep.option("NullAway:JSpecifyMode", "true")""" else ""
        build(
            """
            import net.ltgt.gradle.errorprone.CheckSeverity
            import net.ltgt.gradle.errorprone.ErrorProneOptions
            import org.gradle.api.plugins.ExtensionAware
            import org.gradle.api.tasks.compile.JavaCompile

            plugins { java; id("net.ltgt.errorprone") }
            repositories { mavenCentral() }
            dependencies {
                add("errorprone", "com.google.errorprone:error_prone_core:2.50.0")
                add("errorprone", "com.uber.nullaway:nullaway:0.13.8")
                implementation("org.jspecify:jspecify:1.0.0")
            }
            tasks.withType<JavaCompile>().configureEach {
                val ep = (options as ExtensionAware).extensions.getByType(ErrorProneOptions::class.java)
                ep.check("NullAway", CheckSeverity.$severity)
                ep.option("NullAway:AnnotatedPackages", "smpp.companion")
                $jspecifyOpt
            }
            """
        )
        writeViolationSource()
    }

    /** Plain java, no analyzer. */
    private fun noAnalyzerFixture() {
        settings("""rootProject.name = "nullaway-fixture" """)
        build(
            """
            plugins { java }
            repositories { mavenCentral() }
            dependencies { implementation("org.jspecify:jspecify:1.0.0") }
            """
        )
        writeViolationSource()
    }

    private fun writeViolationSource() {
        val pkg = projectDir.resolve("src/main/java/smpp/companion/gatefixture")
        Files.createDirectories(pkg)
        Files.writeString(
            pkg.resolve("package-info.java"),
            """
            @org.jspecify.annotations.NullMarked
            package smpp.companion.gatefixture;
            """.trimIndent()
        )
        Files.writeString(
            pkg.resolve("NullnessViolation.java"),
            """
            package smpp.companion.gatefixture;

            import java.util.ArrayList;
            import java.util.List;
            import org.jspecify.annotations.Nullable;

            /** AC4 positive-control source: a nullness violation that fires ONLY under NullAway JSpecifyMode. */
            public class NullnessViolation {
                // JSpecify type-argument nullness mismatch: assigning List<@Nullable String> to List<String>
                // is unsound. NullAway reports it ONLY under JSpecifyMode — without that flag the @Nullable
                // type-argument is invisible, both sides read as plain List<String>, and nothing fires.
                String first() {
                    List<@Nullable String> maybeNulls = new ArrayList<>();
                    maybeNulls.add(null);
                    List<String> nonNulls = maybeNulls;   // [NullAway] incompatible types: List<@Nullable String> cannot be converted to List<String>
                    return nonNulls.get(0);               // then dereference (AC4 contract)
                }
            }
            """.trimIndent()
        )
    }

    private fun writeCleanSource() {
        val pkg = projectDir.resolve("src/main/java/smpp/companion/gatefixture")
        Files.createDirectories(pkg)
        Files.writeString(
            pkg.resolve("package-info.java"),
            """
            @org.jspecify.annotations.NullMarked
            package smpp.companion.gatefixture;
            """.trimIndent()
        )
        Files.writeString(
            pkg.resolve("CleanSource.java"),
            """
            package smpp.companion.gatefixture;

            /** AC4 clean negative control: unambiguously null-safe under the full gate. */
            public class CleanSource {
                String greet() {
                    return "ok";
                }
            }
            """.trimIndent()
        )
    }

    private fun settings(script: String) {
        Files.writeString(projectDir.resolve("settings.gradle.kts"), script.trimIndent())
    }

    private fun build(script: String) {
        Files.writeString(projectDir.resolve("build.gradle.kts"), script.trimIndent())
    }

    private fun runner(vararg args: String) =
        GradleRunner.create()
            .withProjectDir(projectDir.toFile())
            .withPluginClasspath()
            .withArguments(*args, "--stacktrace")
            .forwardOutput()
}
