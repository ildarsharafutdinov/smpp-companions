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
 * CODEC-041: positive control for the CODEC-040 dep-allowlist gate. Drives the REAL
 * `smpp.codec-purity` plugin (via GradleRunner.withPluginClasspath) in an isolated fixture, not a
 * copy — so the actual gate code is what must fire on the injected forbidden dependency.
 */
class CodecPurityGateTest {

    @TempDir
    lateinit var projectDir: Path

    @Test
    fun `fails when a non-netty module leaks onto the codec compile classpath`() {
        fixture(
            """
            plugins { java; id("smpp.codec-purity") }
            repositories { mavenCentral() }
            dependencies {
                implementation("io.netty:netty-buffer:4.2.16.Final")     // allowed
                implementation("com.nimbusds:nimbus-jose-jwt:10.9.1")     // forbidden: group != io.netty
            }
            """
        )
        val result = runner("enforceDependencyAllowlist").buildAndFail()
        assertEquals(TaskOutcome.FAILED, result.task(":enforceDependencyAllowlist")?.outcome)
        assertTrue(result.output.contains("CODEC-040"))
        assertTrue(result.output.contains("com.nimbusds"))
    }

    @Test
    fun `passes when the codec compile classpath is netty only`() {
        fixture(
            """
            plugins { java; id("smpp.codec-purity") }
            repositories { mavenCentral() }
            dependencies { implementation("io.netty:netty-buffer:4.2.16.Final") }
            """
        )
        val result = runner("enforceDependencyAllowlist").build()
        assertEquals(TaskOutcome.SUCCESS, result.task(":enforceDependencyAllowlist")?.outcome)
    }

    @Test
    fun `check fails when a non-netty module is on the codec classpath`() {
        // P1: the gate must be wired into the `check` lifecycle task — invoking it directly is not
        // enough. If the `tasks.named("check"){dependsOn(...)}` wiring is ever deleted, this catches
        // the silent-bypass the spec's RELAY-018 note warns about.
        fixture(
            """
            plugins { java; id("smpp.codec-purity") }
            repositories { mavenCentral() }
            dependencies { implementation("com.nimbusds:nimbus-jose-jwt:10.9.1") }
            """
        )
        val result = runner("check").buildAndFail()
        assertEquals(TaskOutcome.FAILED, result.task(":enforceDependencyAllowlist")?.outcome)
        assertTrue(result.output.contains("CODEC-040"))
    }

    @Test
    fun `passes when org_jspecify is on the codec classpath (AC5 jspecify-allowed half)`() {
        // Symmetric control: the existing tests prove a non-allowed group is REJECTED; this proves the
        // whitelisted non-netty groups (org.jspecify AD-35 + org.projectlombok codegen) are ACCEPTED —
        // compileOnly so they never reach the runtime classpath (AD-7/AD-27 codec purity), but ARE on compileClasspath.
        fixture(
            """
            plugins { java; id("smpp.codec-purity") }
            repositories { mavenCentral() }
            dependencies {
                implementation("io.netty:netty-buffer:4.2.16.Final")   // allowed
                compileOnly("org.jspecify:jspecify:1.0.0")             // AD-35: the whitelisted non-netty group
            }
            """
        )
        val result = runner("enforceDependencyAllowlist").build()
        assertEquals(TaskOutcome.SUCCESS, result.task(":enforceDependencyAllowlist")?.outcome)
    }

    @Test
    fun `passes when org_projectlombok is on the codec classpath (compile-time codegen, compileOnly)`() {
        // Symmetric control for the second whitelisted non-netty group: org.projectlombok (Lombok
        // compile-time code generation). Compile-time-only — compileOnly + annotationProcessor — so it
        // sits on compileClasspath but never on runtimeClasspath (codec RUNTIME stays {io.netty}+JDK).
        fixture(
            """
            plugins { java; id("smpp.codec-purity") }
            repositories { mavenCentral() }
            dependencies {
                implementation("io.netty:netty-buffer:4.2.16.Final")   // allowed
                compileOnly("org.projectlombok:lombok:1.18.46")        // whitelisted non-netty group (compile-time codegen)
            }
            """
        )
        val result = runner("enforceDependencyAllowlist").build()
        assertEquals(TaskOutcome.SUCCESS, result.task(":enforceDependencyAllowlist")?.outcome)
    }

    @Test
    fun `CODEC-040 is blind to the errorprone config when smpp_null-safety is applied (AC5)`() {
        // smpp.null-safety places error_prone_core + nullaway on the `errorprone` configuration, which
        // is neither compileClasspath nor runtimeClasspath — so the allowlist gate must never see them,
        // even though both modules now apply smpp.null-safety alongside smpp.codec-purity.
        fixtureWithPluginPortal(
            """
            plugins { java; id("smpp.null-safety"); id("smpp.codec-purity") }
            repositories { mavenCentral() }
            dependencies { implementation("io.netty:netty-buffer:4.2.16.Final") }
            """
        )
        val result = runner("enforceDependencyAllowlist").build()
        assertEquals(TaskOutcome.SUCCESS, result.task(":enforceDependencyAllowlist")?.outcome)
    }

    private fun fixture(script: String) {
        Files.writeString(projectDir.resolve("settings.gradle.kts"), """rootProject.name = "gate-fixture"""")
        Files.writeString(projectDir.resolve("build.gradle.kts"), script.trimIndent())
    }

    // smpp.null-safety applies net.ltgt.errorprone internally, so a fixture that uses it must let the
    // runner resolve that external plugin from the portal (withPluginClasspath only injects smpp.* ids).
    private fun fixtureWithPluginPortal(script: String) {
        Files.writeString(
            projectDir.resolve("settings.gradle.kts"),
            """
            pluginManagement { repositories { gradlePluginPortal(); mavenCentral() } }
            rootProject.name = "gate-fixture"
            """.trimIndent()
        )
        Files.writeString(projectDir.resolve("build.gradle.kts"), script.trimIndent())
    }

    private fun runner(vararg args: String) =
        GradleRunner.create()
            .withProjectDir(projectDir.toFile())
            .withPluginClasspath()
            .withArguments(*args, "--stacktrace")
            .forwardOutput()
}
