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

    private fun fixture(script: String) {
        Files.writeString(projectDir.resolve("settings.gradle.kts"), """rootProject.name = "gate-fixture"""")
        Files.writeString(projectDir.resolve("build.gradle.kts"), script.trimIndent())
    }

    private fun runner(vararg args: String) =
        GradleRunner.create()
            .withProjectDir(projectDir.toFile())
            .withPluginClasspath()
            .withArguments(*args, "--stacktrace")
            .forwardOutput()
}
