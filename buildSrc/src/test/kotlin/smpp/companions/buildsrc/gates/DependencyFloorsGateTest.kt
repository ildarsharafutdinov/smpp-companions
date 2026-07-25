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
 * SEC-099: positive control for the dependency-floor (CVE) gate. Drives the REAL
 * `smpp.dependency-floors` plugin in an isolated fixture. CVE-2025-53864 floor is Nimbus >= 10.0.2.
 */
class DependencyFloorsGateTest {

    @TempDir
    lateinit var projectDir: Path

    @Test
    fun `fails when nimbus resolves below the CVE-2025-53864 floor`() {
        fixture(
            """
            plugins { java; id("smpp.dependency-floors") }
            repositories { mavenCentral() }
            dependencies { implementation("com.nimbusds:nimbus-jose-jwt:10.0.1") } // < 10.0.2 -> vulnerable
            """
        )
        val result = runner("enforceDependencyFloors").buildAndFail()
        assertEquals(TaskOutcome.FAILED, result.task(":enforceDependencyFloors")?.outcome)
        assertTrue(result.output.contains("SEC-099"))
        assertTrue(result.output.contains("CVE-2025-53864"))
    }

    @Test
    fun `passes when nimbus meets the floor`() {
        fixture(
            """
            plugins { java; id("smpp.dependency-floors") }
            repositories { mavenCentral() }
            dependencies { implementation("com.nimbusds:nimbus-jose-jwt:10.9.1") } // >= 10.0.2 -> OK
            """
        )
        val result = runner("enforceDependencyFloors").build()
        assertEquals(TaskOutcome.SUCCESS, result.task(":enforceDependencyFloors")?.outcome)
    }

    @Test
    fun `check fails when nimbus resolves below the floor`() {
        // P1: the gate must be wired into `check`, not merely invocable directly.
        fixture(
            """
            plugins { java; id("smpp.dependency-floors") }
            repositories { mavenCentral() }
            dependencies { implementation("com.nimbusds:nimbus-jose-jwt:10.0.1") }
            """
        )
        val result = runner("check").buildAndFail()
        assertEquals(TaskOutcome.FAILED, result.task(":enforceDependencyFloors")?.outcome)
        assertTrue(result.output.contains("SEC-099"))
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
