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
 * OBS-043: positive control for the OBS-013 forbidden-runtime-dep gate. Drives the REAL
 * `smpp.runtime-purity` plugin in an isolated fixture. Injecting spring-web (a forbidden artifact)
 * must fail the build.
 */
class RuntimePurityGateTest {

    @TempDir
    lateinit var projectDir: Path

    @Test
    fun `fails when a web-stack dep is on the proxy runtime classpath`() {
        fixture(
            """
            plugins { java; id("smpp.runtime-purity") }
            repositories { mavenCentral() }
            dependencies {
                implementation(platform("org.springframework.boot:spring-boot-dependencies:4.1.0"))
                implementation("org.springframework.boot:spring-boot-starter")  // allowed (non-web)
                implementation("org.springframework:spring-web")                 // forbidden -> trips OBS-013
            }
            """
        )
        val result = runner("enforceRuntimeAllowlist").buildAndFail()
        assertEquals(TaskOutcome.FAILED, result.task(":enforceRuntimeAllowlist")?.outcome)
        assertTrue(result.output.contains("OBS-013"))
        assertTrue(result.output.contains("spring-web"))
    }

    @Test
    fun `passes when the runtime classpath has no web stack`() {
        fixture(
            """
            plugins { java; id("smpp.runtime-purity") }
            repositories { mavenCentral() }
            dependencies {
                implementation(platform("org.springframework.boot:spring-boot-dependencies:4.1.0"))
                implementation("org.springframework.boot:spring-boot-starter")  // legit non-web starter
            }
            """
        )
        val result = runner("enforceRuntimeAllowlist").build()
        assertEquals(TaskOutcome.SUCCESS, result.task(":enforceRuntimeAllowlist")?.outcome)
    }

    @Test
    fun `check fails when a web-stack dep is on the proxy runtime classpath`() {
        // P1: the gate must be wired into `check`, not merely invocable directly.
        fixture(
            """
            plugins { java; id("smpp.runtime-purity") }
            repositories { mavenCentral() }
            dependencies {
                implementation(platform("org.springframework.boot:spring-boot-dependencies:4.1.0"))
                implementation("org.springframework:spring-web")
            }
            """
        )
        val result = runner("check").buildAndFail()
        assertEquals(TaskOutcome.FAILED, result.task(":enforceRuntimeAllowlist")?.outcome)
        assertTrue(result.output.contains("OBS-013"))
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
