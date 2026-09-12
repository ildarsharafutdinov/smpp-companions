// Story 5.2 T2 (DEPLOY-003/004/006 Docker halves, DEP-1) — the Docker build wiring for the ONE
// deploy artifact's second shape.
//
// Builds the distroless image over the CLOSED, three-entry Docker build context that
// `assembleDockerContext` (extracted in T3) assembles from 5.2 T1's jlink runtime + 5.1's boot
// jar (never a second compile — FR-DEPLOY-1):
//
//   proxy/build/docker-image/
//     Dockerfile    <- proxy/src/docker/Dockerfile   (the version-controlled image definition)
//     jlink-image/  <- proxy/build/jlink-image/      (T1's modular runtime, modes NORMALIZED)
//     proxy.jar     <- proxy/build/libs/proxy.jar    (the ONE artifact, byte-for-byte)
//
// The context lives in build/ because both COPY sources are build outputs (a Dockerfile only
// COPYs from its own context); the assembly is also fail-closed by construction — any other
// context fails at the Dockerfile's first COPY, never producing a half-image. The context carries
// NO secret material of any kind (FR-DEPLOY-4 / SEC-098 build half): secrets are runtime mounts
// under /run/secrets read by the distroless non-root UID 65532 (T4 proves the contract).
//
// Deliberately NOT wired into `build`/`check`/`test` and NOT @CacheableTask: the task's real
// output lives in the Docker DAEMON, invisible to Gradle, so a tracked output directory would let
// the task go UP-TO-DATE while the daemon no longer has the image (a `docker rmi`, a daemon
// restart) and silently skip the rebuild. The task therefore always builds when invoked, and
// DOCKER'S OWN LAYER CACHE is the incrementality mechanism (the runtime layer stays cached
// across code-only jar rebuilds; the Dockerfile COPYs it first for exactly that reason).
// Daemon-less environments stay GREEN by never invoking it — the same posture as the T3/T4
// Testcontainers suites' `disabledWithoutDocker` gate, which build their image from the SAME
// assembled context (their own declared test inputs — the stale-image trap, spec Design Notes).
package smpp.deploy

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Gradle task behind Story 5.2 T2. Registered in `proxy/build.gradle.kts` as `dockerImage`;
 * invoked explicitly (`./gradlew :proxy:dockerImage`). Fails closed — `GradleException` with the
 * captured tool output — when the CLI is absent, the daemon is unreachable, the build fails, or
 * the build exits 0 without leaving the tagged image behind.
 */
abstract class DockerImageTask : DefaultTask() {

    /**
     * The assembled build context (`assembleDockerContext`'s output — Dockerfile + jlink-image/ +
     * proxy.jar, modes already NORMALIZED there). An INPUT here, deliberately: the daemon-side
     * image is this task's only output and it is untracked (class comment), so the context both
     * feeds the build and pins the task's own re-run condition.
     */
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val contextDirectory: DirectoryProperty

    /** The tag `docker build --tag` applies (a local-development tag; release tagging is out of scope). */
    @get:Input
    abstract val imageTag: Property<String>

    @TaskAction
    fun buildImage() {
        val context = contextDirectory.get().asFile
        check(context.resolve("Dockerfile").isFile && context.resolve("proxy.jar").isFile
            && context.resolve("jlink-image").resolve("bin/java").isFile) {
            "the assembled context is incomplete under $context — the task must run after " +
                ":proxy:assembleDockerContext"
        }
        val tag = imageTag.get().trim()
        check(tag.isNotEmpty()) { "imageTag must be a non-empty docker tag" }

        val docker = resolveDockerBinary()

        // (1) build. Docker's layer cache is the incrementality mechanism (class comment).
        runTool(docker, "docker-build", listOf("build", "--tag", tag, context.absolutePath))

        // (2) fail closed on a build that did not leave the image behind, then log the size
        // (T5 records the measured size in the catalog; the task only reports it).
        val size = runTool(docker, "docker-inspect", listOf("image", "inspect", "--format", "{{.Size}}", tag))
            .trim()
        logger.lifecycle(
            "docker image built: {} ({} bytes) — run: docker run --rm {} <cell args>",
            tag, size, tag)
    }

    /** Resolves the `docker` CLI from PATH, refusing (never silently skipping) when absent. */
    private fun resolveDockerBinary(): File {
        for (dir in (System.getenv("PATH") ?: "").split(File.pathSeparator)) {
            if (dir.isNotBlank()) {
                val candidate = File(dir, "docker")
                // isFile FIRST: a searchable PATH entry named `docker` (a directory) also reports
                // canExecute() true, and handing it to ProcessBuilder dies as a raw IOException
                // instead of this task's fail-closed message.
                if (candidate.isFile && candidate.canExecute()) {
                    return candidate
                }
            }
        }
        throw GradleException(
            "the docker CLI was not found on PATH — :proxy:dockerImage requires the Docker CLI and " +
                "a reachable daemon. The task is deliberately NOT part of build/check: a daemon-less " +
                "environment simply never invokes it (the Testcontainers suites skip the same way, " +
                "disabledWithoutDocker).")
    }

    /**
     * T1's runner contract (`JlinkRuntimeImageTask.runTool`): output lands in temp files, never
     * pipes (a chatty docker stderr could deadlock a bounded pipe read); the run is deadline-
     * bounded so a wedged daemon fails the build instead of hanging it; a non-zero exit fails
     * CLOSED with the captured stdout/stderr.
     */
    private fun runTool(tool: File, label: String, args: List<String>): String {
        val stdout = temporaryDir.resolve("$label-stdout.txt")
        val stderr = temporaryDir.resolve("$label-stderr.txt")
        val process = ProcessBuilder(listOf(tool.absolutePath) + args)
            .redirectOutput(stdout)
            .redirectError(stderr)
            .start()
        if (!process.waitFor(TOOL_DEADLINE_MILLIS, TimeUnit.MILLISECONDS)) {
            process.destroyForcibly()
            process.waitFor()
            throw GradleException(
                "$label exceeded the ${TOOL_DEADLINE_MILLIS}ms deadline: ${tool.name} ${args.joinToString(" ")}")
        }
        val out = stdout.readText()
        if (process.exitValue() != 0) {
            throw GradleException(
                "$label failed (exit ${process.exitValue()}): ${tool.name} ${args.joinToString(" ")}\n" +
                    "--- stdout ---\n$out\n--- stderr ---\n${stderr.readText()}")
        }
        return out
    }

    private companion object {
        /** A first build pulls the base image and sends the ~140 MB context; 10 min is the backstop. */
        const val TOOL_DEADLINE_MILLIS = 10 * 60 * 1000L
    }
}
