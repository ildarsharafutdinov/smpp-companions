// Story 5.2 T2 (DEPLOY-003/004/006 Docker halves, DEP-1) — the Docker build wiring for the ONE
// deploy artifact's second shape.
//
// Assembles the CLOSED, three-entry Docker build context and builds the distroless image over
// 5.2 T1's jlink runtime + 5.1's boot jar (never a second compile — FR-DEPLOY-1):
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
// restart) and silently skip the rebuild. The task therefore always assembles + builds when
// invoked, and DOCKER'S OWN LAYER CACHE is the incrementality mechanism (the runtime layer stays
// cached across code-only jar rebuilds; the Dockerfile COPYs it first for exactly that reason).
// Daemon-less environments stay GREEN by never invoking it — the same posture as the T3/T4
// Testcontainers suites' `disabledWithoutDocker` gate, which build their image from the SAME
// Dockerfile with their own declared test inputs (the stale-image trap, spec Design Notes).
package smpp.deploy

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit

/**
 * Gradle task behind Story 5.2 T2. Registered in `proxy/build.gradle.kts` as `dockerImage`;
 * invoked explicitly (`./gradlew :proxy:dockerImage`). Fails closed — `GradleException` with the
 * captured tool output — when the CLI is absent, the daemon is unreachable, the build fails, or
 * the build exits 0 without leaving the tagged image behind.
 */
abstract class DockerImageTask : DefaultTask() {

    /** The version-controlled image definition (`proxy/src/docker/Dockerfile`). */
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val dockerfile: RegularFileProperty

    /** T1's modular runtime — copied to the context root as `jlink-image/`. */
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val runtimeImage: DirectoryProperty

    /** The ONE boot jar (5.1's artifact) — copied to the context root as `proxy.jar`. */
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val bootJar: RegularFileProperty

    /** The tag `docker build --tag` applies (a local-development tag; release tagging is out of scope). */
    @get:Input
    abstract val imageTag: Property<String>

    /**
     * The assembled build context. Deliberately UNTRACKED (`@Internal` — see the class comment:
     * the real output is daemon-side, and a tracked context would invite a false UP-TO-DATE skip
     * after the daemon lost the image). Kept under `build/` rather than a temp dir because it is
     * also the documented surface for an ad-hoc `docker build` and T5's size evidence.
     */
    @get:Internal
    abstract val contextDirectory: DirectoryProperty

    @TaskAction
    fun buildImage() {
        val dockerfileFile = dockerfile.get().asFile
        check(dockerfileFile.isFile) { "Dockerfile not found: $dockerfileFile" }
        val runtime = runtimeImage.get().asFile
        check(runtime.resolve("bin/java").isFile) {
            "the jlink runtime has no bin/java under $runtime — the task must run after :proxy:jlinkRuntimeImage"
        }
        val jar = bootJar.get().asFile
        check(jar.isFile) { "boot jar not found: $jar — the task must run after :proxy:bootJar" }
        val tag = imageTag.get().trim()
        check(tag.isNotEmpty()) { "imageTag must be a non-empty docker tag" }

        val docker = resolveDockerBinary()
        val context = contextDirectory.get().asFile

        // (1) assemble the closed context FRESH: exactly three entries, no secret material ever.
        // Kotlin's copyTo/copyRecursively do NOT carry POSIX modes (observed: jlink's 0775
        // bin/java landed 0664 — the image then dies `permission denied` at exec), and mirroring
        // the source modes verbatim would make the image depend on the BUILD USER's umask (a 077
        // umask would ship a runtime only root can read — the container runs as UID 65532).
        // The modes are therefore NORMALIZED, below, deterministically.
        context.deleteRecursively()
        dockerfileFile.copyTo(context.resolve("Dockerfile"), overwrite = true)
        runtime.copyRecursively(context.resolve("jlink-image"), overwrite = true)
        jar.copyTo(context.resolve("proxy.jar"), overwrite = true)
        normalizeRuntimeModes(runtime, context.resolve("jlink-image"))

        // (2) build. Docker's layer cache is the incrementality mechanism (class comment).
        runTool(docker, "docker-build", listOf("build", "--tag", tag, context.absolutePath))

        // (3) fail closed on a build that did not leave the image behind, then log the size
        // (T5 records the measured size in the catalog; the task only reports it).
        val size = runTool(docker, "docker-inspect", listOf("image", "inspect", "--format", "{{.Size}}", tag))
            .trim()
        logger.lifecycle(
            "docker image built: {} ({} bytes) — run: docker run --rm {} <cell args>",
            tag, size, tag)
    }

    /**
     * Normalizes the copied runtime's file modes: directories `0755`; files that carry ANY exec
     * bit in the jlink output (the `bin/` launchers — java, jfr, jrunscript, keytool) `0755`;
     * every other file `0644`. Distroless has no chmod and no shell (spec Design Notes: modes
     * ride the copy), the image runs as UID 65532 (everything must be world-readable), and a
     * normalized set keeps the modes deterministic across builder umasks instead of inheriting
     * whatever mask the invoking user carried.
     */
    private fun normalizeRuntimeModes(sourceRoot: File, targetRoot: File) {
        val sourceBase = sourceRoot.toPath()
        Files.walk(sourceBase).use { walk ->
            for (source in walk) {
                val target = targetRoot.toPath().resolve(sourceBase.relativize(source).toString())
                val permissions =
                    if (Files.isDirectory(source) || hasExecuteBit(source)) DIR_OR_EXEC_MODE else FILE_MODE
                Files.setPosixFilePermissions(target, permissions)
            }
        }
    }

    /** True when the file carries ANY execute bit (the jlink `bin/` launchers do). */
    private fun hasExecuteBit(source: Path): Boolean =
        Files.getPosixFilePermissions(source).any { it in EXECUTE_BITS }

    /** Resolves the `docker` CLI from PATH, refusing (never silently skipping) when absent. */
    private fun resolveDockerBinary(): File {
        for (dir in (System.getenv("PATH") ?: "").split(File.pathSeparator)) {
            if (dir.isNotBlank()) {
                val candidate = File(dir, "docker")
                if (candidate.canExecute()) {
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

        private val EXECUTE_BITS = setOf(
            PosixFilePermission.OWNER_EXECUTE,
            PosixFilePermission.GROUP_EXECUTE,
            PosixFilePermission.OTHERS_EXECUTE,
        )

        /** Directories and jlink executables: rwxr-xr-x (0755). */
        private val DIR_OR_EXEC_MODE = PosixFilePermissions.fromString("rwxr-xr-x")

        /** Everything else (libs, conf, release): rw-r--r-- (0644). */
        private val FILE_MODE = PosixFilePermissions.fromString("rw-r--r--")
    }
}
