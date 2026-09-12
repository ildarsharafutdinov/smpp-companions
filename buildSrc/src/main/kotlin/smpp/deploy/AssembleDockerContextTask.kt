// Story 5.2 T3 — the daemon-free half of the Docker build wiring, extracted from `DockerImageTask`
// (5.2 T2) so the Testcontainers boot+smoke+parity suite can consume the SAME assembled context as
// a plain Gradle dependency + test input.
//
// Assembles the CLOSED, three-entry Docker build context over 5.2 T1's jlink runtime + 5.1's boot
// jar (never a second compile — FR-DEPLOY-1):
//
//   proxy/build/docker-image/
//     Dockerfile    <- proxy/src/docker/Dockerfile   (the version-controlled image definition)
//     jlink-image/  <- proxy/build/jlink-image/      (T1's modular runtime, modes NORMALIZED)
//     proxy.jar     <- proxy/build/libs/proxy.jar    (the ONE artifact, byte-for-byte)
//
// The context lives in build/ because both COPY sources are build outputs (a Dockerfile only COPYs
// from its own context); the assembly is also fail-closed by construction — any other context
// fails at the Dockerfile's first COPY, never producing a half-image. The context carries NO
// secret material of any kind (FR-DEPLOY-4 / SEC-098 build half): secrets are runtime mounts
// under /run/secrets read by the distroless non-root UID 65532 (T4 proves the contract).
//
// Unlike `dockerImage`, this task touches ONLY the local filesystem — no docker CLI, no daemon —
// so it is safely wired into `:proxy:test` (the suite builds the image ITSELF via Testcontainers'
// docker-build API from this context, keeping daemon-less builds GREEN through
// `disabledWithoutDocker`), and it is @CacheableTask with a TRACKED output: the Gradle
// incrementality of the shared context lives here, while the daemon-side image stays the
// non-cacheable `dockerImage` task's concern (a tracked image output would UP-TO-DATE-skip after
// a `docker rmi`/daemon restart — the T2 finding).
package smpp.deploy

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions

/**
 * Gradle task behind Story 5.2 T3's context dependency. Registered in `proxy/build.gradle.kts` as
 * `assembleDockerContext`; consumed by `dockerImage` (T2, runs the docker build over the assembled
 * context) and by `:proxy:test` (the T3 suite's Testcontainers image build reads the same three
 * entries, so the suite and the manual task can never drift onto two image definitions).
 */
@CacheableTask
abstract class AssembleDockerContextTask : DefaultTask() {

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

    /** The assembled build context (the documented surface for `dockerImage` and the T3 suite). */
    @get:OutputDirectory
    abstract val contextDirectory: DirectoryProperty

    @TaskAction
    fun assembleContext() {
        val dockerfileFile = dockerfile.get().asFile
        if (!dockerfileFile.isFile) {
            throw GradleException("Dockerfile not found: $dockerfileFile")
        }
        val runtime = runtimeImage.get().asFile
        if (!runtime.resolve("bin/java").isFile) {
            throw GradleException(
                "the jlink runtime has no bin/java under $runtime — the task must run after " +
                    ":proxy:jlinkRuntimeImage")
        }
        val jar = bootJar.get().asFile
        if (!jar.isFile) {
            throw GradleException("boot jar not found: $jar — the task must run after :proxy:bootJar")
        }

        // (1) assemble the closed context FRESH: exactly three entries, no secret material ever.
        // The stale-context wipe fails CLOSED — a silently-surviving leftover (locked/
        // permission-denied entry) could ride the image context as a fourth entry. Kotlin's
        // copyTo/copyRecursively do NOT carry POSIX modes (observed: jlink's 0775 bin/java
        // landed 0664 — the image then dies `permission denied` at exec), and mirroring the
        // source modes verbatim would make the image depend on the BUILD USER's umask (a 077
        // umask would ship a runtime only root can read — the container runs as UID 65532).
        // The modes are therefore NORMALIZED, below, deterministically.
        val context = contextDirectory.get().asFile
        if (context.exists() && !context.deleteRecursively()) {
            throw GradleException(
                "could not delete the stale docker context $context — refusing to assemble over " +
                    "leftover entries (stale files could ride the image build context)")
        }
        dockerfileFile.copyTo(context.resolve("Dockerfile"), overwrite = true)
        runtime.copyRecursively(context.resolve("jlink-image"), overwrite = true)
        jar.copyTo(context.resolve("proxy.jar"), overwrite = true)
        normalizeRuntimeModes(runtime, context.resolve("jlink-image"))
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

    private companion object {
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
