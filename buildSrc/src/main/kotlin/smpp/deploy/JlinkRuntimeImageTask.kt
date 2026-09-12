// Story 5.2 T1 (DEPLOY-001) — the Gradle-side jlink runtime for the ONE deploy artifact.
//
// Builds a modular runtime image of the toolchain JDK into `proxy/build/jlink-image/` for the
// 5.1 boot jar (never a second compile — FR-DEPLOY-1's one-artifact/two-shapes rule):
//
//   1. explode the boot jar's BOOT-INF/ (jdeps cannot read the nested fat jar directly — the
//      spec's Boundaries name the exploded layout as the analysis surface);
//   2. resolve the module set via `jdeps --print-module-deps` over that layout (BOOT-INF/classes
//      as the analysis root, every BOOT-INF/lib/*.jar on the class path, --recursive) — NEVER a
//      hand-maintained list, so it cannot drift from the actual jar (DEPLOY-001);
//   3. add the crypto floor ON TOP of the derived set: `jdk.crypto.ec` + `jdk.crypto.cryptoki`
//      load through the security-provider mechanism (statically invisible to jdeps) and
//      `java.management` rides the floor explicitly (jdeps omits it from --print-module-deps as
//      an already-implied root of jdk.management). The floor is additive — the jdeps output
//      stays the base and is recorded (pre-floor) beside the image as the derivation evidence.
//      The floor is DEFENSE-IN-DEPTH (2026-09-12 owner amendment, spec Change Log): T3's Docker
//      E2E stays GREEN without jdk.crypto.ec/cryptoki on the current RSA-fixture/JDK-25 path
//      (the predicted TLS-handshake/trust-store mechanisms do not fire), so the floor's real
//      bite is Gradle-input drift — a floor change re-runs this task, re-jlinks, and re-runs
//      the suites against the rebuilt image — plus forward defense for EC certs / HSM profiles;
//   4. `jlink --strip-debug --no-man-pages` into the image dir. The runtime is bootable and
//      testable WITHOUT Docker; the distroless Dockerfile (Story 5.2 T2) stays a thin COPY.
//
// The builder JDK is the javaToolchains-resolved toolchain JVM (the environment-supplied asdf
// pin — DEPLOY-014's stance: the JDK is a precondition, major-25 toolchain pin only), NOT
// whatever `jdeps`/`jlink` the PATH carries: asdf shims resolve per-CWD, so a build started
// outside the repo would otherwise silently build the runtime with asdf's global-default JDK
// (observed on this box: a JDK 21 runtime from the 25-pin repo dir). The temurin glibc output
// matches the distroless glibc base (spec Decisions).
package smpp.deploy

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.zip.ZipFile

/**
 * Gradle task behind Story 5.2 T1. Registered in `proxy/build.gradle.kts` as `jlinkRuntimeImage`
 * (kept in the `test` graph there so this task's fail-closed checks run in every build); the
 * floor is DEFENSE-IN-DEPTH (2026-09-12 owner amendment): T3's Docker E2E stays GREEN without
 * jdk.crypto.ec/cryptoki on the current RSA-fixture/JDK-25 path — the floor's real bite is
 * Gradle-input drift (a floor change re-runs this task, re-jlinks, and re-runs the suites
 * against the rebuilt image) plus forward defense for EC certs / HSM profiles.
 */
@CacheableTask
abstract class JlinkRuntimeImageTask : DefaultTask() {

    /** The ONE boot jar (5.1's artifact — packaged byte-for-byte, never rebuilt here). */
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val bootJar: RegularFileProperty

    /**
     * The DEPLOY-001 crypto floor added on top of the jdeps-derived set. Still a load-bearing
     * `@Input`: removing a floor module re-runs this task and rebuilds WITHOUT it (the derived
     * set never carries `jdk.crypto.ec`/`jdk.crypto.cryptoki`). The floor is DEFENSE-IN-DEPTH
     * (2026-09-12 owner amendment): T3's Docker E2E stays GREEN on a runtime built without it —
     * the RSA-fixture handshake and the PKCS12 load need no SunEC/cryptoki on JDK 25 — so this
     * `@Input`'s bite is Gradle-input drift (floor change → re-jlink → the suites re-run against
     * the rebuilt image, and the floor-presence row fails if a module went missing) plus forward
     * defense for EC certs / HSM profiles.
     */
    @get:Input
    abstract val cryptoFloor: ListProperty<String>

    /**
     * The `--multi-release` version jdeps reads MR jars at (the toolchain's major). REQUIRED,
     * not cosmetic: a lib on the class path (commons-logging) is a multi-release jar and jdeps
     * exits 2 without the flag.
     */
    @get:Input
    abstract val multiReleaseVersion: Property<String>

    /**
     * The runtime image (`jlink --output`). Only jlink's own output may live here — the Docker
     * build context (Story 5.2 T2) COPYs this directory wholesale.
     */
    @get:OutputDirectory
    abstract val imageDirectory: DirectoryProperty

    /**
     * The recorded jdeps-derived set (pre-floor, one module name per line) — DEPLOY-001's
     * derivation evidence: what the static analysis of the ACTUAL jar resolved, kept beside the
     * image for review/catalog reads (no test consumes it since the 2026-09-11 owner decision).
     */
    @get:OutputFile
    abstract val derivedModulesFile: RegularFileProperty

    /**
     * The toolchain JDK the image is built from — an environment precondition per DEPLOY-014,
     * deliberately UNTRACKED (`@Internal`): the standing pin is the major-25 toolchain + the
     * asdf environment, and the build performs no JDK-version comparison (owner decision
     * 2026-09-10).
     */
    @get:Internal
    abstract val builderJdkHome: DirectoryProperty

    @TaskAction
    fun buildRuntimeImage() {
        val jar = bootJar.get().asFile
        check(jar.isFile) { "boot jar not found: $jar — the task must run after :proxy:bootJar" }
        val jdkBin = builderJdkHome.get().asFile.resolve("bin")
        val jdeps = requireTool(jdkBin, "jdeps")
        val jlink = requireTool(jdkBin, "jlink")

        // (1) explode BOOT-INF (jdeps cannot read the nested fat jar directly). The stale-tree
        // wipe fails CLOSED: a silently-surviving leftover (locked/permission-denied entry) would
        // leave removed-dependency lib jars in the analysis set and skew the jdeps resolution.
        val exploded = temporaryDir.resolve("exploded")
        if (exploded.exists() && !exploded.deleteRecursively()) {
            throw GradleException(
                "could not delete the stale exploded tree $exploded — refusing to run jdeps over " +
                    "leftover BOOT-INF content (stale lib jars would skew the derived module set)")
        }
        explodeBootInf(jar, exploded)
        val classesDir = exploded.resolve("BOOT-INF/classes")
        val libJars = exploded.resolve("BOOT-INF/lib")
            .listFiles { file -> file.isFile && file.extension == "jar" }
            .orEmpty()
            .sortedBy { it.name }
        check(classesDir.isDirectory && libJars.isNotEmpty()) {
            "the exploded boot jar carries no BOOT-INF/classes + BOOT-INF/lib (is $jar a Spring Boot fat jar?)"
        }
        val classpath = (listOf(classesDir) + libJars).joinToString(File.pathSeparator) { it.absolutePath }

        // (2) the jdeps-derived set. --ignore-missing-deps keeps optional dependencies (e.g. the
        // Netty marshalling module nothing in this jar touches) from failing the analysis; the
        // app classes stay the sole analysis ROOT — naming the lib jars as roots makes jdeps
        // switch to module resolution and die on those same optional requires.
        val derived = runTool(
            jdeps,
            listOf(
                "--print-module-deps",
                "--ignore-missing-deps",
                "--recursive",
                "--multi-release", multiReleaseVersion.get(),
                "--class-path", classpath,
                classesDir.absolutePath,
            ),
        )
            .trim()
            .split(Regex("[,\\s]+"))
            .filter { it.isNotBlank() }
            .toSortedSet()
        check(derived.isNotEmpty()) { "jdeps derived an EMPTY module set from $jar — refusing to jlink" }

        // (3) the floor ON TOP (union): the derived set stays the base, a wholly hand-written
        // list being the drift DEPLOY-001 forbids.
        val floor = cryptoFloor.get().toSortedSet()
        val addModules = (derived + floor).joinToString(",")

        // (4) jlink. The task owns the output directory wholesale — jlink refuses a dirty target.
        val image = imageDirectory.get().asFile
        image.deleteRecursively()
        runTool(
            jlink,
            listOf(
                "--add-modules", addModules,
                "--strip-debug",
                "--no-man-pages",
                "--output", image.absolutePath,
            ),
        )
        check(image.resolve("bin/java").isFile) { "jlink produced no bin/java under $image" }

        // (5) record the derived set (PRE-floor) as the derivation evidence beside the image.
        derivedModulesFile.get().asFile.writeText(derived.joinToString(separator = "\n", postfix = "\n"))

        logger.lifecycle(
            "jlink runtime image: {} — {} add-modules ({} jdeps-derived + floor {}), derived set recorded in {}",
            image,
            derived.size + floor.size,
            derived.size,
            floor,
            derivedModulesFile.get().asFile.name,
        )
    }

    /**
     * Extracts the fat jar's BOOT-INF tree (app classes + dependency jars). The Spring Boot
     * loader classes are not extracted: they are not part of the analyzed surface (the app's
     * main class runs from BOOT-INF; the loader is on the jar's own classpath at `java -jar`).
     * Entry names come from this project's own bootJar — trusted input, no zip-slip hardening.
     */
    private fun explodeBootInf(jar: File, into: File) {
        ZipFile(jar).use { zip ->
            for (entry in zip.entries()) {
                if (!entry.name.startsWith("BOOT-INF/")) {
                    continue
                }
                val target = into.resolve(entry.name)
                if (entry.isDirectory) {
                    target.mkdirs()
                } else {
                    target.parentFile.mkdirs()
                    zip.getInputStream(entry).use { input ->
                        target.outputStream().use { output -> input.copyTo(output) }
                    }
                }
            }
        }
    }

    private fun requireTool(jdkBin: File, tool: String): File {
        val file = jdkBin.resolve(tool)
        check(file.isFile) {
            "$tool not found in the builder JDK ($file) — the toolchain JDK must carry the modular-image tools"
        }
        return file
    }

    /**
     * Runs a JDK tool to completion. Output lands in temp files, never pipes (a chatty jdeps
     * stderr could deadlock a bounded pipe read), and the run is deadline-bounded so a wedged
     * tool fails the build instead of hanging it. A non-zero exit fails CLOSED with the
     * captured stdout/stderr — never a partially-trusted module set.
     */
    private fun runTool(tool: File, args: List<String>): String {
        val stdout = temporaryDir.resolve("${tool.name}-stdout.txt")
        val stderr = temporaryDir.resolve("${tool.name}-stderr.txt")
        val process = ProcessBuilder(listOf(tool.absolutePath) + args)
            .redirectOutput(stdout)
            .redirectError(stderr)
            .start()
        if (!process.waitFor(TOOL_DEADLINE_MILLIS, TimeUnit.MILLISECONDS)) {
            process.destroyForcibly()
            process.waitFor()
            throw GradleException(
                "$tool exceeded the ${TOOL_DEADLINE_MILLIS}ms deadline: ${tool.name} ${args.joinToString(" ")}")
        }
        val out = stdout.readText()
        if (process.exitValue() != 0) {
            throw GradleException(
                "$tool failed (exit ${process.exitValue()}): ${tool.name} ${args.joinToString(" ")}\n" +
                    "--- stdout ---\n$out\n--- stderr ---\n${stderr.readText()}")
        }
        return out
    }

    private companion object {
        /** jdeps/jlink each complete in seconds on this jar; 5 minutes is the wedged-tool backstop. */
        const val TOOL_DEADLINE_MILLIS = 5 * 60 * 1000L
    }
}
