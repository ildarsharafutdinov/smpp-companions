// CODEC-040: the codec module's COMPILE classpath may contain ONLY io.netty:* (+ JDK stdlib).
// Enforced at io.netty GROUP granularity (so netty-common/netty-transport transitives pass, but
// any org.springframework* / com.nimbusds* / io.micrometer* / smpp.companion.proxy leaks fail).
// This is the gate CODEC-041's positive control exercises via GradleTestKit.
// Applied to: the `codec` module. Prerequisite: `smpp.java-conventions` (provides `java`).
import org.gradle.api.artifacts.component.ModuleComponentIdentifier

// A Gradle resolution gate by design (NOT ArchUnit): ArchUnit can't see Maven group coordinates,
// the compile/runtime classpath split, or declared-but-unused deps. CODEC-039 owns the class-dep
// rule ArchUnit IS good at.

tasks.register("enforceDependencyAllowlist") {
    group = "verification"
    description = "CODEC-040: fail if the codec compile classpath contains a module outside {io.netty}."

    doLast {
        // Scan BOTH compile and runtime classpaths — a `runtimeOnly` non-netty dep (e.g. a logging
        // binding) would be invisible on compileClasspath alone (AC4/AD-7 codec purity).
        val offenders = listOf("compileClasspath", "runtimeClasspath")
            .flatMap { conf ->
                project.configurations.named(conf).get()
                    .incoming.resolutionResult.allComponents
                    .mapNotNull { it.id }
                    // filterIsInstance drops the project component (the codec module itself) and the
                    // JDK platform, keeping only external repo dependencies.
                    .filterIsInstance<ModuleComponentIdentifier>()
                    .filter { it.group != "io.netty" }
            }
            .distinctBy { "${it.group}:${it.module}:${it.version}" }
            .sortedBy { "${it.group}:${it.module}" }

        check(offenders.isEmpty()) {
            "CODEC-040: codec compile classpath contains module(s) outside the {io.netty} allowlist " +
                    "(only io.netty:* + JDK stdlib are permitted; AD-7 / AD-27): " +
                    offenders.joinToString(", ") { "${it.group}:${it.module}:${it.version}" }
        }
        logger.lifecycle("CODEC-040 OK — codec compile classpath is {io.netty} + JDK stdlib only.")
    }
}

tasks.named("check") { dependsOn("enforceDependencyAllowlist") }
