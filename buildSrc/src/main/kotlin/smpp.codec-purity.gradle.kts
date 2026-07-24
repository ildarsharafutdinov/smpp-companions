// CODEC-040: the codec module's COMPILE classpath may contain ONLY io.netty:* (+ JDK stdlib).
// Enforced at io.netty GROUP granularity (so netty-common/netty-transport transitives pass, but
// any org.springframework* / com.nimbusds* / io.micrometer* / smpp.companion.proxy leaks fail).
// This is the gate CODEC-041's positive control exercises via GradleTestKit.
// Applied to: the `codec` module. Prerequisite: `smpp.java-conventions` (provides `java`).
import org.gradle.api.artifacts.component.ModuleComponentIdentifier

tasks.register("enforceDependencyAllowlist") {
    group = "verification"
    description = "CODEC-040: fail if the codec compile classpath contains a module outside {io.netty}."

    doLast {
        // filterIsInstance<ModuleComponentIdentifier> drops the project component (the codec module
        // itself) and the JDK platform, keeping only external repo dependencies.
        val offenders = project.configurations.named("compileClasspath").get()
            .incoming.resolutionResult.allComponents
            .mapNotNull { it.id }
            .filterIsInstance<ModuleComponentIdentifier>()
            .filter { it.group != "io.netty" }
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
