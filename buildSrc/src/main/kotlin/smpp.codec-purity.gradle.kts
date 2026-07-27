// CODEC-040: the codec module's classpath may contain ONLY io.netty:* (+ JDK stdlib), plus the
// org.jspecify annotations jar (AD-35 compile-time null-safety) and org.projectlombok (compile-time
// code generation). Both non-netty groups are compile-time-ONLY (compileOnly / annotationProcessor)
// so codec RUNTIME stays {io.netty}+JDK. Enforced at GROUP granularity (netty-common/-transport
// transitives pass; any org.springframework* / com.nimbusds* / io.micrometer* / smpp.companion.proxy
// leak fails). This is the gate CODEC-041's positive control exercises via GradleTestKit.
// Applied to: the `codec` module. Prerequisite: `smpp.java-conventions` (provides `java`).
import org.gradle.api.artifacts.component.ModuleComponentIdentifier

// A Gradle resolution gate by design (NOT ArchUnit): ArchUnit can't see Maven group coordinates,
// the compile/runtime classpath split, or declared-but-unused deps. CODEC-039 owns the class-dep
// rule ArchUnit IS good at.
val allowedGroups: Set<String> = setOf(
    "io.netty",          // codec's runtime substrate
    "org.jspecify",      // AD-35 compile-time nullness annotations (compileOnly)
    "org.projectlombok"  // compile-time code generation (compileOnly + annotationProcessor); zero runtime footprint
)

tasks.register("enforceDependencyAllowlist") {
    group = "verification"
    description =
        "CODEC-040: fail if the codec classpath contains a module outside {io.netty, org.jspecify, org.projectlombok}."

    doLast {
        // Scan BOTH compile and runtime classpaths — a non-allowed `runtimeOnly` dep (e.g. a logging
        // binding) would be invisible on compileClasspath alone (AC4/AD-7 codec purity). org.jspecify
        // and org.projectlombok are compile-time-only, so they appear on compileClasspath but never on
        // runtimeClasspath — codec RUNTIME stays {io.netty}+JDK (AD-7/AD-27).
        val offenders = listOf("compileClasspath", "runtimeClasspath")
            .flatMap { conf ->
                project.configurations.named(conf).get()
                    .incoming.resolutionResult.allComponents
                    .mapNotNull { it.id }
                    .filterIsInstance<ModuleComponentIdentifier>()
                    .filter { it.group !in allowedGroups }
            }
            .distinctBy { "${it.group}:${it.module}:${it.version}" }
            .sortedBy { "${it.group}:${it.module}" }

        check(offenders.isEmpty()) {
            "CODEC-040: codec classpath contains module(s) outside the {io.netty, org.jspecify, org.projectlombok} allowlist " +
                    "(only io.netty:* + org.jspecify + org.projectlombok + JDK stdlib are permitted; AD-7 / AD-27 / AD-35): " +
                    offenders.joinToString(", ") { "${it.group}:${it.module}:${it.version}" }
        }
        logger.lifecycle("CODEC-040 OK — codec classpath is {io.netty, org.jspecify, org.projectlombok} + JDK stdlib only.")
    }
}

tasks.named("check") { dependsOn("enforceDependencyAllowlist") }
