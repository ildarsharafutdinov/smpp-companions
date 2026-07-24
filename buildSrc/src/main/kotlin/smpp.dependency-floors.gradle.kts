// SEC-099 (deterministic CVE-floor gate): fails the build if any dependency resolves BELOW a
// known-CVE fix line. Fast / offline / deterministic — this is the GradleTestKit positive control.
// The real OWASP dependency-check 12.2.2 run (SEC-091) is a SEPARATE, networked CI lane (see the
// root build); this gate does not pretend to be a CVE-database lookup, only a pinned-floor guard.
//   CVE-2025-53864 -> Nimbus JOSE+JWT < 10.0.2 ; floor 10.0.2.
import org.gradle.api.artifacts.component.ModuleComponentIdentifier

val dependencyFloors: Map<String, String> = mapOf(
    "com.nimbusds:nimbus-jose-jwt" to "10.0.2" // CVE-2025-53864 (DoS, CWE-674)
)

tasks.register("enforceDependencyFloors") {
    group = "verification"
    description = "SEC-099: fail if a dependency resolves below a known-CVE fix line " +
        "(CVE-2025-53864 floor: Nimbus >= 10.0.2)."

    doLast {
        val resolved = project.configurations.named("runtimeClasspath").get()
            .incoming.resolutionResult.allComponents
            .mapNotNull { it.id }
            .filterIsInstance<ModuleComponentIdentifier>()

        val violations = resolved.mapNotNull { id ->
            val key = "${id.group}:${id.module}"
            val floor = dependencyFloors[key] ?: return@mapNotNull null
            if (mavenCompare(id.version, floor) < 0) {
                "$key:${id.version} is BELOW the required floor $floor (CVE-2025-53864)"
            } else null
        }
        check(violations.isEmpty()) {
            "SEC-099: dependency security floor violated (known CVE):\n  " +
                violations.joinToString("\n  ")
        }
        logger.lifecycle("SEC-099 OK — all dependencies meet their CVE floors.")
    }
}

tasks.named("check") { dependsOn("enforceDependencyFloors") }

// Numeric dotted Maven comparator. Sufficient for this project's clean numeric coordinates
// (Nimbus ships 10.x.y). Swap in org.apache.maven:maven-artifact ComparableVersion if a coordinate
// with RC/GA/SNAPSHOT qualifiers is ever gated.
fun mavenCompare(a: String, b: String): Int {
    fun pad(xs: List<String>, n: Int) = xs + List(n - xs.size) { "0" }
    val ax = a.split(".")
    val bx = b.split(".")
    val n = maxOf(ax.size, bx.size)
    for (i in 0 until n) {
        val ai = pad(ax, n)[i].toIntOrNull() ?: 0
        val bi = pad(bx, n)[i].toIntOrNull() ?: 0
        if (ai != bi) return ai - bi
    }
    return 0
}
