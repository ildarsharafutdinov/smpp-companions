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
// (Nimbus ships 10.x.y). FAIL-LOUD on any non-numeric segment — a qualifier (RC/GA/SNAPSHOT/-Final)
// cannot be ordered by a numeric comparator, and silently coercing it to 0 (the old behavior) would
// let a malformed/qualified version pass the floor undetected. To gate a qualified coordinate, swap
// in org.apache.maven:maven-artifact ComparableVersion here.
fun mavenCompare(a: String, b: String): Int {
    fun pad(xs: List<String>, n: Int) = xs + List(n - xs.size) { "0" }
    val ax = a.split(".")
    val bx = b.split(".")
    val n = maxOf(ax.size, bx.size)
    for (i in 0 until n) {
        val at = pad(ax, n)[i]
        val bt = pad(bx, n)[i]
        val ai = at.toIntOrNull()
            ?: error("SEC-099: non-numeric version segment '$at' in '$a' — cannot order against floor '$b' (qualifier?); use ComparableVersion.")
        val bi = bt.toIntOrNull()
            ?: error("SEC-099: non-numeric version segment '$bt' in '$b' — cannot order against '$a' (qualifier?); use ComparableVersion.")
        if (ai != bi) return ai - bi
    }
    return 0
}
