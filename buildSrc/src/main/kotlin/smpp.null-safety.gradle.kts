// AD-35: compile-time null-safety gate. NullAway (an Error Prone BugChecker) reads JSpecify
// @NullMarked nullness and FAILS `javac` at ERROR severity on any nullness violation — a fail-closed
// peer to CODEC-040 / SEC-099 / OBS-013, applied on BOTH modules. JSpecify is the annotation standard
// the Spring Framework 7 / Spring Boot 4 stack migrated to.
//
// Wiring: apply ONLY `net.ltgt.errorprone` — it registers the `errorprone` dependency configuration
// AND the `errorprone` extension on JavaCompile.options. NullAway is the `com.uber.nullaway:nullaway`
// *check* placed on that configuration; there is no separate `com.uber.nullaway` Gradle plugin (see
// Story 1.4 Dev Notes). Versions are impl-selected; the green build (AC6) is the mutual-compat proof.
// Applied DIRECTLY from codec/build.gradle.kts + proxy/build.gradle.kts after smpp.java-conventions.
//
// NOTE: net.ltgt.errorprone creates its configuration + extension at apply time, so a precompiled
// script plugin does NOT generate `errorprone { }` / `options.errorprone { }` accessors for them —
// hence the explicit `add(...)` + ExtensionAware lookup below (accessor-free, schema-independent).
import net.ltgt.gradle.errorprone.CheckSeverity
import net.ltgt.gradle.errorprone.ErrorProneOptions
import org.gradle.api.plugins.ExtensionAware
import org.gradle.api.tasks.compile.JavaCompile

plugins {
    id("net.ltgt.errorprone")
}

dependencies {
    // The `errorprone` configuration carries the analyzer jars javac loads via -Xplugin:ErrorProne.
    // Distinct version number from the net.ltgt.errorprone Gradle plugin (pinned in buildSrc/build.gradle.kts).
    add("errorprone", "com.google.errorprone:error_prone_core:2.50.0")
    add("errorprone", "com.uber.nullaway:nullaway:0.13.8")
}

tasks.withType<JavaCompile>().configureEach {
    // MAIN-ish compile tasks that must enforce NullAway. `compileJava` is the obvious one; `compileJmhJava`
    // (the proxy `jmh` sourceSet — Story 1.2 T7 / AC8 decision #3 hardening add #2) is opted in here so JMH
    // benchmark classes under `smpp.companion.*` are JSpecify-clean at ERROR severity (this file's own
    // comment prescribed widening the predicate when a MAIN-ish sourceSet arrives). `compileTestJava` and
    // every other JavaCompile stay in the `else` branch — test sources use AssertJ chains / Spring slices /
    // @TempDir that would false-positive (Dev Notes; code-review decision ②, 2026-07-25).
    val mainCompile = name == "compileJava" || name == "compileJmhJava"
    val errorprone = (options as ExtensionAware).extensions.getByType(ErrorProneOptions::class.java)
    if (mainCompile) {
        // fail-closed: a nullness violation fails javac (non-zero exit).
        errorprone.check("NullAway", CheckSeverity.ERROR)
        errorprone.option("NullAway:AnnotatedPackages", "smpp.companion")
        // load-bearing: reads JSpecify type-argument nullness (e.g. List<@Nullable String>); the AC4
        // positive control proves removing it silently disables the gate.
        errorprone.option("NullAway:JSpecifyMode", "true")
    } else {
        // Test sources are out of scope for v1 (Dev Notes): the test roots use AssertJ fluent chains /
        // Spring slices / @TempDir that would false-positive. MAIN compile only.
        errorprone.disable("NullAway")
    }
}
