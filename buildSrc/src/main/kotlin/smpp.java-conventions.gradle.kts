// Shared JVM build conventions for every smpp-companions module.
//   * Requires JDK 25 (languageVersion pin) — DEPLOY-014 / SEC-085. The JDK is a PRECONDITION
//     supplied by the environment (asdf .tool-versions locally; a CI setup step / image later), NOT
//     auto-provisioned by the build, and the vendor is intentionally not pinned.
//     (Relaxed from an Eclipse-Temurin-only vendor pin + foojay auto-provisioning on 2026-07-25.)
//   * Applies --enable-preview process-wide (compile + test + run) so JEP 505 StructuredTaskScope
//     preview semantics are locked BEFORE any preview code is authored — AD-5.
import org.gradle.api.tasks.JavaExec
import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.api.tasks.testing.Test

plugins {
    `java-library`
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("--enable-preview")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    jvmArgs("--enable-preview")
}

tasks.withType<JavaExec>().configureEach {
    // Covers Spring Boot's `bootRun` (BootRun extends JavaExec) too.
    jvmArgs("--enable-preview")
}
