// Shared JVM build conventions for every smpp-companions module.
//   * Pins the JDK 25 Eclipse Temurin (Adoptium) toolchain — AC1 / DEPLOY-014 / SEC-085.
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
        // "Eclipse Temurin" is distributed by the Eclipse Adoptium working group; the JVM reports
        // java.vendor = "Eclipse Adoptium". There is NO JvmVendorSpec.ECLIPSE_TEMURIN — use ADOPTIUM.
        vendor.set(JvmVendorSpec.ADOPTIUM)
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
