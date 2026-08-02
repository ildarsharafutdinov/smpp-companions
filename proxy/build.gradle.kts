// Runnable Spring Boot 4.1 proxy application. NO embedded web server (AD-16). Owns config / DI /
// lifecycle / Micrometer; Netty is driven directly. Depends INWARD on the pure `codec` module.

plugins {
    id("smpp.java-conventions")
    id("smpp.null-safety")
    id("smpp.dependency-floors")
    id("smpp.runtime-purity")
    id("org.springframework.boot") version "4.1.0"
    id("io.spring.dependency-management") version "1.1.7"
    id("org.owasp.dependencycheck") // SEC-091 CI lane — configured below, NOT wired into `check`
    id("me.champeau.jmh") version "0.7.3" // PERF-001..006 (AC8): JMH codec microbenchmarks (`src/jmh`); nightly-tier
}

// Spring Boot 4.1.0 manages Netty to 4.2.15.Final; the story pins 4.2.16.Final, so override the
// managed version (io.spring.dependency-management honors the standard `netty.version` property).
extra["netty.version"] = "4.2.16.Final"

dependencies {
    // NON-web starter -> plain AnnotationConfigApplicationContext, no embedded server.
    implementation("org.springframework.boot:spring-boot-starter")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.jspecify:jspecify:1.0.0") // AD-35 nullness annotations (on the classpath Spring 7 already uses)
    implementation(platform("io.netty:netty-bom:4.2.16.Final"))
    implementation("io.netty:netty-transport")              // NIO/Epoll transport (relay-ready, Epic 2)
    implementation("io.netty:netty-handler")                // SSLHandler / SSLEngine wiring (Epic 3)
    implementation("com.nimbusds:nimbus-jose-jwt:10.9.1")   // JWT adjudication (Epic 3); >= 10.0.2 floor
    implementation("io.micrometer:micrometer-registry-prometheus") // version managed by SB BOM (1.17.0)
    implementation(project(":codec"))                       // inward seam

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("com.tngtech.archunit:archunit-junit5:1.4.2") // SEC-090 scaffold
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    // T7-c (AC8): let the proxy ArchUnit jmh-isolation test analyze the compiled JMH benchmark classes.
    // Pulls ONLY the jmh source-set output (compiled by `compileJmhJava` — plain javac, no JMH bytecode-
    // generator ASM) so a JMH breakage still cannot fail the PR build (nightly-tier); the explicit
    // `test` -> `compileJmhJava` edge is declared below.
    testImplementation(sourceSets.getByName("jmh").output)
}

// AC8 / PERF-001..006 (Story 1.2 T7; decision #3 RESOLVED): JMH codec microbenchmarks live in the `jmh`
// sourceSet (`src/jmh/java/smpp/companion/jmh/`), run via `./gradlew :proxy:jmh`. The `jmh` task chain —
// including the JMH bytecode generator whose ASM is unverified on JDK 25 — is NOT wired into `build`/`check`,
// so a JMH breakage cannot fail the PR build (nightly-tier). Only `compileJmhJava` (plain javac) is pulled
// into `:proxy:test` so the ArchUnit jmh-isolation guard (T7-c) sees the compiled benchmark classes. Pin
// JMH 1.37 (the plugin default); bump `jmhVersion` here if the JDK-25 smoke test fails at bytecode generation.
jmh {
    jmhVersion.set("1.37")
    // Benchmarks depend ONLY on the pure codec (AD-7), never on test sources — and `includeTests = false`
    // breaks the test<->jmh cycle our T7-c `testImplementation(jmh.output)` edge would otherwise create
    // (jmh -> test via the plugin's default includeTests=true, test -> jmh via that edge).
    includeTests.set(false)
}
tasks.named("test") {
    dependsOn("compileJmhJava")
}

// SEC-091: OWASP dependency-check CI lane. Deliberately NOT wired into `check`, so `./gradlew build`
// stays fast and green (AC1). CI invokes it explicitly: ./gradlew :proxy:dependencyCheckAnalyze --no-parallel
dependencyCheck {
    // CVE-2025-53864 CNA score is 5.8 (NVD "Awaiting Analysis" / unscored as of 2026-07); a 5.0
    // threshold is INTENDED to trip it. NOTE: dependency-check may not fail on NVD-unscored CVEs
    // without failOnUnscored, so this CI lane is defense-in-depth only — the deterministic SEC-099
    // floor gate (enforceDependencyFloors) is the load-bearing Nimbus >= 10.0.2 enforcement.
    // (failBuildOnCVSS is typed Float in the OWASP extension.)
    failBuildOnCVSS = 5.0f
    failOnError = true
    formats = listOf("HTML", "JSON", "SARIF", "JUNIT")
    nvd.apiKey = (System.getenv("NVD_API_KEY") ?: "").ifEmpty { null }
}
