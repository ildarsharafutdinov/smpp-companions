// Runnable Spring Boot 4.1 proxy application. NO embedded web server (AD-16). Owns config / DI /
// lifecycle / Micrometer; Netty is driven directly. Depends INWARD on the pure `codec` module.

import org.gradle.jvm.toolchain.JavaToolchainService
import smpp.deploy.AssembleDockerContextTask
import smpp.deploy.DockerImageTask
import smpp.deploy.JlinkRuntimeImageTask

plugins {
    id("smpp.java-conventions")
    id("smpp.null-safety")
    id("smpp.dependency-floors")
    id("smpp.runtime-purity")
    id("org.springframework.boot") version "4.1.0"
    id("io.spring.dependency-management") version "1.1.7"
    id("org.owasp.dependencycheck") // SEC-091 CI lane — configured below, NOT wired into `check`
    id("me.champeau.jmh") version "0.7.3" // PERF-001..006 (AC8): JMH codec microbenchmarks (`src/jmh`); nightly-tier
    id("io.freefair.lombok") version "9.5.0"
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
    implementation("io.netty:netty-codec-http")             // /metrics endpoint HttpServerCodec (Epic 4); version via netty-bom
    implementation("com.nimbusds:nimbus-jose-jwt:10.9.1")   // JWT adjudication (Epic 3); >= 10.0.2 floor
    implementation("io.micrometer:micrometer-registry-prometheus") // version managed by SB BOM (1.17.0)
    implementation("net.logstash.logback:logstash-logback-encoder:8.1") // JSON-lines logging (Epic 4); NOT BOM-managed — pinned; brings jackson-databind transitively (first Jackson on the proxy classpath — logging-internal only)
    implementation(project(":codec"))                       // inward seam

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("com.tngtech.archunit:archunit-junit5:1.4.2") // SEC-090 scaffold
    // Story 2.1 fixture: Keycloak managed by the test JVM via Testcontainers (replaces docker-compose).
    // Versions come from Spring Boot 4.1's imported testcontainers-bom:2.0.5 (testcontainers.version). NOTE:
    // Testcontainers 2.x renamed the JUnit-Jupiter module junit-jupiter -> testcontainers-junit-jupiter (the
    // old coordinate has no 2.0.x release). Verified Docker-Engine-29 + JDK-25 --enable-preview compatible
    // (smoke run). Test-only -> not on runtimeClasspath, so OBS-013 (runtime purity) / SEC-099 (CVE floors)
    // are unaffected.
    testImplementation("org.testcontainers:testcontainers")
    testImplementation("org.testcontainers:testcontainers-junit-jupiter")
    // Story 2.2 T10 (OBS-038): jSMPP 3.0.2 server-side mock — the INDEPENDENT A-1 conformance oracle
    // (shares NEITHER the production codec's bugs NOR its A-1 assumption; AD-24). testImplementation
    // ONLY (never the production codec — the mirror of codec/build.gradle.kts:38): stays off the main
    // compile/runtime classpaths, so OBS-013 runtime purity / SEC-099 floors (main-configuration
    // gates) are unaffected.
    testImplementation("org.jsmpp:jsmpp:3.0.2")
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
// Story 5.1 T1 (DEPLOY-003 JAR half) — the runnable JAR becomes a first-class deploy shape. Two
// explicit pins replace the bootJar plugin defaults:
//   * Pinned main class — the entrypoint never silently follows main-class discovery.
//   * Stable version-free archive name — operators, the packaged smoke (T5), and the later Docker
//     entrypoint all reference ONE filename across releases (version stays in the manifest).
// Deliberately NO Enable-Preview manifest attribute (owner amendment, 2026-09-10): it is INERT on
// the pinned JDK 25 launcher — the runtime image carries Add-Exports/Add-Opens/Enable-Native-Access
// arms but no Enable-Preview arm (proven on temurin 25.0.3+9: bare `java -jar` of a valid
// reverse-B cell dies UnsupportedClassVersionError at the first preview-marked class, attribute
// present or not). The LOAD-BEARING preview mechanism is the operator flag contract's
// --enable-preview (Story 5.1 T2); no launch configuration travels in the manifest.
tasks.bootJar {
    mainClass.set("smpp.companion.proxy.ProxyCompanionApplication")
    archiveFileName.set("proxy.jar")
}

// Story 5.2 T1 (DEPLOY-001) — the Gradle jlink runtime image: the SAME boot jar above, packaged
// over a jlink-built modular runtime into `proxy/build/jlink-image/` (never a second compile —
// FR-DEPLOY-1's one-artifact/two-shapes rule). The module set is resolved by the task from the
// ACTUAL jar (explode BOOT-INF, `jdeps --print-module-deps`, --recursive) with the crypto floor
// (`jdk.crypto.ec` + `jdk.crypto.cryptoki` — security-provider loaded, statically invisible to
// jdeps — plus `java.management`) added ON TOP; a wholly hand-written --add-modules list is the
// drift DEPLOY-001 forbids. The builder JDK is the javaToolchains-resolved toolchain JVM (the
// environment-supplied asdf pin, DEPLOY-014's precondition stance) — NOT the `jdeps`/`jlink` on
// PATH, which asdf resolves per-CWD (a build started outside the repo would otherwise use the
// global-default JDK). The runtime boots without Docker; Story 5.2 T2's Dockerfile stays a thin
// COPY of this directory. The task records the pre-floor jdeps set beside the image
// (`build/jlink-derived-modules.txt`) as DEPLOY-001's derivation evidence.
val toolchainLauncher = the<JavaToolchainService>().launcherFor(java.toolchain)
val jlinkRuntimeImage = tasks.register<JlinkRuntimeImageTask>("jlinkRuntimeImage") {
    group = "build"
    description =
        "Story 5.2 T1 (DEPLOY-001): jlink the toolchain JDK over the jdeps-derived module set + " +
            "crypto floor into build/jlink-image/ — the distroless Docker runtime (bootable without Docker)"
    dependsOn(tasks.bootJar)
    bootJar.set(tasks.bootJar.flatMap { it.archiveFile })
    cryptoFloor.set(listOf("jdk.crypto.ec", "jdk.crypto.cryptoki", "java.management"))
    imageDirectory.set(layout.buildDirectory.dir("jlink-image"))
    derivedModulesFile.set(layout.buildDirectory.file("jlink-derived-modules.txt"))
    builderJdkHome.set(toolchainLauncher.map { it.metadata.installationPath })
    multiReleaseVersion.set(toolchainLauncher.map { it.metadata.languageVersion.toString() })
}

// Story 5.2 T2 -> T3 — the assembled Docker build context (daemon-free): exactly three entries
// (Dockerfile + jlink-image/ + proxy.jar, runtime modes NORMALIZED — see the task class) under
// `build/docker-image/`. Extracted from `dockerImage` in T3 so `:proxy:test` can consume the SAME
// context as a plain dependency + test input: the T3 Testcontainers suite builds the image itself
// via the docker-build API from these three entries, so the suite and the manual `dockerImage`
// task can never drift onto two image definitions, while daemon-less builds stay GREEN (the
// assembly touches only the local filesystem; the suite itself skips per disabledWithoutDocker).
val assembleDockerContext = tasks.register<AssembleDockerContextTask>("assembleDockerContext") {
    group = "build"
    description =
        "Story 5.2 T2/T3: assemble the closed docker context (Dockerfile + jlink runtime + proxy.jar, " +
            "modes normalized) into build/docker-image/ — shared by :proxy:dockerImage and the T3 suite"
    dependsOn(jlinkRuntimeImage)
    dependsOn(tasks.bootJar)
    dockerfile.set(layout.projectDirectory.file("src/docker/Dockerfile"))
    runtimeImage.set(jlinkRuntimeImage.flatMap { it.imageDirectory })
    bootJar.set(tasks.bootJar.flatMap { it.archiveFile })
    contextDirectory.set(layout.buildDirectory.dir("docker-image"))
}

// Story 5.2 T2 (DEPLOY-003/004/006 Docker halves + the DEP-1 posture) — the distroless image
// wiring: `proxy/src/docker/Dockerfile` (the image definition — distroless base-debian12:nonroot,
// the jlink runtime + proxy.jar COPYs, exec-form ENTRYPOINT carrying the ONE operator flag set
// verbatim, `CMD []` cell-args pass-through, USER nonroot 65532, no secret material in any layer)
// plus this build task. `dockerImage` builds over the assembled context (tag smpp-proxy:local) —
// see the task class for why it is deliberately NOT wired into build/check/test and not
// cacheable: the image lives in the Docker daemon, invisible to Gradle, and daemon-less builds
// must stay GREEN. T3/T4's Testcontainers suites build from the SAME assembled context with their
// own declared test inputs (the stale-image trap), so both paths share one image definition.
tasks.register<DockerImageTask>("dockerImage") {
    group = "build"
    description =
        "Story 5.2 T2 (DEPLOY-003/004/006, DEP-1): docker-build the assembled context into the " +
            "distroless image (tag smpp-proxy:local) and fail closed on inspect"
    dependsOn(assembleDockerContext)
    contextDirectory.set(assembleDockerContext.flatMap { it.contextDirectory })
    imageTag.set("smpp-proxy:local")
}

tasks.named("test") {
    dependsOn("compileJmhJava")
    // A1CarrierPlanDocsTest reads this doc at runtime — declare it as a test input so a docs-only edit
    // cannot leave the task UP-TO-DATE and silently skip the OBS-035/036/037 falsifiability gate
    // (the runtime-file-read Gradle trap; 2.2 review F17, 2026-08-17).
    inputs.file(layout.projectDirectory.file("../docs/a-1-carrier-test-plan.md"))
    // Story 5.1 T1/T5: the packaged boot+smoke test `java -jar`s the REAL bootJar as a subprocess,
    // so the jar must exist before tests run (dependsOn) — and the test must re-run when the jar
    // changes (inputs.file; the same runtime-file-read Gradle trap as the doc input above, else an
    // incremental run executes the smoke against a stale jar).
    dependsOn(tasks.bootJar)
    inputs.file(tasks.bootJar.flatMap { it.archiveFile })
    // Story 5.2 T1 (DEPLOY-001, owner-amended 2026-09-11: "image run is gate, no extra test is
    // required" — the module-set test row was dropped): the jlink task stays in the test graph
    // so its own fail-closed checks (empty jdeps-derived set, jdeps/jlink failure) run in every
    // build. HISTORICAL NOTE: this T1 block itself declares NO image/derived-file inputs (the
    // T1-era module-set test that read them was owner-dropped); the T3 block below carries the
    // image inputs the Docker suites actually read (the stale-image trap, spec Design Notes).
    dependsOn(jlinkRuntimeImage)
    // Story 5.2 T3 — the Docker boot+smoke+parity suite builds the image ITSELF (Testcontainers
    // docker-build API) from the assembled context, so the context is both a DEPENDENCY (it must
    // exist before tests run) and a set of INPUTS (the stale-image trap, spec Design Notes: a
    // Dockerfile/jlink-runtime/jar change must re-run the suite against the rebuilt image — the
    // 5.1 `inputs.file(bootJar)` pattern extended to everything the image bakes). The ASSEMBLED
    // CONTEXT DIRECTORY itself is an input too, closing the buildSrc trap: a change to the
    // assembly logic (e.g. AssembleDockerContextTask's mode normalization in buildSrc) can
    // produce a DIFFERENT context from unchanged sources — naming the output dir makes the
    // suites re-run against that re-assembled context instead of staying UP-TO-DATE on the
    // three source declarations alone. The daemon-free assembly keeps daemon-less builds GREEN;
    // the suite skips per disabledWithoutDocker.
    dependsOn(assembleDockerContext)
    inputs.file(layout.projectDirectory.file("src/docker/Dockerfile"))
    inputs.dir(jlinkRuntimeImage.flatMap { it.imageDirectory })
    inputs.dir(assembleDockerContext.flatMap { it.contextDirectory })
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
