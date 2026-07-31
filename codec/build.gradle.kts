// PURE SMPP 3.4 codec module. RUNTIME classpath = io.netty:* + JDK stdlib ONLY (AD-7, AD-27); the
// compile classpath additionally carries compile-time-only annotations/codegen (jspecify, lombok).
// Enforced by the smpp.codec-purity gate (CODEC-040, positive control CODEC-041).

plugins {
    id("smpp.java-conventions")
    id("smpp.null-safety")
    id("smpp.codec-purity")
    id("io.freefair.lombok") version "9.5.0"
}

// Lombok version: 1.18.46 adds JDK 25 support (overrides the plugin's bundled default).
lombok {
    version = "1.18.46"
}

dependencies {
    // netty-bom 4.2.16.Final pins every io.netty artifact. Only buffer + codec are needed today;
    // their netty-common / netty-transport transitives remain inside the {io.netty} allowlist.
    implementation(platform("io.netty:netty-bom:4.2.16.Final"))
    implementation("io.netty:netty-buffer")
    implementation("io.netty:netty-codec")
    // AD-35 nullness annotations — compileOnly so codec RUNTIME stays {io.netty}+JDK (AD-7/AD-27).
    compileOnly("org.jspecify:jspecify:1.0.0")
    // Lombok is wired by the io.freefair.lombok plugin above (compileOnly + annotationProcessor for
    // every source set); compile-time-only, so codec RUNTIME stays {io.netty}+JDK (AD-7/AD-27) and
    // CODEC-040 allows org.projectlombok on the compile classpath.

    testImplementation(platform("org.junit:junit-bom:6.0.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core:3.27.7")
    testImplementation("com.tngtech.archunit:archunit-junit5:1.4.2") // CODEC-039 inward-only rule
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    // CODEC-031 (AC6): jSMPP 3.0.2 is the INTEROP-ONLY independent decode oracle — the 2nd oracle alongside
    // the hand-authored golden corpus (R33/R14). testImplementation ONLY (never production): it stays off the
    // main compileClasspath/runtimeClasspath, so CODEC-040's {io.netty, org.jspecify, org.projectlombok} main
    // gate and AD-7/AD-27 runtime purity are unaffected (the gate scans the MAIN configurations, not test).
    testImplementation("org.jsmpp:jsmpp:3.0.2")

    // AC7 (T6) fuzz + property testing. Jazzer + jqwik are JUnit Platform test engines; testImplementation
    // ONLY so they stay off the MAIN compile/runtime classpath and CODEC-040's {io.netty, org.jspecify,
    // org.projectlombok} main gate + AD-7/AD-27 runtime purity are unaffected (the gate scans MAIN
    // configurations, not test). Both execute on this toolchain's NATIVE JUnit Platform 6.0.3 — NO downgrade
    // is needed (the earlier "jqwik needs Platform 1.14.4" hypothesis was disproven: the real cause was
    // Jupiter annotations on @Property, below).
    //   • LOAD-BEARING jqwik gotcha (verified 2026-07-31): a Jupiter @DisplayName OR @Tag on a jqwik
    //     @Property method makes jqwik SILENTLY SKIP execution (the method is discovered but never run, and
    //     the build stays GREEN — a no-op-test trap that evades AC9/AC10). The @Property methods therefore
    //     carry NO Jupiter annotations; the display name + tier tags live at the CLASS level (which jqwik
    //     honors), and per-tier properties are split into separate classes. CODEC-011/025 (Jazzer @FuzzTest,
    //     regression mode via the Jupiter engine) are unaffected. See the Dev Agent Record.
    testImplementation("com.code-intelligence:jazzer-junit:0.24.0") // CODEC-011/025 fuzz (regression-mode PR tier; JAZZER_FUZZ=1 nightly)
    testImplementation("net.jqwik:jqwik:1.10.1")                     // CODEC-012/037/038 properties (Platform 6.0.3 native; annotation-free @Property methods)
}
