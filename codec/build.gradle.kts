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
}
