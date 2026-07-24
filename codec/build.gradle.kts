// PURE SMPP 3.4 codec module. Compile classpath = io.netty:* + JDK stdlib ONLY (AD-7, AD-27),
// enforced by the smpp.codec-purity gate (CODEC-040, positive control CODEC-041).

plugins {
    id("smpp.java-conventions")
    id("smpp.codec-purity")
}

dependencies {
    // netty-bom 4.2.16.Final pins every io.netty artifact. Only buffer + codec are needed today;
    // their netty-common / netty-transport transitives remain inside the {io.netty} allowlist.
    implementation(platform("io.netty:netty-bom:4.2.16.Final"))
    implementation("io.netty:netty-buffer")
    implementation("io.netty:netty-codec")

    testImplementation(platform("org.junit:junit-bom:6.0.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core:3.27.7")
    testImplementation("com.tngtech.archunit:archunit-junit5:1.4.2") // CODEC-039 inward-only rule
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
