// buildSrc compiles the convention plugins that carry the load-bearing gates (CODEC-040/041,
// SEC-099, OBS-013/043) AND their GradleTestKit positive-control tests. `kotlin-dsl` applies
// `java-gradle-plugin`, which generates the plugin-under-test-metadata that lets
// GradleRunner.withPluginClasspath() inject the REAL gate plugin into an isolated fixture —
// so the tests exercise the actual gate code, not a copy (the silent-bypass risk the story flags).
plugins {
    `kotlin-dsl`
}

// buildSrc is its own implicit build and does NOT inherit the root dependencyResolutionManagement,
// so repositories are declared here.
repositories {
    gradlePluginPortal()
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:6.0.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation(gradleTestKit()) // GradleRunner / BuildResult / TaskOutcome — from the 9.6.1 distribution
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}
