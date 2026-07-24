package smpp.companion.proxy.bootstrap;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC1 / DEPLOY-014 / SEC-085 (gate-exists form): the running JVM is Eclipse Temurin (Adoptium) on
 * Java 25, matching the explicit toolchain pin. Gradle refuses to build with a non-matching
 * toolchain (the gate); this asserts the pin actually resolved to Temurin 25 at runtime.
 */
@Tag("unit")
@Tag("deploy")
@Tag("p2")
class ToolchainPinTest {

    @Test
    void runsOnEclipseTemurin25() {
        String vendor = System.getProperty("java.vendor", "");
        String version = System.getProperty("java.specification.version", "");
        assertThat(vendor)
            .as("java.vendor — toolchain must be Eclipse Temurin (Adoptium)")
            .containsAnyOf("Temurin", "Adoptium", "AdoptOpenJDK", "Eclipse Adoptium");
        assertThat(version)
            .as("java.specification.version — toolchain must be Java 25")
            .isEqualTo("25");
    }
}
