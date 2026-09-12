package smpp.companion.proxy.bootstrap;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DEPLOY-001's floor-presence row (VG3, landed with Story 5.2's review round) &mdash; the AC
 * clause "the module set is jdeps-derived from the actual jar WITH THE CRYPTO FLOOR PRESENT",
 * which nothing enforced: the 2026-09-12 owner amendment recast the floor as DEFENSE-IN-DEPTH
 * (T3's Docker E2E stays GREEN without {@code jdk.crypto.ec}/{@code jdk.crypto.cryptoki} on the
 * current RSA-fixture/JDK-25 path), and the Gradle-input bite alone only causes a REBUILD,
 * never a failure. This row closes that gap: the BUILT runtime's resolved module set (read from
 * the jlink image's {@code release} file) must CONTAIN every floor module &mdash; removing one
 * from {@code cryptoFloor} in {@code proxy/build.gradle.kts} re-runs the task (the input bite)
 * and re-runs this row against the rebuilt image (the image dir is a declared {@code test}
 * input, the stale-image trap), which then REDs.
 *
 * <p>PRESENCE-ONLY, deliberately: this is NOT the owner-dropped module-set row &mdash; no
 * derived-list diff, no set equality, no jdeps re-run. The floor is the three DEPLOY-001
 * modules; the derived base beside it is recorded (pre-floor) in
 * {@code proxy/build/jlink-derived-modules.txt} as review/catalog evidence, not a test oracle.
 * Daemon-free: it reads the Gradle-built image directory, no Docker involved.
 */
@Tag("integration")
@Tag("deploy")
@Tag("p1")
class JlinkRuntimeCryptoFloorTest {

    /** The DEPLOY-001 crypto floor (must mirror cryptoFloor in proxy/build.gradle.kts). */
    private static final List<String> CRYPTO_FLOOR =
            List.of("jdk.crypto.ec", "jdk.crypto.cryptoki", "java.management");

    /** The jlink image the T1 task builds (a declared test input — see the class javadoc). */
    private static final Path JLINK_RELEASE = Path.of("build", "jlink-image", "release");

    @Test
    @DisplayName("DEPLOY-001 floor presence: the built jlink runtime's resolved module set "
            + "CONTAINS jdk.crypto.ec, jdk.crypto.cryptoki, and java.management")
    void theBuiltRuntimeCarriesTheWholeCryptoFloor() throws IOException {
        assertThat(JLINK_RELEASE)
                .as("the jlink runtime's release file exists (:proxy:jlinkRuntimeImage — wired "
                        + "into :proxy:test; a manual run is ./gradlew :proxy:test)")
                .isRegularFile();
        String modules = Files.readAllLines(JLINK_RELEASE).stream()
                .filter(line -> line.startsWith("MODULES="))
                .map(line -> line.substring("MODULES=".length()).replace("\"", ""))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "no MODULES= line in " + JLINK_RELEASE + " — not a jlink release file?"));
        assertThat(modules.split("\\s+"))
                .as("the runtime resolves every DEPLOY-001 floor module (jdeps never derives "
                        + "them: crypto loads via the security-provider mechanism; the floor is "
                        + "defense-in-depth with its bite here + Gradle-input drift)")
                .contains(CRYPTO_FLOOR.toArray(new String[0]));
    }
}
