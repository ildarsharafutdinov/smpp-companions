package smpp.companion.proxy.bootstrap;

import java.lang.management.ManagementFactory;
import java.util.List;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC1 / AD-5 evidence: {@code --enable-preview} is applied to the TEST/RUN JVM (the
 * smpp.java-conventions wiring). Reads the live JVM input arguments — JEP 505 StructuredTaskScope
 * preview semantics must be locked process-wide before any preview code is authored.
 */
@Tag("unit")
@Tag("deploy")
@Tag("p2")
class EnablePreviewArgTest {

    @Test
    void jvmLaunchedWithEnablePreview() {
        List<String> args = ManagementFactory.getRuntimeMXBean().getInputArguments();
        assertThat(args)
            .as("--enable-preview must be on the test/run JVM command line (AC1 / AD-5)")
            .anyMatch("--enable-preview"::equals);
    }
}
