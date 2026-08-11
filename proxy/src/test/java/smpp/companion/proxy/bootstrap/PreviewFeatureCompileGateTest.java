package smpp.companion.proxy.bootstrap;

import java.util.concurrent.StructuredTaskScope;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Compiler-enforced {@code --enable-preview} bootstrap gate (AC9 / AI-8 / AD-5).
 *
 * <p>This source <b>is</b> the gate: it uses a JEP 505 preview API ({@link StructuredTaskScope}), so the
 * compiler and the JVM enforce the wiring directly &mdash; no source-scan of the Gradle conventions.
 * <ul>
 *   <li><b>COMPILE wiring</b> ({@code JavaCompile#compilerArgs}): this class compiles iff
 *       {@code compileTestJava} carries {@code --enable-preview}. Drop it and {@code compileTestJava}
 *       fails on the preview API &mdash; the build goes RED at compile time. The compiler is the guard.</li>
 *   <li><b>TEST wiring</b> ({@code Test#jvmArgs}): the compiled class is preview-marked, so the test JVM
 *       loads it iff it was launched with {@code --enable-preview}. Drop it and the class fails to load
 *       &mdash; the test goes RED. ({@link EnablePreviewArgTest} adds the explicit, clean-failing
 *       assertion of the same flag.)</li>
 * </ul>
 *
 * <p>This is more robust than a static source-scan of {@code smpp.java-conventions.gradle.kts}: it is
 * compiler/JVM-enforced and cannot be masked by Gradle's incremental UP-TO-DATE check (a runtime file
 * read can be &mdash; see the T1 debug log). It replaces the T1 source-scan gate per an owner decision.
 *
 * <p><b>Scope (owner-approved deviation, flagged for review):</b> this gate covers the COMPILE and TEST
 * wirings only. The <b>RUN</b> wiring ({@code JavaExec}/{@code bootRun}) is intentionally NOT gated here
 * &mdash; no {@code build}/{@code test} task starts the app, so {@code bootRun}'s {@code --enable-preview}
 * is only exercised when an operator runs it. AC9 names "COMPILE <b>and RUN</b>"; the RUN half is
 * deliberately dropped in favour of this simpler compiler-enforced gate.
 *
 * <p><b>Preview-feature dependence (maintenance note):</b> the gate bites iff {@link StructuredTaskScope}
 * remains a preview feature. It is JEP 505 (5th preview) on the pinned JDK 25; if a future JDK graduates
 * it to a stable API, this class stops requiring {@code --enable-preview} and the gate goes silently inert
 * &mdash; at which point reintroduce a static wiring scan (or another preview feature the codebase uses).
 *
 * <p>The preview feature exercised is the project's real control-plane dependency (JEP 505
 * {@code StructuredTaskScope}, confined to {@code security/}+{@code bootstrap/} per AD-5); the relay
 * data-plane splice uses NO preview API.
 */
@Tag("unit")
@Tag("deploy")
@Tag("p2")
class PreviewFeatureCompileGateTest {

    @Test
    void structuredTaskScopeOpensAndJoinsUnderEnablePreview() throws InterruptedException {
        // JEP 505 preview API — StructuredTaskScope.open(Joiner). Compiles + loads + runs only under
        // --enable-preview, so reaching the assertion proves the COMPILE and TEST wirings are active.
        try (var scope = StructuredTaskScope.open(StructuredTaskScope.Joiner.awaitAllSuccessfulOrThrow())) {
            scope.fork(() -> "preview-feature-compile-gate");
            scope.join();
        }
        assertThat(true)
            .as("reaching here proves the preview feature executed under --enable-preview (COMPILE + TEST wirings)")
            .isTrue();
    }
}
