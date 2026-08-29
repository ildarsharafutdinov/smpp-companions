package smpp.companion.proxy.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import smpp.companion.proxy.config.ProxyCompanionProperties;
import smpp.companion.proxy.config.TestCompanionConfigs;
import smpp.companion.proxy.relay.netty.RelayServerLifecycle;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC1 (Story 3.2 T7) — the security-side wiring: Spring DI selects <b>exactly one</b>
 * {@link BindCredentialVerifier} bean per AD-17 cell. Per the AD-12 amendment of 2026-08-18 (which
 * inverts the story's original AC1 direction): <b>every reverse.* cell &rarr; the ROPC adapter</b>
 * (the reverse role is the sole enforcement point before the SMSC), <b>forward.mode-a/mode-c &rarr;
 * the always-allow stand-in</b> (the forward role is a trusted-side relay, no OIDC material). The
 * reverse boots run the REAL provider link end-to-end (TLS factory &rarr; adapter construction
 * incl. the client-secret load; since Story 3.4 T9, 2026-08-29 there is NO provider wire call at
 * startup — the token endpoint is derived from {@code provider-url} at wiring); the forward boots
 * prove the same context yields the stand-in and never constructs an adapter.
 *
 * <p>Also pins the {@link AdjudicationLifecycle} riding along in every context, below the relay
 * acceptor's stop phase (AD-22: the acceptor stops first), and the bean-construction refusal when
 * the provider credential is blank (fail-closed at refresh, SEC-060).
 */
@Tag("unit")
@Tag("security")
@Tag("p1")
@DisplayName("AC1 — VerifierWiringConfig: exactly one BindCredentialVerifier per cell (AD-12 amended)")
class VerifierWiringConfigTest {

    /** Per-invocation temp dir (a fresh instance per parameterized case). */
    @TempDir
    Path dir;

    /**
     * The security-side wiring exactly as the component scan mounts it: the properties record + the
     * T2 bean + the T7 config. (The full-app boots elsewhere prove the scanned assembly; this
     * runner isolates the SELECTION under test. The 3.2-T2 startup probe bean was removed with the
     * probe itself — Story 3.4 T9, 2026-08-29.)
     */
    private ApplicationContextRunner runner(TestCompanionConfigs config) {
        return new ApplicationContextRunner()
                .withUserConfiguration(OidcEnablement.class, IdpSslContextFactory.class,
                        VerifierWiringConfig.class)
                .withPropertyValues(config.propertyValues());
    }

    @ParameterizedTest(name = "{0} → exactly one {1}")
    @MethodSource("cells")
    @DisplayName("cell wiring: exactly ONE verifier bean of the cell's expected type + the lifecycle below the acceptor phase")
    void exactlyOneVerifierOfTheCellsExpectedType(String kind, Class<?> expected) throws IOException {
        runner(base(kind)).run(ctx -> {
            assertThat(ctx).as(kind + " must start").hasNotFailed();
            Map<String, BindCredentialVerifier> beans = ctx.getBeansOfType(BindCredentialVerifier.class);
            assertThat(beans).as(kind + ": exactly one BindCredentialVerifier bean (AC1)").hasSize(1);
            assertThat(ctx.getBean(BindCredentialVerifier.class))
                    .as(kind + ": the single bean is " + expected.getSimpleName())
                    .isInstanceOf(expected);

            // The AD-22 lifecycle rides along, started, and strictly below the relay acceptor's
            // stop phase (Spring stops higher phases first — the acceptor closes BEFORE the drain).
            AdjudicationLifecycle lifecycle = ctx.getBean(AdjudicationLifecycle.class);
            assertThat(lifecycle.isRunning()).as(kind + ": the adjudication lifecycle must be running").isTrue();
            assertThat(lifecycle.getPhase())
                    .as(kind + ": the adjudicator must stop AFTER the acceptor (AD-22)")
                    .isLessThan(RelayServerLifecycle.RELAY_ACCEPTOR_PHASE);
        });
    }

    static Stream<Arguments> cells() {
        return Stream.of(
                Arguments.of("forwardA", AlwaysAllowBindCredentialVerifier.class),
                Arguments.of("forwardC", AlwaysAllowBindCredentialVerifier.class),
                Arguments.of("reverseA", RopcBindCredentialVerifier.class),
                Arguments.of("reverseB", RopcBindCredentialVerifier.class),
                Arguments.of("reverseC", RopcBindCredentialVerifier.class));
    }

    @Test
    @DisplayName("a reverse cell with a BLANK client-secret file refuses startup at bean construction (SEC-060, fail-closed)")
    void reverseCellWithBlankSecretRefusesAtBeanConstruction() throws IOException {
        Path blank = Files.createFile(dir.resolve("blank-oidc-secret"));   // zero bytes — the exact bad value
        TestCompanionConfigs config = TestCompanionConfigs.reverseB(dir)
                .put("companion.reverse.mode-b.oidc.client-secret-path", blank.toString());
        runner(config).run(ctx -> {
            assertThat(ctx).as("a blank provider credential must fail the refresh").hasFailed();
            assertThat(chainMessages(ctx.getStartupFailure()))
                    .as("the refusal must carry the SEC-060 convention")
                    .anyMatch(msg -> msg.contains("SEC-060"));
        });
    }

    private TestCompanionConfigs base(String kind) throws IOException {
        return switch (kind) {
            case "forwardA" -> TestCompanionConfigs.forwardA(dir);
            case "forwardC" -> TestCompanionConfigs.forwardC(dir);
            case "reverseA" -> TestCompanionConfigs.reverseA(dir);
            case "reverseB" -> TestCompanionConfigs.reverseB(dir);
            case "reverseC" -> TestCompanionConfigs.reverseC(dir);
            default -> throw new IllegalArgumentException("unknown base " + kind);
        };
    }

    /** Collects messages across the Throwable cause chain (Spring wraps startup failures deeply). */
    private static List<String> chainMessages(Throwable t) {
        List<String> messages = new ArrayList<>();
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c.getMessage() != null) {
                messages.add(c.getMessage());
            }
        }
        return messages;
    }

    /** Properties enablement for the runner (the full app gets this from @ConfigurationPropertiesScan). */
    @Configuration
    @EnableConfigurationProperties(ProxyCompanionProperties.class)
    static class OidcEnablement {
    }
}
