package smpp.companion.proxy.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;

import smpp.companion.proxy.ProxyCompanionApplication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * AC1/AC3/AC4 — the exhaustive AD-17 fail-fast matrix (SEC-050..061/096/097), each cell driven through
 * REAL Spring binding ({@link ApplicationContextRunner} + {@code @EnableConfigurationProperties}) so a
 * regression that silently skips a check turns the test red. The role&times;mode cell is selected
 * structurally &mdash; each base populates exactly one {@code companion.<role>.<mode>} branch. SEC-061 +
 * the AD-34 cipher intersection live in {@link CompanionTlsBindingTest}.
 *
 * <p>Each base config (via {@link TestCompanionConfigs}) is COMPLETE and otherwise valid, so the ONLY
 * failing condition is the one injected under test &mdash; the "make every assertion bite" discipline
 * (Story 1.2's vacuous-assertion lesson).
 */
@Tag("integration")
@Tag("sec")
@Tag("p1")
@ExtendWith(OutputCaptureExtension.class)
class CompanionConfigMatrixTest {

    @TempDir
    Path dir;

    private ApplicationContextRunner runner(TestCompanionConfigs config) {
        return new ApplicationContextRunner()
                .withUserConfiguration(MatrixConfig.class)
                .withPropertyValues(config.propertyValues());
    }

    /** Asserts the context fails to start AND the cause chain references the given token. */
    private void assertRefused(TestCompanionConfigs config, String scenario, String token) {
        runner(config).run(ctx -> {
            assertThat(ctx).as(scenario + ": must refuse to start").hasFailed();
            assertThat(chainMessages(ctx.getStartupFailure()))
                    .as(scenario + ": failure must reference [" + token + "]")
                    .anyMatch(msg -> msg.contains(token));
        });
    }

    private TestCompanionConfigs base(String kind) throws IOException {
        return switch (kind) {
            case "forwardA" -> TestCompanionConfigs.forwardA(dir);
            case "reverseA" -> TestCompanionConfigs.reverseA(dir);
            case "reverseC" -> TestCompanionConfigs.reverseC(dir);
            default -> throw new IllegalArgumentException("unknown base " + kind);
        };
    }

    // --- AC1 single-branch selection + role × mode matrix -----------------------------------

    @Test
    @DisplayName("AD-17: zero branches configured -> refuse")
    void noBranchConfiguredRefuses() {
        assertRefused(TestCompanionConfigs.noBranch(), "zero branches", "no companion");
    }

    @Test
    @DisplayName("AD-17: two branches configured -> refuse")
    void twoBranchesConfiguredRefuses() {
        TestCompanionConfigs two = TestCompanionConfigs.forwardA(dir)
                .put("companion.reverse.mode-b.smsc.host", "smsc.carrier.example")
                .put("companion.reverse.mode-b.smsc.port", "2775")
                .put("companion.reverse.mode-b.acknowledged", "true");
        assertRefused(two, "two branches", "found 2");
    }

    // SEC-051 (forward × Mode B forbidden) is STRUCTURAL in the tree model: there is no
    // companion.forward.mode-b node (Forward exposes only mode-a/mode-c). It is retired from the
    // runtime matrix — see test-coverage-scenarios.md. (A stray forward.mode-b key is rejected by
    // ignoreUnknownFields=false at bind time; no cross-field validator rule is needed.)

    @Test
    @DisplayName("SEC-052: reverse × Mode B without ack -> refuse")
    void sec052_reverseModeBWithoutAckRefuses() {
        assertRefused(TestCompanionConfigs.reverseB(dir).put("companion.reverse.mode-b.acknowledged", "false"),
                "SEC-052 no-ack", "SEC-052");
    }

    @Test
    @DisplayName("SEC-052: reverse × Mode B with ack -> loud plaintext warning then start")
    void sec052_reverseModeBWithAckWarnsAndStarts(CapturedOutput out) {
        // Full Spring Boot boot (not the slice) so the @PostConstruct CompanionModeBWarning is
        // component-scanned and fires after successful validation. application.yml supplies the common
        // keys; the reverse.mode-b args supply the branch (smsc + ack).
        try (ConfigurableApplicationContext ctx =
                     new SpringApplicationBuilder(ProxyCompanionApplication.class)
                             .web(WebApplicationType.NONE)
                             .run(TestCompanionConfigs.reverseB(dir).args())) {
            assertThat(ctx.isActive()).as("SEC-052 ack: must start").isTrue();
            assertThat(out.getAll())
                    .as("SEC-052 ack: must emit the loud plaintext Mode B warning")
                    .contains("MODE B")
                    .contains("PLAINTEXT");
        }
    }

    @Test
    @DisplayName("SEC-052: reverse × Mode B + ack + a field-level failure refuses WITHOUT the warning")
    void sec052_ackWithFieldLevelFailureRefusesWithoutTheWarning(CapturedOutput out) {
        // The Mode B banner must NOT fire for a config that then refuses (the warning is post-refresh
        // only). A bad bind port fails field-level @Max; the @PostConstruct warning bean never inits.
        Throwable thrown = catchThrowable(() ->
                new SpringApplicationBuilder(ProxyCompanionApplication.class)
                        .web(WebApplicationType.NONE)
                        .run(TestCompanionConfigs.reverseB(dir).put("companion.bind.port", "70000").args()));
        assertThat(thrown).as("a bad bind port must refuse startup").isNotNull();
        assertThat(out.getAll())
                .as("no Mode B banner for a config that refuses to start")
                .doesNotContain("MODE B");
    }

    @Test
    @DisplayName("SEC-056: forward (A/C) missing the server cert+key -> refuse")
    void sec056_forwardMissingServerCertRefuses() {
        assertRefused(TestCompanionConfigs.forwardA(dir).remove("companion.forward.mode-a.server-cert.cert-path"),
                "SEC-056", "server-cert");
    }

    @Test
    @DisplayName("SEC-057: reverse × C missing the client cert+key -> refuse")
    void sec057_reverseCMissingClientCertRefuses() {
        assertRefused(TestCompanionConfigs.reverseC(dir).remove("companion.reverse.mode-c.client-cert.cert-path"),
                "SEC-057", "client-cert");
    }

    @Test
    @DisplayName("SEC-058: forward with an empty/missing routing table -> refuse")
    void sec058_forwardEmptyRoutingRefuses() {
        TestCompanionConfigs noRouting = TestCompanionConfigs.forwardA(dir)
                .remove("companion.forward.mode-a.routing[0].system-id")
                .remove("companion.forward.mode-a.routing[0].host")
                .remove("companion.forward.mode-a.routing[0].port");
        assertRefused(noRouting, "SEC-058", "routing");
    }

    @Test
    @DisplayName("SEC-058: forward with a routing entry missing its system-id -> refuse (per-entry AD-29)")
    void sec058_forwardRoutingEntryMissingSystemIdRefuses() {
        // Keep the routing entry present (host+port) but blank the system-id, so the routing list is
        // non-null/non-empty and the per-entry loop actually executes (AD-29 system_id allow-list).
        assertRefused(TestCompanionConfigs.forwardA(dir).put("companion.forward.mode-a.routing[0].system-id", ""),
                "SEC-058 per-entry", "system-id");
    }

    @Test
    @DisplayName("SEC-059: reverse missing the SMSC endpoint -> refuse")
    void sec059_reverseMissingSmscRefuses() {
        assertRefused(TestCompanionConfigs.reverseA(dir).remove("companion.reverse.mode-a.smsc.host"),
                "SEC-059", "smsc.host");
    }

    @Test
    @DisplayName("SEC-096: reverse × A missing the client trust store -> refuse")
    void sec096_reverseAMissingTrustStoreRefuses() {
        assertRefused(TestCompanionConfigs.reverseA(dir).remove("companion.reverse.mode-a.trust-store.path"),
                "SEC-096", "trust-store");
    }

    @Test
    @DisplayName("SEC-097: forward × A STARTS without an SMSC endpoint (SMSC not required for forward)")
    void sec097_forwardAStartsWithoutSmsc() {
        runner(TestCompanionConfigs.forwardA(dir)).run(ctx ->
                assertThat(ctx).as("SEC-097: forward+A must start without an SMSC endpoint").hasNotFailed());
    }

    // --- AC4 OIDC + ports --------------------------------------------------------------------

    @Test
    @DisplayName("SEC-053: forward with a non-https OIDC provider URL -> refuse")
    void sec053_nonHttpsOidcProviderRefuses() {
        assertRefused(TestCompanionConfigs.forwardA(dir)
                        .put("companion.forward.mode-a.oidc.provider-url", "http://idp.example.com"),
                "SEC-053", "SEC-053");
    }

    @Test
    @DisplayName("SEC-054: forward with an absent OIDC provider URL -> refuse")
    void sec054_absentOidcProviderRefuses() {
        assertRefused(TestCompanionConfigs.forwardA(dir).remove("companion.forward.mode-a.oidc.provider-url"),
                "SEC-054", "SEC-054");
    }

    @ParameterizedTest(name = "SEC-055: bind port {0} (out of range) -> refuse")
    @ValueSource(strings = {"0", "-1", "70000", "99999"})
    @DisplayName("SEC-055: bad SMPP bind port -> refuse")
    void sec055_badBindPortRefuses(String badPort) {
        assertRefused(TestCompanionConfigs.forwardA(dir).put("companion.bind.port", badPort),
                "SEC-055 bind port " + badPort, "bind.port");
    }

    @ParameterizedTest(name = "SEC-055: SMSC port {0} (out of range) -> refuse")
    @ValueSource(strings = {"0", "-1", "70000"})
    @DisplayName("SEC-055: bad SMSC port -> refuse")
    void sec055_badSmscPortRefuses(String badPort) {
        assertRefused(TestCompanionConfigs.reverseA(dir).put("companion.reverse.mode-a.smsc.port", badPort),
                "SEC-055 SMSC port " + badPort, "smsc.port");
    }

    // --- AC3 secrets (SEC-060) + trust store 5-state (SEC-050) -------------------------------

    @ParameterizedTest(name = "SEC-060: missing {0} -> refuse")
    @MethodSource("requiredSecretTypes")
    @DisplayName("SEC-060: a missing required secret file -> refuse (parametrized over secret types)")
    void sec060_missingSecretRefuses(String label, String baseKind, String key) throws IOException {
        assertRefused(base(baseKind).remove(key), "SEC-060 missing " + label, "SEC-060");
    }

    static Stream<Arguments> requiredSecretTypes() {
        // The trust store is validated by the deeper SEC-050 (5-state) + SEC-096 (cell) checks, not
        // requireReadableFile; it is omitted here and covered by those scenarios.
        return Stream.of(
                Arguments.of("server cert (forward A)", "forwardA", "companion.forward.mode-a.server-cert.cert-path"),
                Arguments.of("server key (forward A)", "forwardA", "companion.forward.mode-a.server-cert.key-path"),
                Arguments.of("oidc client credential (forward A)", "forwardA", "companion.forward.mode-a.oidc.client-credential-path"),
                Arguments.of("client cert (reverse C)", "reverseC", "companion.reverse.mode-c.client-cert.cert-path"),
                Arguments.of("client key (reverse C)", "reverseC", "companion.reverse.mode-c.client-cert.key-path"));
    }

    @Test
    @DisplayName("SEC-060: an unreadable secret file (chmod 000, non-root, POSIX) -> refuse")
    void sec060_unreadableSecretRefuses() throws IOException {
        Assumptions.assumeTrue(
                java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
                "unreadable-permission case requires a POSIX filesystem (skipped on Windows/non-POSIX CI)");
        Assumptions.assumeFalse("root".equals(System.getProperty("user.name")),
                "unreadable-permission case is non-deterministic as root (CI runs non-root)");
        TestCompanionConfigs config = TestCompanionConfigs.forwardA(dir);
        Path unreadable = dir.resolve("unreadable-server.crt");
        Files.createFile(unreadable);
        Files.setPosixFilePermissions(unreadable, PosixFilePermissions.fromString("---------"));
        config.put("companion.forward.mode-a.server-cert.cert-path", unreadable.toString());
        assertRefused(config, "SEC-060 unreadable", "not readable");
    }

    @ParameterizedTest(name = "SEC-050: trust store {0} -> refuse")
    @MethodSource("invalidTrustStoreStates")
    @DisplayName("SEC-050: an invalid trust store (empty/wrong-format/wrong-password/zero-entries) -> refuse")
    void sec050_invalidTrustStoreRefuses(String name, String kind, String token) throws Exception {
        TestCompanionConfigs config = TestCompanionConfigs.reverseA(dir);
        Path ts = dir.resolve("truststore.p12");
        switch (kind) {
            case "empty" -> {
                Files.deleteIfExists(ts);
                Files.createFile(ts); // zero bytes
            }
            case "wrong-format" -> {
                Files.deleteIfExists(ts);
                Files.writeString(ts, "this is not a keystore");
            }
            case "wrong-password" -> {
                Files.deleteIfExists(ts);
                KeyStoreFixtures.writeValidTrustStore(ts, "real-password"); // valid store, wrong password supplied
                config.put("companion.reverse.mode-a.trust-store.password", "wrong-password");
            }
            case "zero-entries" -> {
                Files.deleteIfExists(ts);
                KeyStoreFixtures.writeZeroEntryTrustStore(ts, "changeit"); // valid format, zero trustedCertEntry
            }
            default -> throw new IllegalArgumentException("unknown trust-store state " + kind);
        }
        assertRefused(config, "SEC-050 " + name, token);
    }

    @Test
    @DisplayName("SEC-050 (forward×C): an invalid trust store on forward Mode C -> refuse (full AD-13 depth)")
    void sec050_forwardCInvalidTrustStoreRefuses() {
        // forward+C requires the trust store at the SAME 5-state depth as reverse×A/C (AC3 is not
        // role-scoped). A wrong password must refuse here — proving forward+C uses requireTrustStore,
        // not the shallow requireReadableFile (under which the existing valid file would pass).
        assertRefused(TestCompanionConfigs.forwardC(dir)
                        .put("companion.forward.mode-c.trust-store.password", "wrong-password"),
                "SEC-050 forward+C wrong-password", "SEC-050");
    }

    static Stream<Arguments> invalidTrustStoreStates() {
        // The token is per-case so each parametrized branch is independently falsifiable: the empty-bytes
        // case asserts "empty" specifically (removing that branch falls through to KeyStore.load, whose
        // IOException message lacks "empty"); the others assert "SEC-050".
        return Stream.of(
                Arguments.of("empty (zero bytes)", "empty", "empty"),
                Arguments.of("wrong format", "wrong-format", "SEC-050"),
                Arguments.of("wrong password", "wrong-password", "SEC-050"),
                Arguments.of("zero trustedCertEntry", "zero-entries", "SEC-050"));
    }

    // --- Review hardening (code review 2026-08-04): biting tests for guards that previously lacked coverage ---

    @Test
    @DisplayName("SEC-051: a stray companion.forward.mode-b key is rejected (ignoreUnknownFields=false)")
    void sec051_strayForwardModeBKeyRefuses() {
        // forward×B is forbidden, so Forward has no mode-b node. A stray forward.mode-b.* key is an unknown
        // nested field; ignoreUnknownFields=false refuses it at bind time (fail-closed, AD-11/SEC-051).
        runner(TestCompanionConfigs.forwardA(dir)
                .put("companion.forward.mode-b.smsc.host", "smsc.carrier.example"))
                .run(ctx -> {
                    assertThat(ctx).as("SEC-051: a stray forward.mode-b key must refuse startup").hasFailed();
                    assertThat(chainMessages(ctx.getStartupFailure()))
                            .as("the refusal must reference the unknown forward.mode-b property")
                            .anyMatch(msg -> msg.contains("mode-b") || msg.contains("modeB"));
                });
    }

    @Test
    @DisplayName("AD-17: two modes WITHIN the forward role (mode-a + mode-c) -> refuse")
    void twoForwardModesConfiguredRefuses() {
        // The cross-role two-branch test does not cover the within-role Forward compact-constructor guard.
        // Setting any forward.mode-c key makes modeC non-null alongside modeA -> "found 2".
        assertRefused(TestCompanionConfigs.forwardA(dir)
                        .put("companion.forward.mode-c.server-cert.cert-path", dir.resolve("server.crt").toString()),
                "two forward modes", "found 2");
    }

    @Test
    @DisplayName("SEC-058/AD-29: duplicate system_id entries in the routing table -> refuse")
    void sec058_duplicateSystemIdRefuses() {
        assertRefused(TestCompanionConfigs.forwardA(dir)
                        .put("companion.forward.mode-a.routing[1].system-id", "carrierOne")
                        .put("companion.forward.mode-a.routing[1].host", "reverse.internal")
                        .put("companion.forward.mode-a.routing[1].port", "2776"),
                "SEC-058 duplicate system-id", "duplicated");
    }

    @Test
    @DisplayName("SEC-058/AD-29: an explicitly empty (non-null) routing list -> refuse (bites the isEmpty branch)")
    void sec058_emptyRoutingListRefuses() {
        // The routing.isEmpty() branch is unreachable via Spring binding (an absent routing block binds
        // null, caught by @NotNull). Validate the validator directly with an empty list so the branch bites:
        // an empty list PASSES @NotNull (non-null) and would be silently accepted without this guard.
        var validator = jakarta.validation.Validation.buildDefaultValidatorFactory().getValidator();
        var props = new ProxyCompanionProperties(
                new ProxyCompanionProperties.Bind(2775),
                new ProxyCompanionProperties.Memory(64, 1024, 1.5),
                new ProxyCompanionProperties.Tls(
                        List.of("TLSv1.3", "TLSv1.2"),
                        List.of("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
                        List.of("TLS_AES_256_GCM_SHA384")),
                new ProxyCompanionProperties.Forward(
                        new ProxyCompanionProperties.ForwardModeA(
                                new ProxyCompanionProperties.ServerCert("/run/secrets/server.crt", "/run/secrets/server.key"),
                                List.of(), // explicitly empty routing list
                                new ProxyCompanionProperties.Oidc("https://idp.example.com", "/run/secrets/oidc")),
                        null),
                null);
        var violations = validator.validate(props);
        assertThat(violations)
                .as("an empty routing list must be refused (SEC-058 isEmpty branch)")
                .anyMatch(v -> v.getMessage().contains("no default route"));
    }

    @Test
    @DisplayName("SEC-060: a secret path that is a directory -> refuse")
    void sec060_directoryAsSecretRefuses() {
        // Files.exists && Files.isReadable are both true for a readable directory; without the isDirectory
        // check, pointing a cert path at the secrets dir would pass and defer the failure to Epic 3.
        assertRefused(TestCompanionConfigs.forwardA(dir)
                        .put("companion.forward.mode-a.server-cert.cert-path", dir.toString()),
                "SEC-060 directory", "directory");
    }

    @ParameterizedTest(name = "AD-30: safety-factor {0} (non-finite) -> refuse")
    @ValueSource(strings = {"NaN", "Infinity"})
    @DisplayName("AD-30: a non-finite safety-factor -> refuse (bites the isFinite guard)")
    void ad30_nonFiniteSafetyFactorRefuses(String factor) {
        assertRefused(TestCompanionConfigs.forwardA(dir).put("companion.memory.safety-factor", factor),
                "AD-30 safety-factor " + factor, "finite");
    }

    @Test
    @DisplayName("AD-34: an omitted companion.tls.* block refuses cleanly (no NPE) — bites the validateTls null guard")
    void omittedTlsBlockRefusesCleanly() {
        TestCompanionConfigs noTls = TestCompanionConfigs.forwardA(dir)
                .remove("companion.tls.protocols")
                .remove("companion.tls.tls12-cipher-suites")
                .remove("companion.tls.tls13-cipher-suites");
        runner(noTls).run(ctx -> {
            assertThat(ctx).as("an omitted tls block must refuse").hasFailed();
            List<String> messages = chainMessages(ctx.getStartupFailure());
            assertThat(messages).as("refusal must be a clean AD-34 message, not an NPE stack trace")
                    .noneMatch(msg -> msg.contains("NullPointerException"));
            assertThat(messages).as("the clean companion.tls.* required message must be present")
                    .anyMatch(msg -> msg.contains("companion.tls.* is required"));
        });
    }

    @Test
    @DisplayName("AD-30: an omitted companion.memory.* block refuses cleanly (no NPE)")
    void omittedMemoryBlockRefusesCleanly() {
        TestCompanionConfigs noMemory = TestCompanionConfigs.forwardA(dir)
                .remove("companion.memory.max-inbound-depth")
                .remove("companion.memory.concurrent-pairs")
                .remove("companion.memory.safety-factor");
        runner(noMemory).run(ctx -> {
            assertThat(ctx).as("an omitted memory block must refuse").hasFailed();
            List<String> messages = chainMessages(ctx.getStartupFailure());
            assertThat(messages).as("refusal must be a clean AD-30 message, not an NPE stack trace")
                    .noneMatch(msg -> msg.contains("NullPointerException"));
            assertThat(messages).as("the clean companion.memory.* required message must be present")
                    .anyMatch(msg -> msg.contains("companion.memory.* is required"));
        });
    }

    // --- helpers -----------------------------------------------------------------------------

    private static List<String> chainMessages(Throwable t) {
        List<String> messages = new ArrayList<>();
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c.getMessage() != null) {
                messages.add(c.getMessage());
            }
        }
        return messages;
    }

    @Configuration
    @EnableConfigurationProperties(ProxyCompanionProperties.class)
    static class MatrixConfig {
    }
}
