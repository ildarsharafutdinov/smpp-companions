package smpp.companion.proxy.config;

import java.time.Duration;

import java.io.IOException;
import java.nio.file.Path;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;

import smpp.companion.proxy.ProxyCompanionApplication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC2 + the AC9 AD-34 binding pin. {@code companion.tls.*} kebab-case keys in application.yml
 * relaxed-bind into the {@link ProxyCompanionProperties.Tls} record's camelCase fields — verified by
 * booting the REAL context (so the actual application.yml is the property source) and reading the
 * bound bean. AD-34 cipher/protocol values are pinned exactly so a future edit that drops/reorders a
 * suite fails here. SEC-061 (TLS floor) and the AD-34 cipher intersection (decision D2) are asserted
 * through real Spring binding + the class-level validator.
 */
@Tag("integration")
@Tag("sec")
@Tag("p1")
class CompanionTlsBindingTest {

    @Test
    @DisplayName("AD-34: companion.tls.* kebab-case keys relaxed-bind into the record (values pinned exactly)")
    void tlsKebabCaseKeysRelaxedBindIntoTheRecord(@TempDir Path dir) throws IOException {
        // A complete valid forward+A config via properties; the TLS block is NOT overridden, so it
        // comes from application.yml — catching a field-name/yml-key drift an inspection-only check misses.
        // The memory overrides are run() args (highest precedence): since T5b the AD-30 self-check is
        // unconditional, and yml's realistic budget (≈ 6 GiB) exceeds the test JVM's direct-memory ceiling.
        // NO oidc keys — the forward role is a trusted-side relay (AD-12 amended 2026-08-18). The
        // [B] re-shape: the forward branch carries the DIAL material (real fixture trust store — the
        // full boot constructs SmppLegTlsFactory). Story 3.3: the forward boot also BINDS its listener
        // now, so the run args carry a free port + the F13 cap fitted to the minimal budget.
        var legs = smpp.companion.proxy.testsupport.RelayTestFixtures.smppTlsLegs(dir);
        try (ConfigurableApplicationContext ctx =
                     new SpringApplicationBuilder(ProxyCompanionApplication.class)
                             .web(WebApplicationType.NONE)
                             .properties(
                                     "companion.forward.mode-a.trust-store.path=" + legs.trustStore(),
                                     "companion.forward.mode-a.trust-store.password="
                                             + smpp.companion.proxy.testsupport.RelayTestFixtures.SmppTlsLegs.STORE_PASSWORD,
                                     "companion.forward.mode-a.routing[0].system-id=carrierOne",
                                     "companion.forward.mode-a.routing[0].host=reverse.internal",
                                     "companion.forward.mode-a.routing[0].port=2776")
                             .run("--companion.memory.max-inbound-depth=1",
                                     "--companion.memory.concurrent-pairs=1",
                                     "--companion.memory.safety-factor=1.0",
                                     "--companion.bind.port="
                                             + smpp.companion.proxy.testsupport.RelayTestFixtures.freePort())) {
            ProxyCompanionProperties.Tls tls = ctx.getBean(ProxyCompanionProperties.class).tls();
            assertThat(tls).isNotNull();
            // Story 2.2 T7 owner FIXME pin: this boot sets NO companion.bind.adjudication-deadline
            // property, so it comes from application.yml's documented default — the yml key + relaxed
            // binding + the 4s default are all load-bearing (mirror of the T5b budgetCheck==FAIL pin).
            // (companion.bind.port IS set above — Story 3.3 made the acceptor bind on every cell.)
            assertThat(ctx.getBean(ProxyCompanionProperties.class).bind().adjudicationDeadline())
                    .as("companion.bind.adjudication-deadline defaults to 4s from application.yml")
                    .isEqualTo(Duration.ofSeconds(4));
            assertThat(tls.protocols())
                    .as("companion.tls.protocols")
                    .containsExactly("TLSv1.3", "TLSv1.2");
            assertThat(tls.tls12CipherSuites())
                    .as("relaxed binding: companion.tls.tls12-cipher-suites -> tls12CipherSuites")
                    .containsExactly(
                            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
            assertThat(tls.tls13CipherSuites())
                    .as("relaxed binding: companion.tls.tls13-cipher-suites -> tls13CipherSuites")
                    .containsExactly(
                            "TLS_AES_256_GCM_SHA384",
                            "TLS_AES_128_GCM_SHA256",
                            "TLS_CHACHA20_POLY1305_SHA256");
        }
    }

    @Test
    @DisplayName("SEC-061: a sub-TLS-1.2 protocol (SSLv3) refuses startup")
    void sec061_subTls12ProtocolRefusesStartup(@TempDir Path dir) throws IOException {
        new ApplicationContextRunner()
                .withUserConfiguration(TlsMatrixConfig.class)
                .withPropertyValues(TestCompanionConfigs.forwardA(dir)
                        .put("companion.tls.protocols", "SSLv3,TLSv1.2")
                        .propertyValues())
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(chainMessages(ctx.getStartupFailure()))
                            .as("a sub-TLS-1.2 protocol must be refused (SEC-061)")
                            .anyMatch(msg -> msg.contains("SEC-061") || msg.contains("SSLv3"));
                });
    }

    @Test
    @DisplayName("AD-34: cipher suites with an empty JDK intersection refuse startup (decision D2)")
    void ad34_cipherSuitesWithEmptyJdkIntersectionRefuseStartup(@TempDir Path dir) throws IOException {
        new ApplicationContextRunner()
                .withUserConfiguration(TlsMatrixConfig.class)
                .withPropertyValues(TestCompanionConfigs.forwardA(dir)
                        .put("companion.tls.tls12-cipher-suites", "TLS_FAKE_BOGOUS_SUITE")
                        .put("companion.tls.tls13-cipher-suites", "TLS_FAKE_BOGUS13")
                        .propertyValues())
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(chainMessages(ctx.getStartupFailure()))
                            .as("an empty cipher/JDK intersection must be refused (AD-34)")
                            .anyMatch(msg -> msg.contains("intersection") || msg.contains("AD-34"));
                });
    }

    @Test
    @DisplayName("SEC-061: a sub-TLS-1.2 protocol in lowercase (sslv3) refuses startup (case-insensitive floor)")
    void sec061_lowerCaseSubTls12ProtocolRefusesStartup(@TempDir Path dir) throws IOException {
        new ApplicationContextRunner()
                .withUserConfiguration(TlsMatrixConfig.class)
                .withPropertyValues(TestCompanionConfigs.forwardA(dir)
                        .put("companion.tls.protocols", "sslv3,TLSv1.2")
                        .propertyValues())
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(chainMessages(ctx.getStartupFailure()))
                            .as("a lowercase sub-TLS-1.2 protocol must be refused (SEC-061, case-insensitive floor)")
                            .anyMatch(msg -> msg.contains("SEC-061"));
                });
    }

    @Test
    @DisplayName("AD-34: a blank entry in companion.tls.protocols refuses startup")
    void ad34_blankProtocolEntryRefusesStartup(@TempDir Path dir) throws IOException {
        // "TLSv1.3,,TLSv1.2" binds a blank middle entry — bites the protocol.isBlank() guard.
        new ApplicationContextRunner()
                .withUserConfiguration(TlsMatrixConfig.class)
                .withPropertyValues(TestCompanionConfigs.forwardA(dir)
                        .put("companion.tls.protocols", "TLSv1.3,,TLSv1.2")
                        .propertyValues())
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(chainMessages(ctx.getStartupFailure()))
                            .as("a blank protocol entry must be refused (AD-34)")
                            .anyMatch(msg -> msg.contains("blank"));
                });
    }

    @Test
    @DisplayName("AD-34: a JDK-unsupported protocol (TLSv9.99) refuses startup")
    void ad34_unsupportedProtocolRefusesStartup(@TempDir Path dir) throws IOException {
        // TLSv9.99 is not sub-1.2 (so the SEC-061 floor misses it) and not JDK-supported.
        new ApplicationContextRunner()
                .withUserConfiguration(TlsMatrixConfig.class)
                .withPropertyValues(TestCompanionConfigs.forwardA(dir)
                        .put("companion.tls.protocols", "TLSv9.99")
                        .propertyValues())
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(chainMessages(ctx.getStartupFailure()))
                            .as("a JDK-unsupported protocol must be refused (AD-34 cipher/protocol intersection)")
                            .anyMatch(msg -> msg.contains("not supported by the JDK-default SSLContext"));
                });
    }

    @Test
    @DisplayName("AD-34: empty cipher suites refuse startup (the intersection guard owns the empty-ciphers case)")
    void ad34_emptyCipherSuitesRefuseStartup(@TempDir Path dir) throws IOException {
        // Both cipher lists blanked → configured set empty → the AD-34 intersection guard rejects it
        // (empty ∩ JDK-supported = empty). The dedicated empty-ciphers early-return was removed as
        // redundant; this proves the intersection guard still catches an empty configured set.
        new ApplicationContextRunner()
                .withUserConfiguration(TlsMatrixConfig.class)
                .withPropertyValues(TestCompanionConfigs.forwardA(dir)
                        .put("companion.tls.tls12-cipher-suites", "")
                        .put("companion.tls.tls13-cipher-suites", "")
                        .propertyValues())
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(chainMessages(ctx.getStartupFailure()))
                            .as("empty cipher suites must be refused via the AD-34 intersection guard")
                            .anyMatch(msg -> msg.contains("intersection") && msg.contains("AD-34"));
                });
    }

    private static java.util.List<String> chainMessages(Throwable t) {
        java.util.List<String> messages = new java.util.ArrayList<>();
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c.getMessage() != null) {
                messages.add(c.getMessage());
            }
        }
        return messages;
    }

    @Configuration
    @EnableConfigurationProperties(ProxyCompanionProperties.class)
    static class TlsMatrixConfig {
    }
}
