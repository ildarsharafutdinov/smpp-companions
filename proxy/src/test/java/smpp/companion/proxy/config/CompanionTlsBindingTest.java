package smpp.companion.proxy.config;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import smpp.companion.proxy.ProxyCompanionApplication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC9: the {@code companion.tls.*} kebab-case keys in application.yml relaxed-bind into the
 * {@link ProxyCompanionProperties.Tls} record's camelCase fields. Verified by booting the REAL context
 * (so the actual application.yml is the property source) and reading the bound bean — catches a
 * field-name / yml-key drift that an inspection-only check would miss. AD-34 cipher/protocol values
 * are pinned exactly so a future edit that drops/reorders a suite fails here.
 */
@Tag("integration")
@Tag("sec")
@Tag("p2")
class CompanionTlsBindingTest {

    @Test
    void tlsKebabCaseKeysRelaxedBindIntoTheRecord() {
        try (ConfigurableApplicationContext ctx =
                     new SpringApplicationBuilder(ProxyCompanionApplication.class)
                             .web(WebApplicationType.NONE)
                             .properties("companion.role=forward")
                             .run()) {
            ProxyCompanionProperties.Tls tls = ctx.getBean(ProxyCompanionProperties.class).tls();
            assertThat(tls).isNotNull();
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
}
