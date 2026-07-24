package smpp.companion.proxy.config;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;

import smpp.companion.proxy.CompanionApplication;
import smpp.companion.proxy.config.CompanionProperties.Role;
import smpp.companion.proxy.config.CompanionProperties.Tls;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AC9 / AD-17: the app refuses to start when {@code companion.role} is absent or not in
 * {forward, reverse}. The full role&times;mode matrix is Story 1.3; this is the single seed smoke.
 */
@Tag("integration")
@Tag("sec")
@Tag("p2")
class CompanionRoleFailFastTest {

    private static final Tls TLS = new Tls(
        java.util.List.of("TLSv1.3", "TLSv1.2"),
        java.util.List.of("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        java.util.List.of("TLS_AES_256_GCM_SHA384"));

    @Test
    void recordGuardRejectsAbsentRole() {
        // The compact-constructor guard is the fail-fast mechanism for a missing role.
        assertThatThrownBy(() -> new CompanionProperties(null, TLS))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("companion.role");
    }

    @Test
    void recordAcceptsValidRole() {
        new CompanionProperties(Role.FORWARD, TLS); // must not throw
        new CompanionProperties(Role.REVERSE, TLS); // must not throw
    }

    @Test
    void appRefusesToStartWithInvalidRole() {
        // An out-of-set value fails enum conversion at bind time -> startup fails (non-zero exit).
        // Command-line args (highest precedence) override application.yml's valid value — note that
        // SpringApplicationBuilder.properties() is LOWEST precedence and would be overridden by the yml.
        assertThatThrownBy(() ->
            new SpringApplicationBuilder(CompanionApplication.class)
                .web(WebApplicationType.NONE)
                .run("--companion.role=sideways"))
            .isInstanceOf(Exception.class);
    }
}
