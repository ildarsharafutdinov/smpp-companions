package smpp.companion.proxy.config;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import smpp.companion.proxy.ProxyCompanionApplication;
import smpp.companion.proxy.config.ProxyCompanionProperties.Role;
import smpp.companion.proxy.config.ProxyCompanionProperties.Tls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * AC9 / AD-17: the app refuses to start when {@code companion.role} is absent or not in
 * {forward, reverse}. The full role&times;mode matrix is Story 1.3; this is the single seed smoke.
 * Both branches are exercised through real Spring binding: an out-of-set value fails enum
 * conversion; an absent value is rejected by {@code @NotNull} bean validation ({@code @Validated}
 * on {@link ProxyCompanionProperties}).
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
    void recordAcceptsValidRole() {
        new ProxyCompanionProperties(Role.FORWARD, TLS); // must not throw
        new ProxyCompanionProperties(Role.REVERSE, TLS); // must not throw
    }

    @Test
    void appRefusesToStartWithInvalidRole() {
        // An out-of-set value fails enum conversion at bind time -> startup fails (non-zero exit).
        // Command-line args (highest precedence) override application.yml's valid value.
        // The assertion walks the cause chain (Spring wraps the ConversionFailedException/BindException,
        // so the role detail may not be on the top-level message) and requires the failure to be ABOUT
        // the role property — not just any exception (a bare isInstanceOf(Exception.class) would pass on
        // an unrelated wiring failure, which is exactly the false-confidence this AC guards against).
        Throwable thrown = catchThrowable(() ->
                new SpringApplicationBuilder(ProxyCompanionApplication.class)
                        .web(WebApplicationType.NONE)
                        .run("--companion.role=sideways"));
        assertThat(thrown).isNotNull();
        assertThat(chainMessages(thrown))
                .as("startup failure must reference companion.role (invalid value)")
                .anyMatch(msg -> msg.contains("role"));
    }

    @Test
    void appRefusesToStartWithAbsentRole() {
        // companion.role ABSENT through real Spring binding: an ApplicationContextRunner with an empty
        // environment binds role=null -> @NotNull bean validation (@Validated) fires -> context fails
        // to start. This exercises the Spring binding + validation path end-to-end (the fail-fast
        // mechanism, replacing the former compact-constructor null-guard).
        new ApplicationContextRunner()
                .withUserConfiguration(AbsentRoleConfig.class)
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(chainMessages(ctx.getStartupFailure()))
                            .as("absent companion.role -> @NotNull validation references the role property")
                            .anyMatch(msg -> msg.contains("role"));
                });
    }

    /**
     * Collects messages across a Throwable's cause chain (Spring wraps binding failures deeply).
     */
    private static List<String> chainMessages(Throwable t) {
        List<String> messages = new ArrayList<>();
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c.getMessage() != null) {
                messages.add(c.getMessage());
            }
        }
        return messages;
    }

    /**
     * Minimal config that enables ProxyCompanionProperties binding without the full application context.
     */
    @Configuration
    @EnableConfigurationProperties(ProxyCompanionProperties.class)
    static class AbsentRoleConfig {
    }
}
