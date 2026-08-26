package smpp.companion.proxy.config;

import java.time.Duration;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;

import smpp.companion.proxy.ProxyCompanionApplication;
import smpp.companion.proxy.config.ProxyCompanionProperties.Bind;
import smpp.companion.proxy.config.ProxyCompanionProperties.Forward;
import smpp.companion.proxy.config.ProxyCompanionProperties.ForwardModeA;
import smpp.companion.proxy.config.ProxyCompanionProperties.Memory;
import smpp.companion.proxy.config.ProxyCompanionProperties.Oidc;
import smpp.companion.proxy.config.ProxyCompanionProperties.Reverse;
import smpp.companion.proxy.config.ProxyCompanionProperties.ReverseModeC;
import smpp.companion.proxy.config.ProxyCompanionProperties.RoutingEntry;
import smpp.companion.proxy.config.ProxyCompanionProperties.ServerCert;
import smpp.companion.proxy.config.ProxyCompanionProperties.Smsc;
import smpp.companion.proxy.config.ProxyCompanionProperties.Tls;
import smpp.companion.proxy.config.ProxyCompanionProperties.TrustStore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * AD-17 binding smoke, evolved from the Story 1.1 {@code companion.role} seed. The role&times;mode cell
 * is now selected structurally via a single {@code companion.<role>.<mode>} branch; {@code companion.role}
 * itself is retired. This test retains three load-bearing checks through real Spring binding: the record
 * shape accepts a forward and a reverse branch (1); the retired {@code companion.role} key is rejected
 * by {@code ignoreUnknownFields=false} &mdash; fail-closed on a typo'd/legacy key (2); and a boot with no
 * branch refuses (3). The exhaustive matrix (every cell, every SEC) lives in
 * {@link CompanionConfigMatrixTest}.
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
    void recordAcceptsValidBranches() {
        // Construction does not run bean validation; this asserts the tree record shape accepts a
        // forward branch and a reverse branch without throwing. (Matrix validation is exercised
        // end-to-end in CompanionConfigMatrixTest.)
        new ProxyCompanionProperties(
                new Bind(2775, "127.0.0.1", Duration.ofSeconds(4)),
                new Memory(64, 1024, 1.5, Memory.BudgetCheck.FAIL),
                TLS,
                new Forward(
                        new ForwardModeA(
                                new TrustStore("/run/secrets/truststore.p12", "changeit"),
                                List.of(new RoutingEntry("carrierOne", "reverse.internal", 2776, null))),
                        null, null),
                null);
        new ProxyCompanionProperties(
                new Bind(2775, "127.0.0.1", Duration.ofSeconds(4)),
                new Memory(64, 1024, 1.5, Memory.BudgetCheck.FAIL),
                TLS,
                null,
                new Reverse(
                        null, null,
                        new ReverseModeC(
                                new Smsc("smsc.carrier.example", 2775),
                                new ServerCert("/run/secrets/reverse-server.crt", "/run/secrets/reverse-server.key"),
                                new TrustStore("/run/secrets/truststore.p12", "changeit"),
                                new Oidc(java.net.URI.create("https://idp.example.com"), "smpp-client-confidential",
                                        "/run/secrets/oidc-client-secret",
                                        new TrustStore("/run/secrets/idp-truststore.p12", null),
                                        Duration.ofSeconds(4), 64, Duration.ofMinutes(5)))));
    }

    @Test
    void appRefusesToStartWithRetiredRoleKey() {
        // companion.role is retired (the branch path now selects the cell). With ignoreUnknownFields=false
        // a legacy/typo'd companion.role key is an unbindable element -> startup fails (non-zero exit).
        // Command-line args (highest precedence) land on top of application.yml's common keys.
        Throwable thrown = catchThrowable(() ->
                new SpringApplicationBuilder(ProxyCompanionApplication.class)
                        .web(WebApplicationType.NONE)
                        .run("--companion.role=forward"));
        assertThat(thrown).as("a retired/unknown companion.* key must refuse startup").isNotNull();
        assertThat(chainMessages(thrown))
                .as("startup failure must reference the rejected companion.role key")
                .anyMatch(msg -> msg.contains("role"));
    }

    @Test
    void appRefusesToStartWithNoBranch() {
        // Real Spring Boot boot reading ONLY application.yml: the common keys (bind/memory/tls) are
        // present but NO companion.<role>.<mode> branch is -> single-branch selection refuses.
        Throwable thrown = catchThrowable(() ->
                new SpringApplicationBuilder(ProxyCompanionApplication.class)
                        .web(WebApplicationType.NONE)
                        .run());
        assertThat(thrown).as("a boot with no branch must refuse startup").isNotNull();
        assertThat(chainMessages(thrown))
                .as("startup failure must demand exactly one branch")
                .anyMatch(msg -> msg.contains("exactly one"));
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
}
