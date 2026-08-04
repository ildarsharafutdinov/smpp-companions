package smpp.companion.proxy.bootstrap;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import smpp.companion.proxy.ProxyCompanionApplication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC8: Spring Boot boots a NON-web context and shuts down cleanly within the graceful-shutdown
 * timeout. "SIGTERM-equivalent" = closing the context ({@code ContextClosedEvent} ->
 * {@code SmartLifecycle.stop}), which is exactly what the JVM shutdown hook does on SIGTERM.
 * Framework only — not the AD-22 7-step body.
 *
 * <p>Story 1.3 lockstep: the boot now supplies a complete valid forward+A config (mode + the
 * cell-required secret paths + routing + OIDC) so the AD-17 matrix validator passes and the test
 * keeps exercising lifecycle, not the new required fields.
 */
@Tag("integration")
@Tag("deploy")
@Tag("p2")
class BootstrapLifecycleTest {

    @Test
    void bootsAsNonWebContextAndStartsLifecycle(@TempDir Path dir) throws IOException {
        try (ConfigurableApplicationContext ctx = builder(dir).run()) {
            assertThat(ctx.isActive()).isTrue();
            // No embedded web server (AD-16): the context is a plain AnnotationConfigApplicationContext.
            assertThat(ctx.getClass().getSimpleName()).doesNotContain("WebServer");
            // The SmartLifecycle stub was started.
            assertThat(ctx.getBean(ProxyCompanionLifecycle.class).isRunning()).isTrue();
        }
    }

    @Test
    void contextCloseStopsLifecycleWithinGracefulTimeout(@TempDir Path dir) throws IOException {
        ConfigurableApplicationContext ctx = builder(dir).run();
        ProxyCompanionLifecycle lifecycle = ctx.getBean(ProxyCompanionLifecycle.class);
        assertThat(lifecycle.isRunning()).isTrue();

        long start = System.nanoTime();
        ctx.close(); // SIGTERM-equivalent (ContextClosedEvent -> SmartLifecycle.stop)
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        assertThat(lifecycle.isRunning()).isFalse(); // stop() ran
        // Graceful-shutdown phase ceiling is 30s; a stub closes in well under that.
        assertThat(elapsedMs).isLessThan(30_000L);
    }

    /**
     * A forward+A boot: the common keys come from application.yml; the forward.mode-a branch supplies
     * the cell-required material. The secret paths point at empty files under the temp dir
     * (existence+readability is what 1.3 validates; the cert/key content is a runtime TLS concern, Epic 3).
     */
    private static SpringApplicationBuilder builder(Path dir) throws IOException {
        Path cert = Files.createFile(dir.resolve("server.crt"));
        Path key = Files.createFile(dir.resolve("server.key"));
        Path cred = Files.createFile(dir.resolve("oidc-cred"));
        return new SpringApplicationBuilder(ProxyCompanionApplication.class)
                .web(WebApplicationType.NONE)
                .properties(
                        "companion.forward.mode-a.server-cert.cert-path=" + cert,
                        "companion.forward.mode-a.server-cert.key-path=" + key,
                        "companion.forward.mode-a.oidc.provider-url=https://idp.example.com",
                        "companion.forward.mode-a.oidc.client-credential-path=" + cred,
                        "companion.forward.mode-a.routing[0].system-id=carrierOne",
                        "companion.forward.mode-a.routing[0].host=reverse.internal",
                        "companion.forward.mode-a.routing[0].port=2776");
    }
}
