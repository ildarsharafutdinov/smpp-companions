package smpp.companion.proxy.bootstrap;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
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
 */
@Tag("integration")
@Tag("deploy")
@Tag("p2")
class BootstrapLifecycleTest {

    @Test
    void bootsAsNonWebContextAndStartsLifecycle() {
        try (ConfigurableApplicationContext ctx = builder().run()) {
            assertThat(ctx.isActive()).isTrue();
            // No embedded web server (AD-16): the context is a plain AnnotationConfigApplicationContext.
            assertThat(ctx.getClass().getSimpleName()).doesNotContain("WebServer");
            // The SmartLifecycle stub was started.
            assertThat(ctx.getBean(ProxyCompanionLifecycle.class).isRunning()).isTrue();
        }
    }

    @Test
    void contextCloseStopsLifecycleWithinGracefulTimeout() {
        ConfigurableApplicationContext ctx = builder().run();
        ProxyCompanionLifecycle lifecycle = ctx.getBean(ProxyCompanionLifecycle.class);
        assertThat(lifecycle.isRunning()).isTrue();

        long start = System.nanoTime();
        ctx.close(); // SIGTERM-equivalent (ContextClosedEvent -> SmartLifecycle.stop)
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        assertThat(lifecycle.isRunning()).isFalse(); // stop() ran
        // Graceful-shutdown phase ceiling is 30s; a stub closes in well under that.
        assertThat(elapsedMs).isLessThan(30_000L);
    }

    private static SpringApplicationBuilder builder() {
        return new SpringApplicationBuilder(ProxyCompanionApplication.class)
            .web(WebApplicationType.NONE)
            .properties("companion.role=forward");
    }
}
