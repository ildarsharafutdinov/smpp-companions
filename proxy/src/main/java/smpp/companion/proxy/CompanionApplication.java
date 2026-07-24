package smpp.companion.proxy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Process entry point. Boots a NON-web Spring context (AD-16: no embedded server) and owns the
 * graceful-shutdown window for the future AD-22 phase-ordered shutdown body (Epic 4). Lives at the
 * root proxy package so {@code @SpringBootApplication} component scan + {@code
 * ConfigurationPropertiesScan} cover every subpackage (bootstrap, config, relay, security,
 * observability).
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class CompanionApplication {

    public static void main(String[] args) {
        SpringApplication.run(CompanionApplication.class, args);
    }
}
