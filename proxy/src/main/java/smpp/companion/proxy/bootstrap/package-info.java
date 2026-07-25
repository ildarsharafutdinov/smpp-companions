/**
 * Process bootstrap — Spring Boot 4.1 {@code @SpringBootApplication} entry point with NO embedded
 * web server (AD-16). Owns the Spring context lifecycle and the graceful-shutdown window that will
 * bound the future AD-22 phase-ordered shutdown body (Epic 4).
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.proxy.bootstrap;

import org.jspecify.annotations.NullMarked;
