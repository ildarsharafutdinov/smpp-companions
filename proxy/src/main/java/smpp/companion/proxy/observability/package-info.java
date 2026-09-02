/**
 * Structured logging and the read-only {@code /metrics} surface (Micrometer {@code
 * PrometheusMeterRegistry}). Epic 4 body landing (Story 4.1): the endpoint slice is live; the
 * production observer and JSON log lines follow in the story's remaining tasks.
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.proxy.observability;

import org.jspecify.annotations.NullMarked;
