/**
 * Structured logging and the read-only {@code /metrics} surface (Micrometer {@code
 * PrometheusMeterRegistry}). Story 4.1: the endpoint slice (T2) and the production observer,
 * resource gauges, and startup summary line (T3) are live; the relay-seam hardening (T4) and the
 * warning bounding, log-shape, rules, and guard tests (T5-T6) follow in the story's remaining
 * tasks.
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.proxy.observability;

import org.jspecify.annotations.NullMarked;
