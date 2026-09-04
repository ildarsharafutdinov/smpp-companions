/**
 * Structured logging and the read-only {@code /metrics} surface (Micrometer {@code
 * PrometheusMeterRegistry}) &mdash; Story 4.1, shipped whole: the loopback endpoint slice (T2), the
 * production observer ({@code MeteredRelayObserver}, @Primary over the seeded noop), the resource
 * gauges and the startup summary line (T3), the relay-seam hardening (T4: fire-site throw
 * isolation, the {@link CloseReason} deny-path hoist, TRACE-gated PDU bodies), operator-warning
 * flood bounding in the ROPC verifier (T5), and the log-shape, layer-rule, and config-guard tests
 * (T6).
 */
@NullMarked // AD-35: every type in this package is non-null unless explicitly @Nullable.
package smpp.companion.proxy.observability;

import org.jspecify.annotations.NullMarked;
