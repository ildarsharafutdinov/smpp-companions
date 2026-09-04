# Epic 4 Context: Operate the proxy in production — structured logs and read-only loopback /metrics

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Make the proxy operable in production: an operator scrapes a read-only Prometheus `/metrics` endpoint (loopback IPv4 only, cardinality bounded by the routing table), reads structured JSON-lines logs (startup/config-resolved, bind accept/reject with `system_id`, errors; full PDU/body TRACE-only and off by default), and triggers a SIGTERM graceful shutdown validated end-to-end. There is deliberately NO management API — no query/drain/reload/rotate at runtime; `/metrics` is read-only telemetry, never a control surface. The production observability implementation swaps the seeded noop observer behind unchanged seams, so the relay needs no re-architecture to become observable. Status: Epics 1–3 done (tracker flags flipped 2026-09-04). Epic 4 in progress: 4.1 done; 4.2/4.3 specs drafted 2026-09-04 (AD-22 split in two); the relay-timeout round (4.4) still to slice.

## Stories

Decomposition (updated 2026-09-04; the epics file leaves story placeholders and the tracker appends keys as stories are created):

- **4.1 — structured logs and loopback metrics: DONE (2026-09-04).** Carried the full observability impl (Micrometer `RelayObserver`, `/metrics` endpoint, JSON-lines logs) plus the observer-seam hardening and operator-warning bounding that had to land with it.
- **4.2 — AD-22 graceful shutdown pt. 1: deny-in-flight on a live loop + the 5-step skeleton** (spec `4-2-graceful-shutdown-deny-on-live-loop.md`, drafted 2026-09-04). Splits the verifier `close()` into deny/release, stops the acceptor killing the shared loop, lands the coordinator skeleton: deny → drain (empty seam) → release-await → quiesce. Fixes the stranded-continuation residue.
- **4.3 — AD-22 graceful shutdown pt. 2: the connection drain body** (spec `4-3-graceful-shutdown-drain.md`, drafted 2026-09-04). Fills the seam: registry enumeration + mutation fence, `companion.shutdown.drain-timeout`, drain-to-deadline with `SHUTDOWN_DRAIN` force-close, the new-adjudication gate (OBS-017), full ordering proofs (OBS-016, RELAY-022, OBS-020).
- **4.4 — relay-timeout round: NOT YET SLICED** (renumbered from the "story 4.3" references in 4.1's frozen block and earlier notes — adjudication deadline, egress connect bounding, ingress `bind_resp` handling, idle-timeout residue, re-homed to this epic by the deferred-work ledger). Re-check the ledger at story-creation.

## Requirements & Constraints

- **`/metrics` endpoint contract:** read-only Prometheus text exposition over a tiny hardened HTTP handler — GET-only, path exactly `/metrics`, everything else 404/405; bounded header/body limits; no hand-rolled HTTP parsing. Loopback IPv4 (127.0.0.1) is the SOLE authentication of the endpoint — non-loopback binding forbidden; never on the SMPP transit legs. Scrape must be idempotent and mutate nothing.
- **Cardinality is bounded by construction:** `system_id` labels only for routing-table values (bound at startup); unknown/rejected `system_id`s increment an unlabeled counter; no free-form `system_id`, no `command_id`, no channel-id label on any close/reject counter; a burst of distinct unknown ids must not grow the series count.
- **Privacy:** message/PDU bodies never in metrics and never in default-level logs (TRACE-only, off by default, level configurable); the bind password never appears in logs even at TRACE.
- **Logging shape:** JSON-lines with UTC ISO-8601 timestamps; startup line summarizes resolved config with no secret values; bind accept/reject lines carry `system_id` + verdict type and the wire `bind_resp` status code; no stack trace on the SMPP wire or in default-level logs.
- **No management surface:** no dashboard, remote-write, OTel traces, or control endpoints; config and TLS material are immutable at runtime (rotation = re-deploy). Candidate operator-control paths must all dead-end (404/405, no state change).
- **Graceful shutdown (end-to-end this epic):** SIGTERM → stop the acceptor (later binds DENYed, none accepted) → DENY in-flight adjudications fail-closed (no partial-verdict Allow race) → drain relayed traffic up to a timeout by enumerating the connection registry (no dropped/corrupted mid-write PDUs) → drain the control-plane VT pool (no orphaned adjudication VTs) → exit. Spring's graceful-shutdown timeout bounds the window; a peer that never half-closes is force-closed at the timeout, never hangs the exit.
- Scraping must not stall the relay — satisfied by the dedicated-loop design; the formal throughput-while-scraped proof belongs to the perf epic.

## Technical Decisions

- **DI-swap only for the observer:** the 4-method `RelayObserver` interface (`onFramedPdu(Direction)`, `onBindAccept(SystemId)`, `onBindReject(SystemId, Verdict)`, `onConnectionClosed(Direction, CloseReason)`) is unchanged — Epic 2's noop seed already carries the full shape. `relay/` is NOT modified for the swap; the codec never emits metrics; the Micrometer impl is the only thing behind the seam (one counter source).
- **Pinned trigger semantics:** `onBindAccept` fires exactly at the couple (decoded `bind_*_resp` ROK), not at the verdict; `onBindReject` only for verifier-returned Verdicts (routing-miss/config denies go to the unlabeled counter); `onConnectionClosed` exactly-once per channel at the `channelInactive` teardown site (CAS-guarded), backing `relay_connections_closed_total{direction, reason}` over the closed `CloseReason` enum (16 values, pre- and post-couple windows both spanned).
- **Endpoint mechanics:** Netty `HttpServerCodec` + `HttpObjectAggregator` handler on a DEDICATED hand-managed event loop group, started/stopped via `SmartLifecycle`, never sharing the SMPP relay loop; calls `PrometheusMeterRegistry.scrape()`. No Actuator/Tomcat/WebFlux anywhere (non-web Boot app; keep it that way).
- **Gauges:** a custom active-virtual-thread gauge (Micrometer `jvm_threads_*` does not count VTs) and a direct-memory gauge derived from the shared allocator's `ByteBufAllocatorMetric`.
- **Read-vs-emit rule:** internally reading the offending `command_id` for close-case selection is always fine; EMITTING `command_id` to logs/metrics is TRACE-gated and never via a codec helper.
- **Shutdown mechanics to re-author:** today's acceptor stop quiesces the shared relay event loop immediately, terminating established legs before any drain could run — the AD-22 drain body must reorder this (stop acceptor → drain pairs → then loop shutdown). The Netty `shutdownGracefully()` 2s-default quiet period is a known per-shutdown cost; pass an explicit shorter window. The new metrics-loop lifecycle adds a second `SmartLifecycle` — keep explicit phase management (the relay acceptor already stops before the app lifecycle).

## Cross-Story Dependencies

- Depends on Epics 2+3 (done). The packaging epic depends on this one; the perf/docs epic owns the formal load-test proof and the operator docs surface.
- **Deferred items naming this epic as home — re-check the deferred-work ledger at story-creation:**
  - Relay-timeout round: `companion.bind.adjudication-deadline` ships but is unarmed (a never-settling verifier pins the pair until the client gives up); the per-bind egress dial sets no connect timeout (blackholed SMSC hangs ~30s); a decoded `bind_resp` on the ingress leg is dropped rather than handled; accepted-but-never-binding sockets hold their connection-cap slot forever. This round is relay-side work — slice it deliberately; keep it out of the observer-swap story.
  - Observer-seam hardening lands WITH the production observer: no fire site today isolates a throwing implementation (the noop can't throw). Worst arm: a throwing `onBindReject` in the event-loop continuation leaks the original frame, skips the deny synthesis, and hangs the client until TCP timeout.
  - `CloseReason` firing semantics: two enum values (`EGRESS_CONNECT_FAILED`, `BIND_REJECTED`) never fire today — deny/connect-fail closes surface as OTHER; decide the hoist when the metrics observer consumes the taxonomy.
  - `onFramedPdu` fires only post-couple while its javadoc says "pre- or post-couple" — either fire at the handshakes (flips three pinned relay tests) or amend the javadoc.
  - Operator-warning bounding: the ~14-line starred provider-misconfig banner currently logs on EVERY denied bind (flood under a dead/typo'd provider); pick a bound (first-banner + one-liner, once-per-condition, keep per-bind) and align the opaque-token WARN to the same pattern.
  - Smaller: a meaningful upper-bound assertion for the shutdown window (today's bootstrap test only asserts stop-ran); an ArchUnit rule for registry-mutating calls outside the state manager; a wiring-level same-bean assertion that the per-leg initializers share one manager/registry.
- The test-design catalog's observability scenarios cover every branch above (endpoint hardening, cardinality attack, VT gauge, dedicated loop, shutdown ordering/races, log shape, no-management-path) — the AC-level source for story authors.
