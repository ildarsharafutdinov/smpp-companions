# Epic 8 Context: Make it observable and installable — measurability close-out, sandbox Prometheus, Docker Hub publishing via CI

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->
<!-- Compiled 2026-09-20, post-Story-8.1: the observability audit + gap close is DONE (both latency histograms landed,
     spine-Deferred histogram item retired); Stories 8.2/8.3 not yet sliced into story files. -->

## Goal

Close out observability and installability before performance work (execution priority E6 → E8 → E9 → E7). The observability surface has been audited against operator needs and the measurable gaps closed (Story 8.1, done): both latency histograms landed under the unchanged loopback exposition posture. What remains: the docker-compose sandbox gains a Prometheus service that actually scrapes the packaged proxy's loopback-only `/metrics` via a sandbox-only access pattern that leaves the product's binding and fail-closed posture untouched; and the distroless image is published to Docker Hub automatically by a GitHub Actions workflow (build + test gate + push), so `docker compose up` works from a pull instead of a local build — completing the two-first-class-shapes deploy requirement and the shippable-OSS-release success metric. Operator docs follow: deployment-guide publish path, runbook scrape section, sandbox README (+ ru mirror). The epic reverses the 2026-09-11 no-CI stance (owner direction 2026-09-19).

## Stories

- Story 8.1: Observability/measurability audit + gap close
- Story 8.2: Sandbox Prometheus
- Story 8.3: GitHub CI + Docker Hub publish

## Requirements & Constraints

- **Audit discipline stands for the remaining work:** findings land with cited evidence; every gap is closed or explicitly ledgered in the deferred-work ledger — nothing silently dropped. The gaps 8.1 chose not to close (active-connections gauge, file log destination, ERROR severity register) are already ledgered there; do not re-audit and do not silently expand scope.
- **Cardinality rules bind any metrics touch:** no new label dimensions — labels reuse existing dimensions (`direction`, routing-table `system_id`) or stay unlabeled; no `command_id`/`ChannelId`/free-form `system_id` labels; bucket series multiply per label combination, so grids stay bounded. Message content never emitted. The product stays read-only exposition — no dashboard, no telemetry backend, no management API.
- **Loopback-only `/metrics` is untouchable:** the sandbox Prometheus reaches it via a sandbox-only fixture pattern (recommended: the Prometheus compose service joins the proxy's network namespace — a story-owned detail needing a proof before commit), never by widening the product's bind. The sandbox rig is fixture scope (same category as its bundled Keycloak vs "no bundled authority provider"); the product's "no metrics dashboard / telemetry backend" non-goal stands.
- **CI hygiene:** build + test gate + push; Docker Hub credentials live only in the GitHub Actions secret store — never in env vars or the repo; CI pins the toolchain (JDK/Netty versions) the CVE/dependency policy points at. The published image honors the Docker-secrets contract unchanged (secrets stay mounted file paths).
- **Docs ship with the epic:** deployment-guide publish path, runbook scrape section, sandbox README + ru mirror; mirrored RU pages require a conformance sweep under the owner's terminology glossary.
- **Success bar:** `docker compose up` in the sandbox pulls the published image and Prometheus scrapes `/metrics` with the loopback-only binding intact; CI builds + tests + publishes on the owner's trigger.

## Technical Decisions

- **What 8.1 landed (standing surface — don't re-plan it):** two latency histograms under the unchanged exposition posture — bind-adjudication latency (`relay_binds_adjudication_seconds`, unlabeled; grid anchored so the warm p99, the cold-path limit, and the adjudication-deadline default each fall strictly between adjacent edges) and per-PDU relay transit (`relay_pdus_transit_seconds{direction}`, sub-ms→s grid keeping the sub-ms per-PDU budget visible below the 1 ms edge). Both are pre-registered at construction from closed sets (an idle-boot scrape already shows every row at zero; no fire path can create a series) with throw-isolated recording. The bucket grids and scrape arithmetic of record live in the PRD addendum (note A8) and the runbook histogram rows — not the architecture spine.
- **The observer seam is now 5-method** — `onFramedPdu(Direction, Duration)`, `onBindAdjudication(Duration)`, `onBindAccept(SystemId)`, `onBindReject(SystemId, Verdict)`, `onConnectionClosed(Direction, CloseReason)` — pinned by a shape test; the `Duration` carries are timing scalars, never content. The codec stays meter-free; the Micrometer observer impl is the single meter source behind the seam.
- **Remaining stories own no product metrics code:** 8.2/8.3 touch `sandbox/` (Prometheus service + conf + README/ru), `.github/workflows/`, the Docker Hub publish path, and `docs/` updates. `proxy/observability/` is not expected to change; if a finding forces it, the audit-first closed-or-ledgered bar applies.
- **Publishing is execution of the existing deploy-shape requirement** — the Epic-5 distroless + jlink image (same JAR inside), not a new requirement or image variant. Repo/tag strategy and the Docker Hub namespace/token decision are owner inputs to the publish story. Compose files and runbooks switch from local-build to pull once publishing works.
- **The no-CI reversal is already ratified:** the perf-harness story's frozen "No CI scaffolding" Never-item is superseded by a dated amendment — the pipeline is owned by this epic; later stories must not edit it as a side effect, only via visible, task-required edits.

## Cross-Story Dependencies

- **Depends on Epic 5** (the distroless image — currently local-build only until publishing lands) **and Epic 6** (the docker-compose sandbox rig and the operator docs surface this epic updates).
- **Epic 9 depends on this epic:** the whole-codebase human read reviews Epic 8's output. Epic 7 runs after both (priority deferral); its harness story leaves the Epic-8 CI pipeline untouched except via explicit, task-required edits.
- Within the epic: 8.1 (done) preceded all histogram work by construction; the sandbox Prometheus consumes the histogram-bearing surface 8.1 shipped; the docs updates (publish path, scrape runbook rows, pull-based compose) naturally follow the CI/publish story landing.
