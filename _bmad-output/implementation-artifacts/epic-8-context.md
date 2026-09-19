# Epic 8 Context: Make it observable and installable — measurability close-out, sandbox Prometheus, Docker Hub publishing via CI

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->
<!-- Compiled 2026-09-19: Epic 8 added same day by the approved correctness-first re-prioritization (sprint-change-proposal-2026-09-19).
     No story files exist yet — the story list below is the ratified suggested slicing; story keys join the tracker as files are created. -->

## Goal

Close out observability and installability before performance work (execution priority E6 → E8 → E9 → E7). Three things land: the proxy's observability surface is audited against operator needs and closed where measurable gaps remain (prime candidate: latency/timer histograms — a long-deferred item — under the `/metrics` cardinality rules, no new labels); the docker-compose sandbox gains a Prometheus service that actually scrapes the packaged proxy's loopback-only `/metrics` via a sandbox-only access pattern that leaves the product's binding and fail-closed posture untouched; and the distroless image is published to Docker Hub automatically by a GitHub Actions workflow (build + test gate + push), so `docker compose up` works from a pull instead of a local build — completing the two-first-class-shapes deploy requirement and the shippable-OSS-release success metric. Operator docs follow: deployment-guide publish path, runbook scrape section, sandbox README (+ ru mirror). The epic reverses the 2026-09-11 no-CI stance (owner direction 2026-09-19).

## Stories

- Story 8.1: Observability/measurability audit + gap close
- Story 8.2: Sandbox Prometheus
- Story 8.3: GitHub CI + Docker Hub publish

## Requirements & Constraints

- **Audit before close:** the observability audit must land with cited evidence; every gap found is closed or explicitly ledgered — nothing silently dropped.
- **Cardinality rules bind any new metrics:** latency/timer histograms (the named candidate) must not add label dimensions; `system_id` labels stay bounded to routing-table values; message content never emitted. The product remains read-only exposition — still no dashboard, telemetry backend, or management API.
- **Loopback-only `/metrics` is untouchable:** the sandbox Prometheus reaches it via a sandbox-only fixture pattern (recommended: the Prometheus compose service joins the proxy's network namespace) — never by widening the product's bind. The sandbox rig is fixture scope (same category as its bundled Keycloak vs "no bundled authority provider"); the product's "no metrics dashboard / telemetry backend" non-goal stands.
- **CI hygiene:** build + test gate + push; Docker Hub credentials live only in the GitHub Actions secret store — never in env vars or the repo; CI pins the toolchain (JDK/Netty versions) the CVE/dependency policy points at. The published image honors the Docker-secrets contract unchanged (secrets stay mounted file paths).
- **Docs ship with the epic:** deployment-guide publish path, runbook scrape section, sandbox README + ru mirror; mirrored RU pages require a conformance sweep under the owner's terminology glossary.
- **Success bar:** `docker compose up` in the sandbox pulls the published image and Prometheus scrapes `/metrics` with the loopback-only binding intact; CI builds + tests + publishes on the owner's trigger.

## Technical Decisions

- `proxy/observability/` receives gap-close edits only, audit first — the Micrometer/Prometheus exposition model is unchanged; histogram buckets are the deferred detail this epic may now land (loopback posture + cardinality mechanism were fixed earlier; only the bucket detail was deferred).
- Sandbox posture otherwise unchanged: the packaged-container rig keeps its composition; the network-namespace sharing pattern is a flagged networking quirk that needs a story-level proof before commit.
- CI shape: `.github/workflows/` — build + test gate + Docker Hub push; repo/tag strategy and the Docker Hub namespace/token decision are owner inputs to the publish story. Compose files and runbooks switch from local-build to pull once publishing works.
- Publishing is execution of the existing deploy-shape requirement (the Epic-5 distroless + jlink image, same JAR inside), not a new requirement or image variant.
- Story 7.1's frozen "No CI scaffolding" Never-item is superseded by a dated amendment; the Epic-8 pipeline is owned here — later stories must not edit it as a side effect, only via visible edits.

## Cross-Story Dependencies

- **Depends on Epic 5** (the distroless image — currently local-build only) **and Epic 6** (the docker-compose sandbox rig and the operator docs surface this epic updates).
- **Epic 9 depends on this epic:** the whole-codebase human read reviews Epic 8's output. Epic 7 runs after both (priority deferral); its harness story leaves the Epic-8 CI pipeline untouched except via explicit, task-required edits.
- Within the epic: the observability audit precedes any histogram work by construction (audit-first), and the docs updates (publish path, scrape runbook, pull-based compose) naturally follow the CI/publish story landing.
