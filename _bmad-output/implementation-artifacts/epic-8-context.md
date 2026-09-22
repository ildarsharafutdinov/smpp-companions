# Epic 8 Context: Make it observable and installable — measurability close-out, sandbox Prometheus, Docker Hub publishing via CI

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->
<!-- Compiled 2026-09-22, pre-Story-8.3: 8.1 (observability audit + both latency histograms) and 8.2 (sandbox
     Prometheus — 9-service compose, netns-join scrape, loopback-only UI) are DONE; the epic flag in sprint-status
     still reads done from the 8.1/8.2 close — the 8.3 slice reopens it. 8.3 is the last story: CI + publish. -->

## Goal

Close out installability before the review and performance epics (execution priority E6 → E8 → E9 → E7). Observability is done: the surface was audited, both latency histograms landed (8.1), and the sandbox Prometheus scrapes the packaged proxy's loopback-only `/metrics` without touching the product's binding or fail-closed posture (8.2). What remains is the epic's third deliverable: the distroless image is published to Docker Hub automatically by a GitHub Actions workflow (build + test gate + push), so `docker compose up` works from a pull instead of a local build — completing the two-first-class-shapes deploy requirement and the shippable-OSS-release success metric. Operator docs follow: deployment-guide publish path, runbook/compose switch from local-build to pull. The epic reverses the 2026-09-11 no-CI stance (owner direction 2026-09-19).

## Stories

- Story 8.1: Observability/measurability audit + gap close — done
- Story 8.2: Sandbox Prometheus — done
- Story 8.3: GitHub CI + Docker Hub publish — the remaining story

## Requirements & Constraints

- **CI hygiene:** build + test gate + push. Docker Hub credentials live only in the GitHub Actions secret store (DOCKERHUB namespace/token is an owner decision at story time), never in env vars or the repo; CI pins the toolchain (JDK/Netty versions) the CVE/dependency policy points at. No product code change.
- **The image-build Gradle task stays out of `check`** — it is deliberately not cacheable and unwired, because a daemon-less CI would break if `build` depended on it. CI invokes image building explicitly, never via the `check`/`build` path; recorded in the deferred-work ledger so the story does not "fix" that wiring.
- **Base-image digest pinning is this story's owner decision** (CVE freshness of the distroless base vs reproducible builds), parked since 5.2 for the release/publish tooling that this story now is.
- **Ledgered work already assigned to this story:** wire `docker compose config` (+ config sanity) into the story's automation (from 8.2's Never clause — nothing recurring currently reads the sandbox compose files); optionally extend the histogram scrape assertions with the zero-valued `_max` rows (a standalone test-only commit also carries it).
- **The published image honors the deploy contract unchanged:** same distroless + jlink image, same JAR inside; Docker secrets stay mounted file paths; only the published SMPP port is exposed.
- **Docs follow the publish:** deployment-guide publish path; runbook/compose entries switch from local-build to pull once publishing works. The sandbox README/ru already carry the Prometheus pointers from 8.2 — extend, don't rework; RU mirrors follow the terminology glossary + conformance sweep.
- **Success bar:** `docker compose up` in the sandbox pulls the published image and Prometheus scrapes `/metrics` with the loopback-only binding intact; CI builds + tests + publishes on the owner's trigger.

## Technical Decisions

- **Publishing is execution of the existing deploy-shape requirement** — the Epic-5 distroless image, not a new image variant. Docker Hub repo/tag strategy is an owner input to this story.
- **The no-CI reversal is already ratified:** Story 7.1's frozen "No CI scaffolding" Never-item is superseded by a dated amendment — the pipeline is owned by this epic; later stories must not edit it as a side effect, only via visible, task-required edits.
- **What already landed (don't re-plan):** 8.1's two latency histograms under the unchanged loopback exposition (grids and scrape arithmetic of record live in the PRD addendum note A8 and the runbook rows); 8.2's sandbox Prometheus (the compose service joins the proxy's network namespace to scrape loopback — AD-19 untouched; both 9090/9091 targets configured; no healthcheck/`depends_on` by design).
- **No product metrics code in this story:** it touches `.github/workflows/`, the Docker Hub publish path, `sandbox/` (pull-based switch), and `docs/`. `proxy/observability/` is not expected to change; if a finding forces it, the audit-first closed-or-ledgered bar applies.
- **Cardinality rules bind any metrics touch:** no new label dimensions; message content never emitted. (Listed for completeness — this story is not expected to touch metrics.)

## Cross-Story Dependencies

- **Depends on Epic 5** (the distroless image — local-build only until this story lands) **and Epic 6** (the sandbox rig and operator-docs surface the pull-based switch updates).
- **Epic 9 depends on this epic:** the whole-codebase human read reviews this story's `.github/` output as part of Epic 8's corpus. Epic 7 runs after both and leaves the pipeline untouched except via explicit, task-required edits.
- **Ledger defers pointing at this story:** the sandbox compose-config CI check and the `_max` fan-out test (both from the 8.2 review round), plus the two parked 5.2 decisions named above (image-task wiring, digest pinning). Other open 8.2 pends (the 0.183 s identity, the forward-cell formula, the two-instance UP check) are rig-run settlements, not this story's work.
