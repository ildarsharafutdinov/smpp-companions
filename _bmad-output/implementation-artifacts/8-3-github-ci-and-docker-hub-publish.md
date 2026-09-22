---
title: 'Story 8.3 — GitHub CI and Docker Hub publish'
type: 'feature'
created: '2026-09-22'
status: 'ready-for-dev'
route: 'dispatch'
review_loop_iteration: 0
context:
  - {project-root}/_bmad-output/implementation-artifacts/epic-8-context.md
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The distroless proxy image exists only as a local Gradle artifact (`smpp-proxy:local`), and the sandbox rig compiles Kannel from source on every host — six `build: ./kannel` compose stanzas and no pull-based path anywhere. No CI builds, tests, or publishes anything.

**Approach:** GitHub Actions workflows build + test + publish BOTH images to Docker Hub — the proxy's distroless image on the code cadence, the Kannel rig image on owner dispatch — and every consumer surface switches from local build to pull: the six compose stanzas, the README §5.5/§5.6 docker shapes, the three runbook pairs, and the deployment guide. Owner amendment 2026-09-22: the Kannel build is published too; the acceptance bar is runbook-level — any runbook runs green with ready-made, available images, zero local builds.

**Owner decisions (2026-09-22):** Q1 = namespace `ildarshara` — `ildarshara/smpp-companions-proxy` + `ildarshara/kannel` (amended same day from the org-namespace option; no org creation — the two repos under the existing namespace + the secrets are the owner-side prerequisites of the live round). Q2 = proxy tags `latest` + immutable `sha-<short>` + `vX.Y.Z` on git tags. Q3 = push to main publishes, PRs test-only, manual dispatch also publishes. Q4 = Kannel republish by manual dispatch + path-filter on `sandbox/kannel/**`. Q5 = keep the mutable distroless base tag — the parked 5.2 decision closes as resolved-keep-tag, recorded in the deployment guide. Q6 = wire the OWASP lane (scheduled/dispatch, `NVD_API_KEY`). Q7 = the `_max` fan-out test stays a standalone commit — this story touches nothing under `proxy/`.

## Boundaries & Constraints

**Always:**
- Credentials live only in GitHub Actions secrets (`DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` for publishing, `NVD_API_KEY` for the OWASP lane) — never in the repo, env files, or compose (AD-18 spirit).
- Publish is fail-closed behind the green `./gradlew clean build`: publish steps run only after the full suite passes in the same run; PRs never push.
- `:proxy:dockerImage` stays unwired from `build`/`check` (the ledgered daemon-less-CI constraint from 5.2): CI invokes it explicitly, then `docker tag`/`docker push` from `smpp-proxy:local` — zero build-file or buildSrc edits.
- Image references are exact-version tags (the rig's `keycloak:26.7.0` / `prometheus:v3.14.0` idiom); the six Kannel stanzas share ONE image reference.
- Hard pull switch — no `pull_policy` fallback; the local dev-rebuild path stays documented in one line.
- Sandbox RU twins mirror the EN changes with the terminology-glossary conformance sweep over the new text; EN normative.
- The pull-only bar is verified live during the story: the owner provisions the secrets and triggers one real publish; then the rig and a runbook run pull-only, evidence in Implementation Notes.

**Never:**
- No product, test, or build code: `proxy/`, `codec/`, `buildSrc/`, `*.gradle.kts` stay byte-untouched (the `_max` fan-out test stays a standalone commit per Q7).
- No metrics bind/port/posture change (AD-19 byte-intact); no new product meters.
- No Epic-7 harness work; no JMH in the test gate; no closing of other ledgered items.
- No auto-reformat of untouched files; no new RU twins for EN-only docs (`deployment-guide.md`, `runbooks.md`).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| Cold-host rig bring-up | Docker host, zero local images, `docker compose up -d` | All 9 services pull and reach the §4 ready state — no `--build` | Pull failure = loud compose error; no fallback build |
| Runbook, docker shape | §5.6 runbook verbatim, no gradlew | Proxy runs from the pulled image; journey + Prometheus observations as documented | Missing image → docker names the reference |
| PR opened | CI on a pull request | build + test + docker-build proof; zero push | Suite failure → red run; publish steps unreachable |
| Main push / dispatch | CI publish run | Full suite → `dockerImage` → tag (`latest`, `sha-<short>`, `vX.Y.Z` on git tags) → push | Bad/missing secrets → login/push fails red; nothing half-published |
| Kannel source change | Owner dispatches the kannel workflow (or a main-path change to `sandbox/kannel/**` fires it) | Kannel image rebuilt + pushed | The compose-pinned tag moves only by owner dispatch or edit |

</frozen-after-approval>

## Code Map

- `buildSrc/src/main/kotlin/smpp/deploy/DockerImageTask.kt:19-107` -- `docker build` + inspect, fail-closed; deliberately NOT cacheable and NOT wired into build/check — keep it so; CI calls the task by name.
- `proxy/build.gradle.kts:126-158` -- `assembleDockerContext` (cacheable, daemon-free) → `jlinkRuntimeImage` → `dockerImage`, hardcoded `imageTag = smpp-proxy:local` (:155); `:proxy:test` already depends on jlink + context, so CI's docker step is the only addition.
- `proxy/src/docker/Dockerfile` -- `gcr.io/distroless/base-debian12:nonroot` tag-pinned (:18); exec ENTRYPOINT with ZGC + 6 GiB direct-memory flag — a cap, not an allocation; safe on 7 GB runners.
- `sandbox/kannel/Dockerfile` -- one build context: ubi10:10.1 builder compiling Kannel gateway 1.5.0 + opensmppbox + sqlbox + fakesmsc; bases already version/exact-rpm pinned.
- `sandbox/compose.yml:35,54,67,79,99,112` -- the six `build: ./kannel` stanzas to switch (compose currently builds SIX per-service image tags); the pulled services are already exact-pinned (`quay.io/keycloak/keycloak:26.7.0` :141, `prom/prometheus:v3.14.0` :185).
- `sandbox/README.md` + `README.ru.md` -- §4 :197 `up -d --build`; §5.2 :322-349 host-run jar (local by nature — stays); §5.5 :443-491 and §5.6 :493-528 (`dockerImage` → `smpp-proxy:local`; jar bind-mount :499-502 becomes the optional dev loop); §3 port rows :168-186; RU twins mirror the same sections.
- `sandbox/runbooks/{reverse-mode-b,forward-reverse-mode-a,forward-reverse-mode-c}.md` + `.ru.md` -- local-build prerequisites throughout (e.g. reverse-mode-b :48 gradlew build, :54 `up --build`, :164 jar-swap rebuild) + image refs.
- `docs/deployment-guide.md:57-78,194-268,429-441` -- Shape 2 local-image refs; :429-441 names this story's subject as "the future home of any digest pin … release/publish tooling, which deliberately does not exist yet" — update to the resolved keep-mutable-tag decision.
- `_bmad-output/implementation-artifacts/deferred-work.md:809,812,913` -- the entries this story settles (image-task wiring stance, digest-pin decision, compose-config CI wiring); `:910` (the `_max` test) stays open for a standalone commit per Q7.
- `.github/` -- does not exist yet; all three workflow files are new.

## Tasks & Acceptance

**Execution:**
- [ ] `.github/workflows/kannel-image.yml` -- build + push `sandbox/kannel` to `ildarshara/kannel`, triggered by manual dispatch and by main-path changes to `sandbox/kannel/**`. -- The Kannel lane runs on a different cadence than the proxy's.
- [ ] `sandbox/compose.yml` -- the six stanzas `build: ./kannel` → `image:` pulling `ildarshara/kannel` at the upstream-version tag. -- One pull for six boxes; retires the six implicit build tags.
- [ ] `.github/workflows/ci.yml` -- build + test + publish-proxy: setup-java Temurin 25 (no auto-provisioning — the runner's JDK), `./gradlew clean build` (Testcontainers-gated tests run: Docker present), `:proxy:dockerImage` as the docker-build proof, `(cd sandbox && docker compose config)` as the sanity step (the ledgered wiring), then tag (`latest`, `sha-<short>`, `vX.Y.Z` on git tags) and push to `ildarshara/smpp-companions-proxy` behind the secrets login — publishing on main pushes and dispatch, never on PRs. -- The epic's CI deliverable.
- [ ] `.github/workflows/owasp.yml` -- scheduled + dispatch lane running `:proxy:dependencyCheckAnalyze --no-parallel` behind `NVD_API_KEY`. -- Completes 1.1's two-lane CVE design (SEC-091 was always meant to be a CI lane).
- [ ] `sandbox/README.md` + `README.ru.md` -- pull-only bring-up (§4), §3 port rows, §5.5/§5.6 published-image runs, the one-line dev rebuild; RU mirror + glossary sweep. -- The rig doc must match the rig.
- [ ] `sandbox/runbooks/*.md` + `.ru.md` (3 pairs) -- drop the gradlew prerequisites; docker shapes reference the published image; the jar bind-mount marked optional. -- The owner's acceptance bar is runbook-level.
- [ ] `docs/deployment-guide.md` -- publish-path section; Shape 2 refs; the :429-441 digest-pin home records the resolved keep-mutable-tag decision (the parked 5.2 question closes). -- The publish is an operator surface, not just CI.
- [ ] Live round -- owner provisions the two Docker Hub repos under `ildarshara`, the `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` + `NVD_API_KEY` secrets, and triggers the first publish; then pull-only rig bring-up + a §5.6 runbook journey; evidence in Implementation Notes. -- The bar is live, not config-derived.

**Acceptance Criteria:**
- Given a Docker host with no local images, when `docker compose up -d` in `sandbox/`, then every service pulls and the rig reaches its §4 ready state — no local build anywhere.
- Given the same host and a §5.6 runbook run verbatim, then the proxy runs from the pulled image (no gradlew step) and the documented journey + Prometheus observations hold.
- Given a pull request, CI builds and tests but pushes nothing; given a failing suite, the publish steps are unreachable.
- Given the three workflow files, the YAML parses and `docker compose config` passes as a CI step.

## Implementation Notes

## Spec Change Log

## Review Triage Log

## Design Notes

- **Execution order is owner-set (2026-09-22): Kannel first, then proxy** — the kannel workflow + compose pull-switch land before the proxy lanes, so the image the compose switch references already exists when it lands; the docs tasks follow the surfaces they document, live round last.
- Three workflows, three cadences: the proxy publishes on the code cadence; Kannel is a ~10-minute source compile that changes rarely (dispatch + path-filter); the OWASP NVD sweep is a scheduled/dispatch lane — one file would force one cadence on all three.
- `docker tag` from `smpp-proxy:local` rather than parameterizing `imageTag` — the story stays out of build files entirely; the 5.2 ledger's daemon-less-CI warning is exactly about not re-wiring these tasks.
- Publish steps live in the same job after the test steps (not a parallel job) — publish literally cannot run unless the suite passed in that runner; simplest fail-closed shape.
- The Kannel tag rides the upstream version (`1.5.0`), matching the rig's exact-version pin idiom; a dispatch rebuild re-pushes the same tag — owner-controlled mutation, documented as such.
- The first publish is owner-gated: secrets and trigger live outside the repo; the live AC follows the first green publish.

## Verification

**Commands:**
- `(cd sandbox && docker compose config)` -- expected: parses; the six Kannel services resolve `image:` with zero `build:` keys
- `grep -rn 'smpp-proxy:local\|build: \./kannel' sandbox/ docs/` -- expected: zero hits in operator surfaces
- `./gradlew clean build` -- expected: GREEN (the CI gate itself; house rule)

**Manual checks (if no CLI):**
- Live-round evidence in Implementation Notes: the first publish run, the pull-only bring-up, the runbook journey.
