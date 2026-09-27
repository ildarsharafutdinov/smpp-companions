---
title: 'Story 8.3 — GitHub CI and Docker Hub publish'
type: 'feature'
created: '2026-09-22'
status: 'in-progress'
route: 'dispatch'
baseline_commit: '7c932aee485cd3927fb39a74ffaf78c42936bf70'
review_loop_iteration: 0
context:
  - {project-root}/_bmad-output/implementation-artifacts/epic-8-context.md
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The distroless proxy image exists only as a local Gradle artifact (`smpp-proxy:local`), and the sandbox rig compiles Kannel from source on every host — six `build: ./kannel` compose stanzas and no pull-based path anywhere. No CI builds, tests, or publishes anything.

**Approach:** GitHub Actions workflows build + test + publish BOTH images to Docker Hub — the proxy's distroless image on the code cadence, the Kannel rig image on owner dispatch — and every consumer surface switches from local build to pull: the six compose stanzas, the README §5.5/§5.6 docker shapes, the three runbook pairs, and the deployment guide. Owner amendment 2026-09-22: the Kannel build is published too; the acceptance bar is runbook-level — any runbook runs green with ready-made, available images, zero local builds.

**Owner decisions (2026-09-22):** Q1 = namespace `ildarshara` — `ildarshara/smpp-companions-proxy` + `ildarshara/kannel` (amended same day from the org-namespace option; no org creation — the two repos under the existing namespace + the secrets are the owner-side prerequisites of the live round). Q2 = proxy tags `latest` + immutable `sha-<short>` + `vX.Y.Z` on git tags; owner amendment 2026-09-27: `latest` moves ONLY on git-tag (`vX.Y.Z`) pushes — an untagged main push or dispatch publishes `sha-<short>` alone, a tag push publishes `vX.Y.Z` + `latest` + `sha-<short>`; docs surfaces reference `latest`, and the live round cuts the first tag `v0.1.0` to light it up. Q3 = push to main publishes, PRs test-only, manual dispatch also publishes. Q4 = Kannel republish by manual dispatch + path-filter on `sandbox/kannel/**`; owner amendment 2026-09-27: every Kannel publish pushes `1.5.0` + immutable `sha-<short>` + `latest` — `latest` moves on every Kannel publish (its cadence is already owner-gated), compose keeps pinning the exact version tag. Q5 = keep the mutable distroless base tag — the parked 5.2 decision closes as resolved-keep-tag, recorded in the deployment guide. Q6 = wire the OWASP lane (scheduled/dispatch, `NVD_API_KEY`). Q7 = the `_max` fan-out test stays a standalone commit — this story touches nothing under `proxy/`.

## Boundaries & Constraints

**Always:**
- Credentials live only in GitHub Actions secrets (`DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` for publishing, `NVD_API_KEY` for the OWASP lane) — never in the repo, env files, or compose (AD-18 spirit).
- Publish is fail-closed behind the green `./gradlew clean build`: publish steps run only after the full suite passes in the same run; PRs never push.
- `:proxy:dockerImage` stays unwired from `build`/`check` (the ledgered daemon-less-CI constraint from 5.2): CI invokes it explicitly, then `docker tag`/`docker push` from `smpp-proxy:local` — zero build-file or buildSrc edits.
- Image references are exact-version tags (the rig's `keycloak:26.7.0` / `prometheus:v3.14.0` idiom); the six Kannel stanzas share ONE image reference. Owner amendment 2026-09-27: the proxy docs surfaces (README §5.5/§5.6, runbooks, deployment guide) reference `latest` — the release-only channel; the live round cuts the first git tag `v0.1.0` to create it.
- Hard pull switch — no `pull_policy` fallback; the local dev-rebuild path stays documented in one line.
- Sandbox RU twins mirror the EN changes with the terminology-glossary conformance sweep over the new text; EN normative.
- The pull-only bar is verified live during the story: the owner provisions the secrets and triggers one real publish; then the rig and a runbook run pull-only, evidence in Implementation Notes.

**Never:**
- No product, test, or build code: `proxy/`, `codec/`, `buildSrc/`, `*.gradle.kts` stay byte-untouched (the `_max` fan-out test stays a standalone commit per Q7). (Exception — owner-sanctioned CI hotfixes, 2026-09-27: the two AD-12 Keycloak fixture call sites, key-copy mode 0400→0444 and the 4-minute wait deadline→90s; plus the F13-cap recovery leg in `TlsModesLoopbackE2eTest` (bounded-poll for the async capacity return); see Spec Change Log.)
- No metrics bind/port/posture change (AD-19 byte-intact); no new product meters.
- No Epic-7 harness work; no JMH in the test gate; no closing of other ledgered items.
- No auto-reformat of untouched files; no new RU twins for EN-only docs (`deployment-guide.md`, `runbooks.md`).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| Cold-host rig bring-up | Docker host, zero local images, `docker compose up -d` | All 9 services pull and reach the §4 ready state — no `--build` | Pull failure = loud compose error; no fallback build |
| Runbook, docker shape | §5.6 runbook verbatim, no gradlew | Proxy runs from the pulled `latest` image; journey + Prometheus observations as documented | Missing image → docker names the reference |
| PR opened | CI on a pull request | build + test + docker-build proof; zero push | Suite failure → red run; publish steps unreachable |
| Untagged main push / dispatch | CI publish run | Full suite → `dockerImage` → tag + push `sha-<short>` only — `latest` untouched (owner amendment 2026-09-27) | Bad/missing secrets → login/push fails red; nothing half-published |
| Git-tag push `vX.Y.Z` | CI publish run | Full suite → `dockerImage` → tag + push `vX.Y.Z` + `latest` + `sha-<short>` | Bad/missing secrets → login/push fails red; nothing half-published |
| Kannel source change | Owner dispatches the kannel workflow (or a main-path change to `sandbox/kannel/**` fires it) | Kannel image rebuilt; `1.5.0` + `sha-<short>` + `latest` pushed — `1.5.0` and `latest` move, `sha-<short>` is the immutable record | The compose-pinned version tag moves only by owner dispatch or edit |

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
- [x] `.github/workflows/kannel-image.yml` -- build + push `sandbox/kannel` to `ildarshara/kannel` as `1.5.0` + `sha-<short>` + `latest`, triggered by manual dispatch and by main-path changes to `sandbox/kannel/**`. -- The Kannel lane runs on a different cadence than the proxy's; `latest` moves on every Kannel publish (owner amendment 2026-09-27 — the cadence is owner-gated, no churn to protect against).
- [x] `sandbox/compose.yml` -- the six stanzas `build: ./kannel` → `image:` pulling `ildarshara/kannel` at the upstream-version tag. -- One pull for six boxes; retires the six implicit build tags.
- [x] `.github/workflows/ci.yml` -- build + test + publish-proxy: setup-java Temurin 25 (no auto-provisioning — the runner's JDK), `./gradlew clean build` (Testcontainers-gated tests run: Docker present), `:proxy:dockerImage` as the docker-build proof, `(cd sandbox && docker compose config)` as the sanity step (the ledgered wiring), then tag and push to `ildarshara/smpp-companions-proxy` behind the secrets login — untagged main pushes and dispatches push `sha-<short>` only, a `vX.Y.Z` git-tag push additionally pushes `vX.Y.Z` + `latest` (owner amendment 2026-09-27); never on PRs. -- The epic's CI deliverable.
- [ ] `.github/workflows/owasp.yml` -- scheduled + dispatch lane running `:proxy:dependencyCheckAnalyze --no-parallel` behind `NVD_API_KEY`. -- Completes 1.1's two-lane CVE design (SEC-091 was always meant to be a CI lane).
- [ ] `sandbox/README.md` + `README.ru.md` -- pull-only bring-up (§4), §3 port rows, §5.5/§5.6 published-image runs at `ildarshara/smpp-companions-proxy:latest`, the one-line dev rebuild; RU mirror + glossary sweep. -- The rig doc must match the rig.
- [ ] `sandbox/runbooks/*.md` + `.ru.md` (3 pairs) -- drop the gradlew prerequisites; docker shapes reference the published image at `latest`; the jar bind-mount marked optional. -- The owner's acceptance bar is runbook-level.
- [ ] `docs/deployment-guide.md` -- publish-path section; Shape 2 refs at `latest`; the :429-441 digest-pin home records the resolved keep-mutable-tag decision (the parked 5.2 question closes). -- The publish is an operator surface, not just CI.
- [ ] Live round -- owner provisions the two Docker Hub repos under `ildarshara`, the `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` + `NVD_API_KEY` secrets, triggers the first publish (untagged main push -- proves the `sha-<short>`-only path, `latest` untouched), then pushes the first git tag `v0.1.0` (creating `vX.Y.Z` + `latest` -- the docs channel, owner decision 2026-09-27); then pull-only rig bring-up + a §5.6 runbook journey at `latest`; evidence in Implementation Notes. -- The bar is live, not config-derived.

**Acceptance Criteria:**
- Given a Docker host with no local images, when `docker compose up -d` in `sandbox/`, then every service pulls and the rig reaches its §4 ready state — no local build anywhere.
- Given the same host and a §5.6 runbook run verbatim, then the proxy runs from the pulled `latest` image (no gradlew step; `latest` exists because the live round cut `v0.1.0`) and the documented journey + Prometheus observations hold.
- Given a pull request, CI builds and tests but pushes nothing; given a failing suite, the publish steps are unreachable.
- Given an untagged main push, the publish pushes `sha-<short>` and Docker Hub's `latest` stays untouched; given a `vX.Y.Z` tag push, `latest` and `vX.Y.Z` move to that build; given a Kannel publish, `1.5.0` and `latest` move and a fresh immutable `sha-<short>` appears.
- Given the three workflow files, the YAML parses and `docker compose config` passes as a CI step.

## Implementation Notes

- **2026-09-27 — first live `ci` run (owner push, untagged main):** `:proxy:test` red — 445/447 green, both AD-12 Keycloak live suites (`RopcBindCredentialVerifierLiveTest`, `RopcSliceLiveTest`) timed out their 4-minute discovery windows back-to-back on the runner. Not reproducible locally (both suites green the same day, ~48 s incl. boots); `proxy/` byte-untouched, and the runner's Docker+Testcontainers machinery demonstrably worked (the distroless `DockerRig` suites were in the green 445). Fail-closed held as designed: the build died at the test gate, publish steps never reached. The naming evidence (the `last status / last error` tail) lives only in the ephemeral runner's XML report — ci.yml now carries an `if: failure()` post-mortem step dumping failing-suite XML + surviving container state; the next red run self-diagnoses. If the cause is Keycloak-boot-slowness on cold runners, the fix (longer fixture startup timeout) is in frozen test code — owner renegotiation required, not a silent edit.
- **2026-09-27 — verdict + fix (second run's self-diagnosis):** the dump step captured the failed containers' logs inside the XML: KC boots cleanly (pull 5 s, bootstrap 10.8 s, realm imported) then dies — `Failed to load 'https-*' material: AccessDeniedException /opt/keycloak/conf/server-key.pem`. Root cause proven locally with a docker-cp probe: archive copies preserve the EXTRACTING user's uid — the dev box runs tests as uid 1000 == Keycloak's image uid (green by coincidence), GitHub runners run as uid 1001 (the 0400 key lands unreadable → exit 1 → `ConnectException` fills the wait window). Image content ruled out (re-pull digest-identical). Owner-sanctioned fix (renegotiation above): 0444 + 90 s deadline in both fixtures. Also fixed: the dump step's `for … in $(…) || true` bash syntax error (step did its job but exited 2).
- **2026-09-27 — F13-cap recovery race (third run, post-Keycloak-fix):** Keycloak suites green; the sole red was `TlsModesLoopbackE2eTest.capRefusesConnectionsOverTheLimit` — `Connection reset` on the recovery dial (`:350`), with the relay logging TWO cap refusals 2 ms apart: the recovery accept raced the first leg's async `closeFuture` decrement and was correctly refused. Product exonerated (F13 javadoc counting); test-side bounded-poll applied (renegotiation #2 above). The dump step itself now ran clean (no syntax error).

## Spec Change Log

- **2026-09-27 — owner renegotiation, tag semantics (Q2/Q4):** proxy `latest` moves only on `vX.Y.Z` git-tag pushes — untagged main pushes and dispatches publish `sha-<short>` alone. Kannel publishes now carry `1.5.0` + `sha-<short>` + `latest` (was: `1.5.0` alone, mutated in place); compose keeps the exact-version pin. I/O matrix rows split, kannel/ci workflow tasks, an AC, and the design note updated to match.
- **2026-09-27 — owner decision (docs tag + first release):** the proxy docs surfaces reference the image at `latest`; the live round cuts the first git tag `v0.1.0` to create it (after an untagged first publish proves the sha-only path). The image-references constraint, runbook matrix row, docs/live-round tasks, and the runbook AC updated to match.
- **2026-09-27 — owner renegotiation, CI hotfix exception to the Never-clause:** first live `ci` run proved the AD-12 Keycloak fixtures' `0400` key-copy mode assumes the extracting uid equals Keycloak's image uid 1000 — true on the dev box (uid 1000) by coincidence, false on GitHub runners (uid 1001): `AccessDeniedException` → container exit 1 → both live suites `initializationError`. Sanctioned minimal edit, test code otherwise untouched: key-copy mode 0400→0444 (uid-agnostic read; throwaway fixture cert in an ephemeral container) and the discovery wait deadline 4 min→90 s (observed cold boot ~30 s end-to-end; the long window only burned CI time polling a crashed container) — both in `KeycloakContainer` and `TrustOnlyKeycloakContainer`. The Never-clause bullet carries the exception parenthetical.
- **2026-09-27 — owner renegotiation #2, second CI hotfix exception:** the post-fix run sailed past both Keycloak suites (build 13½→6½ min) and exposed the next runner-timing assumption: `TlsModesLoopbackE2eTest`'s F13-cap recovery leg dialed a fresh client immediately after client-side `close()`, assuming capacity returns before the next accept — but the decrement rides the child `closeFuture` (async teardown; runner log: the recovery dial was refused 2 ms after the over-cap one). Product behavior correct per the documented F13 counting (live legs, closeFuture-decremented); the fix is the house bounded-poll pattern on the recovery dial (refused attempts = decrement not yet run; a neutered decrement exhausts the loop and rethrows — the one-shot assertion's bite holds).

## Review Triage Log

## Design Notes

- **Execution order is owner-set (2026-09-22): Kannel first, then proxy** — the kannel workflow + compose pull-switch land before the proxy lanes, so the image the compose switch references already exists when it lands; the docs tasks follow the surfaces they document, live round last.
- Three workflows, three cadences: the proxy publishes on the code cadence; Kannel is a ~10-minute source compile that changes rarely (dispatch + path-filter); the OWASP NVD sweep is a scheduled/dispatch lane — one file would force one cadence on all three.
- `docker tag` from `smpp-proxy:local` rather than parameterizing `imageTag` — the story stays out of build files entirely; the 5.2 ledger's daemon-less-CI warning is exactly about not re-wiring these tasks.
- Publish steps live in the same job after the test steps (not a parallel job) — publish literally cannot run unless the suite passed in that runner; simplest fail-closed shape.
- Tag semantics after the 2026-09-27 owner amendment: the proxy's `latest` moves only on `vX.Y.Z` git-tag pushes — a release act; untagged main publishes stay addressable via the immutable `sha-<short>`. Kannel publishes `1.5.0` + `sha-<short>` + `latest`: the compose pin rides the upstream version (the rig's exact-version idiom), `sha-<short>` is the immutable record of each build, and `latest` moves on every Kannel publish — its cadence is owner-gated (dispatch or a real `sandbox/kannel/**` edit). A dispatch rebuild re-pushes `1.5.0` — owner-controlled mutation, documented as such. The proxy docs surfaces reference `latest` (owner decision 2026-09-27) — always the last release, stable for readers; the live round's `v0.1.0` tag push creates it.
- The first publish is owner-gated: secrets and trigger live outside the repo; the live AC follows the first green publish.

## Verification

**Commands:**
- `(cd sandbox && docker compose config)` -- expected: parses; the six Kannel services resolve `image:` with zero `build:` keys
- `grep -rn 'smpp-proxy:local\|build: \./kannel' sandbox/ docs/` -- expected: zero hits in operator surfaces
- `./gradlew clean build` -- expected: GREEN (the CI gate itself; house rule)

**Manual checks (if no CLI):**
- Live-round evidence in Implementation Notes: the first publish run, the pull-only bring-up, the runbook journey.
