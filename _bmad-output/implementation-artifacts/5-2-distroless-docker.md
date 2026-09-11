---
title: 'Story 5.2 — the distroless Docker deploy shape'
type: 'feature'
created: '2026-09-11'
status: 'ready-for-dev'
route: 'dispatch'
baseline_commit: 6ebab69a284f385c1ae6e28f5daf3d2c4382bb79
review_loop_iteration: 0
context:
  - {project-root}/_bmad-output/implementation-artifacts/epic-5-context.md
  - {project-root}/_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Epic 5 shipped only one of its two deploy shapes: 5.1 made `java -jar` first-class, but no Docker image exists — no Dockerfile, no jlink runtime, the operator flag set has no entrypoint carrier, the DEP-1 secrets contract (mounted files, non-root UID, the env-value stance) is unproven in any container, and every DEPLOY catalog Docker half is open.

**Approach:** Package the SAME `proxy.jar` (5.1's artifact, never rebuilt) over a Gradle-built jlink runtime (module set resolved by jdeps from the actual jar + the crypto floor) in a distroless non-root image whose exec-form ENTRYPOINT carries the ONE operator flag set verbatim — the third kept-in-step representation beside the contract page and `PackagedBootSmokeTest.OPERATOR_JVM_FLAGS`. Prove two-shape parity and the secrets contract end-to-end via Testcontainers (reusing the 5.1 rig's satellites and assertions; env-value secrets are inert by structure — no guard, owner decision 2026-09-11), and true the catalog, ledger, and flag-contract page.

## Boundaries & Constraints

**Always:**
- ONE artifact, two shapes: the image packages the 5.1 boot jar byte-for-byte (`proxy/build/libs/proxy.jar`); no second build, no forked packaging (FR-DEPLOY-1).
- ONE flag set: the ENTRYPOINT carries exactly the contract set (`--enable-preview`, `-XX:+UseZGC`, `-XX:MaxDirectMemorySize=6442450944`, `-Djava.net.preferIPv4Stack=true`); page ↔ Java constant ↔ ENTRYPOINT coherence is a review-time duty of every flag-change story (5.1's rule; no Java parses the page).
- Fail-closed holds identically in-container: the AD-17 config matrix, AD-30 budget check, and secret-file validation refuse, never warn-and-continue.
- Module set resolved from the actual jar via jdeps (over the exploded BOOT-INF layout — jdeps cannot read the nested fat jar directly), never a hand-maintained list; the floor `jdk.crypto.ec` + `jdk.crypto.cryptoki` + `java.management` is added on top (statically invisible via security providers), per DEPLOY-001.
- Secrets: mounted files under `/run/secrets`, read by the non-root UID; NEVER env values (AD-18, upheld STRUCTURALLY — every secret key is a file Path and no value key exists to bind; the env channel carries no guard, owner decision 2026-09-11), NEVER baked into any image layer (FR-DEPLOY-4, SEC-098).
- Docker-gated E2E rides the repo idiom `@Testcontainers(disabledWithoutDocker = true)` (RpcSliceLiveTest precedent) — no new assumeTrue shims; daemon verified on the dev box (29.6.1, cgroup v2).
- Ledger discipline: every catalog Status marker cites a biting test + commit; every new guard ships its mutation row.

**Never:**
- No relay/security/observability/config/bootstrap logic changes at all — 5.2 is pure packaging + tests + docs (the env-value guard variant was owner-dropped 2026-09-11; see Decisions).
- No new operator-facing config keys — metrics stays hostless literal-loopback (AD-19/AD-28, DEPLOY-011: a non-loopback exposure cannot be misconfigured into existence); cell config rides args/path-env overrides exactly as 5.1's packaged smoke.
- No dual-arch CI matrix and no release/publish tooling (owner decision 2026-09-11: no arm64 needed — DEPLOY-013 closes as owner-amended; no CI exists).
- No Epoll/native-transport adoption: the relay is NIO by design (`RelayNettyConfig` uses `NioIoHandler.newFactory()`; no epoll classifier ships in the jar) — DEPLOY-002/010 are premise-voided by dated markers, not by code changes.
- No native-image (AD-23); no launch config in the jar manifest (5.1 decision stands).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Docker happy boot | `docker run` image + reverse-B cell args (secrets mounted readable) | `startup_summary` JSON on stdout; budget interlock passes under the ENTRYPOINT flags; SMPP listener accepts a bind→relay round | Config matrix refusals unchanged (AD-17) |
| SIGTERM via `docker stop` | Exec-form ENTRYPOINT (java is PID 1) | Ordered AD-22 drain lines on stdout, then clean exit 143 | Shell-form/`sh -c` PID-1 wrapping = the failure this row pins (DEPLOY-006) |
| Secret as env VALUE | Docker env carries secret material (e.g. a client-credential value) | Inert: no config key binds it — the app runs solely on file-path secrets; the value is honored nowhere and appears in no stdout/log line (owner decision 2026-09-11: env channel accepted, no guard; DEPLOY-008's E2E asserts this structural arm) | A value key cannot come to exist without violating SEC-076's all-Paths scan |
| Missing / unreadable secret file | Mounted path absent, or perms deny the non-root UID | Non-zero exit at startup validation, before any listener binds (DEPLOY-009) | No partial start |
| Metrics exposure | Any run | Endpoint binds literal 127.0.0.1 INSIDE the container; reachable only via in-container exec; no publishable host key exists (DEPLOY-011) | A `-p 9090` publish finds nothing listening |
| Flag parity | `docker inspect` ENTRYPOINT vs `OPERATOR_JVM_FLAGS` | Identical set, verbatim | Drift = review finding + parity row RED |
| Module floor dropped | jlink image built minus a floor module | Module-set test RED at build time (DEPLOY-001) | Never reaches the image |

## Decisions (planning, 2026-09-11)

- **Slice (owner, 2026-09-11):** 5.2 = jlink runtime + Dockerfile + parity + secrets E2E + catalog/ledger/docs closure. "No arm64 needed" — DEPLOY-013's arm64 half owner-dropped (dated marker at T5); release tooling untouched.
- **Env-value stance (owner, 2026-09-11: "env is accepted"):** no env-channel guard exists or lands — the AD-18 contract is upheld STRUCTURALLY: every secret key is a file Path, no value key exists to bind, and SEC-076's all-Paths scan is the load-bearing mechanism. SEC-075 and DEPLOY-008 close as owner-amended: the Docker E2E proves a container-env secret value is inert (honored nowhere, absent from stdout/logs) in place of the rows' original refusal language.
- **Epoll rows voided (DEPLOY-002/010):** the ratified rows presume an epoll transport the codebase never adopted — the relay deliberately uses Netty-4.2 NIO and no native classifier exists in the jar; Epic 5 owns no main source package, so adopting epoll is out of contract. Rows close as amended (dated markers), like the DEPLOY-014 precedent.
- **jlink build is Gradle-side** (the epic names "Gradle jlink packaging config"): a task explodes the boot jar, runs jdeps, invokes jlink into `proxy/build/jlink-image/` — the runtime is bootable/testable WITHOUT Docker, and the Dockerfile stays a thin COPY. Builder JDK = the pinned environment JDK (asdf `.tool-versions`); glibc output matches the distroless glibc base.
- **Base image:** `gcr.io/distroless/base-debian12:nonroot` — glibc (matches the temurin-built runtime), ships no JVM (ours rides on top), fixed non-root UID/GID 65532.
- **In-container observability without a shell:** distroless has no sh/curl/chmod; probes (metrics scrape, forced-GC ZGC-identity scrape) run via `docker exec` of the image's OWN `java` against a helper class compiled at test time and `docker cp`'d in.
- **Image size and cold start are measured and recorded, not gated:** the spine's figure is ~45–66 MB for the jlink runtime; the context file's "~50–100 MB / <500 ms" pair is unratified. Actuals land in Implementation Notes + the catalog markers.
- **Token gate:** full spec kept (owner precedent — 5.1/4.x specs run larger; reaffirmed 2026-09-11).

</frozen-after-approval>

## Code Map

- `proxy/build.gradle.kts` :82-99 -- 5.1's bootJar (pinned main class, `proxy.jar`), test wiring (`dependsOn bootJar`, jar as test input), Testcontainers 2.0.5 test-deps already declared (SB4-managed BOM) — the jlink task + image-build wiring land here.
- `buildSrc/src/main/kotlin/smpp.java-conventions.gradle.kts` :18,:23,:28,:33 -- toolchain 25 (major-only, asdf supplies the JDK) + `--enable-preview` threading — do not touch.
- `proxy/src/test/java/.../bootstrap/PackagedBootSmokeTest.java` -- the rig to reuse: `OPERATOR_JVM_FLAGS` :127-131 (the flag-set constant the ENTRYPOINT must match), `BOOT_JAR` :108, `launch()` :380 (only `javaBin`+`-jar` construction is JAR-specific — flags, markers, probes, satellites are shape-agnostic), assertions (startup_summary+budget :169-179, relay round :210-227, SIGTERM/exit-143/drain order :245-274).
- Test-support satellites: `testsupport/MockSmsc` (host-side SMSC — container reaches it via the Docker gateway), `testsupport/TokenIdpStandIn` (IMMEDIATE-allow HTTPS IdP), `testsupport/OidcDiscoveryStandIn.java` :30 (fixture certs' SANs are FIXED to localhost/127.0.0.1 — the container→host TLS hop needs a SAN-parameterized variant or a re-point), `testsupport/RelayTestFixtures` (freePort, trust-store fixture, PDU helpers).
- `proxy/src/test/java/.../security/RopcSliceLiveTest.java` + `RpcBindCredentialVerifierLiveTest.java` -- the `@Testcontainers(disabledWithoutDocker = true)` idiom to copy.
- `proxy/src/main/java/.../observability/MetricsEndpointLifecycle.java` :29-36,:74-77 -- metrics binds LITERAL 127.0.0.1, NO host key exists by design (AD-19/AD-28) — in-container scrape only; do not add a host key.
- `proxy/src/main/java/.../relay/netty/RelayNettyConfig.java` :65-71 -- `MultiThreadIoEventLoopGroup` + `NioIoHandler.newFactory()`: NIO is the deliberate transport (grounds the DEPLOY-002/010 voiding).
- `proxy/src/main/java/.../config/CompanionConfigValidator.java` -- the 1.3 fail-fast matrix: `requireReadableFile` :392, `requireTrustStore` :420 (5-state incl. zero-byte + real KeyStore.load) — the DEPLOY-009 E2E arms prove these in-container.
- `proxy/src/main/resources/application.yml` :112-191 -- every secret key is a FILE PATH, commented examples only (`oidc.client-secret-path`, trust-store path+password, cert/key paths); :63-75 memory trio + `budget-check: fail`.
- `docs/operator-jvm-flag-contract.md` -- pinned set :25, floor+mirror rule :28-32, artifact location :34-35, "future Docker entrypoint" sentence :86-94 to true to present tense; entrypoint becomes the third kept-in-step representation.
- Environment (verified 2026-09-11): Docker client+daemon 29.6.1 reachable (containerd 2.3.3, overlay2, cgroup v2); x86_64; `jdeps`/`jlink` via asdf shims (temurin 25.0.3+9); no Dockerfile/docker-compose anywhere in the repo yet.

## Tasks & Acceptance

**Execution:**
- [ ] **T1 — Gradle jlink runtime image** — `proxy/build.gradle.kts` (+ a small buildSrc/task class if warranted): task explodes the built boot jar (BOOT-INF/classes + lib), resolves the module set via `jdeps --print-module-deps` against it, adds the crypto floor (`jdk.crypto.ec`, `jdk.crypto.cryptoki`, `java.management`), and runs `jlink` into `proxy/build/jlink-image/` (strip-debug, no-man-pages; runtime `bin/java` boots). Module-set test (runs in `check`/`test`, no Docker): derived set is non-empty, contains the floor, and the FLOOR is load-bearing — mutation: floor module removed from the task's inputs → row RED (DEPLOY-001). Rationale: epic-named "Gradle jlink packaging config"; runtime testable without Docker.
- [ ] **T2 — Dockerfile + image wiring** — New `proxy/src/docker/Dockerfile` (or `proxy/Dockerfile` — pick one, document): `FROM gcr.io/distroless/base-debian12:nonroot`; `COPY` the jlink runtime + `proxy.jar` (build-context wiring in Gradle: a `dockerImage`-style task or documented context assembly); exec-form `ENTRYPOINT` `[<jre>/bin/java, --enable-preview, -XX:+UseZGC, -XX:MaxDirectMemorySize=6442450944, -Djava.net.preferIPv4Stack=true, -jar, /opt/proxy.jar]` + `CMD` cell-args pass-through; `USER nonroot` (65532); no secret material anywhere in the image (SEC-098 build half). Parity test assertion source: `docker inspect` ENTRYPOINT vs `OPERATOR_JVM_FLAGS` (DEPLOY-003/004 flag halves, DEPLOY-006 exec-form half).
- [ ] **T3 — Docker boot+smoke+parity suite** — Testcontainers (`disabledWithoutDocker`), building the image from the Dockerfile (image as test input — incremental trap: rebuild when jar/runtime/Dockerfile change): happy boot on the reverse-B cell (secrets mounted) asserting `startup_summary` + budget interlock under the ENTRYPOINT flags; one bind→relay round via published port against host-side `MockSmsc`; `docker stop` → ordered AD-22 drain → exit 143 (DEPLOY-005/006, OBS-015 process-exit); in-container metrics scrape via `docker exec` + cp'd helper on 127.0.0.1:9090 (DEPLOY-011 Docker arm) incl. binder gauges; ZGC gc-identity arm — forced GC then scrape asserts the ZGC `jvm_gc_*` timer families exist (deterministic after a forced cycle; DEPLOY-004's deferred introspection arm); IPv4 egress arm (relay round over Inet4 + `preferIPv4Stack` in the ENTRYPOINT, DEPLOY-012 Docker arm); preview-API arm rides the successful boot itself (DEPLOY-003 Docker half — the app IS preview-compiled).
- [ ] **T4 — Docker secrets E2E (DEP-1)** — Same rig: (a) mounted `/run/secrets` files readable by UID 65532 → reaches ready (DEPLOY-007); (b) secret value injected into the container env → INERT (owner stance 2026-09-11): the container runs solely on the mounted file-path secrets, the value is honored nowhere, and it appears in no stdout/log line (DEPLOY-008 structural arm, amended); SEC-077 Docker arm: with a correctly-configured run, `docker inspect` Env carries no secret material (only paths); (c) missing file AND unreadable-perms file → both non-zero pre-bind, no listener (DEPLOY-009); (d) image-layer scan: no cert/key material in any layer (SEC-098 arm — `docker save`/history scan).
- [ ] **T5 — proofs, catalog rows, ledger, docs** — `./gradlew clean build --console=plain` GREEN end-to-end; DEPLOY catalog dated Status markers: 001 (landed), 003/004/005/006/007/009/011/012 Docker halves landed, 008 landed-as-amended (structural arm, owner decision 2026-09-11), 002/010 premise-voided (NIO — cite `RelayNettyConfig`), 013 owner-dropped arm64 ("no arm64 needed"), SEC-075 owner-amended (structural stance — SEC-076's all-Paths scan is the mechanism, no guard), SEC-077/098 Docker arms landed; record measured image size + cold start; `docs/operator-jvm-flag-contract.md` trued (entrypoint present tense, image location beside the jar's); `epic-5-context.md` regenerated per the B5 promise (carrying the 2026-09-11 amendment forward); deferred-work ledger entries for anything resolved/deferred this story.

**Acceptance Criteria:**
- Given the one 5.1 jar, when the image boots in the reverse-B cell, then stdout shows the same `startup_summary` shape as the JAR smoke under an identical flag set — the two shapes run the same bytes (FR-DEPLOY-1).
- Given `docker stop` on a coupled instance, then the AD-22 drain sequence is logged in order and the container exits 143 (java is PID 1 via exec-form ENTRYPOINT).
- Given secrets mounted at `/run/secrets` with the non-root UID able to read them, then the container reaches ready; given a secret value injected via Docker env, then it is inert — the container runs solely on the file-path secrets and the value appears in no stdout/log line (owner stance 2026-09-11).
- Given a secret path pointing at a missing or UID-unreadable file, then the container exits non-zero at startup validation before any listener binds.
- Given the built jlink image, then its module set is jdeps-derived from the actual jar with the crypto floor present, and the runtime boots the jar without `--add-exports` (the 5.1 `DirectMemoryBudgetValidator` constraint holds).
- Given the finished image, then no layer contains cert/key/secret material (FR-DEPLOY-4).

## Implementation Notes

## Spec Change Log

## Review Triage Log

## Design Notes

- Distroless has no shell, no coreutils, no package manager: there is no `chmod`/`chown` INSIDE the container — file modes/ownership ride the mount or the copy. An unprivileged host test process cannot `chown` to UID 65532; the readable-proof may use group/world-readable mode on the host side — the load-bearing half is "the non-root JVM reads the mounted file".
- Container→host satellites: Testcontainers' `host.testcontainers.internal` (gateway) reaches host-bound satellites only if they bind a non-loopback address AND the TLS cert's SAN matches that name — `OidcDiscoveryStandIn` hard-codes SANs to localhost/127.0.0.1 today; parameterize or re-point rather than weakening TLS verification.
- jdeps blind spots are the reason the floor is explicit: `jdk.crypto.ec`/`jdk.crypto.cryptoki` load via the security-provider mechanism (no static refs); `java.management` is already asserted by the binders. A wholly hand-written list is still forbidden — jdeps output is the base, the floor is additive.
- Memory: launch the container WITHOUT a `--memory` cap below the AD-30 budget (heap + 6 GiB direct); the ENTRYPOINT's explicit `MaxDirectMemorySize` makes the JVM independent of container-aware defaults.
- The image is a THIRD representation of the flag set (page, Java constant, ENTRYPOINT): no machine check parses the page (owner rule); the parity row asserts constant ↔ ENTRYPOINT, and page coherence stays a review duty.
- Expected-rig trap from 5.1: test inputs must include everything the image bakes (jar, jlink image, Dockerfile) or incremental runs test a stale image — mirror the 5.1 `inputs.file(bootJar.archiveFile)` pattern.
- Recorded-not-gated numbers: spine says the jlink runtime targets ~45–66 MB; measure the full image and cold start, write the actuals into the catalog markers.

## Verification

**Commands:**
- `./gradlew clean build --console=plain` -- expected: GREEN with the Docker daemon present (E2E rows run); without a daemon the E2E classes skip per the repo's `disabledWithoutDocker` idiom and everything else stays GREEN.
- `./gradlew :proxy:test --tests '*Docker*' --tests '*Jlink*' --console=plain` -- expected: GREEN after `clean` (selectors re-set once suite names land).
- `docker image inspect <image> --format '{{.Size}}'` + `docker history <image>` -- expected: size recorded; no secret-bearing layers.

**Manual checks (if no CLI):**
- `docker run` the image with a reverse-B arg set against the host MockSmsc; observe `startup_summary`, one relayed bind, in-container `/metrics` scrape, and clean `docker stop` drain (exit 143).
