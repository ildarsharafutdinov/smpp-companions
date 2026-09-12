# Epic 5 Context: Ship both deploy shapes — runnable JAR and distroless Docker

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->
<!-- Regenerated 2026-09-12 (Story 5.2 T5), per the B5 promise: the 2026-09-11 interim amendment
     block is absorbed — every passage it superseded is rewritten here as standing truth (the
     DEPLOY-014 exact-build drop, the sliced tracker), and the same-day Story-5.2 owner decisions
     (env-value stance, no arm64, NIO-not-epoll) plus the 2026-09-12 DEPLOY-001 finding are
     carried in Requirements & Constraints below. -->

## Goal

Make the proxy shippable in two first-class, feature-equivalent forms: a standalone runnable JAR (`java -jar`) and a distroless Docker image that packages that SAME jar byte-for-byte over a Gradle-built jlink modular runtime. Identical config surface, modes A/B/C, both roles, and auth paths in either shape — parity proven, not assumed. Certificates are provisioned at deploy time (no runtime ACME/SPIFFE enrollment; rotation = re-deploy), and the Docker secrets contract (DEP-1) is validated end-to-end in the Docker shape: secrets injected as mounted files under `/run/secrets` that the non-root JVM reads; a secret VALUE in the container env is INERT by structure, not rejected (owner decision 2026-09-11 — every secret key is a file Path, no value key exists to bind, no guard exists). This is a packaging epic — no main source package is owned; it mounts everything Epics 1–4 built. Status: Epics 1–4 done; 5.1 done (`6ebab69`); 5.2 in progress — T1–T4 landed 2026-09-11/12, T5 (proofs, catalog markers, ledger, docs — this regeneration) closing the story.

## Stories

- 5.1 — runnable JAR deploy shape: DONE (2026-09-11, `6ebab69`, review round 1 closed). bootJar first-class (pinned main class, stable `proxy.jar`), this flag-contract page, mode banners + JVM binders, and the packaged boot+smoke (`PackagedBootSmokeTest`, catalog DEPLOY-015).
- 5.2 — distroless Docker deploy shape: T1 jlink runtime image (`:proxy:jlinkRuntimeImage` — jdeps-derived module set + crypto floor); T2 Dockerfile + `:proxy:dockerImage` (exec-form ENTRYPOINT with the ONE flag set, `USER nonroot:nonroot`, mode-normalized context assembly); T3 Docker boot+smoke+parity suite (`DockerImageBootSmokeTest`); T4 Docker secrets E2E (`DockerSecretsE2eTest`); T5 proofs/catalog/ledger/docs.

## Requirements & Constraints

- **Two-shape parity is the headline risk:** the Docker image packages the SAME jar the standalone shape runs; identical observable outcomes across `java -jar` and `docker run`. Drift vectors killed: ONE flag set in both launchers (page ↔ `OPERATOR_JVM_FLAGS` ↔ ENTRYPOINT, machine-checked constant↔ENTRYPOINT), one Spring run-args channel (the empty CMD pass-through = args after the jar path), one artifact (never rebuilt inside the image).
- **Docker secrets contract (DEP-1, as owner-amended 2026-09-11):** secrets (TLS cert/key, trust store, OIDC client credential) are FILE PATHS in config pointing at mounted files. Never a secret VALUE in an env var — upheld STRUCTURALLY (all-Paths config surface; the env channel carries no guard), with the container-env value proven inert end-to-end (honored nowhere, absent from stdout/logs). Missing or unreadable secret file → fail-fast non-zero exit BEFORE any listener binds (proven in-container).
- **Runtime image:** distroless `base-debian12:nonroot` + jlink runtime of JDK 25 modules; the module set is jdeps-derived from the actual jar (never hand-maintained) plus the crypto floor `jdk.crypto.ec`/`jdk.crypto.cryptoki`/`java.management` — DEFENSE-IN-DEPTH per the 2026-09-12 finding (the current RSA-fixture handshake and PKCS12 load need none of them at runtime on JDK 25; the floor's bite is Gradle-input drift + forward defense for EC certs / HSM profiles). Measured actuals, recorded not gated: jlink runtime 97 MB, full image 144,197,650 bytes (~137.5 MiB), JVM-only container cold start ~0.6 s, full-app boot-to-startup-decision ~1.6 s (the spine's ~45–66 MB and the context's former "~50–100 MB / <500 ms" pair were never ratified gates).
- **JVM flags in BOTH launchers:** `--enable-preview`, `-XX:+UseZGC`, `-XX:MaxDirectMemorySize=6442450944`, `-Djava.net.preferIPv4Stack=true` — the ENTRYPOINT is EXEC-FORM so `docker stop`'s SIGTERM reaches the JVM as PID 1 and the AD-22 graceful drain runs before exit 143.
- **Container posture:** non-root UID/GID 65532 (live /proc proof); metrics binds the `127.0.0.1` literal INSIDE the container — no host key exists (AD-19/AD-28), in-container exec scrape only, nothing publishable.
- **Platform:** x86_64 only (owner 2026-09-11: "no arm64 needed") — no dual-arch matrix, no CI exists, release/publish tooling untouched. The relay is NIO by design (`RelayNettyConfig`) — the ratified epoll rows (DEPLOY-002/010) are premise-voided by dated markers, no code change.
- **No native-image in v1** (AD-23); no launch configuration in the jar manifest (5.1 decision stands).

## Technical Decisions

- **No main source package.** This epic owns Dockerfiles, Gradle jlink/docker packaging config, and packaged-shape validation; deployability behavior itself lives in `bootstrap` + `config` — 5.2 changed zero main-source lines.
- **One artifact, two shapes, not a fork:** role and mode remain deployment-time config of the one JAR; single-side adoption stays valid.
- **Config fail-fast holds identically in both shapes** — the AD-17 role×mode matrix and the AD-30 budget check refuse, never warn-and-continue (re-proven under the ENTRYPOINT flags in-container). `spring.main.lazy-initialization` stays a documented operator-accepted deviation (5.1, flag-contract page).
- **JDK pin:** major-25 Gradle toolchain + asdf `.tool-versions` environment pin (the exact-build refusal arm was owner-dropped 2026-09-10 — DEPLOY-014); the jlink builder JDK resolves from the toolchain, never PATH (asdf shims are per-CWD).
- **jlink derivation mechanics:** jdeps over the EXPLODED BOOT-INF layout (it cannot read the nested fat jar), app classes as the sole root, `--multi-release 25` mandatory, lib jars on the class path only (naming them as roots hard-fails).
- **Docker-gated E2E** rides `@Testcontainers(disabledWithoutDocker = true)` (daemon-less builds stay GREEN); container→host satellites cross Testcontainers' host-access portal with SAN-matched fixture certs (`docker-host` pair — TLS re-pointed, never weakened). Distroless has no shell: in-container probes run via `docker exec` of the image's own java + a `docker cp`'d helper; forced-GC introspection speaks the JDK attach protocol by hand over AF_UNIX.
- **The `:proxy:dockerImage` task is deliberately outside `build`/`check`** (the image lives in the daemon, invisible to Gradle — a tracked output would UP-TO-DATE-skip after `docker rmi`); docker's layer cache is the incrementality, and the E2E suites build the image themselves from the same assembled context.

## Cross-Story Dependencies

- **Depends on Epic 4 (done):** graceful shutdown, structured logs, and loopback metrics are the behaviors the packaged-shape smokes validate end-to-end (SIGTERM → ordered drain visible in container stdout, exit 143).
- **Epic 6 depends on this epic:** final conformance run on the PACKAGED shapes (plus the Kannel docker-compose sandbox, added 2026-09-12); the operator docs surface must state plainly that v1 authenticates via ROPC (a grant on a removal track) and that operators must pin their Keycloak build. Deferred to Epic 6 by 5.2's close-out: packaged-shape e2e beyond the reverse-B allow journey (mode A/C cells and auth-DENY journeys have no e2e row in either shape — see the deferred-work ledger). *(Amended 2026-09-12 at the Epic 6/7 split: formal performance validation on the packaged shapes moved to EPIC 7 — this line's perf clause now names Epic 7's scope.)*
- The test-design catalog's DEPLOY area (15 scenarios) is the AC-level source for story authors; every row now carries a dated 5.1/5.2 Status marker (DEPLOY-001..015) and the SEC-075/077/098 Docker-era arms are marked.
