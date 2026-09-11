# Epic 5 Context: Ship both deploy shapes — runnable JAR and distroless Docker

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->

> **Amended 2026-09-11 (Story 5.1 review round 1) — two passages below predate same-day owner
> decisions and are SUPERSEDED in place, not regenerated:**
> (1) Technical Decisions' "Exact JDK 25 build pinned (toolchain-level refusal/warning off-pin)" —
> the exact-build refusal arm was DROPPED 2026-09-10 before implementation (owner words: "asdf pin
> is enough, no additional jdk/jre version check is needed"). The standing mechanism is the
> major-25 toolchain pin (`smpp.java-conventions.gradle.kts`) + the asdf `.tool-versions`
> environment pin — see the DEPLOY-014 Status marker and the spec 5-1 Decisions block.
> (2) The Goal/Stores "Epic 5 is next, still backlog with no stories sliced" / "tracker holds only
> `epic-5: backlog`" — the tracker has since flipped: story 5-1 (the runnable JAR deploy shape)
> exists and is in review at amendment time. Regenerate this file when the next Epic-5 story is
> created.

## Goal

Make the proxy shippable in two first-class, feature-equivalent forms: a standalone runnable JAR (`java -jar`) and a distroless Docker image that packages that same JAR over a jlink modular runtime (~45–66 MB). Identical config surface, modes A/B/C, both roles, and auth paths in either shape — parity proven, not assumed. Certificates are provisioned at deploy time (CI/pipeline bake; no runtime ACME/SPIFFE enrollment; rotation = re-deploy), and the Docker secrets contract is validated end-to-end in the Docker shape: secrets injected as mounted files a non-root JVM can read, env-var secret values rejected. This is a packaging epic — no main source package is owned; it mounts everything Epics 1–4 built. Status: Epics 1–4 done; Epic 5 is next, still backlog with no stories sliced.

## Stories

Not yet sliced — the epics file leaves story placeholders and the tracker holds only `epic-5: backlog` with no story keys. The epic's declared work surface: Docker packaging (Dockerfile, distroless + jlink runtime image), Gradle jlink packaging config, release/ship tooling, and boot + smoke validation of both shapes (incl. the Docker-secrets end-to-end pass). Slice at story-creation and re-check the deferred-work ledger then.

## Requirements & Constraints

- **Two-shape parity is the headline risk:** the Docker image must package the SAME JAR the standalone shape runs; identical observable outcomes (config surface, mode journeys, auth verdicts, logs, metrics) across `java -jar` and `docker run`. Drift vectors to kill: JVM flags present in one launcher but not the other, module sets differing, native-transport availability differing.
- **Docker secrets contract:** secrets (TLS cert/key, trust store, OIDC client credential) are FILE PATHS in config pointing at mounted files (Docker secrets / bind-mount / k8s secrets). Never a secret VALUE in an env var (leaks via `/proc/<pid>/environ` and `docker inspect`) — env-injected secret values must be rejected at startup. Missing or unreadable secret file → fail-fast non-zero exit BEFORE any listener binds.
- **Runtime image:** distroless base + jlink runtime of JDK 25 modules; target ~50–100 MB, <500 ms cold-start. The jlink module set must be resolved from the actual fat JAR (jdeps), never a hand-maintained list, and must include `jdk.crypto.ec` (TLS), `jdk.crypto.cryptoki` (PKCS12 trust-store load), and `java.management`.
- **JVM flags in BOTH launchers:** `--enable-preview` (the control plane needs it — an entrypoint that omits it breaks only the Docker shape), `-XX:+UseZGC`, `-XX:MaxDirectMemorySize` per the established direct-memory formula, and IPv4 preference for egress.
- **Container posture:** non-root UID/GID; secrets under `/run/secrets` readable by that UID (0440-style ownership); exec-form ENTRYPOINT (or init) so `docker stop` SIGTERM reaches the JVM as PID 1 and the graceful-shutdown sequence actually runs before exit.
- **Platform gates:** Linux x86 AND ARM — build + packaged smoke on both; Epoll native transport `.so` present per arch with libc matching the base (no silent NIO fallback); IPv4 only (metrics binds the 127.0.0.1 literal, egress connects Inet4Address even for dual-stack hostnames).
- **No native-image build in v1** — JVM build only; keep the codebase native-image-compatible as a documented stretch, and keep AOT constraints out of design decisions.

## Technical Decisions

- **No main source package.** This epic owns Dockerfiles, Gradle jlink/shadow packaging config, release/ship tooling, and packaged-shape validation. Deployability behavior itself lives in `bootstrap` + `config` (startup fail-fast, role×mode matrix, secret-path resolution) — this epic packages and proves it, and should not need to modify relay/security/observability logic.
- **Key decisions governing the epic:** secrets are file-path-injected with fail-fast on missing/unreadable (never env values, any mode); no v1 native-image target (ZGC is unavailable in native-image — a native build would regress the flagship GC for an always-on single instance); routing stays 1:1 (`system_id` allow-list → single egress) in packaged shapes.
- **One artifact, two shapes, not a fork:** role and mode remain deployment-time config of the one JAR; single-side adoption (forward-only or reverse-only) stays a valid deployment.
- **Config fail-fast must hold identically in both shapes** — including an open app-wide decision routed here: whether to refuse `spring.main.lazy-initialization` outright (it can silently bypass the startup validation/fail-fast posture) or document it as an operator-accepted deviation.
- **Open posture decisions homed here by the deferred-work ledger:** the boot-time mode-warning banners currently print plain text to stderr (the one non-JSON stream in a "stdout is pure JSON-lines" deployment) — route them through logback as WARN-level JSON or document the split-stream contract for log shippers; and whether to bind the non-web Micrometer JVM binders (memory/GC/uptime) or record their exclusion.
- **Exact JDK 25 build pinned** (toolchain-level refusal/warning off-pin) — preview semantics ride on the pinned build.

## Cross-Story Dependencies

- **Depends on Epic 4 (done):** graceful shutdown, structured logs, and loopback metrics are the behaviors the packaged-shape smoke validates end-to-end (e.g., SIGTERM → ordered drain sequence visible in container stdout).
- **Epic 6 depends on this epic:** formal performance validation and final conformance run on the PACKAGED shapes; the operator docs surface documents them. The deployment guide must state plainly that v1 authenticates via ROPC (a grant on a removal track) and that operators must pin their Keycloak build.
- **The test-design catalog's DEPLOY area (14 scenarios) is the AC-level source for story authors:** jlink module scan; Epoll/libc arch gate; preview/ZGC/direct-memory flag parity across shapes; the golden two-shape parity smoke (fake verifier + in-JVM mock SMSC + Testcontainers, deterministic via the verifier port seam); SIGTERM propagation; non-root + `/run/secrets` readability; env-value secret rejection; fail-fast on bad secret files; IPv4 binding/egress; dual-arch CI matrix; JDK build pin.
