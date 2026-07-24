# Story 1.1: Gradle Two-Module Substrate and CI Scaffold

Status: ready-for-dev

> Story context engine analysis completed — comprehensive developer guide created. Adversarially verified against all source artifacts (ARCHITECTURE-SPINE, walkthrough, epics, PRD, TEA test-design). No version/AD/scenario-ID misquotes survive; scope is invariant-clean.

## Story

**As a** platform engineer onboarding the smpp-companions codebase,
**I want** a greenfield two-module Gradle substrate pinned to JDK 25 `--enable-preview`, with an ArchUnit-protected PURE codec module, a booting Spring Boot process, a `companion.*` config skeleton, and CI gates that mechanically enforce the codec-purity / toolchain / CVE / runtime-dep invariants,
**so that** every later epic mounts on a substrate whose load-bearing invariants (inward-only seam, no-web-stack, no-rolled-crypto, exact-JDK-pin) cannot silently drift — established before a single line of codec, config-matrix, or shutdown code is written.

## Acceptance Criteria

> Positive-control triplet (CODEC-041 / SEC-099 / OBS-043) carries the real evidence: each injects a known-bad input and asserts its gate fires. CODEC-039/040 pass trivially on the near-empty codec module — that *is* the point (the boundary is locked before code exists). ACs flagged "gate-exists form" have no catalog positive control (residual source gap) — assert the gate is wired and green on-pin, do not over-claim mechanical rejection.

1. **[AC1] Green build on pinned JDK 25 + `--enable-preview`.** `./gradlew clean build` succeeds on an **Eclipse Temurin JDK 25.0.x** toolchain (auto-provisioned via Gradle `javaToolchains`), with `--enable-preview` applied to compile, test, **and** run. The toolchain pin is explicit and non-silently-drifting. *(Maps DEPLOY-014 / SEC-085; gate-exists form — no catalog positive control for off-pin rejection.)*
2. **[AC2] Two-module seam exists and builds.** `settings.gradle` declares `codec` + `proxy`; both compile. `proxy` depends on `codec`; **`codec` has NO dependency on `proxy`.** Dependency direction is strictly inward. *(AD-7.)*
3. **[AC3] Codec purity locked — CODEC-039 green.** ArchUnit rule asserts `smpp.companion.codec..` depends on zero `smpp.companion.proxy..` classes; passes against the codec module today (near-empty). Enforcement becomes meaningful once codec classes exist (Story 1.2); today it locks the boundary so it can never silently drift.
4. **[AC4] Codec dep-allowlist + positive control — CODEC-040/041 green.** Codec resolved compile classpath ⊆ {`netty-buffer`, `netty-codec`, JDK stdlib}. A test fixture injecting `spring-boot-starter-web` / `nimbus-jose-jwt` / `micrometer-core` into the codec classpath makes the gate **FAIL** the build (CODEC-041 — the load-bearing positive control). *(AD-7, AD-27 — structurally enforces "codec never emits metrics / never touches Spring/Nimbus".)*
5. **[AC5] CVE/dependency-check gate + positive control — SEC-091/099 green.** OWASP dependency-check runs in the build; Nimbus resolves **≥ 10.0.2** (CVE-2025-53864 floor). A fixture injecting a known-vulnerable coordinate makes the gate fire (SEC-099 positive control).
6. **[AC6] No forbidden runtime deps + positive control — OBS-013/043 green.** Proxy runtime classpath has NO `spring-boot-starter-web` / Tomcat / WebFlux / Actuator / Reactor. An injected fixture makes the gate fire (OBS-043 positive control). *(AD-16, AD-19.)*
7. **[AC7] No hand-rolled crypto scan — SEC-090 (scaffold form).** ArchUnit/dep scan asserts only JDK `SSLEngine` + Nimbus are used for TLS/JWT (no custom `PKIXBuilderParameters` / signature-verify / TLS-record code). Today records the constraint; becomes meaningful once `security/` code exists (Epic 3). *(SEC-4, AD-13.)*
8. **[AC8] Spring Boot boots and shuts down cleanly.** `main` starts a Spring context to "started" with **no embedded web server**; on SIGTERM-equivalent the context closes and the process exits within the configured graceful-shutdown timeout. **Framework only — NOT the AD-22 7-step body** (that lands in Epic 4). *(AD-16, AD-22 framework, REL-3.)*
9. **[AC9] `companion.*` skeleton binds + one fail-fast smoke.** `@ConfigurationProperties("companion")` relaxed-binds the documented key shapes. With `companion.role` absent or ∉ {`forward`,`reverse`}, the app **refuses to start** (non-zero exit, clear message). The exhaustive role×mode matrix (SEC-050..061) is explicitly out of scope (Story 1.3). *(AD-17 seed, FR-DEPLOY-3.)*
10. **[AC10] Golden-vector corpus scaffold — CODEC-030 shell.** `codec/src/test/resources/golden-vectors/` exists with a provenance-header **convention** + a loader harness. The non-empty + provenance assertion is Story 1.2 (CODEC-030) — cannot fire on an empty corpus today.
11. **[AC11] License present.** Apache-2.0 `LICENSE` + `NOTICE` at repo root. *(PRD §4, §10.)*

## Tasks / Subtasks

**1. Gradle build substrate** (AC1, AC2)
- [ ] `settings.gradle` declaring `codec`, `proxy`.
- [ ] Root `build.gradle`: `javaToolchains` pin (Eclipse Temurin, JDK 25.0.x); `--enable-preview` in compile/test/run `jvmArgs`; `netty-bom` + Spring Boot 4.1.x dependency management.
- [ ] `codec/build.gradle` — deps: `netty-buffer`, `netty-codec`, JDK only.
- [ ] `proxy/build.gradle` — `api`/`implementation` depends on `codec`.
- [ ] Gradle wrapper committed (JDK-25-compatible release, pinned via wrapper).

**2. Codec module isolation** (AC2, AC3, AC4)
- [ ] `codec/src/main/java/smpp/companion/codec/package-info.java` (ArchUnit needs ≥1 compiled class to assert against).
- [ ] ArchUnit CODEC-039 test (inward-only rule).
- [ ] Gradle dep-allowlist task (CODEC-040) + injected-bad-coordinate fixture (CODEC-041).

**3. CI-gates scaffold** (AC1, AC5, AC6, AC7)
- [ ] JDK-pin gate (DEPLOY-014/SEC-085) — explicit toolchain pin.
- [ ] OWASP dependency-check Gradle plugin (SEC-091) + known-vulnerable fixture (SEC-099).
- [ ] Forbidden-runtime-dep scan on proxy (OBS-013) + injected fixture (OBS-043).
- [ ] No-rolled-crypto ArchUnit/dep scan (SEC-090).

**4. `companion.*` config skeleton** (AC9)
- [ ] `@ConfigurationProperties("companion")` class with documented key shapes.
- [ ] `application.yml` skeleton incl. AD-34 cipher/protocol defaults under `companion.tls.*`.
- [ ] Minimal fail-fast validator: `companion.role` absent/invalid → non-zero exit. (Matrix deferred.)

**5. Spring Boot bootstrap** (AC8)
- [ ] `smpp.companion.proxy.bootstrap` `main` (`@SpringBootApplication`); **NO** `spring-boot-starter-web`.
- [ ] `SmartLifecycle` stub bean(s) (start/stop hooks — body deferred).
- [ ] Graceful-shutdown timeout config (bounds the future AD-22 window).
- [ ] Boot-smoke + SIGTERM-exit-within-timeout test.

**6. Golden-corpus + license** (AC10, AC11)
- [ ] `codec/src/test/resources/golden-vectors/` dir + provenance-header convention + loader harness (empty corpus).
- [ ] Apache-2.0 `LICENSE` + `NOTICE`.

## Dev Notes

### Tech Stack & Versions (pinned — use verbatim)

- **JDK** — Eclipse Temurin **25.0.x LTS**, `--enable-preview` process-wide (build+test+run). Rationale: `StructuredTaskScope` is preview-only on JDK 25 (JEP 505); the whole runtime runs under preview semantics once STS lands, so pin the exact build now so toolchain drift cannot silently change preview semantics. [SPINE AD-5, Stack]
- **Netty** — **4.2.16.Final** via `netty-bom`; NIO/Epoll transport (**not** io_uring). 4.2.x is the production line (5.x has no GA). [SPINE Stack; WT §8]
- **Spring Boot** — **4.1.x** (Spring Framework 7.0.8+). Owns config + DI + lifecycle + Micrometer. **NO WebFlux, NO Reactor, NO embedded web server.** [SPINE AD-16; WT §8]
- **Micrometer** — ships with Spring Boot 4; `PrometheusMeterRegistry` (declared now; `/metrics` handler is Epic 4). [SPINE AD-19]
- **Nimbus JOSE+JWT** — **10.9.1** (≥10.0.2 for CVE-2025-53864). Declared on proxy now; JWT logic is Epic 3. [SPINE Stack, AD-12]
- **jSMPP** — `org.jsmpp:jsmpp:3.0.2` (**NOT** 2.3.11), **TEST/INTEROP ONLY — never the production codec**. Declare now; do not author a harness. [SPINE AD-24(3)]
- **GC** — generational ZGC (the only ZGC mode in JDK 25).
- **Platform** — Linux x86/ARM, IPv4. No macOS/Windows build. Apache-2.0.

### Architecture Decisions to Honor (one-line constraint each on this story)

- **AD-7** — `proxy → codec` strictly inward; codec PURE (zero proxy/Spring/Nimbus/Micrometer deps); enforced mechanically (CODEC-039/040/041) from day one.
- **AD-16** — Spring Boot owns config/DI/lifecycle/Micrometer; Netty driven directly; **NO WebFlux/Reactor/web server** (OBS-013).
- **AD-17** — fail-fast startup on ambiguous/insecure/missing config. This story ships **one** smoke (`role`); the full matrix is Story 1.3.
- **AD-18** — secrets are **FILE PATHS** in config, never env-values. Skeleton keys point at paths; existence checks are Story 1.3.
- **AD-22** — phase-ordered shutdown via `SmartLifecycle`. This story mounts the **framework only** (stub start/stop + graceful-shutdown timeout); the 7-step body is Epic 4.
- **AD-23** — JVM build only; **NO native-image target** in v1.
- **AD-27** — `SmppCommandIds.BIND_FAMILY` is codec-owned single source of truth; codec **never emits metrics**. Placeholder/shape only here; impl in Story 1.2.
- **AD-29** — routing is 1:1, no default route. Skeleton defines the shape only; fill/validate in Story 1.3.
- **AD-30** — one named `max_command_length` constant + `MaxDirectMemorySize` formula. **The codec constant is deferred to Story 1.2** (nowhere to live in an empty codec); this story carries only the **config formula-inputs** (`max_frame`, `max_inbound_depth`, `concurrent_pairs`, `safety_factor`) in the `companion.*` skeleton.
- **AD-34** — ship pinned TLS protocol/cipher defaults under `companion.tls.*`: protocols `["TLSv1.3","TLSv1.2"]`; TLS 1.2 set = the four `TLS_ECDHE_*_WITH_AES_*_GCM_SHA*` (no CBC/static-RSA/RC4/3DES); TLS 1.3 set = `{TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256}`. This story **defines** them; per-context intersection fail-fast is Story 1.3.

### Scope Boundaries

**IN-SCOPE:** two-module Gradle seam · JDK 25 Temurin pin + process-wide `--enable-preview` · package skeleton (exact names below) · Spring Boot 4.1 bootstrap with `SmartLifecycle` stubs · `companion.*` `@ConfigurationProperties` skeleton · one fail-fast smoke (`role`) · CI-gates substrate (ArchUnit isolation + dep-allowlist + JDK-pin + CVE + forbidden-runtime-dep + no-rolled-crypto, each with its positive control where the catalog defines one) · isolated empty codec module that passes CODEC-039/040/041 · golden-vector corpus directory + convention (content deferred) · Apache-2.0 LICENSE/NOTICE · green build + boot/SIGTERM smoke.

**DEFERRED (do NOT implement here):**
- Codec impl (framer, bind parser, `SmppCommandIds.BIND_FAMILY`, fuzz, golden-vector content, JMH) → **Story 1.2**.
- Config fail-fast matrix (SEC-050..061/096/097; role×mode; Mode B ack; secret file-path existence; TLS intersection) → **Story 1.3**.
- AD-22 shutdown 7-step body + OBS-015..021 → **Epic 4** (depends on Epic-3 JWKS/adjudication components).

**Epic 1 decomposition (confirmed 3 stories):**
1. **1.1** — this story (scaffold).
2. **1.2** — pure SMPP 3.4 codec (framer + bind parser + command_id SoT + golden-vector content + fuzz + JMH). *Tests: CODEC-001..038, CODEC-030/031/033, PERF-001/002/004. ADs: AD-3, AD-7, AD-24, AD-27, AD-30.*
3. **1.3** — config fail-fast matrix (role×mode + Mode B ack + secret file-path checks + TLS-floor/cipher intersection). *Tests: SEC-050..061, SEC-096/097. ADs: AD-17, AD-18, AD-26, AD-29, AD-34.*

> **Traceability note:** the TEA handoff labels the codec story **"E1/S1"** (smpp-companions-handoff.md). This plan inserts a scaffold story before it, so the handoff's "E1/S1" codec content maps to **Story 1.2** here — not 1.1.

### File Structure to Create

```
settings.gradle
build.gradle                         # javaToolchains pin, --enable-preview, netty-bom, Spring Boot DM
codec/build.gradle                   # netty-buffer, netty-codec, JDK only
proxy/build.gradle                   # depends on codec
gradle/wrapper/...
codec/src/main/java/smpp/companion/codec/package-info.java
codec/src/test/resources/golden-vectors/   # dir + provenance convention (empty)
codec/src/test/...                   # CODEC-039/040/041 + corpus loader harness
proxy/src/main/java/smpp/companion/proxy/{bootstrap,config,relay,security,observability}/package-info.java
proxy/src/main/resources/application.yml    # companion.* skeleton incl. companion.tls.*
proxy/src/test/...                   # boot smoke + SIGTERM-exit test
docs/                                # dir (OPS-1 content later)
LICENSE
NOTICE
```

### Dependencies — add now vs defer

- **Codec (now):** `netty-buffer`, `netty-codec`, JDK stdlib **only**. No Spring/Nimbus/Micrometer/slf4j-binding on codec.
- **Proxy (now):** Spring Boot 4.1.x (**no web starter**), Micrometer, Nimbus (stub ok), `netty-bom`. **NO** spring-boot-starter-web/Tomcat/WebFlux/Actuator/Reactor.
- **Test (now):** JUnit 5 Jupiter, AssertJ, ArchUnit, OWASP dependency-check, Gradle dependency-analysis.
- **Declare now, exercise later:** JQF, jqwik, JMH, jSMPP 3.0.2, BlockHound (wire harnesses when owning story starts).

### Testing Standards

JUnit 5 + AssertJ baseline; ArchUnit for all structural gates. The positive-control triplet **CODEC-041 / SEC-099 / OBS-043 MUST pass now** — each injects a known-bad input and asserts its gate fires. CODEC-039/040 green from day one (trivially — that is the invariant lock). Tagging convention: `@Tag("p0"|"p1")`, `@Tag("unit"|"integration")`, `@Tag("sec"|"codec")` per the test-design QA doc. No `Thread.sleep`; deterministic only.

### Anti-patterns to avoid

- No env-value secrets (AD-18) — config keys point at file paths.
- Codec MUST NOT depend on proxy/Spring/Nimbus/Micrometer (AD-7/AD-27) — the dep-allowlist + ArchUnit rule enforce this from day one.
- No native-image build target (AD-23).
- SMPP layer authored from scratch — no Cloudhopper/jSMPP derivation (MAINT-3); jSMPP is test-only.
- No `spring.threads.virtual.enabled` on any load-bearing path (AD-6) — relay/adjudication threading is hand-managed later.
- No hand-rolled crypto/TLS/JWT (SEC-4).
- Do NOT fill the codec/config-matrix/shutdown-body (all deferred).
- Do NOT refuse Mode B at startup (AD-17/PRD §8) — it warns + acks + starts; the only refuse-to-start smoke here is `role` validation.

### Project Structure Notes

Greenfield — no existing source. Structure follows the SPINE "Structural Seed" + Consistency Conventions exactly: Gradle multi-module (`codec` pure protocol layer + `proxy` runnable app); Java packages `smpp.companion.codec.*` / `smpp.companion.proxy.{relay,security,config,observability,bootstrap}`; config keys `companion.*` (relaxed binding). No conflicts with prior work (this is the first code).

### References

- [Source: `_bmad-output/planning-artifacts/epics.md`#Starter Template (L135-148), Epic 1 (L347-355)]
- [Source: `_bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/ARCHITECTURE-SPINE.md`#AD-7, AD-16, AD-17, AD-18, AD-22, AD-23, AD-27, AD-29, AD-30, AD-34; Stack; Consistency Conventions; Structural Seed]
- [Source: `_bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/walkthrough.md`#§7 module boundary, §8 verified stack]
- [Source: `_bmad-output/planning-artifacts/prds/prd-smpp-companions-2026-07-18/prd.md`#§6.1 FR-TRANSIT-4, §6.4 FR-DEPLOY-2/3, §7 NFRs (MAINT-1..5, SEC-4/5, COMP-2/3/4, REL-3, PERF-4), §8 Mode B, §10 constraints, §11 risks]
- [Source: `_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md`#CODEC-030, CODEC-039, CODEC-040, CODEC-041, SEC-085, SEC-090, SEC-091, SEC-099, OBS-013, OBS-043, DEPLOY-014]
- [Source: `_bmad-output/test-artifacts/test-design/smpp-companions-handoff.md`#E1/S1 codec mapping, risk-to-story, Q6 positive controls]

## Dev Agent Record

### Agent Model Used

_(filled by dev-story)_

### Debug Log References

### Completion Notes List

### File List
