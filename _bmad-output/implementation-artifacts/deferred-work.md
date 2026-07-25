# Deferred Work — smpp-companions

Tracks real-but-deferred items surfaced during review. Not blocking; revisit at the noted story/epic.

## Deferred from: code review of story-1-1-gradle-two-module-substrate-and-ci-scaffold (2026-07-24)

- **AD-30 config formula-inputs deferred to Story 1.3** — `max_frame` / `max_inbound_depth` / `concurrent_pairs` / `safety_factor` not added in 1.1; the config-matrix story (1.3) will own all `companion.*` keys together. (Decision at code review 2026-07-24.) [Dev Notes AD-30; application.yml; CompanionProperties.java]
- **CODEC-039 / SEC-090 ArchUnit rules have no positive control today** — scaffold form accepted by AC3/AC7 ("locks the boundary before code exists"); SEC-090 (PKIX / `javax.net.ssl`, not just `sun.security`) tightens in Epic 3. [codec/proxy ArchUnit tests]
- **`--enable-preview` COMPILE/RUN not runtime-verified** — wiring present in `smpp.java-conventions`; only the test-JVM path is asserted. Future TestKit compile-arg hardening. [proxy/src/test/.../bootstrap/EnablePreviewArgTest.java]
- **`CompanionProperties` has no `tls` / `tls.protocols` null guards** — only `role` is fail-fast-guarded (AC9's one-smoke scope); a tls-absent NPE is a Story 1.3 concern. [proxy/src/main/java/.../config/CompanionProperties.java]
- **`contextCloseStopsLifecycleWithinGracefulTimeout` 30s-ceiling assertion is trivial** — stop()-ran IS checked (`isRunning` false); a meaningful upper-bound test lands with the AD-22 body in Epic 4. [proxy/src/test/.../bootstrap/BootstrapLifecycleTest.java]
- **`BootstrapLifecycleTest` non-web assertion is tautological (forces `.web(NONE)`)** — AD-16 is guarded by OBS-013 + `spring.main.web-application-type: none`; the class-name check can't detect classpath drift. Cosmetic. [BootstrapLifecycleTest.java]
- **`CompanionLifecycle` phase ordering (default `MAX_VALUE` stops first) once a 2nd `SmartLifecycle` lands** — single bean today; Epic 4 manages phases. [proxy/src/main/java/.../bootstrap/CompanionLifecycle.java]
- **SEC-099 has only a Nimbus floor — other deps unchecked** — AC5 is Nimbus-specific; the OWASP lane is the general scanner. Maintenance concern, not a 1.1 defect. [buildSrc/src/main/kotlin/smpp.dependency-floors.gradle.kts]

## Deferred from: story-1-4-compile-time-null-safety-enforcement (2026-07-25)

- **Error Prone `StringCaseLocaleUsage` warning on codec test code** — enabling EP (AD-35) surfaces a
  pre-existing `[StringCaseLocaleUsage]` warning in `GoldenVectorCorpusTest.java:67`
  (`String#toLowerCase()` without a `Locale`). It is a WARNING (build stays green; no test removed or
  `@Disabled`), and is outside this story's null-safety scope, so left untouched. Trivial fix when
  convenient: `.toLowerCase()` → `.toLowerCase(java.util.Locale.ROOT)` (ASCII filename-extension match).

## Deferred from: code review of 1-4-compile-time-null-safety-enforcement (2026-07-25)

- **No dedicated NullAway mutation control for the `AnnotatedPackages` line** — the line is implicitly
  guarded by the AC4 positive control (a broken value → the violation stops firing →
  `UnexpectedBuildSuccess`), and the AC4 contract's three enumerated mutation controls are all present.
  Optional: add a 4th `manualFixture(annotatedPackages = false)` variant asserting the build then
  SUCCEEDS. [buildSrc/src/test/kotlin/smpp/companions/buildsrc/gates/NullSafetyGateTest.kt]
- **CODEC-040-blindness fixture verifies declaration-blindness only** — the "blind to the errorprone
  config" case never resolves the `errorprone` configuration (the gate scans only
  `compileClasspath`/`runtimeClasspath`), so it proves the deps don't leak by construction, not that
  they couldn't under a future `extendsFrom` change. Low value (reflects actual gate design); optional
  scope-note in the test name. [buildSrc/src/test/kotlin/smpp/companions/buildsrc/gates/CodecPurityGateTest.kt:90-104]
