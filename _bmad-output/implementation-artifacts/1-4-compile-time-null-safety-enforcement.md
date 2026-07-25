---
baseline_commit: 26b1d5e
---

# Story 1.4: Compile-Time Null-Safety Enforcement (JSpecify + NullAway Gate)

Status: ready-for-dev

> Sequel to the 2026-07-25 null-safety feasibility analysis and the adversarial `create-story:validate` pass. Decision locked as **AD-35**. Extends Epic 1 (Foundation) — a mechanical-enforcement gate peer to CODEC-040 / OBS-013 / SEC-099. Depends only on 1.1 (done); enforces on current + all future source.
>
> **Versions are NOT pinned in this spec.** Error Prone, NullAway, the `net.ltgt.errorprone` Gradle plugin, and JSpecify versions are selected during implementation (see Dev Notes §Versions). The green build (AC6) is the proof the selection is mutually compatible and JDK-25-/Gradle-9.6.1-/Spring-Boot-4.1-capable.

## Story

**As a** platform engineer on the smpp-companions codebase,
**I want** compile-time null-safety enforced as a fail-closed `buildSrc` gate (NullAway reading JSpecify) on BOTH the `proxy` and `codec` modules,
**so that** a nullness violation fails `javac` before it can ship — complementing AD-17's runtime `@Validated`/`@NotNull` with build-time enforcement, on the annotation standard the Spring Framework 7 / Spring Boot 4 stack already migrated to.

## Acceptance Criteria

> The load-bearing evidence is **AC4** (a GradleTestKit positive control that a known nullness violation fails compilation AND that the gate cannot be silently bypassed). The rest wire the gate and the standard.

1. **[AC1] NullAway gate wired + fail-closed, on BOTH modules.** A new `smpp.null-safety` buildSrc convention plugin applies the `net.ltgt.errorprone` + `com.uber.nullaway` Gradle plugins; NullAway is `CheckSeverity.ERROR` so a nullness violation fails compilation (non-zero exit). Applied DIRECTLY from `codec/build.gradle.kts` and `proxy/build.gradle.kts` via `id("smpp.null-safety")` (after `id("smpp.java-conventions")`), matching how the three sibling convention plugins are applied — no opt-out flag. *(AD-35.)*
2. **[AC2] JSpecify is the annotation standard, on every package.** `org.jspecify:jspecify` is on `proxy` (`implementation`) and `codec` (`compileOnly` — so codec RUNTIME stays `{io.netty}+JDK`, AD-7/AD-35). `@NullMarked` (`org.jspecify.annotations.NullMarked`) is added to ALL SIX existing main `package-info.java` files (JSpecify `@NullMarked` does NOT propagate to sub-packages): `codec/src/main/java/smpp/companion/codec/package-info.java` and the five proxy packages `proxy/src/main/java/smpp/companion/proxy/{bootstrap,config,observability,relay,security}/package-info.java`.
3. **[AC3] NullAway reads JSpecify.** `-XepOpt:NullAway:JSpecifyMode=true`; `AnnotatedPackages = smpp.companion`. A `@Nullable` dereference in real source fails the build.
4. **[AC4] Positive control — the load-bearing test (contract below).** A GradleTestKit fixture under `smpp.null-safety` with a known nullness violation makes the gated compile **FAIL**, the gate is proven **not silently bypassable**, and a clean counterpart compiles. The fixture contract (non-negotiable, or NullAway fires on nothing):
   - **Fixture package + annotation:** the violation class lives in package `smpp.companion.gatefixture` (inside `AnnotatedPackages`), with a `package-info.java` carrying `@NullMarked`; the fixture `build.gradle.kts` applies `smpp.null-safety` and declares `implementation("org.jspecify:jspecify:<selected>")`.
   - **Violation must exercise `JSpecifyMode=true`:** because `@Nullable` dereferences / non-null-param nulls can fire even with JSpecifyMode OFF, the fixture MUST include a **generic-type-argument nullness violation** (e.g. assign `java.util.List<@org.jspecify.annotations.Nullable String>` to `List<String>`, then dereference) — this is the only kind that proves the `JSpecifyMode=true` line is load-bearing.
   - **Named task + dual assertion:** the test drives `compileJava` (via `buildAndFail()`), asserts `result.task(":compileJava")?.outcome == TaskOutcome.FAILED`, AND asserts `result.output` contains the literal `NullAway` (the Error Prone diagnostic category) AND an identifier from the violation source (e.g. the variable/parameter name) — proving the gate fired for the RIGHT reason.
   - **Silent-bypass counterpart (mutation control):** a second/third fixture where each load-bearing config line is removed or mutated in turn — (a) `CheckSeverity.ERROR` downgraded to `WARN`/`DEFAULT`, (b) `JSpecifyMode` removed, (c) the convention plugin not applied to `compileJava` — MUST make the build SUCCEED where it should fail, i.e. the test asserts the gate actually depends on each line. (A literal mirror of CODEC-041's `check`-wiring test does NOT suffice — NullAway fires inside `compileJava`, not a custom task.)
   - **Clean negative control:** a fixture with the same plugin/config and NO violation compiles successfully (`build()` succeeds, `:compileJava` `TaskOutcome.SUCCESS`), proving the gate is not over-firing.
5. **[AC5] CODEC-040 `org.jspecify` whitelist owned by this story + codec purity preserved.** The CODEC-040 allowlist amendment (`setOf("io.netty", "org.jspecify")` in `buildSrc/src/main/kotlin/smpp.codec-purity.gradle.kts`) is **uncommitted at baseline `26b1d5e`** — it is an IMPLEMENTATION change committed with the gate wiring (Task 0), before this AC is verified. Symmetric control: CODEC-041 gains a case asserting a fixture with `compileOnly("org.jspecify:jspecify:<selected>")` + an `io.netty:*` dep makes `:enforceDependencyAllowlist` SUCCEED (the "jspecify allowed" half — currently only the "forbidden rejected" half is tested); the existing forbidden-group rejection (Spring/Nimbus/Micrometer) still fails. Plus a CODEC-040-blindness control: a fixture applying `smpp.codec-purity` + `smpp.null-safety` asserts `:enforceDependencyAllowlist` SUCCEEDS even though Error Prone + NullAway sit on the `errorprone` configuration (proving that config is invisible to the gate).
6. **[AC6] Green build, JDK 25 + `--enable-preview`, with the selected versions.** `./gradlew clean build :buildSrc:test` succeeds with the implementation-selected Error Prone / NullAway / `net.ltgt.errorprone` / JSpecify versions. All currently-green `@Test` methods (18 across buildSrc + codec + proxy at baseline `26b1d5e`; `GoldenVectorCorpusTest` parameterizes at runtime) stay green — no test is removed or `@Disabled` to make the gate pass. No preview-USING source exists in this story's scope, so Error Prone does not analyze preview code today (Epic 2's StructuredTaskScope source will require a re-verify of Error Prone + `--enable-preview` on JDK 25 when it lands).

## Tasks / Subtasks

**0. Own the CODEC-040 whitelist (AC5) — implementation deliverable, NOT the kickoff commit.**
- [ ] The `org.jspecify` addition to `smpp.codec-purity.gradle.kts` (`setOf("io.netty", "org.jspecify")`) is currently an UNCOMMITTED working-tree edit at baseline `26b1d5e`. It is an IMPLEMENTATION change, so it is committed ALONGSIDE the gate-wiring work (Task 1) — NOT in the docs-only kickoff commit (AD-35 ADR + story file + sprint-status entry). It MUST be on the branch before AC5 is verified, so AC5 holds on a clean checkout of the branch.

**1. NullAway convention plugin (AC1, AC3) — plugin mode, explicit.**
- [ ] In `buildSrc/build.gradle.kts` `dependencies { }` add the Gradle **plugin-marker** deps so the precompiled script plugin resolves them: `implementation("net.ltgt.errorprone:net.ltgt.errorprone.gradle.plugin:<selected>")` and `implementation("com.uber.nullaway:nullaway-gradle-plugin:<selected>")`. (These are the GRADLE-PLUGIN coordinates — distinct from the Error Prone / NullAway analyzer coordinates; do not conflate the two version numbers.)
- [ ] `buildSrc/src/main/kotlin/smpp.null-safety.gradle.kts`: `plugins { id("net.ltgt.errorprone"); id("com.uber.nullaway") }`; configure `dependencies { errorprone("com.google.errorprone:error_prone_core:<selected>"); errorprone("com.uber.nullaway:NullAway:<selected>") }` (the `errorprone` configuration carries the analyzer jars); then `tasks.withType<JavaCompile>().configureEach { options.errorprone { check("NullAway", CheckSeverity.ERROR); option("NullAway:AnnotatedPackages", "smpp.companion"); option("NullAway:JSpecifyMode", "true") } }`. Do NOT manually pass `-XDaddTypeAnnotationsToSymbol` — recent `net.ltgt.errorprone` enables it automatically on JDK 21+ (and the `=true` suffix is non-syntax).
- [ ] Apply `id("smpp.null-safety")` directly in `codec/build.gradle.kts` and `proxy/build.gradle.kts`, after `id("smpp.java-conventions")`.

**2. JSpecify annotations (AC2).**
- [ ] `org.jspecify:jspecify` → `proxy` `implementation`, `codec` `compileOnly`.
- [ ] Add `@NullMarked` to all six main `package-info.java` files listed in AC2.

**3. Positive control (AC4).**
- [ ] `buildSrc/src/test/kotlin/smpp/companions/buildsrc/gates/NullSafetyGateTest.kt` (peer to the three existing gate tests, same package `smpp.companions.buildsrc.gates`): GradleTestKit + `withPluginClasspath()` (the `kotlin-dsl`-generated plugin-under-test-metadata injects the REAL `smpp.null-safety`). Implement the full AC4 contract: positive-fail (JSpecifyMode-exercising violation), silent-bypass mutation counterparts, clean negative control; assert `:compileJava` FAILED + `NullAway` + offender in output. The fixture `settings.gradle.kts` must include `pluginManagement { repositories { gradlePluginPortal(); mavenCentral() } }` (the fixture resolves the external plugins, unlike the existing gate fixtures).

**4. CODEC-040 whitelist verification (AC5).**
- [ ] Extend `CodecPurityGateTest.kt` with the symmetric "jspecify allowed" case + the errorprone-config-blindness case.

**5. Annotate existing source + verify (AC6).**
- [ ] Minimal annotations on existing proxy/codec classes so NullAway is green on MAIN sources (`@Nullable` where genuinely nullable; rely on `@NullMarked` for the rest).
- [ ] `./gradlew clean build :buildSrc:test` → green.

## Dev Notes

### Versions — selected during implementation (NOT pinned here)
Select the latest stable versions of these four artifacts that are **mutually compatible** and run on **JDK 25 + Gradle 9.6.1 + Spring Boot 4.1**, resolving from `gradlePluginPortal()` / `mavenCentral()`:
- **Error Prone** — the analyzer (`com.google.errorprone:error_prone_core`), placed on the `errorprone` configuration. Min JDK 21 to run; hooks javac via `-Xplugin:ErrorProne` (NOT a JSR-269 processor).
- **NullAway** — the analyzer (`com.uber.nullaway:NullAway`), an Error Prone `BugChecker`, on the `errorprone` configuration. Must support `-XepOpt:NullAway:JSpecifyMode=true`.
- **`net.ltgt.errorprone`** — the GRADLE plugin (`net.ltgt.errorprone:net.ltgt.errorprone.gradle.plugin`), a SEPARATE version number from the Error Prone analyzer. Must support Gradle 9.6.1 and pass `-XDaddTypeAnnotationsToSymbol` on JDK 21+ automatically.
- **JSpecify** — `org.jspecify:jspecify` (1.0.x GA, `RUNTIME`-retained, `TYPE_USE` — the Spring Framework 7 standard).

**The green build (AC6) is the proof.** Do not assert any specific version is "CI-green on JDK 25" in commits/comments without having run it. The earlier spec's hard pins (Error Prone 2.50.0 / NullAway 0.13.5) were unverified and conflated the analyzer version with the Gradle-plugin version — that is why versions are now impl-time.

### Decisions made in this story (resolving the validation's open questions)
- **Wiring mode = plugin mode** (apply `net.ltgt.errorprone` + `com.uber.nullaway` plugins; analyzers on the `errorprone` config), not manual `-Xplugin` config — less code, harder to mis-wire.
- **Application site = direct, per-module** (`codec/build.gradle.kts` + `proxy/build.gradle.kts`), matching the three sibling convention plugins — no "java-conventions behind a flag" opt-out.
- **Test-source enforcement = MAIN sources only for v1.** NullAway runs at `ERROR` on `compileJava`; explicitly DISABLE on `compileTestJava` (`tasks.named("compileTestJava") { options.errorprone { disable("NullAway") } }`). Rationale: the gate's purpose is production-code nullness; the existing tests use AssertJ fluent chains / Spring slice tests / `@TempDir` that would throw a false-positive wall, ballooning the story. Follow-up story extends the gate to test sources once test roots carry `@NullMarked`. *(If full fail-closed on tests is preferred, instead add `@NullMarked` `package-info.java` to every test root under `smpp.companion.*` and leave NullAway enabled — expect to annotate/suppress test code.)*
- **`-XDaddTypeAnnotationsToSymbol` is NOT added manually** — `net.ltgt.errorprone` passes it on JDK 21+; the earlier `=true` form was wrong syntax anyway.

### False-positive protocol (unannotated third-party code)
None of the project's deps (Spring Boot 4.1, Spring Framework 7, Netty 4.2, JUnit Jupiter 6, AssertJ 3.27, ArchUnit 1.4, Nimbus 10.9) ship `@NullMarked` package-infos, so calls into them are "unknown nullness" (NullAway applies optimistic defaults). Protocol: (a) preferred — annotate the call site (`@Nullable`/`@NonNull` from `org.jspecify.annotations`); (b) last resort — `@SuppressWarnings("NullAway")` with a mandatory `// reason: <one-line>` comment; (c) for Spring's own `@NonNullApi`-marked packages, consider `-XepOpt:NullAway:AcknowledgeRestrictiveAnnotations`. Zeroizable `char[]`/`byte[]` secret fields (AD-12) are declared `@Nullable` since they are nulled after use.

### ADs to honor
- **AD-35** — this story IS AD-35's implementation.
- **AD-7 / AD-27 / CODEC-040** — codec purity: JSpecify is the ONE whitelisted non-netty group; declare it `compileOnly` on codec so runtime stays pure.
- **AD-17** — fail-fast: this adds COMPILE-time fail-fast on top of the existing runtime `@Validated`/`@NotNull`. The two operate at disjoint stages with disjoint annotation sets — no double-reporting.

### Build-time cost
Error Prone runs dataflow analysis on every `javac` invocation, adding measurable per-compile overhead. Acceptable for v1; revisit if CI wall-time regresses materially.

### Why NullAway + JSpecify (not the alternatives)
- **NullAway** — flow-sensitive, low false-positives, reads JSpecify, Spring's own recommendation.
- **Checker Framework** — sounder (full pluggable type system) but high annotation/stub burden + GPL2 framework jar; wrong cost/benefit here.
- **SpotBugs** — flow-insensitive bug-finder, blind to JSpecify (#3143); wrong pick for systematic nullness.
- **JSpecify-alone** — documentation-only; needs a checker.

### References
- [Source: `_bmad-output/planning-artifacts/architecture/.../ARCHITECTURE-SPINE.md`#AD-35]
- 2026-07-25 null-safety feasibility analysis + adversarial `create-story:validate` pass (this session)
- https://spring.io/blog/2025/03/10/null-safety-in-spring-apps-with-jspecify-and-null-away
- https://github.com/uber/NullAway (JSpecify wiki); https://errorprone.info

## Change Log
- 2026-07-25 — Story 1.4 created (null-safety feasibility analysis → AD-35 → this story). CODEC-040 `org.jspecify` whitelist applied as setup (uncommitted; an IMPLEMENTATION change committed with the gate wiring — Task 0 — not the docs-only kickoff).
- 2026-07-25 — Revised per `create-story:validate` findings + version-unpinning directive: (1) Error Prone / NullAway / `net.ltgt.errorprone` / JSpecify versions DEPINNED — selected during implementation, green build is the proof (retires the unverified version claims + the analyzer-vs-plugin-version conflation); (2) AC1 — buildSrc must declare the two Gradle plugins as `implementation` deps or `smpp.null-safety` won't compile; (3) AC2 — `@NullMarked` enumerated across all 6 main package-infos (no sub-package propagation); (4) AC4 — concrete fixture contract, JSpecifyMode-guarding generic-type-arg violation, silent-bypass mutation counterparts, dual diagnostic assertion, named `compileJava` task, clean negative control; (5) AC5 — whitelist owned as an implementation deliverable (committed with the gate wiring, Task 0) + symmetric "jspecify allowed" control + errorprone-config-blindness control; (6) test-source enforcement decided (main-only, v1); (7) dropped redundant `-XDaddTypeAnnotationsToSymbol`; (8) "20 tests" corrected to the verified 18 `@Test` methods. Status: ready-for-dev.
