---
title: 'Story 5.1 — the runnable JAR deploy shape'
type: 'feature'
created: '2026-09-10'
status: 'in-progress'
route: 'dispatch'
baseline_commit: b6de4929ae2930556125da1efb1569e00a396a50
review_loop_iteration: 0
context:
  - {project-root}/_bmad-output/implementation-artifacts/epic-5-context.md
  - {project-root}/_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The proxy ships no first-class deploy shape: `bootJar` runs on plugin defaults only, nothing carries `--enable-preview` into the packaged artifact (a plain `java -jar` of today's jar cannot run preview-compiled classes), no launcher pins the runtime flags the catalog asserts (`-XX:+UseZGC`, `-XX:MaxDirectMemorySize`, IPv4 preference), and the packaged shape has never been booted or smoke-tested as `java -jar`.

**Approach:** Make the standalone runnable JAR a first-class shape — explicit bootJar configuration (pinned main class, stable archive name; NO Enable-Preview manifest attribute — dropped by owner amendment 2026-09-10: inert on the pinned JDK launcher, see Decisions), a documented operator JVM-flag contract (the one pinned flag set `java -jar` must be launched with — no repo launcher script; flags are the operator's invocation per the contract, exercised by the packaged smoke and consumed verbatim by the later Docker entrypoint; the page also carries the lazy-init documented deviation and is the single load-bearing home of `--enable-preview`), JSON-stream mode banners (the parked decision visible at JAR boot), the standard Micrometer JVM binders bound, a JDK exact-build pin guard, and a subprocess packaged boot+smoke test (boot → one bind/relay round → SIGTERM drain) against the existing MockSmsc harness.

## Boundaries & Constraints

**Always:**
- ONE flag set, single source of truth — documented on the operator contract page, executed by the packaged smoke from one Java-side launch constant, carried identically by the (later) Docker entrypoint — the two shapes must not drift (FR-DEPLOY-1). No Java reads the page (owner rule 2026-09-10: no Java tests over *.md docs).
- Fail-closed posture holds identically in the packaged shape: startup validation, the AD-30 budget check, and the JDK build-pin guard all refuse, never warn-and-continue. The lazy-init deviation is the one documented exception, by owner decision.
- Ledger discipline: every deferred-work marker cites a biting test + commit; every new guard ships its mutation row.
- The packaged smoke boots the REAL jar as a subprocess (production main, yml defaults overridable by args) — no ApplicationContextRunner substitute for the shape being proven.

**Never:**
- No Docker/jlink/distroless work (Epic 5 later story): no Dockerfile, no jlink plugin, no Testcontainers parity smoke, no DEP-1 secrets-E2E rows.
- No CI scaffolding (none exists; dual-arch CI is a later slice).
- No native-image anything (AD-23).
- No relay/security/observability logic changes — beyond the banner emission swap and the new binder beans, nothing in those packages is touched.
- No new operator-facing config keys.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Packaged boot | `java -jar proxy-*.jar` + the documented flag set (valid cell args) | Boots to `startup_summary` JSON line; SMPP + metrics listeners bound | Config matrix refusals unchanged (AD-17) |
| Preview classes under plain `java -jar` | No `--enable-preview` on CLI (amended 2026-09-10: the manifest attribute is inert — dropped) | Hard `UnsupportedClassVersionError` naming `--enable-preview` — fail-closed; the contract (T2) is the single load-bearing mechanism | The smoke's `--enable-preview` dropped → packaged boot RED (T5 automated row; proven manually in T1) |
| Lazy-init enabled | `spring.main.lazy-initialization=true` | Boots — documented deviation: startup validation defers to first use | No runtime guard (owner decision); the contract page carries the warning |
| Off-pin JDK | Build/run on JDK ≠ pinned exact build | Build-time refusal naming expected vs actual | Fail, not warn |
| SIGTERM on packaged shape | `kill <pid>` of the booted jar | AD-22 ordered drain log lines, then clean exit | Quiesce bound (4.4 T5) holds |
| Mode A/B boot banners | Any A/B cell boot | WARN-level JSON lines on the logback stream | No plain-text stderr output |
| Budget check under defaults | Contract's `-XX:MaxDirectMemorySize` + yml memory trio | AD-30 self-check passes | Mismatch still refuses per existing check |
| JVM metrics bound | Any packaged boot | Standard Micrometer JVM binder gauges present in the `/metrics` scrape | Absent binder = silent gap; pinned by scrape row |

**Decisions (owner, 2026-09-10):**
- Preview mechanism (owner amendment at T1, 2026-09-10): the `Enable-Preview` manifest attribute is INERT on the pinned JDK (temurin 25.0.3+9 launcher reads Add-Exports/Add-Opens/Enable-Native-Access from manifests but has no Enable-Preview arm — proven by a controlled minimal jar, by zero `Enable-Preview` strings in the runtime image, and by the real packaged boot failing with the attribute present) — DROPPED from the manifest; the T2 contract's `--enable-preview` flag is the single load-bearing preview mechanism. Matrix row 2, AC 1, and the T1/T5 mutation rows amended accordingly.
- Slice: JAR-only foundation — Docker/jlink/distroless, Testcontainers parity smoke, and the DEP-1 secrets E2E belong to a later Epic-5 story.
- Launcher: bare `java -jar` + a documented operator JVM-flag contract. No repo launcher script. Amended at T2 (2026-09-10, owner rule — no Java tests over *.md docs): the contract page DOCUMENTS the flag set; the packaged smoke executes the identical set from a Java-side launch constant (nothing parses the page); the future Docker entrypoint carries the same set. Page↔constant coherence is kept by review — a flag change is a story touching both. The catalog's DEPLOY-003/004 JAR halves land as contract + smoke (dated technique amendment in the markers).
- Mode banners: route through logback as WARN-level JSON (deferred-work :706 resolved by this story).
- Micrometer: the standard JVM binders are bound IN this story (deferred-work :710 resolved here, not Epic 6) — `ResourceMetrics`'s "deliberate exclusion" javadoc is amended to match.
- Lazy-init: documented operator-accepted deviation — NO runtime guard (deferred-work :195 resolved as docs). The flag ships live; the contract page carries the warning that enabling `spring.main.lazy-initialization` defers the AD-17 matrix and AD-30 self-check to first use.
- Token gate: full spec kept (owner precedent — 4.x specs run larger).

</frozen-after-approval>

## Code Map

- `proxy/build.gradle.kts` -- bootJar lives on plugin defaults (Spring Boot 4.1.0); zero explicit packaging config today; Testcontainers 2.0.5 + netty 4.2.16.Final override already here.
- `buildSrc/src/main/kotlin/smpp.java-conventions.gradle.kts` -- `--enable-preview` threaded into JavaCompile/Test/JavaExec(bootRun) ONLY (:23,:28,:31-34); toolchain is major-version-only (25, :16-20); JDK build-pin guard lands here or beside it.
- `.tool-versions` -- the exact environment pin (`java temurin-25.0.3+9.0.LTS`) — the single source the build-pin guard reads.
- `proxy/src/main/java/.../ProxyCompanionApplication.java` -- plain `SpringApplication.run`; no builder customization to fight.
- `proxy/src/main/resources/application.yml` -- production defaults (memory trio 64/1024/1.5 ≈ 6 GiB derived budget, `budget-check: fail`); packaged boots override via args, not edits.
- `proxy/src/main/java/.../relay/netty/DirectMemoryBudgetValidator.java` -- reads `-XX:MaxDirectMemorySize` via `ManagementFactory` input-args (:45); deliberately avoids `jdk.internal.misc.VM` so the boot jar needs NO `--add-exports` (javadoc :19) — do not reintroduce.
- `proxy/src/main/java/.../config/CompanionModeAWarning.java` / `CompanionModeBWarning.java` -- `System.err.println` in `@PostConstruct` (:47 each) — the stream swap target.
- `proxy/src/test/java/.../config/TestCompanionConfigs.java` -- per-cell factories (`reverseB(dir)` etc., `args()` for builder runs) — the packaged smoke's config source.
- `proxy/src/test/java/.../relay/RelayA1SmokeTest.java` + `testsupport/RelayTestFixtures.java` -- the real-socket smoke idiom + MockSmsc harness the packaged test reuses.
- `proxy/src/test/java/.../bootstrap/BootstrapLifecycleTest.java` / `RelayWiringConfigTest` -- the full-yml-boot idiom (builder `.web(NONE)` + run args).
- `proxy/src/main/resources/logback-spring.xml` -- LogstashEncoder JSON-lines; banners join this stream.
- `proxy/src/main/java/.../observability/ObservabilityConfig.java` (:31) + `ResourceMetrics.java` -- the sole `PrometheusMeterRegistry` bean and the two custom gauges; binder beans land beside them, and ResourceMetrics' "no standard binders, deliberate" javadoc is the amendment target (deferred-work :710).
- `proxy/src/test/java/.../observability/MetricsEndpointTest.java` / `ResourceMetricsTest` -- the scrape-assertion idiom the binder row reuses.

## Tasks & Acceptance

**Execution:**
- [x] **T1 — bootJar first-class** — Explicit `bootJar {}` in `proxy/build.gradle.kts`: pinned main class, stable archive name (`proxy.jar`); wire the packaged-smoke test to consume the built jar (task dependency + jar as test input). Mutation (amended 2026-09-10): the load-bearing arm is the CONTRACT FLAG, not a manifest attribute — `--enable-preview` dropped from the packaged boot → hard `UnsupportedClassVersionError` (proven manually in T1 verification; the automated row lands with T5's smoke).
- [x] **T2 — operator flag contract** — Author the contract (the pinned set: `--enable-preview`, `-XX:+UseZGC`, `-XX:MaxDirectMemorySize` coherent with the yml default budget, `-Djava.net.preferIPv4Stack=true`; rationale per flag) as a `docs/` page, INCLUDING the lazy-init deviation paragraph (the owner-decided :195 stance: enabling `spring.main.lazy-initialization` defers the AD-17 matrix and AD-30 self-check to first use — accepted deviation, warning lives here). Amended 2026-09-10 (owner rule: no Java tests over *.md docs): the doc-consistency source-scan, the md-parsing fixture, and the scan's mutation arm were DROPPED — no Java reads the page; T5 executes the identical set from a Java-side launch constant, and page↔constant coherence is a review-time duty of every flag-change story.
- [x] **T3 — banner stream swap** — Both mode warnings emit WARN-level JSON via logback (no `System.err`); boot-capture test asserts the JSON line + no plain-text stderr. Mutation: reverted to println → row RED.
- [x] **T4 — Micrometer JVM binders** — Bind the standard JVM binder set (memory/GC/threads/processor/uptime) via `ObservabilityConfig`; amend the `ResourceMetrics` "deliberate exclusion" javadoc; scrape test asserts the binder gauges appear beside the existing custom gauges. Mutation: binder beans removed → scrape row RED.
- [ ] **T5 — packaged boot+smoke** — Subprocess test: `java -jar` the built jar with the operator flag set as a Java-side launch constant mirroring the T2 contract page (owner rule 2026-09-10 — no Java parses the md; the constant's javadoc points at the page), `reverseB` cell (secret files from a temp dir), MockSmsc on the loopback; assert `startup_summary`, one bind→relay round via real socket, SIGTERM → ordered AD-22 drain lines → clean exit; AD-30 check passes under the constant's flags. Mutation: smoke pointed at a stale jar / drain lines unasserted / the constant's `--enable-preview` dropped (→ `UnsupportedClassVersionError`, the preview arm's automated row) → row RED.
- [ ] **T6 — JDK build-pin guard** — Build refuses on a JDK runtime ≠ the `.tool-versions` pin (reads the running JVM, no provisioning — foojay stays relaxed). Mutation: guard neutered → off-pin simulation row RED.
- [ ] **T7 — proofs, catalog rows, ledger closure** — `./gradlew clean build --console=plain` GREEN end-to-end (clean required — source-scan trap); DEPLOY catalog: dated Status markers for the JAR halves of DEPLOY-003/004 (technique amended: contract + smoke, Docker halves stay open), DEPLOY-014, and any new rows authored as-landed; deferred-work: resolve the banner (:706), binder (:710), and lazy-init (:195 — documented-deviation decision, cites the contract page + commit) entries.

**Acceptance Criteria:**
- Given the built jar and a valid cell, when launched as `java -jar` with the documented flag set, then it boots to `startup_summary` with both listeners bound — the contract's `--enable-preview` is load-bearing: a boot without it refuses hard (`UnsupportedClassVersionError`), fail-closed, and the jar manifest deliberately carries no preview marking (owner amendment 2026-09-10).
- Given the operator flag contract, when lazy-init is considered, then the page documents the deviation — no runtime guard exists (owner decision 2026-09-10), and the warning names what defers to first use.
- Given a mode A or B boot, when the banner fires, then it is a WARN JSON line on the logback stream and stderr carries no plain text.
- Given any boot, when the `/metrics` endpoint is scraped, then the standard JVM binder gauges are present beside the custom relay/ROPC gauges.
- Given the packaged smoke rig, when SIGTERM arrives post-couple, then the AD-22 drain sequence is logged in order before exit.
- Given a JDK other than the pinned build, when any build task runs, then the build fails naming expected vs actual.

## Implementation Notes

## Spec Change Log

- 2026-09-10 (owner amendment at T2, after the scan landed GREEN): NO Java tests over *.md docs — the T2 doc-consistency source-scan (`OperatorFlagContractDocsTest`), the md-parsing fixture (`OperatorFlagContract`), the test-input registration for the page in `proxy/build.gradle.kts`, and the scan's mutation arm were DROPPED; nothing in the repository parses the contract page. The flag set now has two kept-in-step representations: the page (operator documentation) and the T5 Java-side launch constant (the executable definition). Frozen Boundaries #1 and the Launcher decision amended in place per the renegotiation; T2/T5 task text re-pointed; the page's "how pinned" section rewritten. Coherence is a review-time duty — a flag change is a story touching both.
- 2026-09-10 (owner-ratified at T1): `Enable-Preview` manifest attribute DROPPED — proven inert on temurin 25.0.3+9 (controlled minimal-jar boot; zero `Enable-Preview` strings in the runtime image while Add-Exports/Add-Opens/Enable-Native-Access are present; real packaged boot fails with the attribute present). Frozen Approach, matrix row 2, and Decisions amended in place per the renegotiation; AC 1 reworded; T1/T5 mutation rows re-pointed to the contract-flag arm. Load-bearing preview mechanism = the T2 contract's `--enable-preview`.

## Review Triage Log

## Design Notes

- No launch configuration travels in the jar manifest at all (corrected at T1, 2026-09-10): the pinned JDK launcher honors only Add-Exports/Add-Opens/Enable-Native-Access from manifests — there is no Enable-Preview arm, and `-XX` flags never travel either. Under the bare-`java -jar` decision the contract page is the single home for the entire flag set including `--enable-preview`; the jar side carries structure only (pinned main class, stable archive name).
- The flag set must be ONE shared definition (amended 2026-09-10, owner rule: no Java tests over *.md docs) — two kept-in-step representations: the contract page (operator documentation) and the T5 Java-side launch constant (the executable definition, its javadoc pointing at the page). No machine pin reads the page; coherence is a review-time duty — a flag change is a story that touches both, and the future Docker entrypoint story pins its own parity against the same set.
- Memory interlock: yml defaults derive ~6 GiB budget with `budget-check: fail`; the contract's `MaxDirectMemorySize` must satisfy the AD-30 check against those SAME defaults (pick the value once, assert it in the smoke — do not fork yml).
- The subprocess smoke needs the jar built before tests run — wire the dependency in Gradle, and mind the incremental-run trap: the smoke must re-run when the jar changes.

## Verification

**Commands:**
- `./gradlew clean build --console=plain` -- expected: GREEN, including the new packaged-smoke, matrix, and build-pin rows (a "source-pin" docs-scan row was dropped by the 2026-09-10 owner rule — no Java tests over *.md docs).
- `./gradlew :proxy:test --tests '*Packaged*' --tests '*LazyInit*' --tests '*Banner*' --console=plain` -- expected: GREEN after `clean`.

**Manual checks (if no CLI):**
- From `proxy/build/libs`: `java -jar` the boot jar with the documented flag set and a reverse-B arg set against a stub SMSC; observe the JSON startup line, one relayed bind, binder gauges in a `/metrics` scrape, and clean SIGTERM shutdown.
