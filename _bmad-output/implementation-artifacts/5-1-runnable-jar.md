---
title: 'Story 5.1 — the runnable JAR deploy shape'
type: 'feature'
created: '2026-09-10'
status: 'done'
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

**Approach:** Make the standalone runnable JAR a first-class shape — explicit bootJar configuration (pinned main class, stable archive name; NO Enable-Preview manifest attribute — dropped by owner amendment 2026-09-10: inert on the pinned JDK launcher, see Decisions), a documented operator JVM-flag contract (the one pinned flag set `java -jar` must be launched with — no repo launcher script; flags are the operator's invocation per the contract, exercised by the packaged smoke and consumed verbatim by the later Docker entrypoint; the page also carries the lazy-init documented deviation and is the single load-bearing home of `--enable-preview`), JSON-stream mode banners (the parked decision visible at JAR boot), the standard Micrometer JVM binders bound, and a subprocess packaged boot+smoke test (boot → one bind/relay round → SIGTERM drain) against the existing MockSmsc harness. (Amended 2026-09-10: the JDK exact-build pin guard originally enumerated here was owner-dropped before any code was written — see Decisions.)

## Boundaries & Constraints

**Always:**
- ONE flag set, single source of truth — documented on the operator contract page, executed by the packaged smoke from one Java-side launch constant, carried identically by the (later) Docker entrypoint — the two shapes must not drift (FR-DEPLOY-1). No Java reads the page (owner rule 2026-09-10: no Java tests over *.md docs).
- Fail-closed posture holds identically in the packaged shape: startup validation and the AD-30 budget check refuse, never warn-and-continue. The lazy-init deviation is the one documented exception, by owner decision. (Amended 2026-09-10: the JDK build-pin guard was dropped from this enumeration by owner decision — no build-time JDK version check exists; see Decisions.)
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
- JDK build pin (owner decision at T6, 2026-09-10, before any code was written): the exact-build check DROPPED — "asdf pin is enough, no additional jdk/jre version check is needed". The exact-build pin stays the asdf environment pin (`.tool-versions` — the JDK is an environment-supplied precondition, as since story 1-1's 2026-07-25 relaxation); the build keeps its pre-story major-25 toolchain pin (`smpp.java-conventions.gradle.kts`, header already citing DEPLOY-014/SEC-085, unchanged) and deliberately performs no build-time JDK version comparison. T6's task row, the Off-pin JDK matrix row, and the off-pin AC removed; the old T7 renumbered T6.
- Token gate: full spec kept (owner precedent — 4.x specs run larger).

</frozen-after-approval>

## Code Map

- `proxy/build.gradle.kts` -- bootJar lives on plugin defaults (Spring Boot 4.1.0); zero explicit packaging config today; Testcontainers 2.0.5 + netty 4.2.16.Final override already here.
- `buildSrc/src/main/kotlin/smpp.java-conventions.gradle.kts` -- `--enable-preview` threaded into JavaCompile/Test/JavaExec(bootRun) ONLY (:23,:28,:31-34); toolchain is major-version-only (25, :16-20) — and stays that way (the exact-build guard was owner-dropped 2026-09-10; see Decisions).
- `.tool-versions` -- the exact environment pin (`java temurin-25.0.3+9.0.LTS`) — the owner-facing exact-build mechanism; nothing in the build reads it (owner decision 2026-09-10).
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
- [x] **T5 — packaged boot+smoke** — Subprocess test: `java -jar` the built jar with the operator flag set as a Java-side launch constant mirroring the T2 contract page (owner rule 2026-09-10 — no Java parses the md; the constant's javadoc points at the page), `reverseB` cell (secret files from a temp dir), MockSmsc on the loopback; assert `startup_summary`, one bind→relay round via real socket, SIGTERM → ordered AD-22 drain lines → clean exit; AD-30 check passes under the constant's flags. Mutation: smoke pointed at a stale jar / drain lines unasserted / the constant's `--enable-preview` dropped (→ `UnsupportedClassVersionError`, the preview arm's automated row) → row RED.
- [x] **T6 — proofs, catalog rows, ledger closure** (renumbered from T7: the build-pin-guard T6 was owner-dropped 2026-09-10 — see Decisions) — `./gradlew clean build --console=plain` GREEN end-to-end (clean required — source-scan trap); DEPLOY catalog: dated Status markers for the JAR halves of DEPLOY-003/004 (technique amended: contract + smoke, Docker halves stay open), DEPLOY-014 (owner-decision record: standing mechanism = major-25 toolchain pin + asdf environment pin; the exact-build refusal arm dropped 2026-09-10 before implementation), and any new rows authored as-landed; deferred-work: resolve the banner (:706), binder (:710), and lazy-init (:195 — documented-deviation decision, cites the contract page + commit) entries.

**Acceptance Criteria:**
- Given the built jar and a valid cell, when launched as `java -jar` with the documented flag set, then it boots to `startup_summary` with both listeners bound — the contract's `--enable-preview` is load-bearing: a boot without it refuses hard (`UnsupportedClassVersionError`), fail-closed, and the jar manifest deliberately carries no preview marking (owner amendment 2026-09-10).
- Given the operator flag contract, when lazy-init is considered, then the page documents the deviation — no runtime guard exists (owner decision 2026-09-10), and the warning names what defers to first use.
- Given a mode A or B boot, when the banner fires, then it is a WARN JSON line on the logback stream and stderr carries no plain text.
- Given any boot, when the `/metrics` endpoint is scraped, then the standard JVM binder gauges are present beside the custom relay/ROPC gauges.
- Given the packaged smoke rig, when SIGTERM arrives post-couple, then the AD-22 drain sequence is logged in order before exit.

## Implementation Notes

## Spec Change Log

- 2026-09-10 (owner decision at T6, before any code was written): the JDK build-pin guard DROPPED — owner words: "asdf pin is enough, no additional jdk/jre version check is needed". The exact-build pin stays the asdf environment pin (`.tool-versions`); the build keeps its pre-story major-25 toolchain pin (`smpp.java-conventions.gradle.kts`, header already citing DEPLOY-014/SEC-085, unchanged) and deliberately performs no build-time JDK version comparison. Frozen Approach and Boundaries #2 amended in place; the Off-pin JDK matrix row and the off-pin AC removed; the T6 task row deleted and the old T7 renumbered T6; Verification re-worded; Code Map re-pointed. The operator contract page's "the build refuses an off-pin JDK" sentence amended to match. Consistent with the 2026-07-25 story-1-1 relaxation (vendor pin + foojay removed — the JDK is an environment-supplied precondition).
- 2026-09-10 (owner decision at T5 dispatch): matrix row 3 (lazy-init enabled → validation defers to first use) and the `*LazyInit*` verification selector DROPPED — the lazy-init deviation is **documented-only**: the T2 contract page carries the warning, and no test (behavioral or otherwise) pins the deferral mechanics. The md-scan that had incidentally covered the row was deleted by the no-Java-tests-over-md rule (T2 amendment); asked whether to replace it with a behavioral boot test, the owner chose not to. The Decisions-block lazy-init entry, Boundaries #2's "one documented exception" clause, and AC 2 (the page documents the deviation) stand unchanged.
- 2026-09-10 (owner amendment at T2, after the scan landed GREEN): NO Java tests over *.md docs — the T2 doc-consistency source-scan (`OperatorFlagContractDocsTest`), the md-parsing fixture (`OperatorFlagContract`), the test-input registration for the page in `proxy/build.gradle.kts`, and the scan's mutation arm were DROPPED; nothing in the repository parses the contract page. The flag set now has two kept-in-step representations: the page (operator documentation) and the T5 Java-side launch constant (the executable definition). Frozen Boundaries #1 and the Launcher decision amended in place per the renegotiation; T2/T5 task text re-pointed; the page's "how pinned" section rewritten. Coherence is a review-time duty — a flag change is a story touching both.
- 2026-09-10 (owner-ratified at T1): `Enable-Preview` manifest attribute DROPPED — proven inert on temurin 25.0.3+9 (controlled minimal-jar boot; zero `Enable-Preview` strings in the runtime image while Add-Exports/Add-Opens/Enable-Native-Access are present; real packaged boot fails with the attribute present). Frozen Approach, matrix row 2, and Decisions amended in place per the renegotiation; AC 1 reworded; T1/T5 mutation rows re-pointed to the contract-flag arm. Load-bearing preview mechanism = the T2 contract's `--enable-preview`.

## Review Triage Log

Round 1 (2026-09-11, three layers over the baseline→`c9d2aa0` diff):

- **[E1+B1] `PackagedBootSmokeTest.launch()` rescue clause misses `IOException` — medium → patch.** `catch (RuntimeException | Error e)` lets the likeliest mid-launch failures after both satellites are up (`Files.writeString`, `idpTrustStoreFixture`, above all `ProcessBuilder.start()` — all `throws IOException`) escape without `smsc.close()`/`idp.stop(0)`, contradicting the method's own rig javadoc and the house exception-safe-cleanup rule. Verified in source. Fixed: catch widened to `RuntimeException | Error | IOException`.
- **[E2] `/proc/<pid>/cmdline` read can race child death — low → rejected.** Real but the window is milliseconds against a just-booted healthy child, and the row still fails (as `UncheckedIOException` instead of a diagnostic `fail`) — rarely met in everyday use, and the fix adds an exists-guard branch. Rejected per the low rule.
- **[E3+V1+B9] Scrape-idempotency row lost its value-level bite — medium → patch.** Pre-verified (verification-gap layer): a PRE-REGISTERED scrape counter incremented per request — this repo's own meter idiom (`MeteredRelayObserver`'s close grid) — evades the shape-only comparison (every sample value stripped); the only value pin left is `story41_endpoint_probe_total 3.0`; the deleted `isEqualTo(first)` would have gone RED. Fixed: row 1 additionally asserts the non-live sample lines are verbatim-equal between the two scrapes (`stableSamples`: `jvm_gc_`/`jvm_memory_`/`jvm_threads_`/CPU-usage/load-average/uptime excluded — the families that legitimately move in an idle window), restoring the "moves no counter" contract the row's `as()` text still claims.
- **[B2] "Only `jvm_gc_pause` is lazy" is wrong for micrometer 1.17.0 — medium → patch.** `JvmGcMetrics.handleNotification` creates `jvm_gc_concurrent_phase_time` timers just as lazily (concurrent-phase notifications; a plausible posture for a repo whose operator contract pins ZGC), and `jvm_gc_memory_promoted_bytes_total` is generational-only. `scrapeShape` filtered only `jvm_gc_pause` → latent shape-equality flake; the wrong invariant was stated at three sites (scrapeShape javadoc, binder-row comment, `ObservabilityConfig` javadoc). Fixed: filter extended to `jvm_gc_concurrent_phase_time`; all three texts amended to the two lazy timer families (plus the generational nuance in the config javadoc).
- **[B3] No Linux platform guard on the Linux-only packaged suite — low → rejected.** The product is Linux-only (COMP-3) and the row's own `as()` names Linux as the suite's platform — a non-Linux run fails loudly and honestly; an `assumeTrue` skip guard would trade that fail-closed red for a silent skip. Rejected per the low rule (out of the everyday envelope, fix converts failure to skip).
- **[B4] Packaged smoke never asserts the child's stderr — low → patch.** T3's AC second half ("stderr carries no plain text") was proven in-JVM only; `rig.stderr` was read solely in failure diagnostics, so the `:706` resolution's "re-proves it in the deployed shape" was half-true. Fixed: the happy row now asserts the banner marker text is absent from the child's stderr (absence-of-marker, not `isBlank()` — a JVM launched with `JDK_JAVA_OPTIONS` legitimately prints "Picked up …" there), which makes the `:706` claim fully true rather than editing the ledger.
- **[B5] `epic-5-context.md` born stale inside this story's own diff — medium → patch.** Verified: `:30` still asserts "Exact JDK 25 build pinned (toolchain-level refusal/warning off-pin)" — dropped by owner decision the same day (DEPLOY-014 marker, contract page, spec change log) — and `:7`/`:11` say Epic 5 is "still backlog with no stories sliced" while this diff flips 5-1 to in-progress. A later Epic-5 story consuming this context could resurrect the dropped guard. Fixed: dated amendment block added naming both superseded passages (pointer to DEPLOY-014 + the tracker).
- **[B6] T1's Enable-Preview inertness proof is unrecorded/unreproducible — medium → rejected (fix edits this build's spec).** The decision basis (controlled minimal-jar boot, runtime-image string scan, real packaged boot with the attribute present) exists only as prose in the change log and the `build.gradle.kts` comment; its natural home — the spec's `## Implementation Notes` — is this build's spec. Rejected per the rule. Owner flag: worth a dated experiment record outside the spec at flip time.
- **[B7] Operator contract page: floor vs closed set, and where the artifact lives — medium → patch.** Operators had no rule on additional flags: an operator could legally add `-Xmx8g` to one shape only, reintroducing the drift FR-DEPLOY-1 exists to prevent. The frozen intent ("ONE flag set … neither deploy shape authors its own flags … the two shapes must not drift") admits exactly one reading — minimum set + additions mirrored across both shapes. Fixed: the pinned-set section states the floor+mirror rule and the artifact location (`proxy/build/libs/proxy.jar`, `./gradlew :proxy:bootJar`).
- **[B8] DEPLOY-004 marker misstates the ZGC-introspection deferral reason — low → patch.** "Not reachable from outside a subprocess (no management port)" is false — the smoke scrapes the child's `/metrics`, and collector identity rides the gc-labeled `jvm_gc_*` timer series; the honest blocker is the lazy-family timing nondeterminism (first GC notification), not reachability. Fixed: marker reworded so the Docker-half story doesn't inherit a false constraint.
- **[B10] Binder set boundary (`ClassLoaderMetrics`/`FileDescriptorMetrics`) undocumented — low → patch.** T4's ratified five-family set silently omits two Boot-standard binders with no recorded rationale — recreating, one story later, the exact undocumented-exclusion gap the `ResourceMetrics` amendment just closed. Fixed: one sentence in the `ObservabilityConfig` javadoc naming the deliberate boundary (binding them is open scope, not an oversight).
- **[B11] AC 5 asserts more walk sequence than the packaged row pins — low → rejected.** The packaged row pins summary < couple < drain-WARN < clean exit (the drain's ordered evidence); the walk's full step order is pinned by the 4.3 in-JVM suites on the same code path; the offered remedies either edit this build's spec or duplicate 4.3 breadth inside the subprocess row. Rejected per the low rule.

## Design Notes

- No launch configuration travels in the jar manifest at all (corrected at T1, 2026-09-10): the pinned JDK launcher honors only Add-Exports/Add-Opens/Enable-Native-Access from manifests — there is no Enable-Preview arm, and `-XX` flags never travel either. Under the bare-`java -jar` decision the contract page is the single home for the entire flag set including `--enable-preview`; the jar side carries structure only (pinned main class, stable archive name).
- The flag set must be ONE shared definition (amended 2026-09-10, owner rule: no Java tests over *.md docs) — two kept-in-step representations: the contract page (operator documentation) and the T5 Java-side launch constant (the executable definition, its javadoc pointing at the page). No machine pin reads the page; coherence is a review-time duty — a flag change is a story that touches both, and the future Docker entrypoint story pins its own parity against the same set.
- Memory interlock: yml defaults derive ~6 GiB budget with `budget-check: fail`; the contract's `MaxDirectMemorySize` must satisfy the AD-30 check against those SAME defaults (pick the value once, assert it in the smoke — do not fork yml).
- The subprocess smoke needs the jar built before tests run — wire the dependency in Gradle, and mind the incremental-run trap: the smoke must re-run when the jar changes.

## Verification

**Commands:**
- `./gradlew clean build --console=plain` -- expected: GREEN, including the new packaged-smoke and matrix rows (a "source-pin" docs-scan row was dropped by the 2026-09-10 owner rule — no Java tests over *.md docs; the build-pin rows were dropped by the 2026-09-10 owner decision below).
- `./gradlew :proxy:test --tests '*Packaged*' --tests '*Banner*' --console=plain` -- expected: GREEN after `clean` (the `*LazyInit*` selector was dropped by the owner decision below — documented-only, no test).

**Manual checks (if no CLI):**
- From `proxy/build/libs`: `java -jar` the boot jar with the documented flag set and a reverse-B arg set against a stub SMSC; observe the JSON startup line, one relayed bind, binder gauges in a `/metrics` scrape, and clean SIGTERM shutdown.
