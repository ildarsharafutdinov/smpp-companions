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

## Deferred from: story-1-2-smpp-3-4-codec (T1 — command-id source-of-truth, 2026-07-27)

- **RELAY-026 three-way max-frame constant assertion → Story 1.3** — T1 shipped the
  `MaxCommandLengthContractTest` stub pinning `SmppCommandIds.MAX_COMMAND_LENGTH == 65536` (AD-30).
  The full contract — codec-constant ≡ future `MaxDirectMemorySize` formula input
  (`max_frame × max_inbound_depth × concurrent_pairs × safety_factor`) ≡ `companion.*` config default
  all referencing ONE constant — lands when Story 1.3 owns the config keys + formula. (AC4 / RELAY-026.)
- **Planning-doc literal correction pending** — `test-coverage-scenarios.md` CODEC-026 (:221) and
  CODEC-029 (:241) still assert `bind_transceiver = 0x0F` / `0x8000000F` (the `ESME_RINVSYSID` *status*
  code, not a command_id). Story 1.2 implemented the spec-correct `0x09` / `0x80000009` (verified vs
  `docs/SMPP_v3_4_Issue1_2.pdf` §5.1.2 + the jSMPP oracle, CODEC-031). Correct the catalog literals at
  the next planning-docs pass. Not code-blocking.

## Deferred from: code review of 1-2-smpp-3-4-codec (T3 — bind parser + encoder, 2026-07-29)

- **CODEC-024 P2 password `toString()` leak deferred to T6** — `SmppBindRequest` is a `record`, so its
  auto-generated `toString()` renders every component, calling `AsciiString.toString()` on the password
  (which caches a surviving `String`). Logging the PDU object (a plausible relay debug/error path) would
  leak it, and it would FAIL the deferred CODEC-024 P2 "no `String` from password octets" bytecode scan.
  The `AsciiString` password type is the user's 2026-07-28 override (kept); the fix — override
  `SmppBindRequest.toString()` to redact the password — is deferred to T6's CODEC-024 P2 enforcement.
  (Decision at T3 code review 2026-07-29.) [`codec/src/main/java/smpp/companion/codec/bind/SmppBindRequest.java:49`]

## Deferred from: code review of 1-2-smpp-3-4-codec (T4 — golden-vector corpus, 2026-07-29)

- **Golden negative vectors are not a biting oracle — the `CODEC-…` reject tag is never tied to the bytes.**
  `GoldenVectorCorpusTest` skips `assertWellFormedBindPdu` for negatives (`if (!negative)`), so a negative's bytes are
  parsed and discarded; the reject tag is checked for shape only. 2 of 5 negatives (`negative_unterminated_string`,
  `negative_body_shorter_than_fields`) are length-self-consistent with a bind-family `command_id`, so they would pass as
  valid positives if their ` ; reject: ` tag were dropped, and the framer-stage negatives (CODEC-005/008/009) have no
  bite-home in the golden oracle (`SmppFrameDecoderTest` proves those reject paths with its own hand-rolled bytes, not
  the golden vectors). Latent — the vectors are correct today; AC5's literal "tagged with its expected reject outcome" is
  met. **User decision 2026-07-29: defer to T5** — a T5 codec-conformance test will feed each golden negative through the
  real decoder + jSMPP and verify each rejects as tagged (strictly stronger than T4 structural assertions; requires a
  deliberate negative-reject test alongside CODEC-031, which is positive-only field-equality today).
  [codec/src/test/java/smpp/companion/codec/golden/GoldenVectorCorpusTest.java:70-93]
  **✅ RESOLVED 2026-07-30 (Story 1.2 T5):** `BindConformanceTest.negativeVectorRejectsAsTagged` (CODEC-033) now
  feeds every golden negative through the real `SmppFrameDecoder → SmppCodec` pipeline and asserts each rejects/
  awaits exactly as tagged — framer-reject (CODEC-005/008), await (CODEC-009), parser-reject (CODEC-021/022); no
  negative surfaces a typed PDU. (The loader code cited above moved to `GoldenVectors.java` in T5.)

- **No independent per-vector `command_id` pin in the golden loader — membership-only via `SmppCommandIds.isBindFamily`.**
  `GoldenVectorCorpusTest` asserts each positive vector's `command_id` is bind-family but does not pin the specific id
  expected for the named PDU (e.g. that `bind_transceiver_*` carries `0x09`). Deliberate T4 trade-off: it still catches
  the `0x09`↔`0x0F` constant drift (a vector encoding `0x09` would fail `isBindFamily` if the constant drifted to `0x0F`);
  only a wrong-but-bind-family id would slip. Closed by T5's jSMPP decode oracle (CODEC-031), which decodes each vector
  field-by-field and keys on `command_id`. [codec/src/test/java/smpp/companion/codec/golden/GoldenVectorCorpusTest.java:124]
  **✅ RESOLVED 2026-07-30 (Story 1.2 T5):** CODEC-031 (`BindConformanceTest.codecDecodeAgreesWithJsmpp`) decodes
  each golden vector via jSMPP and asserts the `command_id` (and every field) per vector.
- **`bind_transmitter_resp` (command_id `0x80000002`) has no positive golden vector — 5 of 6 `BIND_FAMILY` ids covered.**
  The corpus covers `0x01`/`0x02`/`0x09` (requests) and `0x80000001`/`0x80000009` (responses) but not `0x80000002`.
  The three bind-response ids parse identically (system_id C-octet + optional opaque TLVs) through one decode branch,
  so there is no untested code path; AC5 does not mandate one vector per id, and a 12th vector would be a near-no-op
  against an already-covered path. Add for 6-id symmetry only if desired. [codec/src/test/resources/golden-vectors/]

## Deferred from: code review of story-1-2-smpp-3-4-codec (T7 — JMH microbench, 2026-08-02)

- **PERF-004 (`-prof gc`) is not reproducibly wired — a one-shot manual measurement reverted from the
  committed build.** AC8/PERF-004 requires "`-prof gc` confirms per-op allocation is controlled." The
  committed `jmh {}` block (`proxy/build.gradle.kts:47-53`) sets only `jmhVersion`/`includeTests` — no
  `profilers = [gc]` line — and `CodecMicrobenchmarks` carries no `@Profiler` override (JMH gc profiling
  is CLI/plugin-config-driven, not annotation-driven). The Dev Record confirms `-prof gc` was added
  temporarily to record encode 172.3 B/op, decode 448 B/op, frame 104 B/op, then REVERTED "so default
  throughput runs stay clean"; a fresh `./gradlew :proxy:jmh` yields throughput only and does not
  reproduce the PERF-004 allocation evidence, so a future regression inflating per-op allocation would
  not be surfaced by re-running the committed benchmark. Mild: PERF-006's counting-allocator unit guard
  (`CodecAllocationGuardTest`, PR-tier `:codec:test`) is the durable substitute for the encode path, and
  the Dev Record is transparent about the revert + the substitute. **Deferred:** the no-profilers config
  is a deliberate, documented tradeoff (clean nightly throughput runs); permanently re-wiring `-prof gc`
  (e.g. `profilers = ["gc"]` in the `jmh {}` block, or a documented `./gradlew :proxy:jmh -Pprof=gc`
  invocation) is a design choice, not an unambiguous patch. (Decision at T7 code review 2026-08-02.)
