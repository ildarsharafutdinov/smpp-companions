# Deferred Work — smpp-companions

Tracks real-but-deferred items surfaced during review. Not blocking; revisit at the noted story/epic.

## Deferred from: code review of story-1-1-gradle-two-module-substrate-and-ci-scaffold (2026-07-24)

- **AD-30 config formula-inputs deferred to Story 1.3** — `max_frame` / `max_inbound_depth` / `concurrent_pairs` / `safety_factor` not added in 1.1; the config-matrix story (1.3) will own all `companion.*` keys together. (Decision at code review 2026-07-24.) [Dev Notes AD-30; application.yml; CompanionProperties.java]
  **✅ RESOLVED 2026-08-03 (Story 1.3 T2/T5, simplified):** the three tunable AD-30 inputs
  (`max-inbound-depth`/`concurrent-pairs`/`safety-factor`) land in `application.yml` under
  `companion.memory.*`; the pure `MemoryBudget.compute(...)` formula is implemented (AC5).
  `max-frame`/`max-command-length` are NOT config keys — they ARE `SmppFrame.MAX_COMMAND_LENGTH`,
  referenced directly (RELAY-026 single-source; guarded by `Relay026ConstantContractTest`).
- **CODEC-039 / SEC-090 ArchUnit rules have no positive control today** — scaffold form accepted by AC3/AC7 ("locks the boundary before code exists"); SEC-090 (PKIX / `javax.net.ssl`, not just `sun.security`) tightens in Epic 3. [codec/proxy ArchUnit tests]
- **`--enable-preview` COMPILE/RUN not runtime-verified** — wiring present in `smpp.java-conventions`; only the test-JVM path is asserted. Future TestKit compile-arg hardening. [proxy/src/test/.../bootstrap/EnablePreviewArgTest.java]
  **↳ 2026-08-17 refresh (2.2 code review F2):** the COMPILE half is superseded by Story 2.2 T1's
  compiler-enforced gate (`PreviewFeatureCompileGateTest`). The RUN half (`bootRun`/`JavaExec`) remains
  ungated by owner-approved T1 deviation — ledgered below under the 2.2 review heading.
- **`CompanionProperties` has no `tls` / `tls.protocols` null guards** — only `role` is fail-fast-guarded (AC9's one-smoke scope); a tls-absent NPE is a Story 1.3 concern. [proxy/src/main/java/.../config/CompanionProperties.java]
  **✅ RESOLVED 2026-08-03 (Story 1.3 T1):** `tls` is `@NotNull` (clear message) and the class-level
  `CompanionConfigValidator.validateTls` null-guards `tls`/`protocols` before deref — a missing `tls`
  block fails fast with a clear message, not an NPE.
  **⚠️ Attribution correction (2026-08-06 audit):** this "RESOLVED 2026-08-03 (T1)" marker was FALSE at
  the 78e4ff6 merge — Story 1.3's own 2026-08-04 code review (HIGH finding) proved `validateTls` did NOT
  null-guard at merge (it NPE'd on an omitted `companion.tls.*` block). The guard was re-added in the
  2026-08-04 review fix and is retained through the 2026-08-06 pre-pass refactor (still the root-level
  `@NotNull` blind-spot guard, mutation-verified LIVE by `omittedTlsBlockRefusesCleanly`). The ledger
  credited T1 for a guard T1 had removed — a re-occurrence of the false-RESOLVED failure mode; recorded
  here so the timeline is not misread as continuous correctness since 2026-08-03.
- **`contextCloseStopsLifecycleWithinGracefulTimeout` 30s-ceiling assertion is trivial** — stop()-ran IS checked (`isRunning` false); a meaningful upper-bound test lands with the AD-22 body in Epic 4. [proxy/src/test/.../bootstrap/BootstrapLifecycleTest.java]
- **`BootstrapLifecycleTest` non-web assertion is tautological (forces `.web(NONE)`)** — AD-16 is guarded by OBS-013 + `spring.main.web-application-type: none`; the class-name check can't detect classpath drift. Cosmetic. [BootstrapLifecycleTest.java]
- **`CompanionLifecycle` phase ordering (default `MAX_VALUE` stops first) once a 2nd `SmartLifecycle` lands** — single bean today; Epic 4 manages phases. [proxy/src/main/java/.../bootstrap/CompanionLifecycle.java]
  **[RESOLVED 2026-08-15 (Story 2.2 T6): both lifecycles now carry EXPLICIT phases —
  `ProxyCompanionLifecycle.APP_PHASE = 0` and `RelayServerLifecycle.RELAY_ACCEPTOR_PHASE =
  APP_PHASE + 1000` — so the relay acceptor STOPS first (AD-22 step 1) instead of two default-phase
  beans racing. Pinned by `RelayServerLifecycleTest.relayAcceptorStopsBeforeTheAppLifecycle` (proven
  RED when the `getPhase()` override is removed — mutation M-E). The AD-22 7-step drain BODY itself
  remains Epic 4, as does any further phase management it needs.]**
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
  **✅ RESOLVED 2026-08-03 (Story 1.3 T5, simplified):** the proxy-side `Relay026ConstantContractTest`
  guards (AST scan) that proxy main references `SmppFrame.MAX_COMMAND_LENGTH` with no magic `65536`
  literal. `max-frame`/`max-command-length` are NOT config keys (they can only be the codec constant —
  removed as redundant); the formula references the constant directly. The codec stub is the
  constant-side anchor.
- **Planning-doc literal correction pending** — `test-coverage-scenarios.md` CODEC-026 (:221) and
  CODEC-029 (:241) still assert `bind_transceiver = 0x0F` / `0x8000000F` (the `ESME_RINVSYSID` *status*
  code, not a command_id). Story 1.2 implemented the spec-correct `0x09` / `0x80000009` (verified vs
  `docs/SMPP_v3_4_Issue1_2.pdf` §5.1.2 + the jSMPP oracle, CODEC-031). Correct the catalog literals at
  the next planning-docs pass. Not code-blocking.
  **✅ RESOLVED 2026-08-03 (Story 1.3, opportunistic):** `test-coverage-scenarios.md` CODEC-026/CODEC-029
  literals corrected to `0x09` / `0x80000009`.

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

## Deferred from: story-1-3-config-matrix (T5 — AD-30 config half + RELAY-026, 2026-08-03)

- **AD-30 live `ByteBufAllocatorMetric` startup self-check → Epic 2 (decision D1)** — AD-30 bundles two
  assertions: (1) the static RELAY-026 one-named-constant scan (SHIPPED in 1.3 — `Relay026ConstantContractTest`);
  and (2) a startup self-check reading LIVE `MaxDirectMemorySize` via `ByteBufAllocatorMetric` ≥ the
  computed `MemoryBudget` and failing fast (AD-17) if under-budget. The shared `PooledByteBufAllocator`
  (AD-21) + relay wiring land in Epic 2 — they do not exist in 1.3, so there is no live allocator metric
  to read. 1.3 ships the config inputs + formula + the static scan NOW; Epic 2 mounts the live
  self-check when the allocator exists (closes the JVM-flag gap the static scan cannot reach, per AD-30).
  (Decision D1 at Story 1.3 dev-story 2026-08-03.) [proxy/src/main/java/.../config/MemoryBudget.java; ARCHITECTURE-SPINE.md AD-30:235–238]
- **AD-34 per-egress-context cipher intersection → Epic 3 (decision D2)** — AD-34 names "EVERY context
  (ingress server + every egress target + the IdP mTLS client context)" for the empty-intersection
  fail-fast; those `SSLContext`s are built in Epic 3 (`proxy/security/`, package-info-only today). 1.3
  ships the config-side TLS floor (SEC-061) + a config-time intersection against a JDK-default
  `SSLContext`'s supported suites (proves the configured set is non-empty and JDK-supported); the
  per-egress-context intersection DEFERRED to Epic 3 when those contexts exist. 1.3 deliberately does
  NOT half-build SSLContexts in config validation (that would pre-empt Epic 3's SEC-087/088/089 runtime
  vectors). (Decision D2 at Story 1.3 dev-story 2026-08-03.) [proxy/src/main/java/.../config/CompanionConfigValidator.java; ARCHITECTURE-SPINE.md AD-34:259–262]

## Deferred from: code review of 2-1-security-port-contract-validation-slice (2026-08-10)

> All six are LOW-severity hardening in the **test-tier `RopcSlice` adapter** (`proxy/src/test`), owned by the **Epic 3
> production ROPC adapter**. The ratified `proxy/security/` port contract (AC8 immutable henceforth) is clean; these do
> not affect the port shape. Deferred because Epic 3 replaces this slice behind the unchanged port and should ship the
> production-grade version of each.

- **HTTP 429/404/403 → `DenyInvalid` semantic misclassification** [`RopcSlice.java:253`] — conforms to the story's
  explicit AD-11 refinement ("4xx → DenyInvalid"); both deny (identical fail-closed outcome); only the permit label
  differs. Semantic refinement (429=rate-limit, 404=config error, 403=authz → arguably `DenyIndeterminate`) belongs to
  the Epic 3 production verdict mapping. (Code review 2026-08-10.)
- **`execute()` after `close()` leaks the admission permit + skips zeroize** [`RopcSlice.java:117-126`] — use-after-close:
  `tryAcquire()` succeeds then `execute()` throws `RejectedExecutionException` outside the task's `try/catch` → permit
  permanently leaked (silent permanent saturation after `maxInflight` such calls) + password not zeroized. Requires
  use-after-close; trivial `try/catch(RejectedExecutionException){ release(); zeroize(); }` hardening for Epic 3.
- **JWT `typ` header not validated** [`RopcSlice.java:183-196`] — RFC 8725 §3.9 defense-in-depth against token-type
  confusion; signature + iss/aud/exp/nbf are already checked (no `Allow` leak). Not an AC2 requirement. Epic 3 hardening.
- **`AlwaysAllowBindCredentialVerifier` does not zeroize the password** [`AlwaysAllowBindCredentialVerifier.java:20-22`] —
  the stand-in never inspects the secret (always-allow, documented no-op `cancelHttp`); AC5 "on adjudication completion"
  ownership (verifier vs caller/relay) is ambiguous. Resolve with `relay/` wiring / Epic 3.
  **[RESOLVED 2026-08-15, Story 2.2 T7: ownership = the CALLER (the relay), per the T7 subtask.**
  `BindInterceptor` owns `cred.password().zeroize()` on every path — the verdict continuation's `finally`
  (Allow/Deny/exceptional) AND every teardown arm (`cancelAndWipePending()`: retry-bind, ingress/egress
  death, violation — idempotent, RELAY-005-safe), deliberately NOT at `verify()`-return (the Epic-3 ROPC
  adapter reads the secret while its future is pending; `SmppBytes` copies C-octet fields, so the wipe
  can never corrupt the AD-14 forwarded frame). Proven: the Allow-path zeroize assert
  (`BindInterceptorTest.allowForwardsTheOriginalFrameVerbatimToTheConfiguredEgress`) + the
  deny/teardown-path asserts, with mutation N2 (finally-zeroize removed) RED on exactly the Allow-path
  biter.]
- **`close()` does `shutdownNow()` with no `awaitTermination`** [`RopcSlice.java:353-356`] — cosmetic for the throwaway
  test slice (pool-task `finally` blocks still eventually run on daemon VTs); Epic 3 production adapter should drain
  (`awaitTermination` + fail-closed-log on timeout).
- **`asyncRefreshJwks` bypasses the admission gate + unconditionally nulls the cache** [`RopcSlice.java:312-321`] —
  submitted without `tryAcquire` (can exceed `maxInflight` under kid-rotation) and `jwksCache.set(null)` runs before
  re-fetch succeeds. Fail-closed holds; undermines the bounded-pool/cache invariants under the exact load the cache
  smooths. Epic 3 hardening.

## Deferred from: code review of 2-2-stateless-relay-and-a1-session-affinity-smoke (2026-08-12)

- **App-wide stance on `spring.main.lazy-initialization=true` is undecided** (added 2026-08-15, T5b review
  round 2) — with lazy init enabled, NO bean eagerly instantiates: the AD-30 self-check, the AD-17
  bind-time matrix, and (reproduced on Spring Boot 4.1.0) even a ZERO-BRANCH config boot silently instead
  of refusing. Not a T5b regression (the exposure pre-dates it and is app-wide), but the product's
  fail-closed posture (AD-17) is currently opt-out-able by a single Spring flag no artifact addresses.
  Decide app-wide at the architecture/deploy tier (Epic 5): refuse lazy init, or document it as an
  operator-accepted deviation. Not cell-scoped hardening — pinning only the self-check bean eager would
  leave the AD-17 matrix equally bypassed.

- **`DirectMemoryBudgetValidator.validate()` silently passes negative-equal inputs** (e.g. `validate(-1,-1)`)
  [`proxy/.../relay/netty/DirectMemoryBudgetValidator.java` — the `validate(long, long)` method] — latent: the sole
  caller feeds a non-negative budget from `MemoryBudget.compute` (which guards `product < 0`) and a ceiling from
  `liveDirectMemoryCeiling()` (explicit `-XX:MaxDirectMemorySize` parsed via `ManagementFactory`, else
  `Runtime.maxMemory()` — NOT `VM.maxDirectMemory()`, removed by Review Decision A). Note the parsing-based read
  can yield 0 (explicit `=0`), which strengthens the proposed guard.
  *(Corrected 2026-08-15, review round 2: the entry previously cited the superseded `VM.maxDirectMemory()`
  mechanism and a stale line anchor from the pre-Decision-A implementation.)*
  The method is a public static utility with no documented precondition; a `budget < 0 || liveCeiling <= 0` guard
  would convert the silent pass into a fail-fast. Upstream-guarded today, so not blocking.
- **No mechanical guard forces the Epic-3 widening of the mode-b self-check**
  [`proxy/.../relay/netty/DirectMemoryBudgetStartupCheck.java:34-44`] — `afterPropertiesSet()` no-ops unless
  `reverse.mode-b` is set (slice-correct for Story 2.2). The widen-to-forward/mode-a/c requirement lives on the
  load-bearing Javadoc/dev-notes, but no test/tracker bites if Epic 3 wires a non-mode-b relay allocator without
  widening the guard (AD-30's JVM-flag gap reopens for that cell). Proposed ArchUnit guards were unsound (the
  allocator `@Bean` is unconditional → would false-positive on every forward boot). Track via a sprint-status
  `action_item` anchored to the Epic 3 relay story.

  **✅ RESOLVED 2026-08-15 (Story 2.2 T5b, operator decision):** the self-check is now UNCONDITIONAL — the
  mode-b guard is gone; the check runs for every role×mode cell (every cell relays; the AD-17 constructor
  guarantees exactly one cell). No Epic-3 widening will ever be needed. The mechanical bite exists:
  `DirectMemoryBudgetStartupCheckTest.forwardAWithHugeBudgetRefusesToStart` boots a forward.mode-a full
  context with an over-ceiling budget and asserts the refusal — proven RED when the mode-b guard was
  reintroduced (mutation M2). Over-budget severity now follows `companion.memory.budget-check: fail | warn`
  (default `fail` — unchanged behavior; `warn` = loud accepted-risk banner + start). Spine AD-30 amended;
  see the `.memlog.md` 2026-08-15 entry.

## Deferred from: code review of 2-2-stateless-relay-and-a1-session-affinity-smoke (T6, 2026-08-15)

- **T6 wiring seam (`.childHandler` / `applyToIngress` call sites) has no RED-on-neuter pin**
  [`proxy/.../relay/netty/RelayServerLifecycle.java:87-88`] — dropping either line from `start()` keeps the
  whole suite GREEN: the full-boot test's TCP-connect probe cannot see an empty pipeline, `AUTO_READ=false`
  means nothing reads pre-T8, and the `ServerBootstrap` is a local variable (no structural pin either).
  Behaviorally unobservable until handlers exist. Bites from T7 (`BindInterceptor`) / T9 (the A-1 smoke
  drives real PDUs through the acceptor); **T7's review checklist must confirm a dropped wiring line goes RED.**
- **`RelayServerLifecycle.stop()` quiesces the shared event loop at acceptor phase (RELAY_ACCEPTOR_PHASE)**
  [`proxy/.../relay/netty/RelayServerLifecycle.java:113-115`] — from T7 every per-bind egress connection
  registers on the SAME `relayEventLoopGroup` bean, so acceptor-stop terminates all established legs before
  any app-phase drain could run; the javadoc's "owns only the acceptor window" vs "quiesce the shared event
  loop" tension resolves only when Epic 4's AD-22 7-step drain re-authors this stop body. Spec-mandated today
  (the T6 checkbox pins exactly this stop: close acceptor → `shutdownGracefully` awaited); recorded so T7
  review + Epic 4 own the ordering consciously.
- **`shutdownGracefully()` default 2s quiet period costs every mode-b context close ≥2s**
  [`proxy/.../relay/netty/RelayServerLifecycle.java:115`] — no-arg = 2s quiet / 15s cap, awaited
  `syncUninterruptibly()`: ~+8-10s across the suite's mode-b boots (full suite 47s), 2s per production
  shutdown, up to ~17s of the 30s per-phase window. A documented deliberate choice (javadoc cites Netty's
  defaults); becomes a mini-drain feature once in-flight PDUs exist. Revisit with the Epic-4 drain work
  (or pass an explicit 0-quiet / shorter window then).
- **Wildcard listener posture: the acceptor binds `0.0.0.0` with no bind-host key, connection cap, or idle
  timeout** (owner decision 2026-08-15, T6 code review) [`proxy/.../relay/netty/RelayServerLifecycle.java:89`;
  `ProxyCompanionProperties.Bind` is port-only] — accepted channels are inert-but-never-reaped until T7/T8
  (`AUTO_READ=false`, no handler): an unauthenticated, unbounded socket sink on every interface for a real
  mode-b boot. **Deferred to Epic 3**: the slice is in-JVM/loopback until then; Epic 3 adds bind-host +
  listener hardening (including the connection-cap decision) when it wires the production acceptors.
  **↳ 2026-08-17 refresh (2.2 code review F13):** the "inert" rationale is stale as written — post-T7/T8 an
  uncapped accept creates a LIVE coupled pair (registry entry + adjudication + SMSC egress connection + pooled
  buffers per bind), not an inert socket, so the unbounded-accept sink now allocates real per-connection
  resources. The Epic-3 deferral itself STANDS (owner 2026-08-15); this note only sharpens its weight — the
  connection-cap decision should account for coupled-pair memory residency (AD-30), not just socket count.

## Deferred from: owner notes during Story 2.2 T7 + owner-FIXME round (2026-08-16)

- **Refactor `BindInterceptor` to an explicit Strategy/state-object shape** (owner note 2026-08-16)
  [`proxy/.../relay/BindInterceptor.java`] — the interceptor's control flow is an implicit state machine
  branched in-method (`onRequest`/`onVerdict`/`channelInactive`/`exceptionCaught` each re-derive the state
  from the registry). Candidate state set, as the owner named it plus what the code actually encodes:
  `not-registered` (no `ConnectionRegistry` entry — before the first bind / after teardown),
  `not-spliced` (entry exists, handshake in flight — itself three sub-phases today: ADJUDICATING while
  `pendingVerdict != null`, CONNECTING between the Allow verdict and the egress listener, and
  AWAITING-BIND_RESP once `EgressLeg` is attached but `answered == false`), `spliced` (the AD-25 flip —
  T8's plane), and the transient terminal `tearing-down` (the entry's CAS mark). `EgressLeg.answered` is a
  per-leg mini-state of the same machine. A Strategy refactor (per-state handler objects replacing the
  if/else chains) would make illegal transitions unrepresentable instead of comment-enforced.
  **Revisit AFTER T8 lands** — T8 owns the flip and the post-flip plane, so the complete state set only
  becomes visible then; refactoring now would churn twice. Design constraint to reconcile: AD-32
  deliberately made the REGISTRY ENTRY the "bind in flight" predicate ("the entry's state, not a separate
  boolean") because the EgressLeg/T8 handlers and the teardown racers all share that one cross-handler
  truth — an explicit per-interceptor state field must either derive from it on every read or risk
  drifting from it (state duplication across the two legs + the continuation). Behavior-preserving bar:
  the 10 `BindInterceptorTest` behaviors (RELAY-004, both AD-33 arms, RELAY-002c, AD-14 verbatim,
  fail-closed, late-verdict no-op) stay green unchanged.

## Deferred from: owner note during Story 2.2 T8 review (2026-08-16)

- **Unify the pair-state vocabulary on `couple`-variants; retire `splice`/`flip` as state terms**
  (owner note 2026-08-16, T8 review) — today the CODE predicate is `ConnectionEntry.spliced()` /
  `flipSpliced()` (the AD-25 flag, the only runtime state) while the PROSE mixes three vocabularies:
  "coupled pair" (the ingress↔egress pairing, AD-8/AD-9 — broader than the flag: a pair is coupled
  from optimistic registration, RELAY-006), "pre-couple/post-couple" (the window, ≡ pre-flip/post-flip
  — the same instant), and "the flip"/"the splice" (the transition). Owner direction: ONE vocabulary,
  `couple`-variants (`coupled()` / `couple()` / pre-couple / post-couple), avoiding `splice`/`flip` in
  code and relay prose. **Rename blast radius:** the `spliced` field + both methods
  [`proxy/.../relay/ConnectionEntry.java:52,61-74`]; javadoc/comment prose across `RelayHandler`,
  `BindInterceptor`, `ConnectionRegistry`, both initializers; test names + helpers
  (`RelayHandlerTest.flipsOnlyOnDecodedRok…` / `coupleAndFlip()`, `ConnectionRegistryTest`'s
  `flipSpliced` CAS pins, `RelayPipelineInitializersTest`); the 2-2 story file's prose. **Two decisions
  the round must make first:** (a) the BINDING spine itself speaks splice/flip — AD-25's rule text
  ("the splice flag is flipped by exactly one unit"; the AD is literally titled "Bind→splice
  transition state machine") and AD-2's title ("coupling + framed-ByteBuf splice") — so renaming only
  the code re-creates the same code/prose split one level up; a full unification needs in-place spine
  amendments + `.memlog.md` entries (the contract-amendment discipline). (b) Whether the SEEDED
  `SpliceObserver` seam + its 4 methods rename too (`onFramedPdu` is already couple-neutral; the type
  name is not) — that is a ratified-contract change rippling through ARCHITECTURE-SPINE.md AD-27,
  `epics.md`, the TEA docs, and the readiness report (the 2026-08-11 `onByteTransfer` drop is the
  precedent for the amendment path). **Timing:** a standalone mechanical round AFTER Story 2.2
  completes (T9–T11 + their reviews still cite the current names; renaming mid-story churns review
  diffs twice) and BEFORE Epic 3 widens the relay surface; re-run the full mutation pass after — a
  rename can silently de-target RED-on-neuter biters (N1's neuter site is the `flipSpliced()` call).
  Pairs naturally with the T7-noted Strategy/state-object refactor above — do them together so the
  state names are chosen once.
- **Split `RelayHandler` — it is two direction-dictated state machines in one class** (owner note
  2026-08-16, T8 review) — the single class branches on its `direction` field at every
  pre-couple decision point, encoding two different per-leg machines: the EGRESS handler is the
  flip reader + AD-32 classifier (decoded ROK `bind_resp` → flip; `generic_nack` check on the one
  opaque header read → case-4 verbatim forward; other violations → close, letting `EgressLeg`'s
  AD-33 collapse run), while the INGRESS handler is the violation delegator (pre-couple non-bind →
  `BindInterceptor.teardownForPreCoupleViolation`, the cancelHttp+zeroize seam). Only the POST-flip
  plane is genuinely symmetric (opaque splice, write-completes-gates-read, low-water re-arm,
  pair teardown, exactly-once close). Branch sites today: `RelayHandler.channelRead` (the
  `direction == EGRESS && getInt(4) == GENERIC_NACK` conjunct and the `direction == INGRESS`
  delegation arm) and `peerOf()`. **Candidate shape:** two classes (`RelayIngressHandler` /
  `RelayEgressHandler`) over one shared post-couple splice component — the initializers already wire
  per-leg instances, so the split has ZERO wiring cost (`RelayIngressInitializer` /
  `RelayEgressInitializer` each instantiate their own), and it mirrors T7's own answer to the same
  asymmetry (the nested per-leg `BindInterceptor.EgressLeg`). **Constraints for the round:** the 12
  `RelayHandlerTest` behaviors stay green unchanged-in-intent (the real-pipeline discipline means the
  harness itself may need the class split mirrored); `RelayPipelineInitializersTest` pins
  `RelayHandler.class` by name and must be re-pointed deliberately (not silently); the
  `CLOSE_REASON`/`CLOSE_FIRED` attribute keys are class-scoped — two classes get two key namespaces
  (harmless: one handler per leg, but the marker init must move to both); the flip's structural
  single-site property (the ingress leg can never see a decoded `bind_resp`) should become
  structural-by-TYPE, which a split makes stronger — the flip call site exists only in the egress
  class. **Timing:** same combined post-2.2 / pre-Epic-3 cleanup round as the Strategy/state-object
  refactor and the couple-vocabulary unification above — all three touch the same cluster; do them
  once, together, with the full mutation pass re-run afterward.
- **Split `BindInterceptor` by ROLE — the forward and reverse bind-handshake roles are significantly
  different** (owner note 2026-08-16, T8 review) — today the interceptor is reverse.mode-b-ONLY by
  construction (the constructor refuses to build without `companion.reverse.mode-b.smsc`; every bind
  routes to the single configured egress, NO allow-list, NO routing table — the 2.2 slice scope), but
  the binding spine's FORWARD role adds materially different control-plane semantics when Epic 3
  wires it: the AD-29 1:1 routing table (`system_id` allow-list → the single egress target), the
  routing-miss deny arm (AD-11 fail-closed, AD-33-collapsed — this story explicitly deferred it to
  Epic 3 as "inapplicable to this reverse.mode-b slice"), per-target egress selection
  (`tlsContextId`, AD-34 per-egress cipher contexts), and forward-mode variants of the acceptor
  wiring. Growing the ONE class with `role ==` branches would fork every method; a split
  (per-role interceptors over the shared handshake skeleton — adjudication + `ScopedValue`
  `RequestContext`, the AD-33 deny synth, caller-owned zeroize, RELAY-004 retry-guard, the pinned
  teardown ordering) keeps each role's illegal states unrepresentable. **Enabler:** AD-17 guarantees
  exactly ONE role×mode cell per deployment, so `RelayIngressInitializer` can select the interceptor
  implementation at WIRING time — no runtime role branching anywhere on the hot path. **Split the
  DECISION from the EXECUTION:** choose the seam (shared base vs composed handshake component vs the
  queued Strategy/state-object shape) in the combined post-2.2 cleanup round, but EXECUTE the split
  when Epic 3's forward role actually lands — today a split yields a one-implementation strategy
  (speculative), and the state-machine refactor above is the better vehicle for the shared skeleton.
  **Bar:** the 10 `BindInterceptorTest` behaviors stay green unchanged-in-intent; the reverse.mode-b
  path must NOT grow an allow-list arm (2.2 AC2's scope note is slice-scoped, not contradicted);
  the RELAY-004/AD-33/zeroize pins are role-INDEPENDENT and belong in whatever shared skeleton
  survives. Related: `RelayServerLifecycle` carries the same mode-b-scoping question for Epic 3's
  acceptor widening.
- **Extract a `ConnectionEntry` STATE MANAGER — the handlers call it, it decides, it delegates the
  work back** (owner note 2026-08-16, T8 review) — today the pair's state machine is distributed
  across ~10 decision sites (`BindInterceptor.onRequest`/`onVerdict`/`denyAndTeardown`/
  `channelInactive`/`exceptionCaught`, `EgressLeg.channelRead0`/`channelInactive`,
  `RelayHandler.channelRead`/`channelInactive`/`exceptionCaught`) that each re-derive state from the
  registry entry and branch in-method; each handler knows the WHOLE machine. Owner direction: extract
  one class that MANAGES `ConnectionEntry` state — the handlers/interceptor CALL it, the MANAGER
  decides what to do, and DELEGATES the work back to the interceptor/handler (policy centralizes;
  the wire-effect mechanism — writes, closes, read-arming, `cancelHttp`, zeroize — stays in the
  handlers, which own the `ChannelHandlerContext`s). **Two implementation variants to weigh:**
  (1) a SINGLE manager covering both forward+reverse scenarios, vs (2) DISTINCT managers per role.
  Variant choice is the SAME decision as the `BindInterceptor` role-split note above at a different
  altitude — role split at the interceptor level vs at the manager level; treat them as ONE fork, not
  two. Mechanically, "delegates the work back" needs an executor-facing port (manager holds
  references to the interceptor/handler arms) OR the manager returns a sealed decision the caller
  executes — the latter avoids the circular manager↔handler dependency; record which when chosen.
  **Thread-bounding (the owner's explicit design axis): bound the code by the threads it rides.**
  Facts to design against: ALL entry/registry transitions today ride ONE Netty event loop per pair
  (AD-2 same-loop coupling — the per-bind egress `Bootstrap` groups on the ingress channel's loop),
  which is exactly why two CAS-once `AtomicBoolean`s + a `volatile` egress suffice (CAS only for the
  cross-leg/teardown race); the ONE off-loop entry point is the verdict continuation
  (`whenComplete` → `channel.eventLoop().execute(...)` hop) coming off the verifier's bounded VT
  executor (AD-5/AD-28 — `ScopedValue` `RequestContext` bound at verify-time, control plane). The
  extraction should make that confinement FIRST-CLASS: manager = event-loop-confined policy (like the
  handlers), with the continuation hop as its single off-loop entry; anything VT-side (adjudication
  kickoff) stays in the interceptor's control-plane half. **Two cautions:** (a) the POST-FLIP SPLICE
  is the hot path — every spliced PDU must remain a flag-read + forward, not a manager consultation
  (a virtual dispatch per PDU is a PERF regression Epic 6 would catch late; keep the manager on the
  handshake/teardown plane, or prove the indirection negligible); (b) AD-8 pins "the ONLY mutable
  runtime state is the ConnectionRegistry" — the manager must be POLICY over the registry's STORAGE,
  not a second state copy (the AD-32 rule "the entry's state, not a separate boolean" applies to the
  manager itself); absorbing the registry INTO the manager is an AD-8-adjacent restructuring that
  needs a spine note. **Timing + precedence:** same combined post-2.2/pre-Epic-3 round, and make this
  decision FIRST — it is the umbrella the Strategy/state-object, direction-split, and role-split
  notes fold into (they become "what the manager's executors look like"). **Bar:** the 10
  `BindInterceptorTest` + 12 `RelayHandlerTest` behaviors green unchanged-in-intent; RELAY-005/006
  idempotence + no-orphan pins survive; the CAS-once triggers (`onBindAccept` at the flip,
  `onConnectionClosed` exactly-once) stay exactly-once; RELAY-007 jcstress (nightly) targets the
  manager unchanged if the registry survives as storage.

## Deferred from: code review of 2-2-stateless-relay-and-a1-session-affinity-smoke (2026-08-17)

- **Relay-side adjudication-deadline enforcement (verdict-timeout arm) [F14|low]** — the relay computes and
  ships `companion.bind.adjudication-deadline: 4s` (fail-fast positivity guard included) but arms no timeout:
  its only consumer is `RequestContext.deadline` (`BindInterceptor.java:242-244`), so a never-settling verifier
  future pins the registry entry, the original bind frame, and the legacy client's socket until the client
  disconnects/rebinds/violates. Owner-deferred in story T7 honest-scope note (c) (2026-08-16, "the
  RequestContext deadline … is the verifier's budget"). Ledgered here under its own name because the catalog's
  RELAY-020 tag (`test-coverage-scenarios.md:435`) names a DIFFERENT scenario — post-Allow egress
  connect-refused no-hang — which T7 already implemented. Design fork when picked up:
  complete-exceptionally-at-deadline vs deny+teardown, and whether that obligates `VerdictRequest` to promise
  settlement on `cancelHttp()` (interlocks with review finding F7's frame-ownership question). Natural home:
  the later Epic-2 story / Epic 4 alongside RELAY-020/021 (story Out of scope :339).

- **Ingress-leg `bind_*_resp` handling [F1|medium]** — a decoded bind response arriving on the INGRESS leg is
  released and dropped (`BindInterceptor.java:188-197`): no AD-32 bare-close pre-flip, no splice post-flip
  ("never a silent drop", spine :80 / AC7 :136); no test covers either window. **Owner (2026-08-17): defer** —
  the drop is kept (it incidentally seals the client-forged-ROK flip window: a forwarded pre-flip ROK would
  flip the pair without SMSC consent via `Relayer.channelRead:126-137`, so any future fix must bare-close
  pre-flip, not forward); the AD-32 letter + post-flip splice question rides with RELAY-020/021 in the later
  Epic-2 story.
- **Verdict-future frame ownership on cancellation [F7|medium]** — the `whenComplete` continuation is the only
  releaser of the in-flight `req.originalFrame()` (`BindInterceptor.java:271-274`); the four teardown arms'
  `cancelAndWipePending` (:336-347) never releases it, and the ratified port (`VerdictRequest.java:26-30`) does
  not promise `future()` settles on `cancelHttp()` — a never-settling cancelled verdict leaks one pooled direct
  buffer per abandoned adjudication (also: `eventLoop().execute()` rejection during loop shutdown strands the
  closure). **Owner (2026-08-17): defer to Epic 3** — latent under AlwaysAllow (pre-completed future); decide
  port-amendment (promise settlement on cancel — touches the AC8 ratified-immutable port) vs relay-side
  ownership (release at teardown, CAS/flag against the onVerdict racer arm :289) when the ROPC adapter can
  actually strand a future.
- **Egress connect-phase bounding (blackholed SMSC) [F10|medium]** — the per-bind egress `Bootstrap` sets no
  `CONNECT_TIMEOUT_MILLIS` (`BindInterceptor.java:400-406`): a blackholed endpoint (SYN drop) hangs the legacy
  socket ~30s (Netty default, pinned 4.2.16.Final) while the 4s `adjudication-deadline` never bounds TCP
  establishment (~7.5x PERF-3's 2-5s fail-closed budget); RELAY-020-as-written (connect-refused, RST fails
  fast) passes without the option. **Owner (2026-08-17): defer** — folds into the RELAY-020/021 timeout work
  in the later Epic-2 story; ~30s worst case accepted for the plaintext test-tier slice.
- **`EGRESS_CONNECT_FAILED` / `BIND_REJECTED` CloseReasons never fire [F9|low]** — `denyAndTeardown`
  (`BindInterceptor.java:321-333`) stashes no reason and `ConnectionRegistry` clears the entry attr before
  close, so deny/connect-fail closes surface as `OTHER` (the other 5 dead values are documented
  not-fired-by-design in the 2.2 Debug Log :742-757). **Owner (2026-08-17): defer to Epic 4** — firing
  semantics decided when the metrics observer consumes the taxonomy (needs hoisting the RelayHandler-private
  CLOSE_REASON key `RelayHandler.java:83-84` + a deny-variant→value mapping; may amend the ratified
  not-a-must-fire-list contract).
- **`onFramedPdu` pre-couple firing vs seam contract [F11|low]** — the interface javadoc says "pre- or
  post-couple" (`SpliceObserver.java:30-36`) but the sole fire site is post-flip
  (`RelayHandler.java:197`); the AD-14 verbatim bind forward (`BindInterceptor.java:427`) and the `bind_resp`
  forward (:511) cross uncounted (deny-synthesis + generic_nack forward likewise). **Owner (2026-08-17): defer
  to Epic 4** — folds into the PDU-count metric semantics decision (fire at the handshakes — flips three pinned
  tests RED — vs amend the javadoc to post-couple-only).
- **RELAY-014 backpressure behavioral test (re-affirmed) [F16|low]** — the writability CONDITION and the
  `channelWritabilityChanged` low-water body (`RelayHandler.java:200,219-231`) have no behavioral test (the
  re-arm happy path IS exercised on real sockets — multi-roundtrip traffic needs it; the forward itself is
  unconditional). **Owner (2026-08-17): RELAY-014 deferral re-affirmed** (catalog
  `test-coverage-scenarios.md:405-409`); ledgered here so it stops living only in the story's Out-of-scope.
- **AC9/AI-8 RUN-half `--enable-preview` gate deviation [F2|low]** — owner-approved T1 deviation
  (`PreviewFeatureCompileGateTest.java:29-33`; story Completion Notes :961-967): the RUN wiring
  (`bootRun`/`JavaExec`) is intentionally ungated; COMPILE + TEST are compiler-enforced. **Owner (2026-08-17):
  ledger here** (this entry); AC9 text left as-is with the story Completion Note as the recorded deviation;
  the stale pre-2.2 ledger line refreshed (see the ↳ note above).

## Deferred from: code review of 3-2-oidc-ropc-bind-adjudicator (2026-08-19)

- **Hostless OIDC provider-url passes the scheme-only `isHttps` check [low|pre-existing]** —
  `https://` or `https://:8443` binds and boots; `CompanionConfigValidator.requireOidc`
  (proxy/src/main/java/smpp/companion/proxy/config/CompanionConfigValidator.java:295-297) checks
  scheme only, never `URI.create(...).getHost() == null`. 2.1-era guard re-hung on the reverse
  validators by story 3.2 T1 (not introduced there). T2's discovery/HttpClient build fails
  confusingly on the hostless URL — add the host check when T2 lands (story 3.2 Task 2) or 3.3.
  Found by code review 2026-08-19 (Edge Case Hunter layer).
  **✅ RESOLVED 2026-08-19 (Story 3.2 T2 user-directed FIXME pass):** `Oidc.providerUrl` is now
  URI-typed and `requireOidc` refuses hostless URLs at bind time (SEC-053/054 message,
  `sec053_hostlessOidcProviderUrlRefuses` binds the exact bad value); the discovery build no
  longer validates shape at all.

## Deferred from: owner note during Story 3.2 T2 FIXME pass (2026-08-19)

- **Evaluate an OIDC-discovery/parsing library to replace the hand-rolled
  `OidcStartupDiscovery.{probe,parseDocument}` [low|working-and-tested, but decide BEFORE T4/T5]** —
  the current probe parses the discovery document with raw Nimbus `JSONObjectUtils` string-get
  (proxy/src/main/java/smpp/companion/proxy/security/OidcStartupDiscovery.java `parseDocument`).
  Preferred candidate: `com.nimbusds:oauth2-oidc-sdk` — `OIDCProviderMetadata.parse(json)` (typed
  issuer/endpoints/grant-types, same vendor as the pinned nimbus-jose-jwt 10.9.1, a superset of
  it). Timing: decide before T4 (JWKS) and T5 (RFC 7662 introspection) land — the same SDK ships
  both, so adopting it once avoids three parallel hand-rolled parsers; after T4/T5 the migration
  cost only grows. Constraints the swap must satisfy: (a) `probe` KEEPS the JDK
  `java.net.http.HttpClient` + the `IdpSslContextFactory` TLS context/params (AD-36: no SDK HTTP
  stack — `OIDCProviderMetadata.parse(String)` is a pure parser, use it for the document only);
  (b) the fail-closed refusal matrix stays bit-for-bit (non-200 / unparseable / missing field /
  unreachable → "(AD-12, fail-closed A-2)"; the T2 tests `OidcStartupDiscoveryTest` are the
  contract); (c) the exact `issuer == provider-url` equality and the DAG warning survive; (d) NO
  SDK type crosses the security/ boundary into port types (AC8-immutable port; the local
  `OidcProviderMetadata` record stays the consumed surface — map from the SDK type inside the
  bean); (e) `smpp.runtime-purity`, `smpp.dependency-floors` (needs a floor + CVE lane run), and
  the `NoRolledCryptoArchitectureTest` package allowlist (`com.nimbusds..` already allowed — no
  rule change expected); (f) Keycloak vendor SDKs remain banned regardless. Owner note 2026-08-19
  (recorded verbatim intent: "find a library for oidc discovery or parsing to replace
  OidcStartupDiscovery.{probe,parseDocument}").
