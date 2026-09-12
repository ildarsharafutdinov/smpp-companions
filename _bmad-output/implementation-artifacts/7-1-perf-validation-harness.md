---
title: 'Story 7.1 — the performance-validation harness and the published evidence'
type: 'feature'
created: '2026-09-12'
status: 'ready-for-dev'
route: 'dispatch'
baseline_commit: 2f2b0e81444fdb8256fcf0a208d058385ea9074d
review_loop_iteration: 0
context:
  - {project-root}/_bmad-output/implementation-artifacts/epic-7-context.md
  - {project-root}/_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Every locked performance bet — PERF-1 (≥10K `submit_sm`/sec, stretch ~25K, p50/p90/p99/p99.9 table), PERF-2 (10K idle socket pairs <1 GB heap / <1 vCPU), PERF-3 (bind-latency percentiles + the one real-Keycloak number), PERF-4 (sub-ms per-PDU relay latency + codec JMH bands) — is UNPROVEN: the test-design catalog's PERF area (31 rows) carries zero landed markers, no latency/throughput measurement code exists anywhere in the repo, no test drives more than two real connections, and no HdrHistogram/percentile tooling is on any classpath. AD-21's allocator choice ("load-test pooled against the adaptive before choosing") has never been exercised, and the codec bench's `-prof gc` evidence was a reverted one-shot (1.2 T7 defer). The portfolio's "craft is the headline" claim currently rests on nothing published.

**Approach:** Build ONE open-model load harness in `proxy/src/test/` that drives the PACKAGED JAR shape (subprocess `java -jar proxy.jar` under the operator flag set, load-gen on cores pinned disjoint from the child) against the in-JVM `MockSmsc` sink — prove the harness itself first via the coordinated-omission check (PERF-010: an injected 50 ms SMSC pause must surface in p99.9) — then run the evidence matrix on it: the no-crypto baseline beside the Mode-C mTLS number (PERF-013/011), the stretch/knee/failure-mode sweep (PERF-012/016), the allocator budget check at the knee (PERF-040) and the pooled-vs-adaptive A/B (AD-21), the 10K-idle-pairs demo with linearity ramp and full disclosure (PERF-020/021), the bind-latency cluster incl. the real-Keycloak bind-rate (PERF-030/031/033/034), the ZGC/blocking/shutdown-under-load slices (PERF-050..052/060/061), and the codec JMH band publication incl. the `-prof gc` wiring decision (PERF-001..005). Everything lands in ONE published perf-report page under `docs/` governed by the disclosure/report gates (PERF-070/071). Hot-path defects found, if any, bounce to the owning epic — the harness never patches them (epics.md honest exception).

## Boundaries & Constraints

**Always:**
- Measured on the packaged JAR shape as a subprocess under the ONE operator flag set (`docs/operator-jvm-flag-contract.md` — floor + mirrored additions; the T5 `PackagedBootSmokeTest` launch-constant idiom, never a forked flag list). The load-gen and the `MockSmsc` sink live in the harness JVM; the child gets pinned cores via `taskset`-style process affinity at launch.
- The methodology bar: every published number carries its percentile table (never a peak alone), saturation knee + first-failure-mode, and full environment disclosure (payload, cipher-or-plaintext, single-instance, HW model/cores/RAM, JDK distro + exact build, reboot-before-run, sysctl: `fs.nr_open`/`somaxconn`/SO_RCVBUF/SO_SNDBUF) — PERF-070/071.
- PERF-015 semantics hold in every throughput run: binds established and adjudicated BEFORE the measurement window, verdict never cached (AD-12/SEC-094), bind-rate reported as a separate column — never conflated with `submit_sm` throughput.
- Honest labels: mock-IdP bind-rate is regression-only (PERF-034); the JMH codec numbers are codec-capability-no-I/O, never relay msg/s (PERF-001 note); `MockSmsc` is a sink, never a conformance oracle for published numbers.
- Ledger + catalog discipline: every PERF row marked with a dated Status marker as-landed (scope-honest — rows already covered by earlier stories, e.g. the SEC-094 no-verdict-cache unit, get "covered-by" markers, not duplicate claims); the 1.2-T7 `-prof gc` defer and AD-21's choice close with cited evidence.
- Fail-closed posture of the measured system is untouched: the harness configures via args (TestCompanionConfigs idiom), never edits yml defaults.

**Never:**
- No relay/security/observability/bootstrap MAIN-source changes — the harness is test-tier; `MockSmsc`/fixture extensions live under `proxy/src/test`. A genuine hot-path defect found under load halts the row and bounces to the owning epic (epics.md honest exception; record in deferred-work + memlog).
- No new operator-facing config keys — PERF-020's 10K pairs rides DISCLOSED arg overrides (`companion.memory.concurrent-pairs` + a coherently scaled `MaxDirectMemorySize` per the contract's floor+mirror rule), recorded in the report disclosure, never new yml keys.
- No E2E-001 composed two-instance run (Epic 6's conformance story), no Docker-image perf matrix (parity is structural — one jar/one arg channel; Epic-5 handoff), no docs-surface authoring beyond the perf-report page (Epic 6's docs story).
- No CI scaffolding (none exists, owner 2026-09-11) — the report gates are repo-local checks over the harness's machine-readable summary artifact, not a CI pipeline.
- No Java parses the perf-report page (owner rule 2026-09-10, no Java tests over *.md docs) — the gate checks the JSON/summary artifact the harness emits; the page is human documentation kept coherent at review time.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Harness self-proof (PERF-010) | 50 ms `MockSmsc` pause injected mid-run at fixed offered rate | The pause surfaces in p99.9; a closed-model contrast run shows the delta (the coordinated-omission proof) | Harness that hides the pause = harness bug → row RED before any number is trusted |
| Headline throughput (PERF-011/012) | Mode-C cell, sustained offered ≥10K/s over a defined window; sweep toward 25K | p50/p90/p99/p99.9 table at ≥10K sustained; knee + first failure mode reported (drop/OOM/backpressure/TLS-exec saturation/GC thrash) | Knee reached below 10K = PERF-1 miss → bounce decision to owner (defect vs. anchor) |
| Crypto attribution (PERF-013) | Same harness/payloads/rate, TLS off both transit legs | Throughput/latency delta published beside the mTLS number | No mTLS number publishes without its baseline |
| [B]-topology mTLS cell | PERF-1's "mTLS both legs" anchor vs. post-[B] reality (SMSC leg plaintext; one TLS leg per instance) | Owner decision at T-dispatch: publish the Mode-C-cell number + baseline delta (the composed both-hops number is Epic 6's composed rig); dated technique amendment in the PERF-011 marker | Silent reinterpretation of the locked anchor is forbidden — the amendment is recorded, not implied |
| Idle-pairs demo (PERF-020/021) | 10K bound pairs (~20K loopback sockets), disclosed `concurrent-pairs` + scaled `MaxDirectMemorySize` overrides | GC-settled heap <1 GB, RSS + idle CPU% <1 vCPU over a sustained window; 1K/2K/5K/10K ramp near-linear (a nonlinear jump = defect signal) | AD-30 self-check must PASS under the overrides (coherent scaling) — a failing check means incoherent overrides, not a bypass (`budget-check: warn` is NOT the demo's path) |
| Bind latency (PERF-030/031) | Warm stand-in IdP / cold first-bind paths, deterministic fixtures | p99 ≤250 ms warm / ≤2 s cold | PERF-032's verifier half already covered (4.4 T3 + SEC-009) — marker says "covered-by", no duplicate |
| Real-Keycloak bind-rate (PERF-033) | `KeycloakFixture` (Testcontainers, `disabledWithoutDocker`) | Sustained binds/s vs. the ~15 logins/s/vCPU anchor, labeled real-Keycloak | Daemon-less run skips GREEN; the published column stays empty until a Docker run executes (honest absence) |
| Allocator at the knee (PERF-040) + AD-21 A/B | Offered rate at/beyond knee; pooled vs. adaptive `io.netty.allocator.type` | `usedDirectMemory` ≤ the AD-30 budget at the cliff; the A/B record closes AD-21's "before choosing" | Budget breach at knee = REL-2/AD-30 defect signal → bounce, don't tune away |
| Event-loop blocking (PERF-060) | BlockHound on the child (or JFR fallback) | Zero disallowed blocking on event-loop threads at PERF-1 rate; tail spikes uncorrelated | BlockHound JDK-25 incompatibility → dated disposition + the JFR `jdk.JavaMonitorWait`/blocking-event fallback, honestly labeled weaker |
| SIGTERM under load (PERF-061) | SIGTERM mid-sustained-rate run | AD-22 drain completes within the Spring timeout, zero in-flight `submit_sm` dropped (sequence-numbered payloads) | Drain overrun → defect bounce (4.4 T5's quiesce bound is the existing backstop) |
| Report gates (PERF-070/071) | The harness's machine-readable summary artifact | Schema check: every number disclosure-tagged; no peak without knee + failure mode | Missing tag → gate check RED |

**Decisions (owner, to ratify or amend at dispatch):**
- Measured shape = packaged JAR subprocess (the operator's artifact; Epic-5 handoff "formal validation runs on the packaged shapes"). The in-JVM full-context rig stays available as the development fast path but publishes nothing.
- Percentile recorder: HdrHistogram (new test-tier dependency, through `smpp.dependency-floors` + CVE lane) vs. hand-rolled ring sampler — T1 decision; the catalog's percentile tables are the requirement, the library is means.
- The report gates (PERF-070/071) execute over the harness-emitted JSON summary (repo-local JUnit row), NOT over the docs page — the 2026-09-10 no-Java-tests-over-md rule postdates the catalog's "parsed perf-report / CI gate" technique; page↔summary coherence is a review-time duty (the flag-contract precedent).
- The JMH `-prof gc` arm (PERF-004): re-wire `profilers = ["gc"]` into the `jmh {}` block vs. a documented `./gradlew :proxy:jmh -Pprof=gc` invocation — T6 decision closing the 1.2-T7 defer; the allocation unit guard (`CodecAllocationGuardTest`) stays the durable in-CI substitute either way.

</frozen-after-approval>

## Code Map

- `proxy/src/test/java/smpp/companion/proxy/relay/MockSmsc.java` -- the AD-24(2) in-JVM mock SMSC on the production codec: N concurrent binds (every bind ESME_ROK), per-socket `deliver_sm` injection (`Session.deliver/deliverAll`), injectable bind delay/stall (`start(long)`/`stallBinds()`/`releaseBinds()`), byte-exact captures (`bindFrame()`/`received()`/`awaitPdus(n)`). The harness sink — needs a per-PDU delay-injection arm for PERF-010's coordinated-omission check (bind-delay arms exist; the mid-stream PDU pause is new, test-tier).
- `proxy/src/test/java/smpp/companion/proxy/bootstrap/PackagedBootSmokeTest.java` -- the subprocess-boot idiom this harness generalizes: `java -jar` the built jar with the operator flag set from a Java-side launch constant, `scrape(int port)` (:508, the MetricsEndpointTest raw-socket idiom), SIGTERM → ordered AD-22 drain lines → clean exit. Its rig boots ONE reverse-B cell and drives ONE relay round — the load rig replaces single-shot with scheduled open-model senders.
- `proxy/src/test/java/smpp/companion/proxy/config/TestCompanionConfigs.java` -- per-cell arg factories (`reverseB(dir)` etc.) — the harness's cell-configuration source (Mode-C cell + no-crypto cell + the disclosed PERF-020 overrides).
- `proxy/src/test/java/smpp/companion/proxy/relay/TlsModesLoopbackE2eTest.java` -- the ratified [B]-topology cell definitions on real sockets (forward: plaintext trusted-leg listener + TLS dials; reverse: internet-leg TLS listener + plaintext SMSC dial) — the Mode-C mTLS cell's wiring reference for the [B]-topology decision.
- `proxy/src/test/java/smpp/companion/proxy/testsupport/` -- `RelayTestFixtures` (free-port probe + minimal reverse-B properties), `TokenIdpStandIn` (in-process TLS token endpoint; the parked-latch handler variant is shutdown-oriented — the bind-latency runs need an answering variant), `OidcDiscoveryStandIn`, plus `security/KeycloakFixture.java` (real Keycloak 26.x, Testcontainers; certs under `proxy/src/test/resources/keycloak/certs/`) for PERF-033.
- `proxy/src/jmh/java/smpp/companion/jmh/CodecMicrobenchmarks.java` + `proxy/build.gradle.kts:60-75` -- the Story-1.2 JMH bench (`encodeBindRequest`/`decodeBindRequest`/`frameSubmitSm`; plugin `me.champeau.jmh` 0.7.3, `jmhVersion` 1.37, `includeTests` false, NO profilers — the 1.2-T7 defer). Nightly-tier, deliberately outside `build`/`check`; `compileJmhJava` feeds `:proxy:test` via `JmhIsolationArchitectureTest`. NOTE: the bench encodes/decodes BIND-family PDUs (the codec parses nothing else, AD-3) — PERF-001/002's "submit_sm encode/decode" band rows land as the bind-family analogues + the `frameSubmitSm` hot path; the markers carry the dated technique amendment.
- `proxy/src/test/java/smpp/companion/proxy/observability/MetricsEndpointTest.java` -- `scrapeShape(String)` series-shape extractor + the raw loopback-socket scrape idiom (deliberately no `java.net.http.HttpClient`) — the harness's `/metrics` sampling reuses it (PERF-1's proof = harness + `/metrics`).
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/DirectMemoryBudgetStartupCheck.java` + `config/MemoryBudget.java` -- the AD-30 live self-check + formula the PERF-020 overrides must stay coherent with (the child refuses on an incoherent override — that refusal is part of the demo's honesty).
- `proxy/src/main/resources/application.yml` -- the defaults the harness overrides via args (memory trio 64/1024/1.5 ≈ 6 GiB budget; `concurrent-pairs: 1024` caps pairs — PERF-020's 10K run MUST override, see the matrix).
- `proxy/src/test/java/smpp/companion/proxy/relay/JsmppSmscServer.java` -- the jSMPP independent server-side counterpart (never the production codec) — available to the idle-pair harness as the independent sink if `MockSmsc` self-hosting skews the idle numbers.
- `codec/src/test/java/smpp/companion/codec/perf/CodecAllocationGuardTest.java` -- PERF-006's durable in-CI allocation guard (the `-prof gc` substitute of record).
- `buildSrc/src/main/kotlin/smpp.dependency-floors.gradle.kts` -- the dependency lane any HdrHistogram addition rides (floor + CVE policy, SEC-099's general lane).
- `docs/operator-jvm-flag-contract.md` -- the ONE flag set + the floor+mirror additions rule the PERF-020 overrides cite; `docs/a-1-carrier-test-plan.md` already exists (NOT this story's surface).

## Tasks & Acceptance

**Execution:**
- [ ] **T1 — the open-model load rig + harness self-proof (PERF-010)** — Subprocess rig: boot the built jar (task-dependency + jar-as-test-input, the PackagedBootSmokeTest wiring) under the operator flag set with pinned child cores; harness-JVM `MockSmsc` sink extended with a mid-stream per-PDU pause arm; open-model load-gen (independent fixed-rate scheduler, never req/resp closed-loop); percentile recorder per the T1 dependency decision. Self-proof row: injected 50 ms pause surfaces in p99.9 + a closed-model contrast run exposes the delta; daemon-less/GREEN-on-any-host posture preserved (no Docker needed for the core rig). Mutation: closed-loop gating reintroduced → the contrast row collapses → RED.
- [ ] **T2 — the throughput evidence: baseline, mTLS cell, knee, allocator, per-PDU latency (PERF-011..017, PERF-040, AD-21, PERF-015)** — No-crypto baseline run (TLS off both transit legs, identical payloads/rate/cores); Mode-C mTLS-cell run (the [B]-topology decision applied — see the matrix row) sustaining ≥10K with the p50/p90/p99/p99.9 table; the payload-corner sweep (180 B GSM-7, UCS-2 single, 3-segment UDH burst — p99 each, PERF-014); sweep toward 25K recording the knee + FIRST failure mode; the per-PDU added-latency p99 <1 ms vs. the zero-latency sink (PERF-017, harness-side technique — see Design Notes); PERF-040's `usedDirectMemory` ≤ AD-30 budget sampled at the cliff; the pooled-vs-adaptive allocator A/B recorded (closes AD-21's "before choosing"); PERF-015's pre-window-binds + separate bind-rate column asserted by the harness itself. All numbers tagged per PERF-070 into the machine-readable summary.
- [ ] **T3 — the idle-pairs demo (PERF-020/021)** — 10K bound pairs (~20K loopback sockets) under the DISCLOSED coherent overrides (`concurrent-pairs` ≥10K + scaled `MaxDirectMemorySize`; the AD-30 check passes, not warned); GC-settle protocol, RSS sampled at multiple post-settle points, idle CPU% integrated over a window; the 1K/2K/5K/10K linearity ramp with the nonlinear-jump defect signal; full environment disclosure.
- [ ] **T4 — the bind-latency cluster (PERF-030/031/033/034)** — Warm-path p99 ≤250 ms and cold-path p99 ≤2 s on deterministic fixtures (answering IdP stand-in variant; no `Thread.sleep` in measurement); the real-Keycloak bind-rate via `KeycloakFixture` (verify/extend its daemon-gating idiom at T4 — the repo's `@Testcontainers(disabledWithoutDocker = true)` posture; the published column fills only from a Docker run); mock-IdP bind-rate labeled regression-only in a separate column (PERF-034). PERF-032 marker = covered-by (4.4 T3 + SEC-009).
- [ ] **T5 — GC/blocking/shutdown-under-load slices (PERF-050/051/052/060/061)** — JFR on the child at the offered rates: worst-case ZGC pause + cycle-frequency/allocation-rate ceiling across the sweep (050/051); the oscillating-across-the-knee run with jitter + randomized disconnects asserting transit integrity (052); event-loop blocking check (060 — BlockHound-on-child if JDK-25-compatible, else the dated JFR fallback disposition); SIGTERM mid-rate → drain within the Spring timeout, zero in-flight drop via sequence-numbered payloads (061).
- [ ] **T6 — the report, the gates, the JMH bands, closure (PERF-070/071, PERF-001..005, PERF-004 defer)** — The perf-report page under `docs/` (human documentation; every table carries its conditions) + the repo-local gate check over the harness's JSON summary (schema: disclosure tags on every number, no peak without knee + failure mode); the JMH band publication (re-run `./gradlew :proxy:jmh`, publish encode/decode/frame bands vs. the PERF-4 bands with the bind-family-analogue technique amendment) + the `-prof gc` wiring decision closing the 1.2-T7 defer; `./gradlew clean build --console=plain` GREEN end-to-end (clean REQUIRED — source-scan UP-TO-DATE trap); PERF catalog dated Status markers for every row this story lands + covered-by markers where earlier stories own the slice; deferred-work closures with cited evidence (AD-21 choice, PERF-004).

**Acceptance Criteria:**
- Given the rig at a fixed offered rate, when a 50 ms SMSC pause is injected mid-run, then it surfaces in p99.9 and the closed-model contrast exposes the delta — no number is published from an unproven harness.
- Given the Mode-C cell and the no-crypto baseline on the same harness/payloads/cores, when both run at ≥10K `submit_sm`/sec sustained, then the percentile tables, the crypto-cost delta, the knee, and the first failure mode are all published together — and PERF-015's pre-window-binds + separate bind-rate column held.
- Given the 10K idle pairs under disclosed coherent overrides, when GC settles, then heap <1 GB, idle CPU <1 vCPU, the ramp is near-linear, and the AD-30 self-check PASSED (not warned) under the overrides.
- Given the bind-latency fixtures, when warm and cold paths run, then p99 ≤250 ms / ≤2 s respectively; the real-Keycloak column is filled only by a real `KeycloakFixture` run and the mock column is labeled regression-only.
- Given the child under PERF-1 offered rate, when SIGTERM arrives, then the AD-22 drain completes within the Spring timeout with zero in-flight `submit_sm` dropped.
- Given the summary artifact, when the gate check runs, then every number is disclosure-tagged and no peak publishes without its knee + failure mode; the JMH bands are published with the `-prof gc` decision recorded.

## Implementation Notes

## Spec Change Log

## Review Triage Log

## Design Notes

- The harness JVM hosts load-gen + `MockSmsc` + measurement; the child hosts the proxy. End-to-end latency is harness-side timestamped (send → sink receive); PERF-017's "injected timestamp/SpliceObserver seam" technique predates the subprocess-shape decision — the added-latency number = (through-proxy latency) − (direct loopback baseline at the same rate), honestly labeled to include transit; the marker carries the dated technique amendment.
- Measurement-time child additions (JFR `-XX:StartFlightRecording`, a BlockHound `-javaagent`, the AD-21 A/B's `io.netty.allocator.type`) are HARNESS-scoped, disclosed in the report's conditions — they are not the operator contract page's flag set and mirror nowhere; the contract's floor+mirror rule governs operator additions only.
- PERF-020's port arithmetic: ~20K sockets stays under the 64K ephemeral ceiling on one loopback IP (catalog note); `fs.nr_open`/`somaxconn` limits are recorded, not tuned blind — a refused fd is a disclosure line, not a surprise.
- The rig boots cells via args (`TestCompanionConfigs`), so the no-crypto cell is the Mode-C cell minus the TLS wiring — never a second properties fork.
- Keep the JMH publication honest: `includeTests=false`, nightly-tier posture, and the `JmhIsolationArchitectureTest` guard are 1.2-T7 standing decisions — the T6 publication re-runs, it does not re-architect.
- One-task-per-conversational-step, one commit per task (repo rule). The report page and the summary artifact co-commit with T6.

## Verification

**Commands:**
- `./gradlew clean build --console=plain` -- expected: GREEN end-to-end including the harness self-proof row, the gate-check row, and every landed PERF row that is daemon-less; Docker-gated rows (Keycloak) ride `disabledWithoutDocker`.
- `./gradlew :proxy:test --tests '*Perf*' --console=plain` -- expected: GREEN after `clean` (the source-scan trap); the scale rows (idle pairs, sustained throughput) stay individually invocable and skip-green on hosts that opt out via the documented tag, exactly like the Docker suites.

**Manual checks (if no CLI):**
- `./gradlew :proxy:jmh` from a clean checkout yields the three band lines; the report page's numbers reconcile with the summary artifact committed beside it.

## Dev Agent Record

### Agent Model Used

### Debug Log References

### Completion Notes List

### File List
