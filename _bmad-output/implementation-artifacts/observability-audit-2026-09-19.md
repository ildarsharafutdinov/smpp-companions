---
title: 'Observability audit — Story 8.1 Task 1'
type: 'audit-report'
created: '2026-09-19'
story: '8-1-observability-audit-and-gap-close.md'
baseline_commit: '86f02cf5a79d7b833dc104b1e3f2ee3ef02ac701'
audited_surface: 'JSON-lines log events + loopback /metrics exposition + scrape-handler exacts'
norms: 'PRD FR-OBS-1/2, OBS-1..3, PERF-3/4 · PRD addendum A2 · ARCHITECTURE-SPINE AD-19/AD-27/AD-32/AD-33 · spine Deferred (histogram item)'
status: 'final — gates the Story 8.1 close list'
---

# Observability audit — 2026-09-19

Cited-evidence audit of the proxy's whole observability surface against the operator-facing norms
that govern it, per Story 8.1 Task 1 (the spec's frozen Approach: audit first — this report gates
the close list). Four comparisons, row by row: **(a)** metrics vs PRD addendum A2 + FR-OBS-2,
**(b)** log events vs FR-OBS-1 + A2's baseline-logging block, **(c)** handler exacts vs AD-19,
**(d)** a gap table where every row is cited and carries exactly one disposition: closed-here
(Story 8.1 task ref) · ledgered (a `deferred-work.md` entry Task 7 will append) · closed-no-change
(superseded by a cited, ratified architecture decision — recorded so nothing is silently dropped).

## Method (the spec's Design Note, executed)

Inventory from a **live scrape** + the **existing source-pin tests**, cross-checked row by row
against A2 / FR-OBS-1 / FR-OBS-2; every row cites file:line or test name.

The live inventory: two boots of the real boot jar (`proxy/build/libs/proxy.jar`, built at this
tree) under the operator JVM flag set (`--enable-preview -XX:+UseZGC -XX:MaxDirectMemorySize=6442450944
-Djava.net.preferIPv4Stack=true`, the `PackagedBootSmokeTest.OPERATOR_JVM_FLAGS` contract) with the
minimal AD-30 budget args (1/1/1.0) and fixture material in `/tmp`:

- **forward.mode-a** (routing table {alpha, beta}) — reached `startup_summary`
  (`"role":"forward"`, `"mode":"a"`, `routing_system_ids":["alpha","beta"]`); two consecutive
  `GET /metrics` scrapes → `200`, `content-type: text/plain; version=0.0.4; charset=utf-8`,
  **87 distinct series**; the two scrape bodies are **shape-identical** (series name+labels
  equal after stripping live sample values — the read-only contract, live); live probes: `POST
  /metrics` → `405` + `allow: get`; `GET /metrics/foo` → `404`; `GET /metrics?x=1` → `404`; every
  response carries `connection: close`. SIGTERM → clean exit.
- **reverse.mode-b** (mock OIDC config, `acknowledged=true`) — reached `startup_summary`
  (`"role":"reverse"`, `"mode":"b"`, `routing_system_ids":[]`); scrape → **86 distinct series**
  (the same surface minus the two `relay_binds_accepted_total{system_id=…}` series — the routing
  table IS the label domain, empty on reverse cells — plus `ropc_adjudications_active 0.0`).
  Stdout: 6 lines, **all six parse as one JSON object each** (the Mode B banner rides as one WARN
  JSON line). SIGTERM → clean exit. (The forward boot's stdout likewise parsed 17/17 lines.)

Both scrapes contain **zero `_bucket`/`_sum` histogram rows** — no timer/histogram meter exists in
main sources (grep for `Timer|Histogram|DistributionSummary|nanoTime|currentTimeMillis` over
`proxy/`+`codec/` main: no meter hits; the only `Timer`-named thing is `BindInterceptor`'s
`ChannelTimer` deadline-scheduler seam). The only `_sum`/`_max`-shaped rows are the Micrometer JVM
GC timer families (`jvm_gc_pause_seconds_*`, `jvm_gc_concurrent_phase_time_seconds_*`), created
lazily on the first GC notification (documented: `ObservabilityConfig.java:31-35`,
`docs/runbooks.md:250-253`).

The series arithmetic (live, both cells): 38 observer meters (`MeteredRelayObserver` — 2 PDU +
2 accept + 32 close + reject + unknown; the `MeteredRelayObserverTest:127` pin) + 1-2 resource
gauges (`relay_direct_memory_used_bytes` everywhere; `ropc_adjudications_active` reverse-only) +
48 JVM binder series = 87 forward / 86 reverse. On the reverse cell the observer is 36 (no accept
series — empty table).

## (a) Metrics vs PRD addendum A2 + FR-OBS-2

Norm: `addendum.md:30` (A2 `/metrics` block — counters/gauges/optional histograms, content never
emitted), `addendum.md:31` (loopback posture), `prd.md:132` (FR-OBS-2), `prd.md:183-185`
(OBS-1..3). As-built owners: `MeteredRelayObserver.java` (counters), `ResourceMetrics.java`
(gauges), `ObservabilityConfig.java` (registry + JVM binders).

| A2 / FR-OBS-2 requirement | As-built | Verdict | Citation |
|---|---|---|---|
| Counter: binds accepted, optionally per `system_id` | `relay_binds_accepted_total{system_id}` pre-registered ONLY for routing-table ids at construction; off-table ids → unlabeled `relay_binds_unknown_total`; reverse cells have zero labeled series (live) | **met** (the "optionally dimensioned" choice = bounded to the routing table) | `MeteredRelayObserver.java:135-144,181-197`; attack test `MeteredRelayObserverTest:47-96`; runbooks `:222` |
| Counter: binds rejected **(by reason)** | `relay_binds_rejected_total` unlabeled; the reason (`verdict` type) is log-only — AD-33 collapses both `Deny*` to one wire status, and a verdict label is refused by the counter-label rule | **met with a recorded supersession** — gap row G5 | `MeteredRelayObserver.java:74-75,159-162,200-214`; spine AD-33 `ARCHITECTURE-SPINE.md:255-258`; runbooks `:223` |
| Counters: submit_sm relayed, DLRs relayed | NOT implemented as named — post-couple PDUs are opaque framed bytes; `relay_pdus_total{direction}` counts every relayed PDU per leg, no PDU type crosses the seam | **met with a recorded supersession** — gap row G4 | spine AD-3 `:80` (opacity), AD-27 `:224` (no-PDU-type seam); `RelayObserver.java:29-41`; shape pin `RelayObserverShapeTest:49-66`; runbooks `:221` |
| Gauge: active connections | **absent** — no series reads the pair count; gap row G3 | **gap** | live scrape (no such name in either cell); `ResourceMetrics.java:58-73` registers exactly two gauges |
| Gauge: active virtual threads | `ropc_adjudications_active` (the `ropc-adjudication` VT pool's own count; `jvm_threads_*` cannot see VTs); present on reverse cells only — forward absence is truthful (no pool) | **met** | `ResourceMetrics.java:49-50,65-72`; live reverse scrape `ropc_adjudications_active 0.0`; runbooks `:241` |
| Gauge: JVM heap used/committed | `jvm_memory_used/committed/max_bytes` + buffer pools, plus GC/threads/processor/uptime families (48 live series) | **met** | `ObservabilityConfig.java:62-103`; test `MetricsEndpointTest:164-196`; runbooks `:243-253` |
| Optional histogram: bind latency | **absent** — zero timer/histogram in main; the spine-Deferred item | **gap** — G1, closed here (Task 2) | spine Deferred `:409`; grep (Method); live scrape (zero `_bucket`) |
| Optional histogram: per-PDU relay latency | **absent** — same | **gap** — G2, closed here (Task 2) | spine Deferred `:409`; live scrape |
| Message content never emitted | No PDU type/content crosses the seam; `command_id` reaches logs only TRACE-gated (AD-32 read-vs-emit); no content in any meter | **met** | `RelayObserver.java:11-18`; `ObservabilityLayerRulesTest:60-82`; `MeteredRelayObserverTest:47-96` (PRIV-1 proof) |
| FR-OBS-2: throughput counters, resource gauges, "configurably dimensioned per `system_id` (operator-controllable cardinality)" | PDU/close counters + direct-memory/VT/JVM gauges; the `system_id` label domain IS the routing table (operator edits config → domain changes at next boot; nothing runtime-created) | **met** | live scrapes; `MeteredRelayObserver.java:124-168`; runbooks `:216-217` |
| FR-OBS-2 / A2: loopback IPv4 only, never on SMPP legs; `system_id` labels bounded; PII never | Literal `127.0.0.1` bind on a dedicated one-thread `companion-metrics` loop; no host key exists | **met** | `MetricsEndpointLifecycle.java:77,101-102,121`; source pins `MetricsEndpointTest:282-305`; live (endpoint answered on loopback only) |
| OBS-1/3 + A2 "what is NOT built" (no dashboard/backend/remote-write/OTel/mgmt API) | Read-only scrape only; no such surface exists | **met** | `addendum.md:32`; `MetricsHttpHandler.java:29-33` (no scrape counter); live idempotence |
| Six reserved `CloseReason` values registered but never fire | Documented reservation (taxonomy stability); ten fire today | **met — recorded reservation, not a delta vs any norm** | `CloseReason.java:28-60`; runbooks `:227-234` |

## (b) Log events vs FR-OBS-1 + A2 baseline logging

Norm: `prd.md:131` (FR-OBS-1), `addendum.md:29` (A2 baseline-logging block). As-built owners:
`logback-spring.xml`, `StartupSummaryLogger.java`, `MeteredRelayObserver` INFO lines, the relay
WARN catalog, `CoupledRelayHandler`'s TRACE body logger.

| FR-OBS-1 / A2 event | As-built | Verdict | Citation |
|---|---|---|---|
| Structured JSON-lines to stdout | `LogstashEncoder`, `[ISO_OFFSET_DATE_TIME]`, UTC pinned, INFO root; both live boots emitted pure JSON-lines (6/6 lines parse on the reverse boot) | **met** | `logback-spring.xml:1-22`; source pin `StructuredLogTest:90-102`; full-boot parse `:104-184`; runbooks `:152-157` |
| Startup / config-resolved event | `startup_summary` on `ApplicationReadyEvent` — role/mode, bind host/port, metrics port (omitted iff node absent), routing ids, TLS protocols, AD-30 budget + ceiling; secret-free (asserted) | **met** | `StartupSummaryLogger.java:50-78`; `StructuredLogTest:157-180`; live boots; runbooks `:161` |
| Errors | Emitted **entirely at WARN** (banners, routing miss, deadline elapsed, drain force-close, cap exhaustion, observer-swallow guards), throwables under `stack_trace`; **zero `log.error`/`System.err` calls exist in main** (grep) — the proxy's own worst severity is WARN | **met under the as-built register; severity classification is a judgment call → gap row G7 (ledgered, low)** | grep over `proxy/src/main` (no hits); `BindInterceptor.java:402,615`; runbooks WARN catalog `:164` |
| Bind accept / reject with `system_id` | `bind_accept` (event, system_id, outcome="coupled") at the AD-25 couple; `bind_reject` (event, system_id, verdict, `bind_resp_command_status="0x0000000D"`) — the AD-33 wire collapse mirrored on the line | **met** | `MeteredRelayObserver.java:191-192,207-209`; real-fire-site proof `StructuredLogTest:188-217`; literal pin `MeteredRelayObserverTest:133-135`; runbooks `:162-163` |
| Full PDU/body logging only at TRACE (off by default) | Dedicated logger `smpp.companion.proxy.relay.pdu`; direction + raw `command_id` + hex body; bind family redacted at every level (password never crosses at any level); default boot shows no bodies | **met** | `CoupledRelayHandler.java:96-104`; `StructuredLogTest:219-285`; `application.yml:21-27`; runbooks `:169-182` |
| Level configurable | standard `logging.level.*` over the encoder | **met** | `application.yml:21-27`; runbooks `:173-174` |
| High-frequency events log nothing | `onFramedPdu`/`onConnectionClosed` are metrics-only by design | **met** | `MeteredRelayObserver.java:52-54,170-224`; runbooks `:166-167` |
| FR-OBS-1 "stdout/**file**" | stdout only — no file appender ships | **partial → gap row G6 (ledgered, low)** | `logback-spring.xml` (single CONSOLE appender) |

## (c) Handler exacts vs AD-19

Norm: `ARCHITECTURE-SPINE.md:181-184` (AD-19 rule text). As-built owners:
`MetricsEndpointLifecycle`, `MetricsHttpHandler`, `ObservabilityConfig`.

| AD-19 exact | As-built | Verdict | Citation |
|---|---|---|---|
| Tiny loopback HTTP handler on a DEDICATED, hand-managed Netty event loop; never shares the relay group | Own `ServerBootstrap` + `MultiThreadIoEventLoopGroup(1, "companion-metrics")` created in `start()`, not a shared bean; loop-thread presence/absence asserted in tests | **met** | `MetricsEndpointLifecycle.java:101-118`; `MetricsEndpointTest:198-222` (thread names + quiesce) |
| Started/stopped via `SmartLifecycle` | Phase `APP_PHASE+500` — stops after the app window opens, before the acceptor (scrapes live late in shutdown) | **met** | `MetricsEndpointLifecycle.java:71,182-185`; `MetricsEndpointTest:265-280` |
| Calls `PrometheusMeterRegistry.scrape()`; no Actuator web stack, no Tomcat, no WebFlux | Handler calls `registry.scrape()`; actuator absent from the classpath (OBS-013 runtime-purity gate); no Jackson on the main classpath | **met** | `MetricsHttpHandler.java:116`; `buildSrc/src/main/kotlin/smpp.runtime-purity.gradle.kts`; `NoJacksonArchitectureTest`; `ObservabilityConfig.java:19-23` |
| Method MUST be GET → else 405 (+`Allow: GET`) | Non-GET → 405 with `Allow: GET`, one bounded debug line | **met** (live: POST → `405`, `allow: get`) | `MetricsHttpHandler.java:95-103`; `MetricsEndpointTest:111-122` |
| Path exactly `/metrics` → else 404 (query strings included) | `SCRAPE_PATH` equality; sub-paths, `/`, trailing slash, `?x=1` all 404 | **met** (live) | `MetricsHttpHandler.java:104-108`; `MetricsEndpointTest:124-133` |
| Bounded max header/body size | 1024 B initial line / 8 KiB headers / 8 KiB content; oversized → 413, connection closed, never a trace on the wire (failed-DecoderResult refusal + aggregator's own 413 + `exceptionCaught` defense) | **met** | `MetricsHttpHandler.java:65-71,86-94,133-147`; `MetricsEndpointTest:135-162` |
| Bind loopback IPv4 only — sole authentication; non-loopback forbidden in v1 | Literal `LOOPBACK_BIND_HOST = "127.0.0.1"`; NO host key (source-pinned `doesNotContain(".metrics().host")`); yml ships only the port (default 9090); absent node = endpoint down; occupied port = fail-fast with the loop quiesced | **met** (live) | `MetricsEndpointLifecycle.java:77,94-97,121-135`; `MetricsEndpointTest:224-263,282-305` |
| Read-only exposition; `system_id` labels only from the routing table; unknown ids → unlabeled counter; no free-form `system_id` label | Pre-registered closed sets; `relay.binds.unknown` absorbs off-table ids; scrape mutates nothing (shape- and value-idempotent) | **met** (live: two scrapes shape-identical) | `MeteredRelayObserver.java:27-47,124-168`; `MeteredRelayObserverTest:47-96`; `MetricsEndpointTest:58-109` |
| Counter-label rule: NO `system_id`/`command_id`/`ChannelId` on any close/reject counter | Close counter labeled `{direction, reason}` only (2×16 grid); reject/unknown unlabeled | **met** | `MeteredRelayObserver.java:146-167`; AD-19 counter-label clause `ARCHITECTURE-SPINE.md:184` |
| Read-vs-emit: reading `command_id` always permitted; EMITTING it is TRACE-gated, never via a codec helper; codec emits no metrics | `command_id` hex only on the TRACE body logger (relay-owned); codec meter-free (AD-27); Netty ban on the seam | **met** | `CoupledRelayHandler.java:96-104`; `ObservabilityLayerRulesTest:60-82`; spine AD-27 `:224` |
| Message content never emitted | No content handle crosses the seam; scrape body is names/labels/values only | **met** | `RelayObserver.java:11-18`; live scrapes |
| Baseline ops logging = JSON-lines; VT gauge; no dashboard/backend/mgmt API | See section (b); `ropc_adjudications_active`; nothing else exists | **met** | `ResourceMetrics.java:65-72`; OBS-1..3 `prd.md:183-185` |
| Throw-isolated recording (the spec's Always-row; scrape-throw → 500) | Scrape exceptions answered 500 + closed; observer triggers catch-guarded AND fire-site `fireGuarded` isolates any throwing impl from the relay path | **met** | `MetricsHttpHandler.java:114-121`; `MeteredRelayObserver.java:170-224`; `CoupledRelayHandler.java:184,304,321`; `ThrowingObserverHardeningTest` |
| A2's retired "opt-in to bind elsewhere" stays superseded (loopback-only v1) | `addendum.md:31` records the supersession; nothing implements a bind-elsewhere arm | **met** | `addendum.md:31`; spine Cross-artifact items `:425` |

## (d) Gap table

Every delta found, each cited, each with exactly one disposition. "Closed-here" rows name the
Story 8.1 task that closes them; "ledgered" rows are what Task 7 appends to `deferred-work.md`;
"closed-no-change" rows are deltas that a ratified architecture decision supersedes — recorded
here so the accounting is complete (nothing silently dropped).

| # | Gap | Evidence | Disposition |
|---|---|---|---|
| G1 | **No bind-adjudication latency histogram** — A2's optional "bind latency" was never landed (the spine-Deferred item); operators get zero signal against PERF-3 (p99 ~250 ms warm / ≤2 s cold / 2–5 s DENY clamp, `prd.md:142`); the deadline machinery times nothing (zero `nanoTime` in main; `RequestContext`'s `Instant deadline` and the F14 `ChannelTimer` arm exist untouched as hook points) | spine Deferred `:409`; grep (Method); live scrapes (zero `_bucket`); `BindInterceptor.java:545` (the arm); `RequestContext.java:22` | **closed here — Task 2**: unlabeled bind-adjudication-latency histogram, PERF-3-anchored buckets covering ~[50 ms … 8 s] (exact edges implementation-owned → A2 note Task 5 + runbooks Task 4); spine retirement Task 6 |
| G2 | **No per-PDU relay transit histogram** — A2's optional "per-PDU relay latency"; PERF-4's sub-ms budget (`prd.md:143`) is invisible below 1 s today; the seam carries no duration (`onFramedPdu(Direction)` only) | spine Deferred `:409`; live scrapes; `RelayObserver.java:41`; single fire site `CoupledRelayHandler.java:184` | **closed here — Task 2**: per-PDU transit histogram labeled `{direction}` ONLY, sub-ms→s buckets; requires the ratified Q1=B seam change (owner decision 2026-09-19) landing as an explicit dated contract change with the `RelayObserverShapeTest` update in-step + Spec Change Log entry |
| G3 | **No active-connections gauge** — A2's gauge list names "active connections"; no series reads the live pair count (`ConnectionRegistry` exists, nothing gauges it) | `addendum.md:30`; live scrapes (no such name); `ResourceMetrics.java:58-73` (exactly two gauges) | **ledgered (Task 7)** — outside the ratified close scope (histograms only; a new gauge is new surface), but A2 names it, so it must not vanish |
| G4 | **submit_sm-relayed / DLRs-relayed counters not implemented as A2 names them** — structurally impossible without violating post-couple opacity (AD-3: every post-couple PDU is opaque framed bytes) and the no-PDU-type seam (AD-27); `relay_pdus_total{direction}` is the conforming per-leg count and the runbook documents the semantics | spine AD-3 `:80`, AD-27 `:224`; `RelayObserverShapeTest:49-66`; runbooks `:221` | **closed — no change** (superseded by ratified architecture; the operator doc already states the substitution) |
| G5 | **Binds-rejected "by reason" dimension absent from metrics** — AD-33 collapses every proxy-side denial to one wire status and confines the rich outcome to logs; a verdict label would fan a dimension AD-19's counter-label rule refuses; the reason IS observable in the `bind_reject` line's `verdict` field | `addendum.md:30`; spine AD-33 `:255-258`; `MeteredRelayObserver.java:200-214`; runbooks `:163` | **closed — no change** (superseded; log-carried by design) |
| G6 | **No file log destination** — FR-OBS-1 says "stdout/file"; the shipped config is stdout-only JSON-lines (one CONSOLE appender), the container-first contract | `prd.md:131`; `logback-spring.xml:10-19` | **ledgered (Task 7, low)** — a file appender means new config keys and a rotation policy, both outside this story's Never-list; stdout is the documented deploy contract (runbooks `:152-157`) |
| G7 | **Zero ERROR-level emissions from product code** — FR-OBS-1's "errors" class is carried at WARN (with `stack_trace`); an operator alerting on `level=ERROR` never fires on proxy-originated lines | grep over `proxy/src/main` (no `log.error`/`System.err`); runbooks `:156-157,164` | **ledgered (Task 7, low)** — a severity-register decision (introduce ERROR for genuine faults vs keep the WARN register), owner-owned; not closable as a histogram-gap side effect |

No other gaps: every other A2 / FR-OBS-1 / FR-OBS-2 / AD-19 row in sections (a)-(c) is met with
citations above. The `ClassLoaderMetrics`/`FileDescriptorMetrics` exclusion is a recorded
deliberate decision, not a gap (`ObservabilityConfig.java:36-38`, review round 1 [B10]); the six
reserved `CloseReason` values likewise (`CloseReason.java:52-60`).

## What this audit gates (the close list for Tasks 2-7)

1. **Task 2 (code)** — land BOTH ratified histograms under AD-19 cardinality: bind adjudication
   latency **unlabeled** (bucket series multiply per label value — a verdict label is a forbidden
   new dimension, `system_id` would multiply × routing table); per-PDU transit labeled
   `{direction}` only. Pre-registered at construction (the `MeteredRelayObserver` ctor pattern,
   `MeteredRelayObserver.java:124-168`), throw-isolated recording (the existing catch-guard +
   `fireGuarded` posture). Hook points confirmed by this audit: bind = the existing settle
   points (arm at `BindInterceptor.java:545`'s `ChannelTimer` window / the verifier settle — both
   today untimed); PDU transit = stamp at ingress framed-PDU arrival, record at egress forward,
   carried to the observer via the Q1=B seam change (never double-stamped inside relay internals).
2. **Task 3 (tests)** — update the 38-meter pin (`MeteredRelayObserverTest:127`) and the 4-method
   shape pin (`RelayObserverShapeTest:49-56`); add the once-per-event, bucket-bound,
   cardinality-attack, and throw-isolation rows per the story's I/O matrix.
3. **Task 4 (runbooks)** — `/metrics` reference rows for the new `_bucket`/`_sum`/`_count` series
   (name, type, labels, bucket anchors, recording semantics) at `docs/runbooks.md:214-241`.
4. **Task 5 (addendum A2)** — dated note recording the landed bucket choices (`addendum.md:30`'s
   own pointer: "Bucket choices and scrape-impl → here, not the PRD").
5. **Task 6 (spine)** — retire the Deferred histogram item (`ARCHITECTURE-SPINE.md:409`) with a
   dated amendment + `.memlog.md` entry.
6. **Task 7 (ledger)** — append `deferred-work.md` entries for G3, G6, G7 (source_spec, summary,
   evidence — the ledger's current field shape).

The audit report itself changes no code, no story checkboxes, and no ledger rows.
