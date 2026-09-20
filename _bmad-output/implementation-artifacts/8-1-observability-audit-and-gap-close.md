---
title: 'Story 8.1 — Observability/measurability audit + gap close'
type: 'feature'
created: '2026-09-19'
status: 'in-progress'
route: 'dispatch'
baseline_commit: '86f02cf5a79d7b833dc104b1e3f2ee3ef02ac701'
review_loop_iteration: 0
context:
  - {project-root}/_bmad-output/implementation-artifacts/epic-8-context.md
  - {project-root}/_bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/ARCHITECTURE-SPINE.md
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The proxy's observability surface (JSON-lines logs + loopback-only `/metrics`) has never been audited end-to-end against operator needs. It exposes counters and gauges only — the spine-Deferred "Prometheus histogram buckets / scrape-handler exacts" item means operators get zero latency signal, and no cited-evidence audit exists to say what else is missing.

**Approach:** Run a cited-evidence audit of the full surface — metrics vs PRD FR-OBS-1/2 + addendum A2, log events vs FR-OBS-1, handler exacts vs AD-19 — landing as a dated report. Close the measurable gaps in code — **both addendum-A2 latency histograms (owner decision 2026-09-19, Open Question 1 = B: bind adjudication latency, unlabeled; per-PDU relay transit `{direction}`)**, under AD-19 cardinality, no new label dimensions. Ledger every gap not closed. Retire the spine-Deferred item with a dated amendment.

## Boundaries & Constraints

**Always:**
- AD-19 posture byte-intact: literal `127.0.0.1` bind, dedicated `companion-metrics` loop, GET-only exact `/metrics`, read-only exposition (no scrape counter), one-shot connections.
- Cardinality mechanism unchanged: construction-time pre-registration from closed sets; labels reuse existing dimensions (`direction`, routing-table `system_id`) or stay unlabeled; bucket series multiply per label combination — keep the grid bounded.
- Any new recording site is throw-isolated — never throws into the verdict/relay path.
- Every audit finding is closed (biting test cited) or ledgered in `deferred-work.md` (evidence cited). Nothing silently dropped.
- Bucket choices + scrape-impl recorded where addendum A2 points (addendum + runbooks; `prd.md` untouched); `codec/` stays meter-free (AD-27); TRACE-gating and content-never-emitted rules stand.

**Never:**
- No new label dimensions; no `command_id`/`ChannelId`/free-form `system_id` labels.
- No host config key, no non-loopback bind, no Actuator/web stack, no dashboard/telemetry backend/management API.
- No message/PDU content in metrics or logs.
- No sandbox-Prometheus, CI, or docs-publish work (Stories 8.2/8.3); no Epic-7 harness metrics.
- The `RelayObserver` seam change Q1=B requires lands ONLY as an explicit, dated contract change: shape test updated in-step + Spec Change Log entry; no silent bypass. Per-PDU recording is throw-isolated and adds no label beyond `direction`.
- No auto-reformat of untouched code — hand style stands.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| Bind adjudicated (reverse cell) | ROPC verdict Allow or any Deny class | Ratified histogram records duration exactly once per completed adjudication | Recorder catch-guarded; verdict path unaffected |
| Per-PDU relay transit | Post-couple framed PDU (both directions) | Histogram per existing `direction` dimension; bounded sub-ms→s buckets; one record per relayed PDU | Same throw isolation |
| Cardinality attack | Many distinct unknown `system_id`s bind | Zero new series (unchanged); unlabeled overflow counters absorb | N/A |
| Scrape after histograms land | `GET /metrics` | Existing series + histogram `_bucket`/`_sum`/`_count` rows; shape-idempotent across scrapes | 405/404/413/500 rows unchanged |
| Audit finding outside close scope | Any gap not closed here | `deferred-work.md` entry (source_spec, summary, evidence) | N/A |

</frozen-after-approval>

## Code Map

- `proxy/.../observability/` — `ObservabilityConfig` (sole `PrometheusMeterRegistry` bean; binds JVM binders), `MeteredRelayObserver` (`@Primary`; pre-registers the counter surface at construction), `MetricsEndpointLifecycle` (SmartLifecycle; literal `LOOPBACK_BIND_HOST`; dedicated 1-thread loop; absent node = down; occupied port = fail-fast), `MetricsHttpHandler` (GET-only exact path; caps 1024B/8KiB/8KiB; `Connection: close`; scrape-throw → 500), `ResourceMetrics` (2 gauges), `RelayObserver` (4-method seam), `CloseReason`/`Direction` (closed enums), `logback-spring.xml`.
- Current meters (NO timer/histogram exists): `relay_pdus_total{direction}`, `relay_binds_accepted_total{system_id=routing table}`, `relay_binds_rejected_total`, `relay_binds_unknown_total` (unlabeled), `relay_connections_closed_total{direction,reason}` (2×16), gauges `relay_direct_memory_used_bytes` / `ropc_adjudications_active`, JVM binder families.
- Latency hook points: `RequestContext(SystemId, ChannelId, Instant deadline)`; `BindInterceptor`'s `ChannelTimer` arm at `adjudicate` / cancel at `onVerdict`; `RopcBindCredentialVerifier` settle (untimed today; zero `System.nanoTime` in main sources).
- Tests `proxy/src/test/.../observability/`: `MetricsEndpointTest` (source-pins loopback literal + no host key), `MeteredRelayObserverTest` (cardinality attack; 38-meter pin — UPDATE on new meters), `RelayObserverShapeTest` (4-method pin), `ObservabilityLayerRulesTest` (Netty ban), `ThrowingObserverHardeningTest`. Config: `companion.metrics.port` only — no new keys expected.
- Planning: spine Deferred ~line 409 (the item retired here); `addendum.md` A2 ("Optional histograms: per-PDU relay latency, bind latency … Bucket choices and scrape-impl → here, not the PRD"); PRD FR-OBS-1/2, OBS-1/2, PERF-3 (p99 ~250 ms warm / ≤2 s cold / 2–5 s DENY clamp; `adjudication-deadline` default 4 s); `docs/runbooks.md` "The `/metrics` reference" (~line 184; no RU mirror).
- Report precedent: dated file at implementation-artifacts root (cf. `epic-1-retro-2026-08-08.md`).

## Tasks & Acceptance

**Execution:**
- [x] `_bmad-output/implementation-artifacts/observability-audit-2026-09-19.md` -- dated audit report with cited evidence: (a) metrics vs addendum A2 + FR-OBS-2, (b) log events vs FR-OBS-1/A2, (c) handler exacts vs AD-19, (d) gap table — closed-here | ledgered, every row cited. -- The audit gates the close list.
- [x] `proxy/.../observability/` + the timing hook points (`BindInterceptor`/verifier settle for bind; the relay ingress/egress seam for PDU transit) -- implement BOTH ratified histograms: bind adjudication latency (unlabeled, PERF-3-anchored buckets) + per-PDU relay transit (`{direction}`, sub-ms→s buckets); pre-registered at construction, throw-isolated recording; the `RelayObserver` seam change lands with its shape-test update in-step. -- Closes the spine-Deferred measurable gap.
- [x] `proxy/src/test/.../observability/` -- update the meter-count pin + shape-test pin; new tests: bind records once per completed adjudication (Allow AND each reachable Deny class), PDU records once per relayed PDU per direction, buckets bounded, cardinality attack still zero-series, recorder throw-isolation; cover the I/O matrix rows. -- Mutation-resistant pinning per house rules.
- [x] `docs/runbooks.md` -- `/metrics` reference rows for the new histogram series (name, type, labels, bucket anchors, recording semantics). -- Operator docs must match the exposition.
- [x] `.../prds/prd-smpp-companions-2026-07-18/addendum.md` -- A2: dated note recording the landed bucket choices. -- A2's own pointer requires it.
- [ ] spine `ARCHITECTURE-SPINE.md` + `.memlog.md` -- retire the Deferred item with a dated amendment. -- Spine stays true; contract-amendment discipline.
- [ ] `_bmad-output/implementation-artifacts/deferred-work.md` -- append one entry per audit gap NOT closed here. -- "Closed or explicitly ledgered" is the epic's bar.

**Acceptance Criteria:**
- Given a running reverse-cell proxy with adjudicated binds (≥1 Allow, ≥1 Deny) and relayed PDUs, when scraping `/metrics`, then BOTH histograms' `_bucket`/`_sum`/`_count` series appear — bind unlabeled, PDU transit `{direction}` only, documented bounded buckets, no other new series.
- Given the audit report, every enumerated gap carries a closed-here citation or a `deferred-work.md` entry — zero uncited rows.
- Given the ratified seam change, `RelayObserverShapeTest` is updated in-step (dated Spec Change Log entry) and still pins the contract exactly — no unpinned methods.
- Given `MeteredRelayObserverTest`, the pinned meter count includes every new series and passes on `clean build`.
- Given two consecutive scrapes, the series set is shape-idempotent (no scrape counter, no runtime-created series).

## Implementation Notes

## Spec Change Log

- **2026-09-19, Task 2 — `RelayObserver` seam extended for the ratified Q1=B histograms (explicit, dated; no silent bypass).** Owner decision 2026-09-19 (Open Question 1 = B) required carrying durations to the observer; landed as TWO visible contract edits, pinned in-step in `RelayObserverShapeTest` (4-method pin → 5, every method re-pinned):
  1. `onFramedPdu(Direction)` → **`onFramedPdu(Direction, Duration transit)`** — the per-PDU relay transit (framed-PDU arrival at the relay seam → forward onto the peer leg), stamped/computed at the single fire site in `CoupledRelayHandler.relayFramedPdu`, one call per relayed PDU, adds no label beyond `direction`.
  2. New fifth trigger **`onBindAdjudication(Duration latency)`** — fires exactly once per completed adjudication at the settle funnel (`BindInterceptor.onVerdict`), for every settled verifier future alike (Allow, `Deny*`, exceptional, cancel-aborted); never for never-armed arms (synchronous blow-up / null return) or non-verdict denials (routing miss, gate). Unlabeled. This method is the bind-histogram's recording route chosen over the Design Note's "inside the verifier's settle" alternative so `security/` stays meter-free and `MeteredRelayObserver` stays the single meter source (AD-27).
  A `Duration` is a timing scalar — no PDU type, no content, no new label dimension (AD-19/AD-27 hold). Fixture doubles (`CapturingRelayObserver`, `ThrowingRelayObserver` + its `Trigger` set) and their self-smoke followed mechanically; `MeteredRelayObserverTest`'s 38-meter pin is left red for Task 3 per the T2/T3 split (noted in that file).

## Review Triage Log

*Round 2026-09-20 (post-T4 review; layers: blind-hunter 12, edge-case-hunter 3, verification-gap 2 pre-verified gaps + 1 other). No intent_gap, no bad_spec — no loopback.*

- **`false`** — ECH: deadline/teardown-aborted adjudications never settle (cancelHttp aborts without completing the future) → histogram undercounts DENY-clamp population. Disproved: `RopcBindCredentialVerifier`'s `cancelHttp` ALWAYS completes the pin (`DenyIndeterminate` — its own javadoc, ~:853-856), and `BindAdjudicationRecordingTest:215` pins the cancel-aborted settle row; the F14 deadline path routes through the same settle funnel. The bad outcome does not occur today. *(The related doc-citation defect is the E2 row below.)*
- **`medium`/patch** — E2: `BindInterceptor` settle-funnel javadoc cites "the port's no-op-if-done contract" for the cancelHttp pin-settle; the `VerdictRequest` port is settlement-silent ("the Verdict (if any) is observed via `future()`"), the settle is the ROPC adapter's own guarantee — a future port-conforming adapter silently breaks deadline-abort recording while the doc claims contract backing. Reword to the adapter guarantee.
- **`medium`/patch** — transit-window javadoc overstated (ECH#3 + BH#6 + VG-other, one root cause): `CoupledRelayHandler.relayFramedPdu` javadoc claims the two clock reads book-end "the pre-forward processing (entry lookup, coupled check, peer-liveness)" — the entry lookup and coupled check run in the `channelRead` prelude BEFORE the stamp; only the channel/peer fetch + liveness sit inside. The runbook row's "arrival at the relay seam → forward" stays accurate (the seam IS `relayFramedPdu` entry). Fix the parenthetical.
- **`medium`/binds-T6** — spine AD-27 and the `epics.md` AD-27 twin still pin the 4-method `onFramedPdu(Direction)` enumeration, false vs the landed 5-method seam; T6's task text names only the Deferred retirement. T6's acceptance clause "Spine stays true" binds the dated amendment to cover the AD-27 method-list refresh (+ the epics.md twin) alongside it. Logged now; closed in the T6 round.
- **`medium`/patch** — runbook adjudication row reads role-neutral: forward cells wire the `AlwaysAllowBindCredentialVerifier` stand-in (`VerifierWiringConfig`: reverse leaf → ROPC, else AlwaysAllow), so every forward bind records ~0 — the series is the reverse cell's ROPC signal. The page's own precedent (`relay_binds_accepted_total` "series only on forward cells", runbooks.md:73) is to note the asymmetry. Add the role note.
- **`medium`/patch** — no end-to-end guard for the new histogram surface: `PackagedBootSmokeTest`/`ComposedPackagedE2eTest` scrapes after real traffic assert counters only; a pipeline wiring regression leaving the histograms dead passes every test. Extend the existing scrape assertions with the transit `_count` rows (and the forward cell's adjudication `_count` 1.0 — its AlwaysAllow settle records; the reverse e2e bind is a routing miss, structurally 0, not worth pinning).
- **`medium`/patch (pre-verified)** — VG: the transit duration carry at the fire site is unpinned — `Duration.ZERO` at `CoupledRelayHandler:~200` left the whole suite green (empirical mutation, reverted); only `isNotNegative` asserts the value. Add a strictly-positive assertion (any-of over the full-cycle row's fired PDUs, robust to clock granularity).
- **`medium`/patch (pre-verified)** — VG: the adjudication-latency carry at the settle site is unpinned — `Duration.ZERO` at `BindInterceptor:~672` shipped green; `BindAdjudicationRecordingTest:126-128` asserts non-negativity only. Add `isStrictlyPositive()` in the deny-settle row (deterministic: the settle provably spans the arm plus intervening work).
- **`low`/patch** — burst row of `MeteredRelayObserverTest` fires 50 transits (alternating directions) but never asserts the 25/25 landing on the two pre-registered series (the dedicated per-direction row pins recording with direct fires). Two assertion lines.
- **`low`/patch** — `MeteredRelayObserver` class javadoc: "onBindAdjudication, carrying the same per-bind cadence as the reject line whose verdict it precedes" — false for `Allow` (no reject line on accept). Reword.
- **`low`/patch** — `NoopRelayObserver`: the T2 rewrite left "before the real observability body lands" stale in the very sentence it rewrote (that body landed Epic 4, as the sentence now says). Fix the tail.
- **`low`/patch** — `MetricsEndpointTest:222` asserts `relay_pdus_transit_seconds_sum{direction="INGRESS"} 0` only — a dropped EGRESS `_sum` row would pass. Add the EGRESS twin.
- **`low`/patch** — runbook histogram block lacks the scrape fan-out row counts (adjudication 10 rows = 8 buckets + `_sum` + `_count`; transit 22 = 2×(9+2)); operators diffing a scrape must derive them from the edge lists. One clause.
- **`medium`/binds-T5** — post-T2 scrape arithmetic (41 observer meters; series totals vs the audit's frozen 87/86 series + 38 meters) recorded nowhere — the next live conformance check has no current arithmetic. The A2 dated note (T5) is the designated home. Logged now; closed in the T5 round.
- **`reject`** — story Code Map stale after T2/T3 (4-method seam, "NO timer/histogram exists", 38-meter pin) — the fix edits this build's spec; the Spec Change Log above and the code remain the record.
- **`reject`** — story Implementation Notes empty with four tasks checked — the fix edits this build's spec; per-task commits and this log are the record.

*Patch round 2026-09-20: all 11 patch items applied and re-verified (37/37 green across the six covering suites, cleanTest-forced). Two instruction corrections during patching, both verified against the code before landing: timer `_count` rows render integer (`… 1`), unlike counters (`1.0`); the reverse cell of the composed rig DOES settle an ROPC Allow (the routing-miss arm is forward-only, `BindInterceptor:407`), so its adjudication `_count` 1 is pinned too. The two binds-T5/T6 rows above remain open for their rounds.*

*Round 2026-09-20 (post-T5 review; layers: blind-hunter 11, edge-case-hunter 3, verification-gap 1 pre-verified gap + 1 other). No intent_gap, no bad_spec — no loopback. The binds-T5 row above is CLOSED by this round: the A8 note records the scrape arithmetic. Only binds-T6 remains open.*

- **`medium`/patch** — the runbook transit fan-out count is wrong and mixes counting conventions in one sentence (BH1 + ECH1 + VG-other + the T5 implementer's report, four independent findings): `docs/runbooks.md:238` "transit 22 rows = 2 × (9 buckets + `_sum` + `_count`)" — the pinned grid is 9 edges + `+Inf` = 10 bucket rows per direction (`MeteredRelayObserverTest:297-302` `containsExactly` incl. `+Inf`), so 24 rows; the same sentence's adjudication "8 buckets" counts `+Inf` while transit's "9 buckets" does not. The slip entered in the T4 triage row's own patch instruction ("transit 22 = 2×(9+2)") and rode into the runbook verbatim; the A8 note landed in this diff already recording 24 as the arithmetic of record — a knowingly-contradicted operator doc must not ship. Fix the count to 24/10-buckets and update A8 bullet 5 to record the fix landed (same round).
- **`medium`/patch (pre-verified)** — VG + BH7, one root: the F14 deadline-exchange adjudication record is unpinned — no test fires the deadline arm and asserts the record (VG's filed mutation: nulling the arm at `onAdjudicationDeadline` ships every suite green while the runbook's "a deadline deny records at ~the deadline" promise silently breaks — the DENY-clamp population on the only cell where the series carries signal). Pin it in `BindInterceptorTest.neverSettlingVerifierIsDeniedAtTheConfiguredDeadline` after the existing late-settle pump: exactly one record, strictly positive.
- **`low`/patch** — BH3: the new integer timer `_count` scrape pins are substring-prefix unanchored (`.contains("…_count 1")` matches `_count 10`+; counters are safe only via their `.0` suffix) across both packaged rigs. Anchor each with a trailing newline.
- **`low`/patch** — BH4: `PackagedBootSmokeTest` pins the transit `_count` rows but not the adjudication `_count`, though its bind demonstrably settles a genuine Allow (its own comment, `:396`); the composed rig pins both cells. A pipeline regression killing only the adjudication histogram passes the smoke rig. Add the pinned row (anchored).
- **`low`/patch** — BH8: the runbook adjudication row states cancel/deadline settle-recording unconditionally ("that cancellation is itself a settle"), dropping the adapter-dependence caveat the E2 patch put into the code javadoc — a future port-conforming adapter (settlement-silent port) silently stops deadline/teardown recording while the operator doc asserts it as contract. Carry one caveat clause.
- **`low`/patch** — BH9: A8's arithmetic bullet bakes the 2-id-table constants ("41", "121") into "the baseline for the next live conformance check" without the N-dependence (the bullet's own breakdown says "2 accept"); a conformance check on an N-id table fails against a number that was never table-independent. Add the formula clause: N-id forward cell = 39+N observer meters / 119+N scrape rows; reverse 39/120 exact (empty table).
- **`low`/patch** — BH11: `BindAdjudicationRecordingTest:143` as-text "(uninstrumented here) reject trigger" over the very `bindRejects()` assertion it labels — the trigger IS captured and asserted there; "uninstrumented" can only mean "no Micrometer meter", which the reader must guess. Drop or reword the parenthetical.
- **`false`** — ECH2: `RejectedExecutionException` from `timer.schedule` after the arm strands the settle (no `whenComplete` → unrecorded adjudication). Disproved as an operational outcome: the production timer is the ingress loop's own scheduler (`BindInterceptor:189-190`), rejection exists only past `shutdownGracefully`'s quiet+timeout grace; the ONLY group-shutdown caller runs in `stop()`'s finally AFTER deny+drain (`ProxyCompanionLifecycle:201-221`), the new-adjudication gate armed at acceptor stop (`BindInterceptor:134,194`) gates fresh binds first, and the single-threaded loop serializes a running channelRead ahead of any queued teardown — so reaching rejection requires a pre-gate bind still grinding a multi-second backlog past the shutdown cap (the documented wedged-loop degenerate, `ProxyCompanionLifecycle:225-228`), where the throw routes to `exceptionCaught` fail-closed teardown and the process is committed to exit with the arena (the residual one missed record/frame dies with the JVM). No in-operation undercount occurs.
- **`false`** — BH2: the transit window is "too thin to deliver its purpose" / the runbook misdescribes it. The thinness is real (the window is `peerOf` + `isActive` between two `nanoTime` reads, `CoupledRelayHandler:190-202`) and fully disclosed: the runbook row states the seam-to-forward window and explicitly excludes the peer's write; the javadoc names exactly what sits inside; A8 says the same. The Design Note's wider stamp ("ingress framed-PDU arrival") would add only the prelude's ~µs field reads — same metric character; decode is structurally un-includable (codec is meter-free, AD-27) and end-to-end per-PDU latency is the Epic-7 harness's charter, which this story's Never list excludes. No ratified text promises what the reviewer says it does; no false sentence to fix.
- **`false`** — BH6: the Allow-arm throw isolation is "unpinned". `recordAdjudicationLatency()` fires at `onVerdict` entry BEFORE the race-free re-check and any verdict branching (`BindInterceptor:586-588`) — the deny-arm row 5 of `ThrowingObserverHardeningTest` proves that exact statement's isolation; the Allow path executes the identical call site with no verdict-dependent code between fire and `openEgressAndForward`. The isolation is not verdict-dependent, so the existing row pins it.
- **`false`** — BH10: `MetricsEndpointTest:218`'s `le="1.0E-4"` literal is a "formatting artifact" pin. The pin matches the exposition bytes operators' Prometheus parsers consume — a rendering change IS a scrape-surface change and should flip the test; the proposed parse-based idiom would silently accept consumer-visible drift (the grid-pin test already parses edges where parsing is the point, `MeteredRelayObserverTest:297-302`).
- **`reject`** — BH5: the binds-T5 row "not closed by the diff" — the fix edits this build's spec; the round header above closes it, and the round's closing note below records the patch outcome.
- **`reject`** — ECH3: "task 4 checked while the shipped doc contradicts the exposition" — the fix edits this build's spec (the checked task's record is the spec); the substance is the runbook count slip, patched by the first row above.

*T5 patch round 2026-09-20: all 7 patch entries applied and re-verified — full `clean build` GREEN, 65/65 across the eight covering suites (BindInterceptorTest 22, ThrowingObserverHardeningTest 8, MetricsEndpointTest 11, BindAdjudicationRecordingTest 5, MeteredRelayObserverTest 5, RelayObserverShapeTest 10, PackagedBootSmokeTest 2, ComposedPackagedE2eTest 2; XML filename-matched — the display-name trap). Two smallest-diff tail-edits by the implementer, both verified against the diff: A8 bullet 5's "states" → "stated" (the bullet now tells the slip as past tense after the same-round fix), and the new F14 pin's comment states the fixture truth (the latched stand-in settles at `completeAllow`; the production adapter settles inside `cancelHttp`) — the pin guards the shared settle funnel either way. The new deadline pin directly reads the record the VG mutation erases, so it bites structurally. Only binds-T6 remains open, for the spine round.*

## Design Notes

- Bind-latency hook: record at the existing settle points (`ChannelTimer` arm/cancel → duration = now − arm) or inside the verifier's settle. Buckets anchored to PERF-3: cover ~[50 ms … 8 s] so warm p99 (~250 ms), cold ≤2 s, and the 4 s deadline each fall between edges; exact edges are implementation-owned, recorded in addendum A2 + runbooks.
- PDU-transit hook: stamp at ingress framed-PDU arrival, record at egress forward — extend the seam minimally (carry the duration/timestamps to the observer) rather than double-stamping inside relay internals; buckets span sub-ms→s so the sub-ms PERF-4 budget is visible below 1 ms.
- Why bind stays unlabeled: bucket series multiply per label value; a verdict-class label would add a dimension (forbidden); `system_id` would multiply × routing table.
- Audit method: inventory from a live scrape + the existing source-pin tests, cross-checked row-by-row against A2 / FR-OBS-1 / FR-OBS-2; each row cites file:line or test name.

## Verification

**Commands:**
- `./gradlew clean build` -- expected: GREEN (clean, not incremental — source-scan tests silently skip on UP-TO-DATE otherwise)
- `./gradlew :proxy:test --tests '*MeteredRelayObserverTest' --tests '*MetricsEndpointTest'` -- expected: updated pins pass (after a clean)
