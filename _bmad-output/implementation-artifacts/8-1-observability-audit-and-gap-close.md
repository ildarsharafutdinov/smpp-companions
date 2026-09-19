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
- [ ] `docs/runbooks.md` -- `/metrics` reference rows for the new histogram series (name, type, labels, bucket anchors, recording semantics). -- Operator docs must match the exposition.
- [ ] `.../prds/prd-smpp-companions-2026-07-18/addendum.md` -- A2: dated note recording the landed bucket choices. -- A2's own pointer requires it.
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

## Design Notes

- Bind-latency hook: record at the existing settle points (`ChannelTimer` arm/cancel → duration = now − arm) or inside the verifier's settle. Buckets anchored to PERF-3: cover ~[50 ms … 8 s] so warm p99 (~250 ms), cold ≤2 s, and the 4 s deadline each fall between edges; exact edges are implementation-owned, recorded in addendum A2 + runbooks.
- PDU-transit hook: stamp at ingress framed-PDU arrival, record at egress forward — extend the seam minimally (carry the duration/timestamps to the observer) rather than double-stamping inside relay internals; buckets span sub-ms→s so the sub-ms PERF-4 budget is visible below 1 ms.
- Why bind stays unlabeled: bucket series multiply per label value; a verdict-class label would add a dimension (forbidden); `system_id` would multiply × routing table.
- Audit method: inventory from a live scrape + the existing source-pin tests, cross-checked row-by-row against A2 / FR-OBS-1 / FR-OBS-2; each row cites file:line or test name.

## Verification

**Commands:**
- `./gradlew clean build` -- expected: GREEN (clean, not incremental — source-scan tests silently skip on UP-TO-DATE otherwise)
- `./gradlew :proxy:test --tests '*MeteredRelayObserverTest' --tests '*MetricsEndpointTest'` -- expected: updated pins pass (after a clean)
