---
title: 'Story 4.3 — AD-22 graceful shutdown pt. 2: the connection drain body'
type: 'feature'
created: '2026-09-04'
status: 'in-progress'
review_loop_iteration: 0
baseline_commit: e614291ae4e4890f92127fcd268602dae1634754
context:
  - /home/ildar/Documents/smpp-bmad/_bmad-output/implementation-artifacts/epic-4-context.md
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Story 4.2's coordinator skeleton walks an empty drain seam — on SIGTERM established pairs are still torn down at loop quiesce with no drain window, mid-write PDUs can be cut, there is no way to enumerate live pairs, no drain deadline, and no gate against adjudications starting after the acceptor stops.

**Approach:** Fill AD-22 step 3 end-to-end: a read-only `ConnectionRegistry` enumeration surface (with a mutation fence), the `companion.shutdown.drain-timeout` key (Clock-injectable, default 10s), the drain body — enumerate pairs, let in-flight writes flush and peers half-close until the deadline, force-close the remainder stashing `CloseReason.SHUTDOWN_DRAIN` — and the new-adjudication gate (fail-closed DENY after acceptor stop, OBS-017). Prove the full six-event ordering (OBS-016), drain integrity (RELAY-022), and force-close at deadline (OBS-020).

## Boundaries & Constraints

**Always:**
- The coordinator order completes the spine (ARCHITECTURE-SPINE.md:196-199): acceptor-stopped (4.2) → adjudications-denied (4.2) → **drain: enumerate → drain to deadline → force-close remainder** → vt-drained (4.2) → exit. Drain sits strictly between deny and release-await; 4.2's ordering prefix pin EXTENDS to the six-event probe — it is not re-authored.
- Enumeration is a read-only snapshot on `ConnectionRegistry` (its `size()` javadoc at :128-131 already names "AD-22 drain enumeration"; `ConnectionRegistryTest:267` pre-pins no-orphans). ALL mutation still routes through `RelayStateManager` — the single-sited hygiene (`cancelHttp()` + password zeroize) is untouched. An ArchUnit rule fences registry mutators to the state manager (and tests).
- The gate: after the acceptor stops, `BindInterceptor.adjudicate()` fail-closed-DENYs any bind on an established socket without contacting the verifier — non-ROK `bind_resp`, no registry entry (OBS-017). New connects are refused by the closed listener.
- Force-close at the deadline stashes `CloseReason.SHUTDOWN_DRAIN` (the pre-staged unfired value, CloseReason.java:102-103) — never `OTHER`; no half-flushed PDU on the wire (OBS-020).
- `companion.shutdown.drain-timeout` (Duration): default 10s in `application.yml`, strictly below the 30s phase window (application.yml:17-19); lands in `ProxyCompanionProperties` per house rules (no `@DefaultValue`, `ignoreUnknownFields=false`, compact-ctor positive guard) and in `TestCompanionConfigs.common()` for runner boots.
- The deadline is Clock-injectable — no real wall-clock waits in tests (RELAY-022; OBS-020 blind-spot 5).
- Registry reaches zero with sequence-number integrity and no dropped/corrupt PDUs (RELAY-022); a backlog larger than the deadline drains is force-closed in bulk and stop still returns inside the 30s window (bounded WARN).

**Ask First:**
- The gate cannot hook `adjudicate()` locally (needs structural relay changes) → HALT.
- Clock injection needs widening `RequestContext`/verifier surfaces → HALT.
- Deadline semantics force changes in `security/` → HALT with options.
- Any new dependency or `smpp.runtime-purity` gate edit → HALT with the proposed diff.

**Never:**
- No relay-timeout round — adjudication-deadline arming, egress connect bounding, ingress `bind_resp` forwarding, idle reaper (story 4.4).
- No packaged-shape SIGTERM→PID-1 validation (DEPLOY-006, Epic 5); no under-load shutdown proof (PERF-061, Epic 6).
- No operator-triggered drain/query/reload — drain runs ONLY inside context close (OBS-3).
- No observer/endpoint changes (4.1 is done); `SHUTDOWN_DRAIN` becoming a fired value is the only observability delta.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| SIGTERM mid-splice | N coupled pairs relaying traffic | six ordered events; pairs drain; registry → 0; no dropped/corrupt PDUs (RELAY-022) | N/A |
| Peer never half-closes | quiescent-but-open pair at deadline | force-close stashed `SHUTDOWN_DRAIN`; exit proceeds; no half-flushed PDU (OBS-020) | bounded WARN |
| Backlog > deadline | more traffic than the window drains | all remaining pairs force-closed at deadline; stop returns inside the 30s window | bounded WARN |
| Late bind on live socket | bind sent after acceptor stop | DENY (non-ROK `bind_resp`), no verifier contact, no registry entry (OBS-017) | N/A |
| New connect after stop | TCP connect to the bind port | refused (listener closed) (OBS-017) | N/A |
| Empty registry | SIGTERM with zero pairs | drain is a fast no-op walk | N/A |
| Invalid drain-timeout | binding `""`/non-positive/non-duration | fail-fast at config bind (invalid value, not key-removal) | startup refuses |

</frozen-after-approval>

## Code Map

*(Anchors re-verified at post-4.2 HEAD `e614291`.)*

- `proxy/src/main/java/smpp/companion/proxy/relay/ConnectionRegistry.java:43,57-131` — `ConcurrentHashMap<ChannelId,ConnectionEntry>` keyed by ingress id; NO enumeration today (`register`:57, `attachEgress`:72, `entryFor`:87, `beginTeardown`:106 CAS-once, `size`:129 — javadoc names "AD-22 drain enumeration"). Every mutator's only production caller is ALREADY `RelayStateManager` — the fence formalizes a true invariant. `ConnectionEntry.java:44` — public-final but PACKAGE ctor, pending handles package-private → the snapshot exposes a small relay-owned projection (ingress+egress channels, systemId), never the entry itself.
- `proxy/src/main/java/smpp/companion/proxy/relay/RelayStateManager.java:137-167,175-188` — `beginTeardown(Channel)` → sealed `Teardown.Won(entry)/Lost`; `cancelHttp` (:147-153) + password zeroize (:156-162) run before `Won` returns. NO reason stash in the manager — stashing is caller-side `CoupledRelayHandler.stash` (:363-365, package-private) → force-close composes as a manager method, keeping the fence intact.
- `proxy/src/main/java/smpp/companion/proxy/relay/BindInterceptor.java:245-288,403-445` — THE GATE SEAT: `onRequest`'s `entry == null` new-bind arm (:248-259) — the routing-miss precedent (release frame + `writeBindFailureAndClose`; no entry, no verifier, no observer fire). `register` (:263) precedes verifier contact (:313), so the gate sits BEFORE register — OBS-017's no-registry-entry demands it. Post-couple arm (:265-277) must keep relaying during drain. Deny write path: `denyAndTeardown`:403, `writeBindFailureAndClose`:421, `synthesizeBindFailure`:432 (status `0x0000000D`). Per-channel ctor (:166-172, built in `RelayIngressInitializer`:74) — no lifecycle flag injectable today.
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayServerLifecycle.java:84,121-138` — acceptor-close-only stop (:133); `running` (:84) private, `isRunning()` (:138) has zero readers → the gate needs NEW shared state, armed here (step 1 = "no new binds").
- `proxy/src/main/java/smpp/companion/proxy/bootstrap/ProxyCompanionLifecycle.java:74-155` — ctor (:99-104) takes ONLY verifier+group (adapter narrowed :102 — null on forward cells) → widens with registry + manager + `Shutdown` props + `Clock`. Walk (:122-144): deny:133 → seam call:135 → release:137 → finally quiesce:140-142 (`SHUTDOWN_QUIET_PERIOD_MS=100`:81, `SHUTDOWN_TIMEOUT_MS=2_000`:84; phases — app 0:74, deny 750, metrics 500, acceptor 1000). THE SEAM: `drainRelayedConnections()`:153-155, contract javadoc :146-152.
- `proxy/src/main/java/smpp/companion/proxy/observability/CloseReason.java:52-53,103` — `SHUTDOWN_DRAIN` declared, ZERO firing sites (grep-verified); the reserved-list javadoc still says "story 4.2" — update when it fires.
- `proxy/src/main/java/smpp/companion/proxy/config/ProxyCompanionProperties.java:43-62,367-392` — top record nests Bind/Memory/Tls/Forward/Reverse/Metrics (:49-61; compact single-branch ctor :71-80). `Bind` is the `Shutdown` precedent: annotated fields :368-375 + compact-ctor `requireNonNull`:385 + positive IAE :386-390 (Metrics javadoc :408-412 explains the dual guard — BV fires only on the binder path). `ignoreUnknownFields=false` (:43) → yml key + record land together.
- `proxy/src/main/resources/application.yml:17-19,29-86` — the 30s per-phase ceiling; companion tree: `bind`:31 (`adjudication-deadline: 4s`:42 — the Duration-with-yml-default precedent), `memory`:49, `tls`:63, `metrics`:85 → the `shutdown:` block lands right after.
- Tests: `config/TestCompanionConfigs.java:152-191` — `common()`; the no-yml rule (:167-171: runner boots state every required key). `config/CompanionConfigMatrixTest.java:239-247` — bind-the-invalid-value pattern, never key removal. Record-ctor builders `GracefulShutdownRacesTest.reverseBProperties`:599-624 (6 args, last `null` = metrics) and `ProxyCompanionLifecycleTest.reverseBProperties`:309-329 — both gain the `Shutdown` component.
- `bootstrap/GracefulShutdownRacesTest.java:314-380,439-517,653-667` — the ordering-prefix row (4 watchers on a daemon pool, `pollStamp` 5ms/15s; chain asserted :363-370) EXTENDS to six events; rig overloads :439-445/:456-517 (the `oidcTimeout` Duration arg is the knob pattern); coordinator constructed directly (:478 — a decorated registry can stamp drain-started); `RecordingVerifier`:527-558.
- `bootstrap/ProxyCompanionLifecycleTest.java:218-271` — idle <1.5s bound (:235 says "no drain body yet — 4.3") + the SOURCE-SCAN walk pin :243-271 (stays as belt; T6 adds the behavioral pin). Direct ctor sites (:91, :149, :196, :224) re-sign.
- `bootstrap/BootstrapLifecycleTest.java:66-92` — idle <5s bound; rationale (:83-88) names this story's coupling.
- `relay/ConnectionRegistryTest.java:254-270` — the no-orphans pin (:267) + 12 sibling pins the snapshot must not break.
- ArchUnit substrate: `proxy/build.gradle.kts:35` (archunit-junit5 1.4.2); `relay/RelayCoupleSiteArchitectureTest.java:43-66` — the model (forbid rule + positive control, `class.getName()` refs, `@AnalyzeClasses(packages="smpp.companion.proxy", DoNotIncludeTests)`).
- Clock: ZERO usage repo-wide today — a `@Bean Clock.systemUTC()` (RelayNettyConfig/VerifierWiringConfig style) is the first; ONLY the coordinator's deadline consumes it.
- Catalog rows: `_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md` — OBS-016 (:1164, six events, pairwise first-timestamps), OBS-017 (:1170), OBS-020 (:1189, injectable Clock mandatory), RELAY-022 (:451).

## Tasks & Acceptance

**Execution:** *(one task per conversational step, one commit per task — house rule)*

- [x] **T1 — enumeration + mutation fence** — `ConnectionRegistry`: read-only snapshot projection (ingress+egress channels, systemId — never `ConnectionEntry`); unit rows: empty, N pairs, snapshot isolated from later mutation, the :267 no-orphans pin stays green. ArchUnit: mirror `RelayCoupleSiteArchitectureTest` (forbid + positive control) fencing `register`/`attachEgress`/`beginTeardown`/attribute clears to `RelayStateManager` + tests; widen the couple rule to any-arity (3.4 ledger fold). Mutation: fence commented out → RED.
- [ ] **T2 — fixture consolidation (ledger fold)** — fold the parked-IdP / `reverseBProperties` / respond / drain / realmBase fixtures from `AdjudicationLifecycleTest`, `ProxyCompanionLifecycleTest`, `GracefulShutdownRacesTest` (+ `rebindableProbe` ×2) into `testsupport/` BEFORE the gate/body rows add a fourth consumer. Mechanical, GREEN-only.
- [ ] **T3 — config: drain deadline** — `ProxyCompanionProperties.Shutdown(Duration drainTimeout)` on the Bind precedent (required node, compact-ctor `requireNonNull` + positive guard); `application.yml` `shutdown: drain-timeout: 10s` after `metrics:`; `TestCompanionConfigs.common()` key; both `reverseBProperties` builders gain the component. Matrix rows bind `""`/`0s`/`-5s`/non-duration — the invalid value, never key-removal. Mutation: guard neutered → matrix RED.
- [ ] **T4 — new-adjudication gate (OBS-017)** — new injectable gate state (house @Bean), armed in `RelayServerLifecycle.stop()` at acceptor close; consumed in `onRequest`'s `entry == null` arm BEFORE `register`: release frame + `writeBindFailureAndClose` (the routing-miss arm's shape); post-couple relaying untouched. Rows: bind on an established socket after stop → non-ROK `bind_resp`, registry size unchanged, verifier never contacted; fresh connect refused. Mutation: gate check neutered → RED.
- [ ] **T5 — drain body** — widen the coordinator ctor (registry, manager, `Shutdown` props, `Clock` — all `requireNonNull`) + the `Clock` @Bean; fill `drainRelayedConnections()`: snapshot → empty ⇒ immediate no-op; else poll `size()==0` against the Clock deadline; at deadline force-close the remainder via a `RelayStateManager` drain-teardown (`beginTeardown` → `Won` ⇒ stash `SHUTDOWN_DRAIN` both legs → close) + ONE bounded WARN naming the count; fix `CloseReason`:52-53's stale "story 4.2" javadoc. Coordinator-level rows: empty no-op bound, deadline force-close (mutable Clock + recording manager), WARN shape; the four direct-ctor sites re-sign. Mutation: deadline check / force-close loop neutered → RED.
- [ ] **T6 — proofs + bound + behavioral pins** — races rows: OBS-016 six-event chain (extend :314-380; drain-completed watcher = `registry.size()==0`, drain-started via the rig's direct coordinator construction — e.g. a decorated registry stamping the first snapshot); RELAY-022 (N pairs mid-splice, sequence-number integrity, registry → 0); OBS-020 (peer never FINs, small injectable deadline, force-closed `SHUTDOWN_DRAIN` observed via the observer seam, no half-flushed frame). `BootstrapLifecycleTest`: idle <5s rationale rewrite + deadline-aware margin note. Behavioral pins (4.2 ledger fold): walk order = the six-event chain itself; throw-path = a throwing manager → release skipped, finally-quiesce still terminates the group. AD-10 row (4.2 ledger fold): release()'s client close + secret zeroize observed (shared-backing-array all-zero probe). `clean build` + mutation pass over any un-neutered guard.

**Acceptance Criteria:**
- Given N coupled pairs mid-splice at context close, when the drain runs, then the six ordered events hold (acceptor-stopped ≤ adjudications-denied ≤ drain-started ≤ drain-completed ≤ vt-drained ≤ exit), the registry reaches zero, and no PDU is dropped or corrupted.
- Given a peer that never half-closes, when the drain deadline passes, then the pair is force-closed as `SHUTDOWN_DRAIN`, no partial frame is on the wire, and the process still exits inside the 30s window.
- Given the acceptor stopped, when a bind arrives on an established socket, then adjudication DENYs fail-closed without verifier contact and no registry entry appears.
- Given an invalid `companion.shutdown.drain-timeout` value, when the context binds, then startup fails fast with the guard's message.
- Given any new guard neutered, when the mutation pass runs, then at least one test goes RED.

## Spec Change Log

## Design Notes

- **Gate anchor refinement (re-decomposition 2026-09-05):** the frozen letter names `adjudicate()`, but in the code `register` (BindInterceptor:263) precedes verifier contact (:313) and OBS-017 requires NO registry entry — so the check sits in `onRequest`'s new-bind arm, before `register`. Identical observable (deny without verifier contact); the anchor moves to satisfy no-registry-entry. Post-couple PDUs keep relaying — the drain requires it.
- **Force-close composes relay-side:** `CoupledRelayHandler.stash` is package-private and the manager owns all mutation — a manager drain-teardown method keeps the fence intact while the coordinator stays in `bootstrap/`.
- **Poll, not callbacks:** the registry has no hook; `size()→0` is the completion signal its javadoc already names. The injectable Clock makes OBS-020 deterministic (advance the clock — no wall-clock wait); it is the repo's FIRST Clock bean and only the coordinator consumes it (`BindInterceptor`:301's `Instant.now()` is 4.4's adjudication-deadline arming — untouched; the Ask-First on widening stays respected).
- **Re-decomposed against post-4.2 HEAD** (baseline `f9549a9` → `e614291`): anchors re-verified; ledger folds from the 4.2/3.4 review rounds — fixture consolidation (T2), ArchUnit any-arity widening (T1), walk-order/throw-path behavioral pins + AD-10 release-observability row (T6). Deliberately NOT folded: quiesce outer bound (4.4/Epic 6), oidc.timeout window validation (config-matrix decision), zero-orphans 1500ms bound tuning, wiring-level same-bean pin, F9 CloseReason hoist.
- **Empty registry stays instant:** the no-op return keeps both idle bounds (<5s / <1.5s) — only the rationale text changes.
- **Backlog > deadline:** bulk force-close + ONE WARN naming the count; bounds stay behavioral (the test tier has no log-capture idiom).

## Verification

**Commands:**
- `./gradlew clean build --console=plain` -- expected: GREEN (all tests + OBS-013 purity + SEC-099 floors). `clean` required — source-scan tests silently skip on incremental runs.
- `./gradlew :proxy:test --tests 'smpp.companion.proxy.bootstrap.*' --tests 'smpp.companion.proxy.relay.*' --tests 'smpp.companion.proxy.config.*' --console=plain` -- expected: all drain-path suites pass.

**Manual checks (if no CLI):**
- Boot a forward cell with a coupled pair mid-traffic; SIGTERM; confirm the ordered shutdown sequence on stdout, the pair draining (or force-closing at the deadline), and exit well under 30s.
