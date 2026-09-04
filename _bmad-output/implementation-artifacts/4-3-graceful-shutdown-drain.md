---
title: 'Story 4.3 — AD-22 graceful shutdown pt. 2: the connection drain body'
type: 'feature'
created: '2026-09-04'
status: 'ready-for-dev'
review_loop_iteration: 0
baseline_commit: f9549a9ebfd20a6a7864935baa93fa41842b4e4a
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

- `proxy/src/main/java/smpp/companion/proxy/relay/ConnectionRegistry.java:43,106-131` — `ConcurrentHashMap<ChannelId, ConnectionEntry>`; NO enumeration API today (only `int size()`). Add the read-only snapshot here. Pre-pin: `relay/ConnectionRegistryTest.java:267` (no orphaned entry — "a phantom pair corrupts AD-22 drain enumeration").
- `proxy/src/main/java/smpp/companion/proxy/relay/RelayStateManager.java:137-167` — `beginTeardown(Channel)` → sealed `Won(entry)/Lost` with single-sited hygiene before returning `Won`. The drain drives this per pair; never bypass.
- `proxy/src/main/java/smpp/companion/proxy/relay/BindInterceptor.java:291-347` — `adjudicate()` await point (the gate hooks here); `denyAndTeardown` :403-414 + `synthesizeBindFailure` :432-445 reuse for the gate's DENY arm.
- `proxy/src/main/java/smpp/companion/proxy/bootstrap/ProxyCompanionLifecycle.java` — 4.2's skeleton; the no-op drain seam is the fill site (deny → **drain** → release-await → quiesce).
- `proxy/src/main/java/smpp/companion/proxy/observability/CloseReason.java:102-103` — `SHUTDOWN_DRAIN` ("full AD-22 body is Epic 4"), currently unfired; shape-test-pinned enum, values unchanged.
- `proxy/src/main/java/smpp/companion/proxy/config/ProxyCompanionProperties.java:382-389` — compact-ctor guard pattern for the new `Shutdown` node; `proxy/src/main/resources/application.yml:17-19` — the 30s ceiling; add `companion.shutdown.drain-timeout: 10s`.
- `proxy/src/test/java/smpp/companion/proxy/config/TestCompanionConfigs.java:152-191` — `common()` (runner boots load no yml — add the key); matrix guard precedent `config/CompanionConfigMatrixTest.java` (bind the invalid value, never remove the key).
- `bootstrap/BootstrapLifecycleTest.java` — 4.2's upper bound extends with the deadline (drain-timeout + bounded margin, still ≪ 30s).
- Catalog AC source: `_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md` — RELAY-022 (:451), OBS-016 (:1164), OBS-017 (:1170), OBS-020 (:1189).

## Tasks & Acceptance

**Execution:** *(one task per conversational step, one commit per task — house rule; runs after 4.2 is done)*

- [ ] **T1 — enumeration + mutation fence** — `ConnectionRegistry` read-only snapshot surface + unit tests (empty, N pairs, no-orphans per :267) + ArchUnit rule: registry mutators (`register`/`attachEgress`/`beginTeardown`/attr clears) called only from `RelayStateManager` and tests.
- [ ] **T2 — config: drain deadline** — `ProxyCompanionProperties.Shutdown` node (`drainTimeout`, compact-ctor positive guard), yml default 10s, `TestCompanionConfigs.common()` addition, matrix guard binding invalid values (blank/non-positive/non-duration — not key-removal).
- [ ] **T3 — new-adjudication gate** — `BindInterceptor.adjudicate()` consumes the coordinator's shutdown gate: fail-closed DENY via the existing `denyAndTeardown`/`synthesizeBindFailure` path, no verifier contact, no registry entry; OBS-017 row (late bind on established socket; new connect refused).
- [ ] **T4 — drain body** — fill the coordinator seam: enumerate → drain to the Clock-injectable deadline (let in-flight writes flush, peers half-close) → force-close remainder via `RelayStateManager.beginTeardown` stashing `SHUTDOWN_DRAIN`; bulk force-close at deadline with bounded WARN; fast no-op on empty registry.
- [ ] **T5 — proofs + bound** — OBS-016 six-event ordering probe (pairwise first-timestamp ≤ next), RELAY-022 (sequence-number integrity, registry → 0), OBS-020 (force-close at deadline, no half-flushed PDU), `BootstrapLifecycleTest` bound extended with the deadline, mutation pass on every new guard (fence, gate, deadline, force-close path — RED-on-neuter).

**Acceptance Criteria:**
- Given N coupled pairs mid-splice at context close, when the drain runs, then the six ordered events hold (acceptor-stopped ≤ adjudications-denied ≤ drain-started ≤ drain-completed ≤ vt-drained ≤ exit), the registry reaches zero, and no PDU is dropped or corrupted.
- Given a peer that never half-closes, when the drain deadline passes, then the pair is force-closed as `SHUTDOWN_DRAIN`, no partial frame is on the wire, and the process still exits inside the 30s window.
- Given the acceptor stopped, when a bind arrives on an established socket, then adjudication DENYs fail-closed without verifier contact and no registry entry appears.
- Given an invalid `companion.shutdown.drain-timeout` value, when the context binds, then startup fails fast with the guard's message.
- Given any new guard neutered, when the mutation pass runs, then at least one test goes RED.

## Spec Change Log

## Design Notes

- **Drain semantics:** a grace window for in-flight writes to flush and peers to half-close, then force-close. "No half-flushed PDU" is pinned at the force-close — close only when the channel is writable/quiescent or the deadline forces it (OBS-020's letter).
- **Deadline vs outer window:** the key default (10s) is deliberately well under the 30s phase ceiling so force-close is deterministic rather than waiting for Spring's hard cutoff; the outer window remains the backstop.
- **Registry-zero proof** uses the existing `size()` observation — enumeration adds the walk, `size()` stays the assertion.

## Verification

**Commands:**
- `./gradlew clean build --console=plain` -- expected: GREEN (all tests + OBS-013 purity + SEC-099 floors). `clean` required — source-scan tests silently skip on incremental runs.
- `./gradlew :proxy:test --tests 'smpp.companion.proxy.bootstrap.*' --tests 'smpp.companion.proxy.relay.*' --tests 'smpp.companion.proxy.config.*' --console=plain` -- expected: all drain-path suites pass.

**Manual checks (if no CLI):**
- Boot a forward cell with a coupled pair mid-traffic; SIGTERM; confirm the ordered shutdown sequence on stdout, the pair draining (or force-closing at the deadline), and exit well under 30s.
