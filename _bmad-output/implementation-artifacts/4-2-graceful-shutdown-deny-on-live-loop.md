---
title: 'Story 4.2 — AD-22 graceful shutdown pt. 1: deny-in-flight on a live loop + the 5-step skeleton'
type: 'feature'
created: '2026-09-04'
status: 'in-progress'
review_loop_iteration: 0
baseline_commit: f9549a9ebfd20a6a7864935baa93fa41842b4e4a
context:
  - /home/ildar/Documents/smpp-bmad/_bmad-output/implementation-artifacts/epic-4-context.md
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** On SIGTERM the acceptor's `stop()` quiesces the shared relay event loop at phase 1000, so when deny-in-flight finally runs (phase 0) every cancelled adjudication's continuation hits a dead loop — `eventLoop().execute()` rejects, the closure strands (deferred-work ledger residue), and the legacy client never receives its fail-closed `bind_resp`. The verifier's `close()` also fuses deny with pool-await/client-close/secret-zeroize, so nothing can sequence those apart.

**Approach:** Land AD-22 steps 1, 2, 4, 5 with an explicit **empty step-3 seam**: split the adapter `close()` into deny (`shutdownNow()` — futures settle `DenyIndeterminate` per Story 3.2 AC5) and release (await + `http.close()` + zeroize); re-author `RelayServerLifecycle.stop()` to close the acceptor only (loop survives); land the drain coordinator skeleton in `ProxyCompanionLifecycle.stop()`: deny → drain (no-op seam, story 4.3) → release-await → quiesce with an explicit short quiet period. Prove the Allow-race, VT hygiene, and a meaningful shutdown upper bound.

## Boundaries & Constraints

**Always:**
- The spine's 5-step ordering (ARCHITECTURE-SPINE.md:196-199, amended 2026-08-27) is the contract; this story lands steps 1, 2, 4, 5 and the step-3 seam exists as an explicit no-op the coordinator walks through (javadoc names story 4.3 as its filler). Exit stays bounded by `spring.lifecycle.timeout-per-shutdown-phase: 30s` (application.yml:17-19).
- Deny runs while the relay loop is ALIVE: every cancelled adjudication's continuation (`BindInterceptor.onVerdict`) executes and writes its non-ROK `bind_resp`; the eventLoop-execute-rejection stranding is unreachable in the re-authored order.
- Phase plan: acceptor stays the highest phase (stops first, acceptor-close only), metrics keeps its scrape-late window (phase 500), deny lands strictly between acceptor and app phases, release-await + loop quiesce land at the app phase after the (empty) drain step.
- The loop quiesce leaves `RelayServerLifecycle.stop()` and uses an explicit short quiet period (pattern: `MetricsEndpointLifecycle` 100ms/2s at :80-83) — never Netty's 2s default.
- The adapter split stays local to `security/`: `deny()` idempotent, `release()` idempotent, each callable once-independently; the old fused `close()` semantics must remain reachable for the bean destroy path (deny+release in sequence).
- Stop is idempotent end-to-end: double `stop()`, or the group bean's `destroyMethod="shutdownGracefully"` backstop (RelayNettyConfig.java:65) re-firing after the coordinator, is a no-op — no double-free, no hang.
- Pinned behavior tests that encode today's (wrong) ordering are re-authored, not deleted — each keeps pinning a real invariant (phase order, stop-synchronous deny, neuter-guard pattern).
- No new config keys this story (the drain deadline key is 4.3).

**Ask First:**
- Honoring the ordering needs more than the `close()` split + re-phasing (structural `security/` rework) → HALT with options.
- A pinned test cannot be re-authored without weakening what it pins → HALT and show it.
- Any new dependency or `smpp.runtime-purity` gate edit → HALT with the proposed diff.

**Never:**
- No drain body — no registry enumeration, no drain deadline, no force-close, no new-adjudication gate (story 4.3).
- No relay-timeout round — adjudication-deadline arming, egress connect bounding, ingress `bind_resp` forwarding, idle reaper (story 4.4).
- No packaged-shape SIGTERM→PID-1 validation (DEPLOY-006, Epic 5); no under-load proof (PERF-061, Epic 6).
- No observer/endpoint changes; no resurrecting the retired JWKS steps (`epics.md:219`'s 7-step list is a superseded snapshot — cite the 5-step spine).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| SIGTERM, in-flight adjudication | bind awaiting verdict; context close | deny fires on the live loop; future settles `DenyIndeterminate`; client receives non-ROK `bind_resp`; password zeroized | N/A |
| Allow racing deny | verdict completing as deny fires (RELAY-023/OBS-019) | fail-closed: couple flag never flips; client holds non-ROK `bind_resp` | N/A |
| Bind starting in the acceptor→deny window | bind accepted just before acceptor stop | `shutdownNow()` cancels it into the same fail-closed deny path | N/A |
| SIGTERM, idle app | zero pairs, zero adjudications | ordered skeleton walks the empty drain seam; fast exit well under 30s | N/A |
| SIGTERM, coupled pairs mid-splice | established splices; context close | unchanged from today at the seam: pairs torn down at quiesce (no drain yet — 4.3), exit inside the window | N/A |
| Double stop | `stop()` twice + destroyMethod backstop | second call a no-op; no hang, no double-free | N/A |

</frozen-after-approval>

## Code Map

- `proxy/src/main/java/smpp/companion/proxy/security/RopcBindCredentialVerifier.java:853-874` — today's fused `close()`: `closed=true` → `adjudicationPool.shutdownNow()` (:856, javadoc already says "AD-22 step 2") → `awaitTermination(callTimeout+1s)` → `http.close()` → `clientSecret.zeroize()`. VT pool construction :319-321 (`newThreadPerTaskExecutor` + `Semaphore` admission).
- `proxy/src/main/java/smpp/companion/proxy/security/AdjudicationLifecycle.java:28-66` — phase 0 today (tie with app; runs AFTER the loop dies — the bug); `stop()` calls the fused `close()`. Declared in `security/VerifierWiringConfig.java:54-57`.
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayServerLifecycle.java:64-119` — phase `APP_PHASE+1000`; `stop()` :107-119 = close acceptor → `shutdownGracefully()` Netty defaults on the shared loop. Re-author to acceptor-close only.
- `proxy/src/main/java/smpp/companion/proxy/bootstrap/ProxyCompanionLifecycle.java:15-45` — `APP_PHASE=0`; `stop()` is a flag-flip stub whose javadoc pre-declares the AD-22 body — the coordinator home.
- `proxy/src/main/java/smpp/companion/proxy/relay/BindInterceptor.java:291-346,355-383` — read-only this story: the `whenComplete` continuation hops `channel.eventLoop()` (:343-346); `onVerdict` settle → AD-25 re-check → deny arm. No edits expected here in 4.2.
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayNettyConfig.java:65` — group bean `destroyMethod="shutdownGracefully"` backstop; `observability/MetricsEndpointLifecycle.java:80-83` — the explicit-quiet-period precedent.
- Tests pinning today's stop: `relay/netty/RelayServerLifecycleTest.java:94-106` (neuter-guard + `group.isShutdown()` + port reclaim — the quiesce pin moves to full-app close), `:201-218` (phase constants/order — keep); `security/AdjudicationLifecycleTest.java:62-127` (phase pins; `stopDeniesInFlightAdjudications` :90-127 latch-parked IdP — keep stop-synchronous deny); `security/VerifierWiringConfigTest.java:78-84`; `bootstrap/BootstrapLifecycleTest.java:60-73` (today only stop-ran + trivial 30s ceiling — becomes the meaningful upper bound; deferred-work ledger entry).
- Catalog AC source: `_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md` — RELAY-023 (:457), OBS-019 (:1183), OBS-021 (:1195).

## Tasks & Acceptance

**Execution:** *(one task per conversational step, one commit per task — house rule)*

- [x] **T1 — security: deny/release split** — `RopcBindCredentialVerifier`: idempotent `deny()` (`shutdownNow`; settle `DenyIndeterminate`) + idempotent `release()` (await + `http.close()` + `clientSecret.zeroize()`); fused `close()` = deny→release for the destroy path. Re-phase `AdjudicationLifecycle` between acceptor and app (or reduce it to the deny call with the coordinator owning release — mechanism free, ordering pinned). Re-author `AdjudicationLifecycleTest` + `VerifierWiringConfigTest` (deny stays stop-synchronous).
- [x] **T2 — acceptor re-author** — `RelayServerLifecycle.stop()` = acceptor close only (no loop quiesce; explicit-args quiesce moves to the coordinator). Re-author `RelayServerLifecycleTest:94-106` (quiesce asserted at full-app close instead); keep `:201-218` phase pins.
- [x] **T3 — coordinator skeleton** — `ProxyCompanionLifecycle.stop()` walks deny → drain (no-op seam, javadoc: filled by 4.3) → release-await → quiesce (explicit short quiet period); idempotent; double-stop + destroyMethod-backstop no-op row.
- [ ] **T4 — races + bound** — integration rows: RELAY-023/OBS-019 (latch-held Allow → couple never flips, non-ROK `bind_resp`, password zeroized), OBS-021 (post-stop ThreadMXBean: zero orphaned adjudication VTs), ordering prefix pin (acceptor-stopped ≤ adjudications-denied ≤ vt-released ≤ loop-quiesced — the OBS-016 probe's 4.3 extension lands later), `BootstrapLifecycleTest` meaningful upper bound. Mutation pass on every guard (RED-on-neuter).

**Acceptance Criteria:**
- Given an in-flight adjudication at context close, when deny fires, then the continuation runs on the live relay loop, the future settles `DenyIndeterminate`, the client receives its non-ROK `bind_resp`, and the bind password is zeroized.
- Given an Allow verdict settling exactly as deny fires, when the race resolves, then the couple flag never flipped and the client holds a non-ROK `bind_resp`.
- Given context close (idle or coupled), when the skeleton walks, then stop completes within a meaningful asserted upper bound (well under the 30s ceiling) and a second `stop()` is a no-op.
- Given any guard neutered (phase order, stop-synchronous deny, idempotence), when the mutation pass runs, then at least one test goes RED.

## Spec Change Log

## Design Notes

- **Why deny must precede the loop's death:** every cancelled verdict's continuation is `channel.eventLoop().execute(...)` — on a quiesced loop that is a rejection and a stranded closure. Today the loop dies at phase 1000 and deny runs at phase 0; this story inverts that.
- **The empty-drain seam is deliberate:** 4.3 fills a no-op; no sequencing line moves twice across the two stories.
- **`AdjudicationLifecycle` end-state is mechanism, not contract:** keeping it as the deny-phase bean vs folding deny/release into the coordinator are both acceptable — the invariant is the phase-ordered sequence, not the bean count. Prefer the simpler (Ildar's standing preference: simpler fail-closed).
- **Quiesce cost note:** the 2s-default quiet period (deferred-work ledger, "≥2s per mode-b close") dies here — the explicit args land with the skeleton.

## Verification

**Commands:**
- `./gradlew clean build --console=plain` -- expected: GREEN (all tests + OBS-013 purity + SEC-099 floors). `clean` required — source-scan tests silently skip on incremental runs.
- `./gradlew :proxy:test --tests 'smpp.companion.proxy.bootstrap.*' --tests 'smpp.companion.proxy.security.*' --tests 'smpp.companion.proxy.relay.*' --console=plain` -- expected: all shutdown-path suites pass.

**Manual checks (if no CLI):**
- Boot a forward cell, park a bind against a fake verifier, send SIGTERM: the client sees a non-ROK `bind_resp` before the socket drops, and the process exits well under 30s.
