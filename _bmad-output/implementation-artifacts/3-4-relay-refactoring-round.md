---
title: 'Story 3.4: Relay refactoring round — couple vocabulary, direction split, state manager'
type: 'refactor'
created: '2026-08-27'
status: 'ready-for-dev'
review_loop_iteration: 0
baseline_commit: cda2013948b9b2793fa0bb19a21e7f46fe664a79
context: []
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The relay core still carries its 2.2-era shape under a 3.3-widened surface. One `RelayHandler` (345 lines) branches on `direction` at every pre-couple decision point — two direction-dictated state machines in one class (`RelayHandler.java:155,167,334`). The pair's state machine is distributed across ~10 decision sites (`BindInterceptor`, `EgressLeg`, `RelayHandler`, `ConnectionRegistry`) that each re-derive state in-method and re-implement the AD-32 teardown ordering at six places. And the pair-state vocabulary is six families deep — `couple`/`pair`/`leg`/`session`/`spliced`/`flip` — e.g. `RelayHandler.teardownPair` calls `BindInterceptor.teardownForPreCoupleViolation` for the same operation family, and `pre-flip`/`pre-couple` mix within single comments. The 2026-08-16 owner-note cluster, re-scoped by the 2026-08-21 owner-directed split, deferred exactly this round to Story 3.4, running POST-widening (deferred-work.md §"Story 3.3 scoping decision").

**Approach:** One combined, behavior-identical refactoring round, umbrella-first. Decide the `ConnectionEntry` state-manager shape FIRST (single-vs-per-role manager; decision-return mechanics — the fork the interceptor role-split folds into at manager altitude; owner 2026-08-16: "make this decision FIRST — it is the umbrella"). Then execute under it: the couple-vocabulary unification (code + prose to `couple`-variants; the spine-amendment path per the ledger's "one level up" warning), the `RelayHandler` direction-split (two per-leg classes over one shared post-couple splice component — the initializers already wire per-leg instances, so zero wiring cost), and the state-manager extraction (handlers call it, it decides, it delegates the wire-effect work back). Close with the full RED-on-neuter mutation re-run — a rename silently de-targets biters (2.2's N1 neuter site IS the `flipSpliced()` call site).

## Boundaries & Constraints

**Always:**
- Behavior-identical: wire bytes, teardown ordering, pinned trigger events, and fail-closed arms unchanged. All 352 tests at `cda2013` stay green except deliberately re-targeted names (every re-target enumerated in the File List) — the 12 `RelayHandlerTest` + 11 `BindInterceptorTest` behaviors green **unchanged-in-intent**.
- AD-25 invariants stay structural: exactly one flipper (a data-plane handler, never the control plane); flip ONLY on decoded `bind_*_resp` ROK; `BindInterceptor`'s successor remains the sole `bind_*_resp` forwarder. The split must make single-flipper **structural-by-TYPE** — the flip call site exists only in the egress class.
- AD-8/AD-32 state contract: the registry entry's state (exists / tearing-down / coupled) IS the teardown predicate — no second boolean, no shadow state in the manager ("the entry's state, not a separate boolean"). Sync remove-and-mark BEFORE close, then cancel+wipe, then close — unchanged at every site; centralizing the ordering is the point, altering it is a violation.
- Thread-bounding first-class: all entry/registry transitions stay on the pair's single event loop (AD-2); the verdict continuation hop stays the ONE off-loop entry; no new executors anywhere (AD-28). The post-couple splice stays flag-read + forward — never a manager consultation per PDU (PERF; Epic 6 would catch the regression late).
- Renames of spine-named types follow the contract-amendment discipline: dated in-place spine markers + append-only `.memlog.md` entry + deliberate test-contract re-pointing (`RelayHandler`, `ConnectionRegistry`, `SpliceObserver` are named in normative AD text; RELAY-001/004/007/025 and OBS-038 name them in the test contract; `Relay025StatelessnessScanTest:109` resolves `ConnectionRegistry.java` by FILENAME).
- Every guard that moves or renames keeps its RED-on-neuter control (AI-1): fresh mutation rows for re-named neuter sites; the full pass runs after ALL renames/splits land.

**Ask First:**
- The Design Notes forks: **D1** vocabulary-sweep scope (incl. the `SpliceObserver` rename sub-fork), **D2** manager variant + mechanics (= the T1 checkpoint), **D3** split-half naming, **D4** F7 absorb-or-re-home, **D5** optional F9 key-hoisting absorb.
- Any wire-visible or timing change however small; any package move crossing an AD-27 ownership line; any new dependency (none expected).

**Never:**
- No behavior fixes riding along: F1 (ingress-leg `bind_resp`), F10 (egress connect timeout), F14 (adjudication deadline), F16 (backpressure behavioral test) stay with the Epic-4 / RELAY-020/021 round; F9's CloseReason *semantics* stay Epic-4.
- No new features; no config-surface change; no `security/`, `tls/`, or `observability/` behavioral change (any observability touch is naming-only per D1).
- No package moves across the five sub-packages (`relay/` ↔ `security/`/`config/`/`observability/`/`bootstrap/`); placement *within* `relay/` is free.
- Do not re-litigate 3.3 (TLS machinery, F13 cap, the executed role-split arms) or 3.2 (adjudication mapping; zeroize *protocol* moves only if T1 absorbs its state — timing discipline unchanged).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Vocabulary rename | `spliced()`/`flipSpliced()` → `couple`-variants across main + test | Wire-identical; every re-targeted test name enumerated; scan/shape/pipeline tests re-pointed deliberately | Missed re-target surfaces as build/scan failure, never silent green |
| Direction split | egress-leg decoded `bind_resp` ROK | Flip fires from the egress class ONLY; the ingress class cannot reference the flip by type | Non-ROK `bind_resp` → forward-then-teardown, unchanged |
| Ingress pre-couple violation | non-bind PDU pre-couple on ingress leg | Delegation to the interceptor's cancelHttp+zeroize seam (successor of `teardownForPreCoupleViolation`), ordering pinned | Bare-close fallback preserved |
| Manager extraction | teardown from any of the six sites | ONE centralized ordering (remove+mark → cancel+wipe → close); CAS-once + idempotence semantics unchanged | RELAY-005/006 + exactly-once pins stay RED-sensitive |
| Post-couple PDU | coupled pair, data PDU either direction | Flag-read + forward; zero manager/virtual dispatch on the splice path | Dead-peer + partial-frame guards unchanged (RELAY-009/010) |
| Verdict continuation | Allow/Deny settles off the VT executor | Single hop onto the pair's event loop; entry re-checked before acting | Absent/tearing-down entry → no-op (AD-25/AD-32 race-free rule) |
| Mutation re-run | each renamed/moved guard neutered | Its biter RED at the NEW site; fresh ledger rows; zero `MUTATED` residue | backup → neuter → RED → restore, byte-identical |
| Final gates | `clean build :buildSrc:test` | BUILD SUCCESSFUL; `:proxy:test` XML ≥352 / 0 failed / 0 skipped, delta = new guard pins only, enumerated | Console counts lie — XML only |

</frozen-after-approval>

## Code Map

- `proxy/.../relay/RelayHandler.java` (345) — the split subject. Fields `:98-100`; the single shared `channelRead` `:110-179`; **the AD-25 flip `:131`** (the only production `flipSpliced()` caller — the N1 neuter site); direction checks `:155` (EGRESS+nack conjunct) and `:167` (INGRESS delegation); `peerOf` `:333-335` (third direction reader); `teardownPair` `:240`; `channelInactive` `:263`; `CLOSE_REASON`/`CLOSE_FIRED` attribute keys `:83/:87`
- `proxy/.../relay/BindInterceptor.java` (648) — role map: wiring/role-resolution `:113-217` (pending handles `:149/:151`, `EgressConnector` seam `:215`); intake state machine `onRequest` `:238-280`; adjudication `:283-374`; deny/teardown/synth `:376-463` (`teardownForPreCoupleViolation` `:431`, `synthesizeBindFailure` `:450`); egress dial + couple `openEgressAndForward` `:477-534`; ingress teardown window `:536-583`; nested `EgressLeg` `:585-647` (`answered` `:607`). The four pre-existing owner-FIXMEs `:142,284,298,601` — not new, do not sweep silently
- `proxy/.../relay/ConnectionEntry.java` (93) — the four AD-8 fields `:42-53`; `attach` `:56`, `spliced()` `:61`, `flipSpliced()` `:72`, `tearingDown()` `:77`, `beginTearingDown()` `:90`; CAS-once contract javadoc `:26-31`
- `proxy/.../relay/ConnectionRegistry.java` (127) — AD-8's named home; map `:38`, `ENTRY` attr `:41`, `register` `:52`, `attachEgress` `:67`, `entryFor` `:82`, `beginTeardown` `:101-113` (the removal half of the state machine), `size` `:124`
- `proxy/.../relay/netty/RelayIngressInitializer.java:78`, `RelayEgressInitializer.java:99` — the only two `new RelayHandler(...)` sites (per-leg split = zero wiring cost)
- Tests that de-target on rename — re-point deliberately, never silently: `relay/Relay025StatelessnessScanTest` (filename resolution `:109` + reflection `:107-115` — the hardest), `relay/netty/RelayPipelineInitializersTest` (`.class` lookups `:135-151`), `RelayHandlerTest` (whole file; helpers `couple()` `:485`, `coupleAndFlip()` `:494`; `EgressConnector` impl `:505`), `BindInterceptorTest` (`coupledEgress()` `:489`; `EgressConnector` `:502`), `BindInterceptorForwardRoleTest` (`EgressConnector` `:195`), `ConnectionRegistryTest` (CAS-once pins `:116,:139,:194`), `observability/SpliceObserverShapeTest` (`PRE_COUPLE_NON_BIND_PDU` literal `:115`), `observability/CapturingSpliceObserver`, `testsupport/RelayTestFixtures`, `TlsModesLoopbackE2eTest`, `JsmppA1OracleTest`, `RelayA1SmokeTest` (assertion strings `:164,166,242,438`)
- Spine: `ARCHITECTURE-SPINE.md` AD-25 `:211-214` (names `RelayHandler`; "splice/flip" wording), AD-8 `:115-118` (names `ConnectionRegistry`), AD-2 `:72-75`, AD-27 `:221-224` (`SpliceObserver` 4-method shape + pinned triggers), AD-32 `:246-253`; `.memlog.md` L105 = the interface-shape amendment precedent (`onByteTransfer` drop, 2026-08-11, with Propagated list)

## Tasks & Acceptance

**Execution:**
- [ ] T1 — THE UMBRELLA DECISION, FIRST (owner checkpoint): state-manager variant (single manager vs per-role managers — one fork with the interceptor role-split at manager altitude), mechanics (sealed decision returned to the caller vs executor-facing port), and state-absorption scope (`pendingVerdict`/`pendingPassword`? `EgressLeg.answered`? `CLOSE_*` attributes?). Recorded as a dated `.memlog.md` `(decision)` entry + Design Notes addendum BEFORE T3/T4 execute. (AC1)
- [ ] T2 — Couple-vocabulary unification: code identifiers to `couple`-variants (`spliced()` → `coupled()`, `flipSpliced()` → successor named once with the T1 state names); relay prose + test names/assertion strings swept; spine-sweep scope per D1's resolution; full deliberate re-targeting list. (AC2)
- [ ] T3 — `RelayHandler` direction-split: two per-leg classes over one shared post-couple splice component; flip structural-by-type; `CLOSE_*` key strategy per D5; `RelayPipelineInitializersTest` re-pointed; AD-25 dated spine marker + memlog entry. (AC3)
- [ ] T4 — State-manager extraction per T1: policy OVER the registry's storage (no second state copy); the six teardown sites folded into one ordering; hot path untouched; `EgressLeg`/pending-handle placement per T1. (AC4, AC5)
- [ ] T5 — Ledger hygiene: F13 RESOLVED marker (work landed 3.3 T6, ledger unmarked), the four 2026-08-27 story-text-pass markers (executed by `cda2013`), F7 disposition marker per D4. Marker form: a dated `**✅ RESOLVED …**` continuation under the entry (the two existing prose forms; no fielded entry has been resolved yet — this story sets that precedent, append the marker, don't restructure the fields). (AC8)
- [ ] T6 — Full RED-on-neuter mutation re-run, POST-renames: fresh rows for every renamed/moved neuter site; the 2.2 N-series relay biters re-proven at their new sites; final gates. (AC6, AC7)

**Acceptance Criteria:**
- Given the T1 decision recorded in the memlog, when T3/T4 execute, then the split/manager shape matches it exactly — drift requires a new owner checkpoint.
- Given the vocabulary round, when it lands, then every surviving `splice`/`flip` occurrence in relay code or prose is either quoted spine contract text (exactly per D1's resolution) or swept — the survivor inventory lands in the Completion Notes.
- Given the split, when a decoded ROK `bind_resp` arrives, then the flip call site exists in exactly one class and the ingress class cannot express it (structural-by-type); `onBindAccept` still fires exactly at the flip.
- Given teardown from ANY site, then ordering is remove+mark → cancel+wipe → close, unchanged; RELAY-005/006 idempotence + no-orphan pins green; `onConnectionClosed` exactly-once per channel.
- Given the post-couple hot path, then a coupled PDU remains flag-read + forward — no manager consultation, no new virtual dispatch per PDU.
- Given each neutered/moved guard, then its biter goes RED at the NEW site (fresh ledger rows; restore byte-identical; zero `MUTATED` residue).
- Given `./gradlew clean build :buildSrc:test`, then BUILD SUCCESSFUL with `:proxy:test` ≥352 tests / 0 failed / 0 skipped (XML counts; any delta from 352 enumerated — new guard pins only).
- Given the deferred-work ledger at wrap, then F13 and the four story-text-pass entries carry dated RESOLVED markers and F7's disposition (absorbed-with-pin or re-homed) is recorded — no ledger marker owed by this story remains open.

### Review Findings

## Spec Change Log

## Design Notes

**Canonical vocabulary — the spine already ratifies couple/pair:** couple = verb/state ("post-bind the pair is coupled", spine L44; "that coupling *is* the session affinity", AD-9 L123), pair = noun (per-bind pair, coupled channel pair), leg = each half (`Direction`), session = the SMPP/routing-layer word. The CODE diverges (`spliced`/`flipSpliced`/`RelayHandler.splice()`/`SpliceObserver`). Owner direction (2026-08-16): ONE vocabulary, `couple`-variants, avoiding splice/flip in code and relay prose.

**D1 — vocabulary-sweep scope (Ask First):** (a) code+prose only, vs (b) full unification including spine AD-25/AD-2 title + rule text ("Bind→splice transition state machine", "flip-flag") with dated in-place markers + memlog. The ledger warns (a) "re-creates the same code/prose split one level up" — lean (b). Sub-fork: does `SpliceObserver` rename? A ratified-contract change rippling AD-27, epics.md, the TEA docs, and the readiness report; memlog L105 is the amendment-path precedent. `onFramedPdu` is already couple-neutral; `PRE_COUPLE_NON_BIND_PDU` already speaks couple.

**D2 — manager variant + mechanics (the T1 fork):** (1) single manager covering both roles vs (2) per-role managers — the SAME fork as the interceptor role-split at a different altitude; treat as ONE. Mechanics: sealed decision returned to the caller (lean — avoids the circular manager↔handler dependency; record which is chosen). Thread-bounding: manager = event-loop-confined policy like the handlers; the verdict continuation hop is its single off-loop entry; VT-side adjudication kickoff stays in the interceptor's control-plane half.

**Candidate explicit state set (2026-08-16 T7 note + as-built):** `not-registered` → `registered/adjudicating` (RELAY-004 in-flight predicate) → `egress-attached/connecting` → `awaiting-bind_resp` (`EgressLeg.answered == false`) → `coupled` (the AD-25 flip) → `tearing-down` (CAS mark). AD-32 constraint: any explicit state DERIVES from the registry entry on every read — never a shadow boolean.

**D3 — split-half naming:** candidate `RelayIngressHandler`/`RelayEgressHandler` over a shared splice component (name it once with the T2 vocabulary). Spine AD-25 names `RelayHandler` — dated marker + memlog either way. `ConnectionRegistry`/`ConnectionEntry` type names: KEEP — AD-8 names the registry, RELAY-025 resolves it by filename, and the types were never the inconsistent words (all couple/pair vocabulary lives in identifiers and prose, not type names).

**D4 — F7 (Ask First):** verdict-future frame ownership — a cancelled, never-settling verdict leaks one pooled buffer (the `whenComplete` continuation is the only releaser of `req.originalFrame()`). Owner deferred to "Epic 3" (now done) → 3.4 must consciously **absorb** (small: one release arm + one pin — lean, fail-closed hygiene) or **re-home** to the Epic-4 RELAY-020/021 timeout round.

**D5 — optional mechanical absorb:** F9's `CLOSE_REASON` key hoisting (today `RelayHandler`-private, class-scoped) rides the direction-split naturally; the reason *semantics* stay Epic-4. Zero-cost if the split already moves the keys — decide with T1's state-absorption scope.

**Scatter map (T4 input):** pending handles `BindInterceptor:149,151` (settle/wipe protocol at `:332-333`, `:348,371-372`, `:408-419`); `EgressLeg.answered` `:607`; `CLOSE_REASON`/`CLOSE_FIRED` attrs `RelayHandler:83,87`; the registry's removal half `ConnectionRegistry:101-113`; teardown ordering re-implemented at six sites — `BindInterceptor:384,431,539,560` + `RelayHandler:240,263`.

**Mutation-pass traps (inherited, 2.2 + 3.3):** neuter-site renames silently de-target biters (N1's site IS the flip call — T6 re-proves it at the successor site); a biter whose assertion can throw must release latches in `finally`; force `cleanTest` for source-scan tests (Gradle UP-TO-DATE skips them); EmbeddedChannel gotchas — `DefaultChannelId.newInstance()`, `runPendingTasks()` after completing held futures, pre-close delivery for exactly-once pins.

## Verification

**Commands:**
- `./gradlew clean build :buildSrc:test` — expected: BUILD SUCCESSFUL
- `./gradlew :proxy:test` post-`cleanTest` — expected: ≥352 tests / 0 failed / 0 skipped, XML-verified (console counts lie)
- `grep -rn "FIXME\|@Disabled" <diff files>` — expected: zero new occurrences (the four owner-FIXMEs at `BindInterceptor:142,284,298,601` pre-exist)
- `grep -rn "MUTATED" proxy/src` — expected: empty (mutation-residue scan)

## Dev Agent Record

### Agent Model Used

### Debug Log References

### Completion Notes List

### RED-on-neuter mutation ledger (T6 / AI-1)

### File List
