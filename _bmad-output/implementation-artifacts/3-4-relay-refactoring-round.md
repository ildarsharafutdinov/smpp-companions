---
title: 'Story 3.4: OIDC token-path simplification + relay refactoring round'
type: 'refactor'
created: '2026-08-27'
status: 'ready-for-dev'
review_loop_iteration: 0
baseline_commit: cda2013948b9b2793fa0bb19a21e7f46fe664a79
context: []
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem, OIDC half (owner-directed 2026-08-27, ahead of the refactor):** the ROPC adapter carries two interop arms this deployment does not need. (1) An RFC 7662 opaque-token introspection fallback — a second wire arm, its discovery requirement, and its client-auth path — for a single operator-run Keycloak (pinned ≥26.7.0) whose token endpoint issues JWTs; the verdict is already decided by the token endpoint's own response before the token body is ever touched. (2) Local JWS signature verification (`verifyJwt` + `JwksCache` + its AD-28(2) refresh VT + the `oidc.jwks-cache-ttl` knob + the `jwks_uri` discovery requirement) re-proving a token the proxy itself just obtained over the AD-12-mandated HTTPS, client-authenticated provider link — the proxy is the token's only consumer and never forwards it.

**Problem, relay half:** the relay core still carries its 2.2-era shape under a 3.3-widened surface. One `RelayHandler` (345 lines) branches on `direction` at every pre-couple decision point — two direction-dictated state machines in one class (`RelayHandler.java:155,167,334`). The pair's state machine is distributed across ~10 decision sites that each re-derive state in-method and re-implement the AD-32 teardown ordering at six places. The pair-state vocabulary is six families deep — `couple`/`pair`/`leg`/`session`/`spliced`/`flip`. The 2026-08-16 owner-note cluster, re-scoped by the 2026-08-21 split, deferred exactly this round to Story 3.4, POST-widening (deferred-work.md §"Story 3.3 scoping decision").

**Approach:** Two owner-directed simplifications FIRST: (T1) JWT-only adjudication — the opaque/7662 arm, its discovery requirement, and its config surface are removed; a non-JWT token response fails closed (D6). (T2) the TLS channel to the IdP becomes the sole trust anchor — local signature verification, claim checks, `JwksCache`, its refresh thread, its knob, and the `jwks_uri` requirement are removed (D7); spine amendments AD-12/AD-8(c)/AD-28(2) + epics 4-path enumeration + register + TEA rows swept with dated markers + memlog entries. THEN the refactoring round, umbrella-first: decide the `ConnectionEntry` state-manager shape FIRST (owner 2026-08-16: "it is the umbrella"), then the couple-vocabulary unification, the `RelayHandler` direction-split (two per-leg classes over one shared post-couple splice component), and the state-manager extraction. Close with the full RED-on-neuter mutation re-run — a rename silently de-targets biters (2.2's N1 neuter site IS the `flipSpliced()` call site).

## Boundaries & Constraints

**Always:**
- Fail-closed everywhere (AD-11): a non-JWT token response denies `DenyIndeterminate` + WARN (D6 lean) — never an allow, never a silent skip; every removal leaves the surviving paths' guards RED-on-neuter-controlled (AI-1).
- The AD-12 port shape is untouched: `BindCredentialVerifier` / `Verdict` / `VerdictRequest` / `BindCredential` / `RequestContext` signatures and the AC2 verdict mapping (bare 401 / 400 `invalid_grant`|`invalid_client` → `DenyInvalid`; else `DenyIndeterminate`) are unchanged; zeroize protocol unchanged.
- Relay behavior-identical: wire bytes, teardown ordering, pinned trigger events, and fail-closed arms unchanged. All 352 tests at `cda2013` stay green except deliberately re-targeted names and deliberately retired rows — every delta enumerated in the File List. The 12 `RelayHandlerTest` + 11 `BindInterceptorTest` behaviors green **unchanged-in-intent**.
- AD-25 invariants stay structural: exactly one flipper (a data-plane handler, never the control plane); flip ONLY on decoded `bind_*_resp` ROK. The split must make single-flipper **structural-by-TYPE**.
- AD-8/AD-32 state contract: the registry entry's state (exists / tearing-down / coupled) IS the teardown predicate — no second boolean, no shadow state in the manager. Sync remove-and-mark BEFORE close, then cancel+wipe, then close — unchanged at every site.
- Thread-bounding first-class: all entry/registry transitions stay on the pair's single event loop (AD-2); the verdict continuation hop stays the ONE off-loop entry; T2 REMOVES an executor (the JWKS refresh VT) and none may be added (AD-28). The post-couple splice stays flag-read + forward.
- Contract-amendment discipline for both halves: dated in-place spine markers (AD-12, AD-8 clause (c), AD-28 arm (2), AD-25) + append-only `.memlog.md` entries + epics.md 4-path/register sweep + TEA row retirement + deliberate test re-pointing (`Relay025StatelessnessScanTest:109` resolves `ConnectionRegistry.java` by FILENAME).

**Ask First:**
- The Design Notes forks: **D1** vocabulary-sweep scope (incl. the `SpliceObserver` rename sub-fork), **D2** manager variant + mechanics (= the T3 checkpoint), **D3** split-half naming, **D4** F7 absorb-or-re-home, **D5** optional F9 key-hoisting absorb, **D6** non-JWT posture, **D7** what survives of the JWT body + the Nimbus dependency.
- Any wire-visible or timing change beyond T1/T2's enumerated removals; any package move crossing an AD-27 ownership line; any new dependency (none expected — T2 only shrinks).

**Never:**
- No new auth paths, no token caching, no verdict caching, no local password checks (AD-15 unchanged); no security-tier changes beyond T1/T2's enumerated removals.
- No behavior fixes riding along in the relay half: F1 (ingress-leg `bind_resp`), F10 (egress connect timeout), F14 (adjudication deadline), F16 (backpressure behavioral test) stay with the Epic-4 / RELAY-020/021 round; F9's CloseReason *semantics* stay Epic-4.
- No new features; no config-surface additions (T1/T2 only REMOVE keys — `jwks-cache-ttl` dies with the cache; a stale key must refuse startup under `ignoreUnknownFields=false`).
- No package moves across the five sub-packages; placement *within* `relay/` or within `security/` is free.
- Do not re-litigate 3.3 (TLS machinery, F13 cap, the executed role-split arms) or 3.2 beyond T1/T2's enumerated removals (verdict mapping, zeroize, Mode B ack — all unchanged).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Opaque token response | token endpoint 200, token is NOT a three-segment JWS | `DenyIndeterminate` + WARN (JWT-only policy); NO introspection wire call (arm removed) | Fail-closed deny; never allow |
| JWT token response | token endpoint 200, three-segment JWS | `Allow` derived from the endpoint verdict alone — no signature verification, no JWKS fetch, no claim checks (per D7) | Structural JWT-ness gate fails → D6 arm |
| Discovery without `jwks_uri`/`introspection_endpoint` | provider discovery document omits either | ACCEPTED — the field-completeness requirement shrinks to issuer + token endpoint (both still HTTPS-fail-fast) | Absent `issuer`/`token_endpoint` still refuses startup |
| Stale `jwks-cache-ttl` key | config carries the removed knob | Refuses startup (`ignoreUnknownFields=false`) — retirement is loud | Fail-fast, key-named message |
| Vocabulary rename | `spliced()`/`flipSpliced()` → `couple`-variants across main + test | Wire-identical; every re-targeted test name enumerated; scan/shape/pipeline tests re-pointed deliberately | Missed re-target surfaces as build/scan failure, never silent green |
| Direction split | egress-leg decoded `bind_resp` ROK | Flip fires from the egress class ONLY; the ingress class cannot reference the flip by type | Non-ROK `bind_resp` → forward-then-teardown, unchanged |
| Ingress pre-couple violation | non-bind PDU pre-couple on ingress leg | Delegation to the interceptor's cancelHttp+zeroize seam (successor of `teardownForPreCoupleViolation`), ordering pinned | Bare-close fallback preserved |
| Manager extraction | teardown from any of the six sites | ONE centralized ordering (remove+mark → cancel+wipe → close); CAS-once + idempotence semantics unchanged | RELAY-005/006 + exactly-once pins stay RED-sensitive |
| Post-couple PDU | coupled pair, data PDU either direction | Flag-read + forward; zero manager/virtual dispatch on the splice path | Dead-peer + partial-frame guards unchanged (RELAY-009/010) |
| Verdict continuation | Allow/Deny settles off the VT executor | Single hop onto the pair's event loop; entry re-checked before acting | Absent/tearing-down entry → no-op (AD-25/AD-32 race-free rule) |
| Mutation re-run | each renamed/moved/removed guard neutered | Its biter RED at the NEW site (or the retired guard's row struck with evidence); zero `MUTATED` residue | backup → neuter → RED → restore, byte-identical |
| Final gates | `clean build :buildSrc:test` | BUILD SUCCESSFUL; `:proxy:test` XML count = 352 − retired + added, every delta enumerated; 0 failed / 0 skipped | Console counts lie — XML only |

</frozen-after-approval>

## Code Map

**OIDC half (T1/T2):**
- `proxy/.../security/RopcBindCredentialVerifier.java` — the structural dispatch `:342-361` (three-segment JWS → `verifyJwt :384-409`; else → `introspect :459`); the 7662 arm `introspect :452-464` / `mapIntrospection :476` / `introspectRequest :498-513` (AD-12 says: never cached, online-only); `verifyJwt`'s Nimbus path `SignedJWT.parse :392` → `typ` RFC 8725 gate `:396-397` → kid lookup `:406` → `RSASSAVerifier :409`; `EXPECTED_TYP :129-133`; `jwks` field `:143`, construction `:191-192`
- `proxy/.../security/JwksCache.java` — DELETE whole class (AD-28(2) refresh VT `:77`, TTL guard `:74`, fetch+parse `:112-119`, fail-closed retain-on-misbehavior `:122`)
- `proxy/.../security/OidcStartupDiscovery.java` — field-completeness `:145-187` shrinks (drop `introspection_endpoint :159,164,169-172` and `jwks_uri :165,169,173` requirements); `OidcProviderMetadata :205-219` loses both URI components; HTTPS fail-fast unchanged
- `proxy/.../config/ProxyCompanionProperties.java:282,305-307` — the `jwksCacheTtl` component + `@NotNull`/`@DurationMin` messages die; `application.yml:113-114,123,132` comments/templates swept
- `proxy/build.gradle.kts:28` — `nimbus-jose-jwt` survives ONLY for discovery-JSON parsing (`JSONObjectUtils`) unless D7 rules otherwise; the `NoRolledCryptoArchitectureTest` `com.nimbusds..` allowlist needs no rule change
- OIDC-half tests: `security/JwksCacheTest` (DELETE), `RpcBindCredentialVerifierTest` AC3/AC4 rows (verify + introspection retire; non-JWT deny row new), `OidcStartupDiscoveryTest` completeness rows, `RpcSliceFailClosedTest`, `AdjudicationLifecycleTest` (JWKS close ordering), `KeycloakFixture` + `OidcDiscoveryStandIn` (stand-in stops serving jwks/introspection), `RpcBindCredentialVerifierLiveTest` (paths 2/4 of the 4-path validation retire), `CompanionConfigMatrixTest` jwks-cache-ttl rows
- Spine/contract: `ARCHITECTURE-SPINE.md` AD-12 `:139-142` (JWKS-endpoint + introspection-fallback wording), AD-8 `:115-118` clause (c) (the JWKS cache + `AtomicReference<JwkSet>` sentence), AD-28 `:226-229` arm (2) (the JWKS refresh executor), epics.md `:378` 4-path enumeration (paths 2 and 4 die), the AD-12 accepted-risk register, `.memlog.md` L105 amendment precedent

**Relay half (T3–T8):**
- `proxy/.../relay/RelayHandler.java` (345) — the split subject. Fields `:98-100`; the single shared `channelRead` `:110-179`; **the AD-25 flip `:131`** (the only production `flipSpliced()` caller — the N1 neuter site); direction checks `:155` (EGRESS+nack conjunct) and `:167` (INGRESS delegation); `peerOf` `:333-335` (third direction reader); `teardownPair` `:240`; `channelInactive` `:263`; `CLOSE_REASON`/`CLOSE_FIRED` attribute keys `:83/:87`
- `proxy/.../relay/BindInterceptor.java` (648) — role map: wiring/role-resolution `:113-217` (pending handles `:149/:151`, `EgressConnector` seam `:215`); intake state machine `onRequest` `:238-280`; adjudication `:283-374`; deny/teardown/synth `:376-463` (`teardownForPreCoupleViolation` `:431`, `synthesizeBindFailure` `:450`); egress dial + couple `openEgressAndForward` `:477-534`; ingress teardown window `:536-583`; nested `EgressLeg` `:585-647` (`answered` `:607`). The four pre-existing owner-FIXMEs `:142,284,298,601` — not new, do not sweep silently
- `proxy/.../relay/ConnectionEntry.java` (93) — the four AD-8 fields `:42-53`; `attach` `:56`, `spliced()` `:61`, `flipSpliced()` `:72`, `tearingDown()` `:77`, `beginTearingDown()` `:90`; CAS-once contract javadoc `:26-31`
- `proxy/.../relay/ConnectionRegistry.java` (127) — AD-8's named home; map `:38`, `ENTRY` attr `:41`, `register` `:52`, `attachEgress` `:67`, `entryFor` `:82`, `beginTeardown` `:101-113` (the removal half of the state machine), `size` `:124`
- `proxy/.../relay/netty/RelayIngressInitializer.java:78`, `RelayEgressInitializer.java:99` — the only two `new RelayHandler(...)` sites (per-leg split = zero wiring cost)
- Tests that de-target on rename — re-point deliberately, never silently: `relay/Relay025StatelessnessScanTest` (filename resolution `:109` + reflection `:107-115` — the hardest), `relay/netty/RelayPipelineInitializersTest` (`.class` lookups `:135-151`), `RelayHandlerTest` (whole file; helpers `couple()` `:485`, `coupleAndFlip()` `:494`; `EgressConnector` impl `:505`), `BindInterceptorTest` (`coupledEgress()` `:489`; `EgressConnector` `:502`), `BindInterceptorForwardRoleTest` (`EgressConnector` `:195`), `ConnectionRegistryTest` (CAS-once pins `:116,:139,:194`), `observability/SpliceObserverShapeTest` (`PRE_COUPLE_NON_BIND_PDU` literal `:115`), `observability/CapturingSpliceObserver`, `testsupport/RelayTestFixtures`, `TlsModesLoopbackE2eTest`, `JsmppA1OracleTest`, `RelayA1SmokeTest` (assertion strings `:164,166,242,438`)
- Spine: AD-25 `:211-214` (names `RelayHandler`; "splice/flip" wording), AD-8 `:115-118` (names `ConnectionRegistry`), AD-2 `:72-75`, AD-27 `:221-224` (`SpliceObserver` 4-method shape + pinned triggers), AD-32 `:246-253`

## Tasks & Acceptance

**Execution:**
- [ ] T1 — JWT-only adjudication: delete the RFC 7662 arm (`introspect`/`mapIntrospection`/`introspectRequest`, the discovery `introspection_endpoint` requirement, the metadata component, stand-in/fixture serving); non-JWT token response → the D6 fail-closed arm; sweep yml comments + matrix rows; register the policy in the discovery/probe docs surface. (AC1)
- [ ] T2 — TLS-as-sole-trust-anchor: delete `verifyJwt`'s signature/kid/typ verification and `JwksCache` (class + refresh VT + `oidc.jwks-cache-ttl` knob + `jwks_uri` requirement); keep the structural JWT-ness gate per D7; spine amendments AD-12 / AD-8(c) / AD-28(2) + epics 4-path + register + TEA rows, dated markers + `.memlog.md` entries (rationale: owner 2026-08-27 — the proxy is the token's only consumer; the HTTPS client-authenticated provider link is the trust anchor). (AC2, AC3)
- [ ] T3 — THE UMBRELLA DECISION, FIRST among the refactoring tasks (owner checkpoint): state-manager variant (single manager vs per-role managers — one fork with the interceptor role-split at manager altitude), mechanics (sealed decision returned to the caller vs executor-facing port), and state-absorption scope (`pendingVerdict`/`pendingPassword`? `EgressLeg.answered`? `CLOSE_*` attributes?). Recorded as a dated `.memlog.md` `(decision)` entry + Design Notes addendum BEFORE T5/T6 execute. (AC4)
- [ ] T4 — Couple-vocabulary unification: code identifiers to `couple`-variants (`spliced()` → `coupled()`, `flipSpliced()` → successor named once with the T3 state names); relay prose + test names/assertion strings swept; spine-sweep scope per D1's resolution; full deliberate re-targeting list. (AC5)
- [ ] T5 — `RelayHandler` direction-split: two per-leg classes over one shared post-couple splice component; flip structural-by-type; `CLOSE_*` key strategy per D5; `RelayPipelineInitializersTest` re-pointed; AD-25 dated spine marker + memlog entry. (AC6)
- [ ] T6 — State-manager extraction per T3: policy OVER the registry's storage (no second state copy); the six teardown sites folded into one ordering; hot path untouched; `EgressLeg`/pending-handle placement per T3. (AC7, AC8)
- [ ] T7 — Ledger hygiene: F13 RESOLVED marker (work landed 3.3 T6, ledger unmarked), the four 2026-08-27 story-text-pass markers (executed by `cda2013`), F7 disposition marker per D4. Marker form: a dated `**✅ RESOLVED …**` continuation under the entry (the two existing prose forms; no fielded entry has been resolved yet — this story sets that precedent, append the marker, don't restructure the fields). (AC11)
- [ ] T8 — Full RED-on-neuter mutation re-run, POST-renames: fresh rows for every renamed/moved neuter site; struck-with-evidence rows for retired guards (7662 arm, verify path, cache TTL); the 2.2 N-series relay biters re-proven at their new sites; final gates. (AC9, AC10)

**Acceptance Criteria:**
- Given a provider whose token endpoint returns a non-three-segment (opaque) token, then the verdict is `DenyIndeterminate` with a WARN stating the JWT-only policy, no introspection wire call exists in the codebase, and a new pin proves the arm.
- Given a JWT-issuing provider, then `Allow` derives from the token endpoint's HTTPS-authenticated response alone — zero JWKS infrastructure remains (no `JwksCache`, no refresh thread, no `jwks-cache-ttl` knob, no `jwks_uri` requirement), the structural JWT-ness gate matches D7's resolution, and a stale `jwks-cache-ttl` key refuses startup.
- Given the spine at wrap, then AD-12, AD-8 clause (c), and AD-28 arm (2) carry dated in-place amendment markers, `.memlog.md` carries the entries with a Propagated list, epics.md's 4-path enumeration and the register are swept, and the retired TEA rows are marked.
- Given the T3 decision recorded in the memlog, when T5/T6 execute, then the split/manager shape matches it exactly — drift requires a new owner checkpoint.
- Given the vocabulary round, when it lands, then every surviving `splice`/`flip` occurrence in relay code or prose is either quoted spine contract text (exactly per D1's resolution) or swept — the survivor inventory lands in the Completion Notes.
- Given the split, when a decoded ROK `bind_resp` arrives, then the flip call site exists in exactly one class and the ingress class cannot express it (structural-by-type); `onBindAccept` still fires exactly at the flip.
- Given teardown from ANY site, then ordering is remove+mark → cancel+wipe → close, unchanged; RELAY-005/006 idempotence + no-orphan pins green; `onConnectionClosed` exactly-once per channel.
- Given the post-couple hot path, then a coupled PDU remains flag-read + forward — no manager consultation, no new virtual dispatch per PDU.
- Given each neutered/moved guard, then its biter goes RED at the NEW site, and each retired guard's ledger row is struck with evidence (restore byte-identical; zero `MUTATED` residue).
- Given `./gradlew clean build :buildSrc:test`, then BUILD SUCCESSFUL with `:proxy:test` count = 352 − retired + added (XML counts; every delta enumerated), 0 failed / 0 skipped.
- Given the deferred-work ledger at wrap, then F13 and the four story-text-pass entries carry dated RESOLVED markers and F7's disposition (absorbed-with-pin or re-homed) is recorded — no ledger marker owed by this story remains open.

### Review Findings

## Spec Change Log

- **2026-08-27 (pre-dev, owner-directed):** scope widened ahead of any implementation — two OIDC token-path simplifications inserted as T1/T2 (remove the RFC 7662 opaque-token arm, JWT-only; remove local JWT signature verification and with it `JwksCache`, its refresh VT, the `jwks-cache-ttl` knob, and the `jwks_uri` discovery requirement). Title, Intent, Boundaries, I/O matrix, Code Map, and ACs re-baselined; the refactoring round (former T1–T6) renumbered T3–T8 with the umbrella-first constraint preserved.

## Design Notes

**Rationale record (owner, 2026-08-27):** the proxy is the token's ONLY consumer — it never forwards, caches, nor shows the token to anyone; the verdict is the token endpoint's own response (AC2 mapping unchanged). Re-proving the provider's honesty locally (signature verification against fetched keys) guards against a threat that already owns the HTTPS channel the keys came over; the introspection arm exists for opaque-token provider fleets this single-pinned-Keycloak deployment is not. Simpler + fail-closed wins.

**D6 — non-JWT posture (Ask First):** token shape is observable only at bind time (a startup probe would need a real credential), so the arm is RUNTIME: `DenyIndeterminate` + a WARN naming the JWT-only policy and the operator remediation (configure the client/realm to issue JWT access tokens). Lean: that, verbatim.

**D7 — what survives of the JWT + Nimbus (Ask First):** lean = keep ONLY the structural three-segment gate (the "always returns JWT" requirement — cheap, no library: split on `.`); DROP `typ`/`iss`/`exp`/`kid` handling with the verification (unverified-claim checks are theater — the endpoint verdict already decided). `nimbus-jose-jwt` then survives only for discovery-JSON parsing (`JSONObjectUtils` — the proxy has no Jackson); keep the dep and its `com.nimbusds..` crypto-allowlist entry. Alternative (not lean): parse claims for expiry logging — rejected: adds parse surface for zero verdict effect.

**D1 — vocabulary-sweep scope (Ask First):** (a) code+prose only, vs (b) full unification including spine AD-25/AD-2 title + rule text ("Bind→splice transition state machine", "flip-flag") with dated in-place markers + memlog. The ledger warns (a) "re-creates the same code/prose split one level up" — lean (b). Sub-fork: does `SpliceObserver` rename? A ratified-contract change rippling AD-27, epics.md, the TEA docs, and the readiness report; memlog L105 is the amendment-path precedent. `onFramedPdu` is already couple-neutral; `PRE_COUPLE_NON_BIND_PDU` already speaks couple.

**D2 — manager variant + mechanics (the T3 fork):** (1) single manager covering both roles vs (2) per-role managers — the SAME fork as the interceptor role-split at a different altitude; treat as ONE. Mechanics: sealed decision returned to the caller (lean — avoids the circular manager↔handler dependency; record which is chosen). Thread-bounding: manager = event-loop-confined policy like the handlers; the verdict continuation hop is its single off-loop entry; VT-side adjudication kickoff stays in the interceptor's control-plane half.

**Candidate explicit state set (2026-08-16 T7 note + as-built):** `not-registered` → `registered/adjudicating` (RELAY-004 in-flight predicate) → `egress-attached/connecting` → `awaiting-bind_resp` (`EgressLeg.answered == false`) → `coupled` (the AD-25 flip) → `tearing-down` (CAS mark). AD-32 constraint: any explicit state DERIVES from the registry entry on every read — never a shadow boolean.

**D3 — split-half naming:** candidate `RelayIngressHandler`/`RelayEgressHandler` over a shared splice component (name it once with the T4 vocabulary). Spine AD-25 names `RelayHandler` — dated marker + memlog either way. `ConnectionRegistry`/`ConnectionEntry` type names: KEEP — AD-8 names the registry, RELAY-025 resolves it by filename, and the types were never the inconsistent words (all couple/pair vocabulary lives in identifiers and prose, not type names).

**D4 — F7 (Ask First):** verdict-future frame ownership — a cancelled, never-settling verdict leaks one pooled buffer (the `whenComplete` continuation is the only releaser of `req.originalFrame()`). Owner deferred to "Epic 3" (now done) → 3.4 must consciously **absorb** (small: one release arm + one pin — lean, fail-closed hygiene) or **re-home** to the Epic-4 RELAY-020/021 timeout round.

**D5 — optional mechanical absorb:** F9's `CLOSE_REASON` key hoisting (today `RelayHandler`-private, class-scoped) rides the direction-split naturally; the reason *semantics* stay Epic-4. Zero-cost if the split already moves the keys — decide with T3's state-absorption scope.

**Scatter map (T6 input):** pending handles `BindInterceptor:149,151` (settle/wipe protocol at `:332-333`, `:348,371-372`, `:408-419`); `EgressLeg.answered` `:607`; `CLOSE_REASON`/`CLOSE_FIRED` attrs `RelayHandler:83,87`; the registry's removal half `ConnectionRegistry:101-113`; teardown ordering re-implemented at six sites — `BindInterceptor:384,431,539,560` + `RelayHandler:240,263`.

**Mutation-pass traps (inherited, 2.2 + 3.3):** neuter-site renames silently de-target biters (N1's site IS the flip call — T8 re-proves it at the successor site); a biter whose assertion can throw must release latches in `finally`; force `cleanTest` for source-scan tests (Gradle UP-TO-DATE skips them); EmbeddedChannel gotchas — `DefaultChannelId.newInstance()`, `runPendingTasks()` after completing held futures, pre-close delivery for exactly-once pins.

## Verification

**Commands:**
- `./gradlew clean build :buildSrc:test` — expected: BUILD SUCCESSFUL
- `./gradlew :proxy:test` post-`cleanTest` — expected: count = 352 − retired + added, every delta enumerated; 0 failed / 0 skipped, XML-verified (console counts lie)
- `grep -rn "FIXME\|@Disabled" <diff files>` — expected: zero new occurrences (the four owner-FIXMEs at `BindInterceptor:142,284,298,601` pre-exist)
- `grep -rn "MUTATED" proxy/src` — expected: empty (mutation-residue scan)
- `grep -rn "7662\|introspect\|jwks\|Jwks" proxy/src/main` — expected: empty (T1/T2 removal completeness)

## Dev Agent Record

### Agent Model Used

### Debug Log References

### Completion Notes List

### RED-on-neuter mutation ledger (T8 / AI-1)

### File List
