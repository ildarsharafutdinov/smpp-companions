---
title: 'Story 3.3: TLS modes A/B/C on the internet leg + forward-role landing'
type: 'feature'
created: '2026-08-21'
status: 'done'
review_loop_iteration: 0
baseline_commit: 96189384cf2b8439e3bd88b8c915d84a7986395f
context: []
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Epic 3's TLS half is unbuilt: the acceptor still mounts only `reverse.mode-b` (`RelayServerLifecycle.java:71-74` early-return), modes A/B/C exist as validated config with zero runtime (no `SslHandler` anywhere in main), the forward role has no acceptor/routing gate, and the spine's internet-leg dial direction contradicts the as-built 1.3 config.

**Approach:** Execute the user-ratified **[B] topology** (2026-08-21: "Yes / no constraint → [B]") — the forward dials the reverse **per SMPP session**; the reverse holds the internet-leg TLS listener — by first sweeping the spine to [B], then landing the runtime: per-cell Netty `SslContext` factories with startup AD-34 intersection, the forward interceptor (routing gate → per-session egress dial), the reverse TLS acceptor, and F13 listener hardening.

## Boundaries & Constraints

**Always:**
- Fail-closed (AD-11) on every new decision path: routing-miss → AD-33-collapsed deny; empty cipher/protocol intersection per context at startup → refuse; trust store 5-state (absent/empty/wrong-format/wrong-password/zero-entries) → refuse; Mode C = `clientAuth(REQUIRE)`, never WANT; over-cap connection → refuse.
- 1 : 1 : 1 per session — one client session ↔ one internet-leg connection ↔ one SMSC session; verbatim frames, per-session sequence space; pairing/registry keyed per session (channel), never per `system_id`; N concurrent sessions per `system_id` route to the same single target.
- PKIX defaults only — no custom chain validation, no `PKIXBuilderParameters`; trust never falls back to JDK `cacerts` (AD-13/AD-26); TLS material immutable after startup (AD-18 file paths, rotation = re-deploy).
- All existing green tests stay green except the deliberately flipped pins (T2 blast radius, enumerated in Code Map); every fail-fast guard ships a RED-on-neuter control (AI-1 standing gate).

**Ask First:**
- Any spine/AD deviation beyond the ratified [B] sweep; any new runtime dependency (none expected — `netty-handler` is on the classpath); any touch to the AD-12 port types or `VerifierWiringConfig` semantics; any wire-visible behavior beyond the shipped AD-33 collapse.

**Never:**
- No TLS on the trusted legacy leg or the SMSC leg; no multiplexing, control channel, or warm-lane pool (rejected — [B] chosen); no vendor SDK, no BouncyCastle (JDK provider path); no Epic-4 metrics/observer changes (routing-miss = log-only); no relay cleanup-cluster refactors (couple-vocabulary, `RelayHandler` split, state-manager — Story 3.4); do not re-litigate 3.2 (adjudication, zeroization, Mode B ack — all shipped).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Mode A bind | forward.mode-a cell, bind from allowed `system_id` | One-way TLS dial to target; bind relayed; session 1:1:1 end-to-end | N/A |
| Mode C bind | forward.mode-c → reverse.mode-c | mTLS dial (per-instance client cert); reverse `REQUIRE`s it; relay proceeds | N/A |
| Mode C, no client cert | peer connects to reverse listener without cert | TLS handshake fails at the reverse | Connection closed, no SMPP PDU emitted |
| Routing miss | bind `system_id` ∉ routing table | `ESME_RBINDFAIL` header-only resp + close (AD-33) | Log-only (no observer fire) |
| Unknown `tlsContextId` | routing entry references absent `companion.forward.tls-contexts` key *(re-keyed, memlog 2026-08-26)* | Refuse startup | Fail-fast, SEC-id message |
| Empty intersection | configured ciphers ∩ context-supported = ∅ on any axis | Refuse startup | Fail-fast (AD-34/D2) |
| Trust store bad | any of the 5 states on any context | Refuse startup | Fail-fast (AD-13) |
| Raw-IP target | routing target host is an IP literal | `endpointIdentificationAlgorithm = null` (explicit); IP-SAN + verify-on is the alternative posture | N/A |
| Target unreachable | forward dial to reverse target fails | AD-33 connect-fail collapse (shipped arm) | Deny + close |
| Cap exceeded | accepted connections > `companion.memory.concurrent-pairs` *(knob re-keyed, memlog 2026-08-26)* | Refuse new connection (close + log) | Cap IS the AD-30 budget input — equality by construction (separate guard retired with the knob) |
| Mode B regression | reverse.mode-b boot | Behavior byte-identical to 2.2 (plaintext, ack, adjudicate) | N/A |

</frozen-after-approval>

## Code Map

- `proxy/.../relay/netty/RelayServerLifecycle.java` — acceptor; widen `:71-74` mode-b guard to per-cell branch; `RELAY_ACCEPTOR_PHASE :59` stop-order anchor
- `proxy/.../relay/BindInterceptor.java` — ctor refusal `:158-164`; verdict flow `:199-287`; deny collapse `:333-345` (`synthesizeBindFailure :390-403`); per-bind egress dial `openEgressAndForward :412-442` (AD-2 same-loop); `EgressLeg :510-555` — role-split executes here
- `proxy/.../relay/netty/RelayIngressInitializer.java:52-61`, `RelayEgressInitializer.java:44-50` — SslHandler `addFirst` insertion points; singleton `@Component`s need per-cell parametrization
- `proxy/.../relay/ConnectionRegistry.java` — per-channel entries at first bind (`register :52-57`) — unchanged keying
- `proxy/.../config/ProxyCompanionProperties.java` — re-shape per Design Notes table: `ForwardModeA :132-138` (−serverCert, +trustStore), `ForwardModeC :144-152` (−serverCert, +clientCert), `ReverseModeA :159-167` (−trustStore, +serverCert), `ReverseModeC :188-198` (−clientCert, +serverCert), `Tls :205-210` (+`contexts` map), `Bind :341-347` (+host, +max-connections); `RoutingEntry :400-410` unchanged (correct under [B])
- `proxy/.../config/CompanionConfigValidator.java` — dispatch `:155-184`, routing `:252-281`, 5-state `:352-406`, TLS floor `:425-486` — extend per re-shape
- `proxy/.../security/IdpSslContextFactory.java` — pattern to mirror: 5-state load `:161-200`, `intersectTlsPolicy :229-259` (both-axis, empty→refuse)
- `proxy/.../security/VerifierWiringConfig.java:38-45` — forward→AlwaysAllow already wired; DO NOT TOUCH
- Test blast radius (move in lockstep, `ignoreUnknownFields=false`): `config/TestCompanionConfigs.java` (five cells `:41-93`, `common() :139-166`, `touch()` empty certs must become real fixtures), `CompanionConfigMatrixTest`, `CompanionTlsBindingTest`, `CompanionRoleFailFastTest :83-102`, `bootstrap/BootstrapLifecycleTest.java:76-89`, `relay/netty/RelayServerLifecycleTest.java` (`forwardABuilder :210-232`, inert-boot `:99-113` must flip live), `relay/netty/DirectMemoryBudgetStartupCheckTest.java:122/240`
- `proxy/src/test/resources/keycloak/certs/generate.sh` — committed-PKI precedent; extend for SMPP-leg material (reverse listener server cert, forward per-instance client cert, mutual trust stores)
- `proxy/.../security/SecurityTlsSurfaceArchitectureTest.java:49-101` — SEC-090 scoped to `..security..` today; widen to cover the new TLS factory package
- `proxy/build.gradle.kts:26-27` — `netty-handler` present (bom 4.2.16.Final); expect NO new deps
- Spine: `ARCHITECTURE-SPINE.md` AD-12 `:140`, AD-17 `:171-172`, AD-20 `:188-189`, AD-26 `:218-219`, AD-34 `:263`, register; `.memlog.md` append-only sweep entry

## Tasks & Acceptance

**Execution:**
- [x] Spine sweep to [B] — AD-12/17/20/26 + Accepted-Risk Register (Mode A harvest entry retires → submission-oracle residual) + epics.md refs + `.memlog.md` dated entry — contract-amendment discipline
- [x] Config re-shape (per Design Notes table) + `tls.contexts` map + `bind.host`/`bind.max-connections` + validator matrix + full test blast radius + real cert fixtures — config-tier refusal tests (null-vs-blank rule)
- [x] SMPP-leg TLS factory (server/client `SslContextBuilder`, JDK provider; 5-state stores; per-context AD-34 intersection; AD-20 endpoint-identification) + SEC-090 gate widened — unit tests + mutations
- [x] Reverse acceptor widening — mode-a/c internet TLS listener on `bind.port`, `clientAuth(REQUIRE)` in C, initializer parametrization — per-cell wiring tests
- [x] Forward role — interceptor role-split execution (shared skeleton; forward arm = routing gate → miss-deny → AlwaysAllow verdict → per-session egress dial with client SslHandler per `tlsContextId`); `RelayServerLifecycle` forward branch — wiring tests
- [x] F13 — `bind.host` + `max-connections` cap at the acceptor + AD-30-consistency startup guard — cap/refusal tests
- [x] Loopback integration suite — Mode A e2e, Mode C mTLS e2e + REQUIRE-negative, routing-miss on-wire collapse, N sessions per `system_id`, cap, Mode B regression
- [x] Consolidated RED-on-neuter mutation ledger + final gates (AI-1)

**Acceptance Criteria:**
- Given a forward.mode-c full context with real fixtures, when a client binds an allowed `system_id`, then the bind traverses trusted leg → mTLS dial → reverse adjudication (ROPC) → SMSC dial, verbatim, one session per connection.
- Given a bind whose `system_id` is not in the routing table, then the client receives the AD-33 `ESME_RBINDFAIL` collapse and the connection closes; nothing fires `onBindReject`.
- Given any cell whose configured TLS sets intersect empty on either axis, or any trust store in a bad state, then startup refuses with the SEC-id message.
- Given a Mode C reverse listener, when a peer presents no client cert or an unanchored one, then the TLS handshake fails and no SMPP bytes are read.
- Given the accepted-connection cap exceeded (`companion.memory.concurrent-pairs`), then new connections are refused; the cap reads the AD-30 budget input directly — equality by construction, the separate cap≤budget guard retired with the `bind.max-connections` knob (memlog 2026-08-26).
- Given `./gradlew clean build :buildSrc:test`, then BUILD SUCCESSFUL with `:proxy:test` 0 failed / 0 skipped (XML counts).

### Review Findings

**Code review 2026-08-27** — 4 adversarial layers (blind-hunter, edge-case-hunter, verification-gap, acceptance-auditor) over the `9618938`→working-tree diff (45 files); 39 raw findings → 21 after dedup + source verification; 4 dismissed.

**Decision needed** (both resolved by owner 2026-08-27 → patches):

- [x] [Review][Patch] Restore the Mode A loud startup warning (D1 → option 1) — add a `CompanionModeAWarning`-style log-only startup WARN for `reverse.mode-a` (mirrors `CompanionModeBWarning`; not wire-visible); fix the stale `epic-3-context.md:17,24` prose (story-text pass).
- [x] [Review][Patch] Add SEC ids to the AD-34/ctor-wrap refusals (D2 → option 1) — `SmppLegTlsFactory:106,285,293,302` get the new policy-intersection SEC id (register touch; sweep the register/markers in the story-text pass).

**Patches:**

- [x] [Review][Patch] AC4 "unanchored cert" arm untested [TlsModesLoopbackE2eTest] — only the cert-less probe exists; add a foreign-CA fixture + REQUIRE-negative row presenting an unanchored cert, assert handshake failure.
- [x] [Review][Patch] AD-20 endpoint-identification never observed [SmppLegTlsFactory.java:227] — pin `engine().getSSLParameters().getEndpointIdentificationAlgorithm()` null-vs-`"HTTPS"` per entry shape (deleting the line keeps every suite green today).
- [x] [Review][Patch] Cap decrement/recovery untested [TlsModesLoopbackE2eTest cap row] — close the capped connection, reconnect, assert re-accept (neutering `ConnectionCapHandler.java:58` stays green: the cap degrades to N-total-per-process).
- [x] [Review][Patch] `bind.host` never verified honored [RelayServerLifecycle.java:91] — no test observes the bound address; reverting to `bind(port)` stays green (a wildcard bind serves every loopback test). Pin `localAddress()` host or add a 127.0.0.2 negative.
- [x] [Review][Patch] AD-28 delegated-task executor never observed [SmppLegTlsFactory.java:130] — every test constructs the factory with `Runnable::run`; no test proves handshake tasks land on the bounded pool (only the saturation arm is ledger-recorded).
- [x] [Review][Patch] Orphan `companion.forward.tls-contexts` entries escape all validation [SmppLegTlsFactory.java:216] — the validator derives `keySet()` only (`CompanionConfigValidator.java:177`); the factory loads only routing-referenced ids, so an unreferenced entry with nonexistent/unparseable material boots clean (AD-18 broken on the new surface). Eager-load every map entry fail-closed.
- [x] [Review][Patch] AD-34 misses suite/protocol applicability [SmppLegTlsFactory.java:283] — the two intersections are computed independently; TLS-1.3-only suites + `protocols=[TLSv1.2]` passes startup and fails every handshake. Refuse when no enabled suite applies to any selected protocol; add the mixed-case test.
- [x] [Review][Patch] `isIpLiteral` accepts invalid dotted-quads [SmppLegTlsFactory.java:379] — `999.1.2.3` matches the regex → verification OFF, but a resolver treats it as a DNS name (silent AD-20 downgrade); require octets ≤ 255, else fall to hostname-ON (the method's own fail-closed rule).
- [x] [Review][Patch] Factory null-material re-checks missing [SmppLegTlsFactory.java:184] — a directly-constructed mode-c record with null trust-store silently yields `ClientAuth.NONE` (null client-cert dials cert-less); `resolveClientCert:247` sets the factory-re-check precedent — mirror it for both mode-c materials.
- [x] [Review][Patch] `TargetTls` javadoc contradicts the seam [RelayEgressInitializer.java:64] — `@param ... non-null` while the `@Autowired` singleton legitimately delegates null (the plaintext SMSC leg); document null-means-plaintext.
- [x] [Review][Patch] Unused `RoutingTable.present()` [RoutingTable.java:56] — zero callers in main or test; drop it and the javadoc claim referencing it.
- [x] [Review][Patch] Stale 2.2-era comments beside new behavior [TestCompanionConfigs.java:156, CompanionTlsBindingTest.java:65, RelayServerLifecycle.java:110] + `BindInterceptor`'s fully-qualified inline `@lombok.extern.slf4j.Slf4j` — all contradict the shipped every-cell-binds acceptor.
- [x] [Review][Patch] e2e oracle reads implausible `command_length` unguarded [TlsModesLoopbackE2eTest.java:435] — bound-check (<16 or >1 MiB → EOF) so a malformed harness PDU fails loudly, not with AIOOBE.

*All 15 patches applied 2026-08-27 (owner: apply-every). Gate: `./gradlew clean build :buildSrc:test` BUILD SUCCESSFUL; `:proxy:test` **352 tests / 0 failed / 0 skipped** (XML counts — 347 post-rework + 5 new review tests); FIXME/@Disabled scan of changed files: zero new occurrences. New fixture: `generate.sh` §10 (foreign CA + unanchored client pair, committed). New warning bean: `CompanionModeAWarning` (D1). New SEC id: **SEC-100** = TLS policy/material startup refusal (D2; register sweep pending in the story-text pass). One collateral fix during application: `BindInterceptor`'s inline `@lombok.extern.slf4j.Slf4j` → import + `@Slf4j`.*

**Deferred** (owner-scheduled; see deferred-work.md §2026-08-27):

- [x] [Review][Defer] Story contract text not swept to the re-keyed/retired surface [3-3-tls-modes-and-forward-acceptor.md:84] — AC5 names the retired `max-connections` + deleted cap≤budget guard; T2/T6 notes, I/O-matrix, Design Notes, File List name top-level `tls.contexts` — deferred: memlog-scheduled story-text pass at review wrap.
- [x] [Review][Defer] Mutation ledger stale + fresh RED-on-neuter pass owed [3-3-tls-modes-and-forward-acceptor.md:137] — M3 ran pre-rekey, M4/M10 pin deleted guards — deferred: memlog-scheduled with the story-text pass.
- [x] [Review][Defer] Dev Record test count stale (352 vs memlog/XML 347) [3-3-tls-modes-and-forward-acceptor.md:121] — deferred: re-baseline in the story-text pass.
- [x] [Review][Defer] Companion docs unswept [epic-3-context.md:17] — pre-[B] inverted topology, "not yet created" story claim, retired key at deferred-work.md:511, stale sprint-status comment — deferred: enumerated in the memlog NOT-yet-swept list.
- [x] [Review][Defer] ROPC adjudication not e2e-proven through TLS [TlsModesLoopbackE2eTest] — deferred: already recorded (close-out 2026-08-25).
- [x] [Review][Defer] Override cert never e2e-dialed [deferred-work.md:511] — deferred: already recorded (close-out 2026-08-25).

## Spec Change Log

## Design Notes

**[B] decision record (user, 2026-08-21):** dial direction was never load-bearing (no carrier inbound constraint); forward dials per session — symmetric with the existing per-bind SMSC dial, zero new choreography components; the [A1] warm-lane pool and [A2] multiplexed standing connection were rejected (complexity / SMPP seq demux impossibility). Spine sweep required: AD-12/17/20/26 + register re-point to "the forward's TLS client validates the reverse's internet-leg server cert"; AD-29 is correct **as-built** (routing entry = the forward's dial target) and gains only the `tls.contexts` completion.

**Per-cell TLS material under [B]** (re-shapes the 1.3 records; pre-release break, no shims):

| cell | listener on `bind.port` | per-session dial | TLS material |
|---|---|---|---|
| forward.mode-a | trusted leg, plaintext | → routing target | client ctx: trust store |
| forward.mode-c | trusted leg, plaintext | → routing target | + per-instance client cert |
| reverse.mode-a | internet leg, TLS server | → SMSC, plaintext | server cert |
| reverse.mode-b | legacy direct, plaintext | → SMSC, plaintext | none (unchanged) |
| reverse.mode-c | internet leg, TLS server | → SMSC, plaintext | server cert + trust store (`REQUIRE`) |

`companion.forward.tls-contexts` map (re-keyed from top-level `tls.contexts`, memlog 2026-08-26 — the forward branch consumes it exclusively; the `companion.tls` node keeps POLICY only): id → client-cert/key override; routing entry `tlsContextId` selects; absent → instance-level default context (AD-29/AD-13 per-instance default, per-target permitted).

## Verification

**Commands:**
- `./gradlew clean build :buildSrc:test` -- expected: BUILD SUCCESSFUL
- `./gradlew :proxy:test` post-`cleanTest` -- expected: 0 failed / 0 skipped, XML-verified (console counts lie)
- `grep -rn "FIXME\|@Disabled" <diff files>` -- expected: zero new occurrences

## Dev Agent Record

### Agent Model Used

GLM 5.2 (Claude Code harness, 2026-08-25; resumed once after an API-limit kill mid-run — the working tree survived byte-identical).

### Debug Log References

- `./gradlew clean build :buildSrc:test` — **BUILD SUCCESSFUL** (the Verification gate).
- `:proxy:test` XML (post-`cleanTest`, counted from `build/test-results/test/*.xml`): **352 tests, 0 failed, 0 skipped** (up from the 3.2 baseline's 331-run surface; +21 net new tests across 4 new suites + widened existing ones). Re-verified at the 2026-08-27 story-text close-out gate: `clean build :buildSrc:test` GREEN, XML 352/0/0 — the memlog 2026-08-26 gate line's 347 was the pre-review-patch count (352 = 347 + 5 review tests).
- `grep -rn "FIXME\|@Disabled" <diff files>` — zero new occurrences (pre-existing `owner FIXME` comments in untouched regions remain, e.g. `BindInterceptorTest`'s T7 notes).
- Two empirical Netty/JDK findings drove code fixes (both proven by standalone scratch experiments before the fix): (1) TLS 1.3 `startHandshake()` RETURNS for a cert-less client — the server's `(certificate_required)` alert lands one flight later and surfaces on first I/O, so the REQUIRE-negative pin asserts the read, not the handshake call; (2) an accepted-but-unregistered child channel CANNOT be `close()`d ("channel not registered to an event loop") — `ConnectionCapHandler` uses `unsafe().closeForcibly()` (Netty's own `ServerBootstrapAcceptor` failure-path idiom), which sends an RST.

### Completion Notes List

- **T1 (spine sweep)** — AD-12/AD-17/AD-20/AD-26 amended in place with dated `[B]` markers; the register's Mode A entry rewritten (harvest → submission oracle); epics.md bullets + summary-table rows + register swept; `.memlog.md` gained the dated amendment entry (append-only). The spine's topology mermaid is unchanged — its edge already shows forward→reverse DATA flow; [B] changes who listens vs dials, which the AD prose now owns.
- **T2 (config re-shape)** — `ForwardModeA(trustStore, routing)`, `ForwardModeC(clientCert, trustStore, routing)`, `ReverseModeA(smsc, serverCert, oidc)`, `ReverseModeC(smsc, serverCert, trustStore, oidc)`, `Tls(+policy keys only)`, `Bind(+host)`, `ForwardMode(+tls-contexts map)`; validator re-dispatched per the new shapes + SEC-098 (unknown `tls-context-id`, re-keyed to `companion.forward.tls-contexts`; the F13/AD-30 cap≤budget guard retired with `bind.max-connections` — memlog 2026-08-26); `application.yml` (bind.host default, tls-contexts template, re-shaped branch comments); every full-boot fixture now carries REAL SMPP-leg material (the boots construct `SmppLegTlsFactory`). SEC-id re-pointings under [B]: SEC-056 = reverse's server cert; SEC-057 = forward's client cert; SEC-096 = forward's dial trust store; SEC-098 new; SEC-050 unchanged.
- **T3 (TLS factory)** — new package `smpp.companion.proxy.tls`: `SmppLegTlsFactory` (eager fail-closed per-cell listener + per-routing-entry egress `SslContext`s; JDK provider; 5-state stores; per-context AD-34 intersection; AD-20 per-target endpoint-identification — null for IP literals) and `TlsWiringConfig` (the AD-28(1)/AD-4 bounded hand-managed platform-thread delegated-task executor, AbortPolicy = abort-handshake-on-saturation; Netty's `SslHandler.executeDelegatedTask` rethrows REE — verified in the 4.2.16.Final sources). SEC-090 widened: the three forbid rules now cover ALL of `smpp.companion.proxy` main + a positive control pins the factory on Netty `SslContext`/`SslContextBuilder`.
- **T4 (reverse acceptor)** — `RelayServerLifecycle` binds `bind.host:bind.port` for EVERY cell (the 2.2 mode-b guard retired); `RelayIngressInitializer` prepends the listener `SslHandler` iff `listenerTls()` (reverse a/c). Wiring pinned by full boots (reverse-a/c live TLS listeners; forward's trusted-leg listener — the flipped 2.2 inert pin) + pipeline-shape tests.
- **T5 (forward role)** — `BindInterceptor` role-split: the forward arm gates on `RoutingTable.route(systemId)` BEFORE registration/adjudication (miss → `writeBindFailureAndClose`, log-only, never `onBindReject`, no dial); the hit dials the ROUTING target with a per-bind TLS-carrying `RelayEgressInitializer` (client `SslHandler` per entry, `SslHandler` first). The reverse arm is byte-identical to 2.2/3.2 behavior (fixed SMSC target, plaintext singleton initializer). `VerifierWiringConfig` untouched (forward→AlwaysAllow already wired — AD-12 amendment).
- **T6 (F13)** — `bind.host` (`@NotNull`+`@NotBlank`, yml default `0.0.0.0`) + `ConnectionCapHandler` on the acceptor's server pipeline (closeForcibly + WARN; decrement exactly-once per child closeFuture); the cap reads `companion.memory.concurrent-pairs` DIRECTLY — `bind.max-connections` and the validator's cap≤budget guard were retired mid-review (memlog 2026-08-26: two knobs for one number = drift surface; the budget input IS the physically-consistent cap).
- **T7 (loopback e2e)** — `TlsModesLoopbackE2eTest` (10 tests — 7 shipped + the 2026-08-27 review rows `modeCRequireRefusesTheUnanchoredPeer` / `bindHostScopesTheListener` / `delegatedHandshakeTasksRunOnTheExecutor`, with cap decrement/recovery folded into the cap row; real sockets, two in-JVM relay instances + `MockSmsc`): Mode A e2e, Mode C mTLS e2e, REQUIRE-negative (cert-less + unanchored), routing-miss on-wire collapse (0x0000000D + close + nothing at the reverse), N-sessions-per-system_id (per-channel pairing), cap refusal + recovery, `bind.host` scoping, Mode B regression. The deep Mode-B/A-1 coverage remains `RelayA1SmokeTest` (green).
- **T8 (mutation ledger)** — see below.
- **Housekeeping** — `keycloak/certs/generate.sh` extended with sections 7–9 reusing the EXISTING committed CA (no regeneration of the Keycloak artifacts — provenance script + committed PEMs/stores stay mutually consistent); `RelayTestFixtures` gained the generic `relayHarness`, the four TLS-cell property builders, and `smppTlsLegs` (classpath materializer).

### RED-on-neuter mutation ledger (T8 / AI-1)

Every mutation: backup → neuter → run the pinning suite → confirm RED → restore (verified zero `MUTATED` residue afterward). All 13 RED (M14/M15 added by the 2026-08-27 story-text pass, replacing the retired M4/M10 and superseding M3's pre-rekey run):

| # | Neutered guard | RED test |
|---|---|---|
| M1 | TLS factory 5-state (empty + zero-`trustedCertEntry`) | `SmppLegTlsFactoryTest` 5-state matrix |
| M2 | AD-34 per-context intersection (ciphers + protocols) | `SmppLegTlsFactoryTest` empty-intersection |
| M3 | SEC-098 unknown `tls-context-id` *(ran against the retired top-level `companion.tls.contexts` sourcing — superseded by M14)* | `CompanionConfigMatrixTest` SEC-098 |
| M4 | ~~F13/AD-30 cap≤`concurrent-pairs`~~ *(guard retired with the knob, memlog 2026-08-26; matrix tests retired with it)* | — |
| M5 | Routing-miss gate (`if (false)`) | `BindInterceptorForwardRoleTest` routing miss |
| M6 | Cap refusal (`if (false && …)`) | `TlsModesLoopbackE2eTest` F13 cap |
| M7 | Ingress `SslHandler` insertion | `TlsModesLoopbackE2eTest` Mode A e2e |
| M8 | `ClientAuth.REQUIRE` → `NONE` | `SmppLegTlsFactoryTest` REQUIRE engine pin |
| M9 | `bind.host` `@NotBlank` removed | `CompanionConfigMatrixTest` blank host |
| M10 | ~~`max-connections` `@Min(1)` removed~~ *(knob deleted, memlog 2026-08-26)* | — |
| M11 | Forbidden `X509TrustManager` dep planted in `tls/` (outside `security/`) | `SecurityTlsSurfaceArchitectureTest` widened rule |
| M12 | Egress `SslHandler` insertion (condition inverted) | `TlsModesLoopbackE2eTest` Mode C e2e |
| M13 | Role-split dial target (forward arm → fixed reverse-arm target) | `BindInterceptorForwardRoleTest` routing hit |
| M14 | SEC-098 re-keyed guard (validator arm — `CompanionConfigValidator` SEC-098 check) *(fresh pass 2026-08-27, story-text)* | `CompanionConfigMatrixTest` `sec098_unknownTlsContextIdRefuses` |
| M15 | Orphan `tls-contexts` eager-load (factory arm — the `configured.entrySet()` validation loop) *(fresh pass 2026-08-27, story-text; review patch guard)* | `SmppLegTlsFactoryTest` `tlsContextOverrideResolution` orphan arms |

M14/M15 executed 2026-08-27 at the story-text pass: both RED against their biters (`CompanionConfigMatrixTest.java:66` / `SmppLegTlsFactoryTest.java:381` — the orphan `assertThatThrownBy`), guards restored byte-identical from backup, zero `MUTATED` residue (verified by scan + empty `git diff`).

### File List

Main (7 changed, 6 new):
- `proxy/src/main/java/smpp/companion/proxy/config/ProxyCompanionProperties.java` — [B] record re-shape (+`ForwardMode.tls-contexts` map, +`Bind.host`; the F13 cap rides `memory.concurrent-pairs` — no `maxConnections` knob)
- `proxy/src/main/java/smpp/companion/proxy/config/CompanionConfigValidator.java` — re-shaped dispatch + SEC-098 (re-keyed to `companion.forward.tls-contexts`)
- `proxy/src/main/java/smpp/companion/proxy/config/CompanionModeAWarning.java` — NEW (review D1 2026-08-27: the reverse×A one-way-TLS startup WARN banner)
- `proxy/src/main/java/smpp/companion/proxy/config/RoutingTable.java` — NEW (AD-29 runtime allow-list)
- `proxy/src/main/java/smpp/companion/proxy/tls/SmppLegTlsFactory.java` — NEW
- `proxy/src/main/java/smpp/companion/proxy/tls/TlsWiringConfig.java` — NEW (AD-28(1) executor bean)
- `proxy/src/main/java/smpp/companion/proxy/tls/package-info.java` — NEW
- `proxy/src/main/java/smpp/companion/proxy/relay/BindInterceptor.java` — role-split + routing gate + per-entry TLS dial
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayServerLifecycle.java` — per-cell bind on host:port
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayIngressInitializer.java` — listener TLS parametrization
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayEgressInitializer.java` — per-dial `TargetTls` seam
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/ConnectionCapHandler.java` — NEW (F13)
- `proxy/src/main/resources/application.yml` — host default + tls-contexts template + [B] branch comments (cap via `memory.concurrent-pairs`)

Test (14 changed, 4 new, plus 5 committed fixture artifacts):
- NEW: `tls/SmppLegTlsFactoryTest`, `relay/BindInterceptorForwardRoleTest`, `relay/TlsModesLoopbackE2eTest`, and the pipeline/cert additions below
- `relay/netty/RelayPipelineInitializersTest` — +3 TLS pipeline-shape tests
- `relay/netty/RelayServerLifecycleTest` — forward pin flipped live; reverse-a/c TLS-listener boots
- `config/CompanionConfigMatrixTest` — re-targeted SEC-056/057/060/050/096 + 8 new [B]/F13/SEC-098 refusals
- `config/TestCompanionConfigs`, `config/CompanionRoleFailFastTest`, `config/CompanionTlsBindingTest`, `bootstrap/BootstrapLifecycleTest`, `relay/netty/DirectMemoryBudgetStartupCheckTest`, `relay/BindInterceptorTest`, `relay/RelayHandlerTest`, `security/{AdjudicationLifecycleTest,IdpSslContextFactoryTest,OidcStartupDiscoveryTest,RopcBindCredentialVerifierTest,RopcBindCredentialVerifierLiveTest}` — blast-radius lockstep (record arities, [B] shapes, host/cap args, real fixtures)
- `testsupport/RelayTestFixtures` — generic harness + TLS-cell fixtures + `smppTlsLegs`
- `security/SecurityTlsSurfaceArchitectureTest` — SEC-090 widened + positive control
- `proxy/src/test/resources/keycloak/certs/{smpp-reverse-server,smpp-reverse-server-key,smpp-forward-client,smpp-forward-client-key}.pem`, `smpp-truststore.p12` — committed SMPP-leg PKI; `generate.sh` extended (§7–9, same CA; §10 = foreign-CA + unanchored client pair, review patch 2026-08-27)

Docs/contract (4):
- `ARCHITECTURE-SPINE.md` — AD-12/17/20/26 + register (dated [B] amendments)
- `.memlog.md` — dated amendment entry (append-only)
- `epics.md` — AD bullets + summary rows + register swept
- this file — tasks ticked + Dev Agent Record
