---
title: 'Story 3.3: TLS modes A/B/C on the internet leg + forward-role landing'
type: 'feature'
created: '2026-08-21'
status: 'in-progress'
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
| Unknown `tlsContextId` | routing entry references absent `tls.contexts` key | Refuse startup | Fail-fast, SEC-id message |
| Empty intersection | configured ciphers ∩ context-supported = ∅ on any axis | Refuse startup | Fail-fast (AD-34/D2) |
| Trust store bad | any of the 5 states on any context | Refuse startup | Fail-fast (AD-13) |
| Raw-IP target | routing target host is an IP literal | `endpointIdentificationAlgorithm = null` (explicit); IP-SAN + verify-on is the alternative posture | N/A |
| Target unreachable | forward dial to reverse target fails | AD-33 connect-fail collapse (shipped arm) | Deny + close |
| Cap exceeded | accepted connections > `bind.max-connections` | Refuse new connection (close + log) | Startup guard ties cap to AD-30 budget |
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
- [ ] Spine sweep to [B] — AD-12/17/20/26 + Accepted-Risk Register (Mode A harvest entry retires → submission-oracle residual) + epics.md refs + `.memlog.md` dated entry — contract-amendment discipline
- [ ] Config re-shape (per Design Notes table) + `tls.contexts` map + `bind.host`/`bind.max-connections` + validator matrix + full test blast radius + real cert fixtures — config-tier refusal tests (null-vs-blank rule)
- [ ] SMPP-leg TLS factory (server/client `SslContextBuilder`, JDK provider; 5-state stores; per-context AD-34 intersection; AD-20 endpoint-identification) + SEC-090 gate widened — unit tests + mutations
- [ ] Reverse acceptor widening — mode-a/c internet TLS listener on `bind.port`, `clientAuth(REQUIRE)` in C, initializer parametrization — per-cell wiring tests
- [ ] Forward role — interceptor role-split execution (shared skeleton; forward arm = routing gate → miss-deny → AlwaysAllow verdict → per-session egress dial with client SslHandler per `tlsContextId`); `RelayServerLifecycle` forward branch — wiring tests
- [ ] F13 — `bind.host` + `max-connections` cap at the acceptor + AD-30-consistency startup guard — cap/refusal tests
- [ ] Loopback integration suite — Mode A e2e, Mode C mTLS e2e + REQUIRE-negative, routing-miss on-wire collapse, N sessions per `system_id`, cap, Mode B regression
- [ ] Consolidated RED-on-neuter mutation ledger + final gates (AI-1)

**Acceptance Criteria:**
- Given a forward.mode-c full context with real fixtures, when a client binds an allowed `system_id`, then the bind traverses trusted leg → mTLS dial → reverse adjudication (ROPC) → SMSC dial, verbatim, one session per connection.
- Given a bind whose `system_id` is not in the routing table, then the client receives the AD-33 `ESME_RBINDFAIL` collapse and the connection closes; nothing fires `onBindReject`.
- Given any cell whose configured TLS sets intersect empty on either axis, or any trust store in a bad state, then startup refuses with the SEC-id message.
- Given a Mode C reverse listener, when a peer presents no client cert or an unanchored one, then the TLS handshake fails and no SMPP bytes are read.
- Given `max-connections` exceeded, then new connections are refused and the startup guard has proven cap ≤ AD-30 budget consistency.
- Given `./gradlew clean build :buildSrc:test`, then BUILD SUCCESSFUL with `:proxy:test` 0 failed / 0 skipped (XML counts).

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

`tls.contexts` map: id → client-cert/key override; routing entry `tlsContextId` selects; absent → instance-level default context (AD-29/AD-13 per-instance default, per-target permitted).

## Verification

**Commands:**
- `./gradlew clean build :buildSrc:test` -- expected: BUILD SUCCESSFUL
- `./gradlew :proxy:test` post-`cleanTest` -- expected: 0 failed / 0 skipped, XML-verified (console counts lie)
- `grep -rn "FIXME\|@Disabled" <diff files>` -- expected: zero new occurrences
