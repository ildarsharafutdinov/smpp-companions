---
baseline_commit: b7927b2
epic: 2
story: 2
story_key: 2-2-stateless-relay-and-a1-session-affinity-smoke
status: done
---

# Story 2.2: Stateless Relay Splice + A-1 Session-Affinity Smoke (plaintext, always-allow adjudication)

Status: done

> **Epic 2's core deliverable — the relay that retires assumption A-1.** Story 2.1 ratified the `proxy/security/`
> port contract against real ROPC; this story builds the **stateless Netty relay** (`proxy/relay/`) that splices
> framed PDUs bidirectionally over coupled ingress↔egress channel pairs, and **smoke-tests assumption A-1**
> (carrier multi-bind + DLR session affinity) — the epic's explicitly-named "earliest genuine risk checkpoint"
> — against an in-JVM mock SMSC, BEFORE any TLS/OIDC security investment (Epic 3).
>
> **Two contract seeds land here, not in 2.1:** (a) `proxy/relay/` (full body — it is an empty `package-info.java`
> today); (b) `proxy/observability/` (`SpliceObserver` interface + noop impl + `Direction`/`CloseReason` — **2.1
> scoped these OUT**, so `RelayHandler` has nothing to call until 2.2 authors them). Epic 3 swaps the always-allow
> verifier behind the unchanged `security/` port; Epic 4 swaps the noop `SpliceObserver` behind the unchanged
> `observability/` interface. **Wire, never re-author, the 2.1 port types.**
>
> **Scope discipline (SLICE-SCOPED to `companion.reverse.mode-b`):** this story's relay boots as a
> **`companion.reverse.mode-b` deployment** — plaintext (`acknowledged: true`), single egress = the configured
> `reverse.mode-b.smsc` target, gated by the seeded `BindCredentialVerifier` (`AlwaysAllow`→`Allow`). **NO static
> `system_id` allow-list: any bind whose verifier returns `Allow` routes to the single egress.** AD-29's 1:1
> allow-list is the *forward-role* contract — the binding spine (ARCHITECTURE-SPINE.md AD-29/AD-11/AD-33) is
> **UNTOUCHED**; reverse.mode-b has no routing table by design, so AD-29's allow-list and AD-33's routing-miss arm
> are *inapplicable to this slice, not contradicted* (the forward-role allow-list stays for production / Epic 3).
> In 2.2 (AlwaysAllow + no allow-list) NO bind is ever denied except on egress-unreachability; the deny *code* still
> ships for Epic 3, exercised here only via a fake `Deny`-verifier. Plaintext on both legs (no `SslHandler` — TLS is
> Epic 3). This story proves the **proxy's splice/coupling mechanics** end-to-end AND the **jSMPP independent A-1
> conformance oracle (OBS-038)** — so A-1 is proven in CI by both the proxy's own mock and an independent stack. The
> full FR-TRANSIT-3 conformance sweep + the real-carrier ops check remain later (see "Out of scope").

## Story

**As a** platform engineer on the smpp-companions codebase (architect Winston + developer Amelia),
**I want** the stateless SMPP relay splicing framed PDUs bidirectionally over coupled ingress↔egress channel pairs
(driving Netty directly, via `ConnectionRegistry` + `BindInterceptor` + `RelayHandler`), backed by the seeded
`AlwaysAllowBindCredentialVerifier` and a noop `SpliceObserver`, exercised against an in-JVM mock SMSC,
**so that** assumption A-1 (carrier multi-bind + DLR session affinity) is smoke-tested at the earliest genuine
risk checkpoint — proving the proxy's splice/coupling mechanics hold end-to-end BEFORE any TLS/OIDC investment —
and the `relay/` (full) + `observability/` (seed) packages Epic 2 owns are in place for Epic 3/Epic 4 to swap impls
behind unchanged interfaces.

## Acceptance Criteria

> **Load-bearing evidence is AC3** (the AD-25 single-flipper + AD-32 pre-couple policy — the relay's hardest
> invariant), **AC6** (the A-1 session-affinity smoke), and **AC7** (REL-1 transit integrity). The rest wire the
> runtime-state bean, the memory gate, the pipelines, the two contract seeds, and the standing RED-on-neuter gate.

1. **[AC1] `ConnectionRegistry` couples ingress↔egress per AD-8.** One concurrent bean keyed by ingress `ChannelId`;
   each entry holds the peer-egress `Channel`, the AD-25 splice flip-flag, ephemeral session metadata, and a
   `tearing-down` mark. A `Channel` attribute caches the entry for O(1) event-loop access. Teardown removes the entry
   via `channelInactive` on either leg. **Holds NO `message_id`→`system_id` mapping** (REL-4 — proven by RELAY-025).
   *(AD-8; ARCHITECTURE-SPINE.md:115–118.)*

2. **[AC2] `BindInterceptor` handles the bind family pre-couple per AD-7/AD-15/AD-25/AD-27/AD-33.** Consumes
   `codec`'s `SmppCommandIds.BIND_FAMILY` (redefining locally is forbidden, AD-27); **routes EVERY bind to the single
   configured egress (`companion.reverse.mode-b.smsc`) — NO `system_id` allow-list, NO routing table (AD-29's 1:1
   allow-list is the forward-role contract, inapplicable to this reverse.mode-b slice)**; invokes the seeded
   `BindCredentialVerifier` (`AlwaysAllow`→`Allow`); constructs `BindCredential(new SystemId(req.systemId()),
   new Password(req.password()))`; on `Allow`, opens the egress connection; forwards the ORIGINAL bind `ByteBuf`
   (`SmppBindRequest.originalFrame()`, AD-14 identity-preserved); forwards the decoded `bind_*_resp` to the legacy
   client (the AD-25 forwarder split — **BindInterceptor forwards bind-family, RelayHandler does NOT**). On a verifier
   `Deny*` → **AD-33 deny** (ONE generic bind-failure `bind_*_resp`); the deny code ships here for Epic 3 and is
   exercised ONLY via a fake `Deny`-verifier in tests (the wired `AlwaysAllow` never denies). **Caller-owned
   zeroization:** `cred.password().zeroize()` in a `finally` on every path (Allow/Deny/cancelHttp/timeout/exception)
   — resolves the open 2.1 review finding (deferred-work.md §"AlwaysAllow zeroization"). `onBindReject` called ONLY
   for `Verdict` denies (AD-19: with no routing table there are NO labeled `system_id` values, so the reject /
   teardown counters are unlabeled full-stop). *(AD-7:102–106, AD-15:154, AD-25:211, AD-27:221, AD-33:255. AD-29's
   allow-list + AD-11's routing-miss clause are forward-role, inapplicable to this slice.)*

3. **[AC3 — LOAD-BEARING] `RelayHandler` implements the AD-25 bind→splice transition + AD-32 pre-couple policy.**
   The splice flag is flipped by **exactly one unit — `RelayHandler` on the ingress event loop** — upon decoded
   `bind_*_resp` where `SmppBindResponse.isOk()` (`commandStatus == ESME_ROK`); **never** a peeked `command_id`,
   never "any frame from egress." Non-ROK → do NOT flip; tear down. **Race-free re-check:** BOTH the Allow/flip path
   AND the Deny callback re-check the `ConnectionRegistry` entry before proceeding (absent or `tearing-down` → no-op).
   Post-flip, every PDU (incl. `unbind`) is opaque framed-`ByteBuf` splice both directions; **no live pipeline surgery**
   (`pipeline.remove()` on a live channel forbidden, AD-2). **AD-32 (final spine, uniform bare-close):** before the
   flip, on EITHER leg — bind-family → AD-3/AD-25 cooperative; egress `generic_nack`/non-ROK `bind_*_resp` from SMSC
   → forwarded verbatim (AD-32 case 4); **everything else** (`unbind`/`enquire_link`/`submit_sm`/unknown `command_id`/
   etc.) → **emit NO response, close** (zero knobs, no carve-outs — the `unbind`/`enquire_link` carve-outs were
   user-locked dropped at gate-fix). **Teardown ordering:** same event loop — synchronously remove the entry + mark
   `tearing-down` BEFORE close → `VerdictRequest.cancelHttp()` (abort the in-flight ROPC) + `password().zeroize()` →
   close. The offending `command_id` appears ONLY in TRACE logs, never as a metric label (AD-19). *(AD-2:72, AD-3:77,
   AD-25:211, AD-32:246; .memlog.md:101,103,104 gate-fixes.)*

4. **[AC4] Netty pipelines driven directly; shared event loop; backpressure substrate (AD-1/AD-2/AD-16/AD-30).**
   Ingress pipeline `SmppFrameDecoder → SmppCodec → BindInterceptor → RelayHandler`; egress
   `SmppFrameDecoder → SmppCodec → RelayHandler`. **No `SslHandler`** (plaintext to the mock — TLS is Epic 3).
   Shared event loop for both legs (HexDumpProxy pattern); `AUTO_READ=false` + write-completes-gates-read with an
   explicit low-water re-arm; per-channel inbound queue bounded. A `SmartLifecycle` bean starts/stops the
   `ServerBootstrap` (driven directly — NO WebFlux/Reactor, AD-16), with an **explicit `getPhase()`** so it does not
   collide with `ProxyCompanionLifecycle` (2.2 introduces the 2nd `SmartLifecycle` — deferred-work.md phase-ordering
   item). Wired via `ProxyCompanionApplication`; `spring.main.web-application-type: none` stays. *(AD-1:67, AD-2:72,
   AD-16:159, AD-30:236.)*

5. **[AC5] `SpliceObserver` interface + noop impl seeded in `observability/` (AD-27 — NOT authored by 2.1).** Full
   4-method shape: `onFramedPdu(Direction)`, `onBindAccept(SystemId)`, `onBindReject(SystemId, Verdict)`,
   `onConnectionClosed(Direction, CloseReason)` — **no PDU type, no content.** PDU count is observed by counting `onFramedPdu` fires (no byte-volume signal crosses the seam — REVISED 2026-08-11, owner decision; see Dev Record + Change Log).
   Plus `enum Direction { INGRESS, EGRESS }` and **`enum CloseReason` = the 16-value exhaustive set** (final spine
   AD-27:224 + gate-fix .memlog.md:96): `PEER_HALF_CLOSE, PEER_RST, EGRESS_CONNECT_FAILED, OVERSIZED_FRAME,
   UNDERSIZED_FRAME, DECODE_ERROR, UNKNOWN_COMMAND_ID, PRE_COUPLE_NON_BIND_PDU, CLEAN_UNBIND_HANDSHAKE,
   GENERIC_NACK_PRE_BIND, BIND_REJECTED, BIND_FAILED_NON_ROK, INGRESS_TLS_HANDSHAKE_FAILED,
   EGRESS_TLS_HANDSHAKE_FAILED, SHUTDOWN_DRAIN, OTHER`. Noop `@Component` impl (the default bean). `RelayHandler`
   holds the injected reference and fires the **pinned** triggers: `onBindAccept` exactly at the ROK flip (NOT at the
   verdict); `onConnectionClosed` **exactly-once per channel** (CAS-guarded on the channel attribute, owned by the
   `channelInactive` teardown site — the violation handler only stashes the `CloseReason`, never calls
   `onConnectionClosed` directly). `@NullMarked` already on `observability/package-info.java`. *(AD-27:221;
   .memlog.md:87,96.)*

6. **[AC6 — LOAD-BEARING] A-1 session-affinity smoke (RELAY-011 in-JVM + OBS-038 jSMPP oracle).** Two complementary
   proofs: (a) **RELAY-011** — the in-JVM mock (built on the production codec, AD-24) accepts **≥2 concurrent
   `bind_transceiver` under the SAME `system_id`**, returns ROK on each, emits a `deliver_sm` on the SMSC socket that
   received each bind; the test asserts each legacy bind couples to its own egress pair and a `deliver_sm` on pair A's
   SMSC socket is forwarded to legacy client A — **never** B (zero DLR cross-bleed). (b) **OBS-038** — the SAME affinity
   scenario driven against a **jSMPP 3.0.2 server-side mock** (the independent oracle — shares NEITHER the production
   codec's bugs NOR its A-1 assumption): ≥2 concurrent binds under one `system_id` both ROK, and a `submit_sm` on bind
   A yields a `deliver_sm` on bind A's coupled channel, NOT bind B's. Together they prove the proxy preserves
   socket-pairing (NO `system_id`→channel lookup for DLR routing — AD-9/REL-4) AND that an independent stack affirms
   the affinity behavior. **Honest scoping (load-bearing):** these two CI proofs retire A-1 *in CI* (mechanics +
   independent oracle). The in-JVM mock alone trivially affirms A-1, which is exactly why the **jSMPP oracle (b) is
   mandatory in this story, not deferred.** The remaining gap — real-carrier behavior — is the non-CI ops plan
   (OBS-035/036/037, authored here as docs). So A-1 is "proven in CI" at this story; fully "retired" only after the
   ops carrier check. *(FR-TRANSIT-2; AD-9:120; Epic 2 goal epics.md:360; RELAY-011 :387, OBS-038 :1267.)*

7. **[AC7] REL-1 transit integrity (RELAY-008/009/010).** Across a coupled pair, a `submit_sm` (legacy→SMSC) and a
   `deliver_sm` (SMSC→legacy) roundtrip assert: **no drop, no duplicate, no corruption; PDU boundaries preserved**
   (one framed PDU in → exactly one framed PDU out, each forwarded exactly once). Post-couple TCP half-close on either
   leg propagates teardown to BOTH legs + registry; in-flight framed PDUs deterministically drained or dropped (no
   partial frame reaches the wire). Peer RST mid-splice tears down both legs AND teardown is OBSERVED
   (`SpliceObserver`/counter) — never a silent drop. *(REL-1; AD-2:72.)*

8. **[AC8] AD-30 live allocator self-check mounts (retro AI-6 "with-relay").** The one shared `PooledByteBufAllocator`
   bean (AD-21 — does not exist yet) is created; on startup, the JVM's live direct-memory ceiling (via `jdk.internal.misc.VM.maxDirectMemory()` — NOT `ByteBufAllocatorMetric`,
   which exposes only `usedDirectMemory()`/`usedHeapMemory()`) is compared against `MemoryBudget.compute(...)`
   (Story 1.3) and **fail-fast** (AD-17, non-zero exit) if the live ceiling < budget. The formula references `SmppFrame.MAX_COMMAND_LENGTH` directly (NOT a literal/config key — the static
   RELAY-026 scan already enforces this; keep it green). *(AD-21:191, AD-30:236; deferred-work.md D1; sprint-status
   AI-6.)* *(Amended 2026-08-15, T5b, operator decision: the self-check is UNCONDITIONAL — it runs for every
   role×mode cell, so Epic 3 never needs to widen a guard — and the over-budget severity follows
   `companion.memory.budget-check: fail | warn`: `fail` is the default (incl. an absent key — prior behavior);
   `warn` is an explicit accepted-risk opt-in (loud banner + start, the Mode B pattern). No value skips the
   check itself. NOTE: this AC's base text still names `jdk.internal.misc.VM.maxDirectMemory()` — that
   mechanism was replaced by Review Decision A (2026-08-12) with `ManagementFactory`/`Runtime.maxMemory()`
   (no JDK-internal API, no production `--add-exports`); see the spine AD-30 amendment. Spine AD-30 amended
   in place; see the T5b Dev Notes entry.)*

9. **[AC9] Green build + RED-on-neuter (standing gate AI-1) + bootstrap gates (AI-5/AI-8).** `./gradlew clean build`
   green on JDK 25 + `--enable-preview`. Every fail-closed guard — AD-32 bare-close (AC3),
   non-ROK teardown (AC3), AD-30 self-check (AC8), AD-25 flip re-check (AC3) — backed by a test that goes **RED when
   the guard is removed** (mutation/neuter pass; RED-on-neuter assertion bodies release latches/resources in `finally`
   — MEMORY `mutation-pass-needs-exception-safe-test-cleanup`). No test removed or `@Disabled` to pass. **AI-5:** codec
   `SmppBindRequest.toString()` overrides to redact the password + a static/ArchUnit scan forbidding `.toString()` on
   the password across codec+port+relay (lands BEFORE relay logging). **AI-8:** `--enable-preview` asserted on
   COMPILE and RUN (not just the test-JVM path `EnablePreviewArgTest` covers today). *(Epic-1 retro systemic lesson;
   sprint-status AI-1/AI-5/AI-8.)*

## Tasks / Subtasks

> T1–T3 are foundation/gates that MUST land first (the relay's dependencies + the "before relay code/logging" gates).
> T4–T6 are runtime infrastructure beans. T7–T8 are the handlers. T9 is the A-1 smoke (in-JVM), T10 is the jSMPP
> independent A-1 oracle, T11 is the standing gate.

- [x] **Task 1 (AC: 9) — Bootstrap gate: `--enable-preview` on COMPILE + RUN (AI-8).**
  - [x] Extend `proxy/src/test/.../bootstrap/EnablePreviewArgTest.java` (today asserts the test-JVM path only) to also assert `--enable-preview` is present on the `compileJava` task and the `run`/`bootRun` JVM args — a plain JUnit test can't introspect Gradle's resolved task model, so source-scan `smpp.java-conventions.gradle.kts:22–34` for the three `--enable-preview` wirings (`options.compilerArgs.add` on `JavaCompile`, `jvmArgs` on `Test`, `jvmArgs` on `JavaExec`) using the same `Files.walk` + regex + comment-strip pattern `Relay026ConstantContractTest` applies to Java sources. The existing `ManagementFactory.getRuntimeMXBean().getInputArguments()` assertion stays as the live test-JVM proof.
  - [x] If pinning the JDK 25 vendor is in scope here, add the CI/setup step; otherwise flag it (open question Q1). STS stays confined to `security/`+`bootstrap/` (the relay data-plane splice uses NO preview API — AD-5:87).
  - [x] RED-on-neuter: removing the compile-arg wiring turns this test RED.

- [x] **Task 2 (AC: 5) — `observability/` contract seed: `SpliceObserver` + `Direction` + `CloseReason` + noop impl (AD-27).**
  - [x] `SpliceObserver` interface — exactly the 4 methods (no PDU type, no content; PDU count via `onFramedPdu` fires — REVISED 2026-08-11). `onBindReject(SystemId, Verdict)` imports `proxy.security.Verdict`.
  - [x] `enum Direction { INGRESS, EGRESS }`.
  - [x] `enum CloseReason` — the 16 values verbatim (AC5 list). Document that this is exhaustive over the spine's close paths (gate-fix .memlog.md:96).
  - [x] `NoopSpliceObserver @Component` — every method a no-op; the default injectable bean (Epic 4 swaps the impl only).
  - [x] Test: ArchUnit/shape test asserting the 4-method shape + that `CloseReason` is the closed 16-value set + `@NullMarked` present. A capturing-fake `SpliceObserver` for the relay tests lives in `proxy/src/test` (T7/T9 consume it).
  - [x] Verify `observability/package-info.java` already carries `@NullMarked` (it does).

- [x] **Task 3 (AC: 9) — Password hygiene: codec `SmppBindRequest.toString()` redaction + no-String-from-password scan (AI-5 / CODEC-024 P2).**
  - [x] In `codec`: override `SmppBindRequest.toString()` to redact `password` (mirror `Password.toString()` → `"***"`; never call `AsciiString.toString()` on the password — it caches an immortal `String`). *(deferred-work.md:64–72.)*
  - [x] Static/ArchUnit scan (extend the `Relay026ConstantContractTest` source-scan pattern, or a new gate) forbidding `.toString()` on any password-typed expression across `codec` + `proxy/security` + `proxy/relay`.
  - [x] RELAY logging rule (dev note): log `SystemId` only; NEVER log `SmppBindRequest`/`Password`/`BindCredential` objects.
  - [x] RED-on-neuter: dropping the codec override → the scan goes RED; the override itself gets a golden-string assertion.

- [x] **Task 4 (AC: 1) — `ConnectionRegistry` (AD-8).**
  - [x] Concurrent bean keyed by ingress `ChannelId` (`ConcurrentHashMap`). Entry: `{ peer-egress Channel, splice flip-flag (volatile/AtomicBoolean), session metadata, tearing-down mark }`.
  - [x] `Channel` attribute (`AttributeKey`) caching the entry for O(1) on the event loop.
  - [x] `channelInactive` on either leg removes the entry (idempotent — RELAY-005); egress-connect-failure-after-entry removes it + tears down ingress (RELAY-006).
  - [x] **No `message_id`→`system_id` map anywhere** — RELAY-025 ArchUnit scan forbids it (statelessness, REL-4).
  - [x] Tests: RELAY-005 (idempotent double-teardown, double-zeroize safe), RELAY-006 (no orphaned entry on egress-connect-fail). jcstress (RELAY-007) is DEFERRED to the nightly hardening story — note in Completion Record.
  - [x] RED-on-neuter for the idempotent-teardown guard.

- [x] **Task 5 (AC: 8) — Shared `PooledByteBufAllocator` + AD-30 live self-check (AD-21/AD-30, AI-6).**
  - [x] `@Bean PooledByteBufAllocator` (ONE shared, wired to every channel ingress+egress — NOT per-channel). `io.netty.allocator.type=pooled`.
  - [x] Startup self-check: read the JVM's live direct-memory ceiling via `jdk.internal.misc.VM.maxDirectMemory()` (mind the `jdk.internal.misc` module-open on JDK 25; `ManagementFactory` arg-parsing is a fallback), compare to `MemoryBudget.compute(maxInboundDepth, concurrentPairs, safetyFactor)` (inputs from `companion.memory.*`), **fail-fast** if under budget. (`ByteBufAllocatorMetric` exposes only `usedDirectMemory()`/`usedHeapMemory()` — current usage, NOT the ceiling.)
  - [x] Reference `SmppFrame.MAX_COMMAND_LENGTH` directly in any sizing (keep `Relay026ConstantContractTest` green — no magic `65536`).
  - [x] Test: bind `companion.memory.*` to values that exceed a deliberately-small live budget → assert fail-fast (null-vs-blank trap: bind the specific value, do not remove the key).
  - [x] RED-on-neuter: removing the self-check → the under-budget startup goes GREEN when it must fail.
  - [x] **T5b (2026-08-15, operator decision):** self-check made UNCONDITIONAL (mode-b guard dropped — every
    role×mode cell; `forwardAWithHugeBudgetRefusesToStart` full-boot test proves the forward cell carries it)
    + `companion.memory.budget-check: fail | warn` over-ceiling policy (`fail` default incl. absent/null —
    fail-closed; `warn` = loud accepted-risk banner + start; NO skip value; invalid enum token fails the bind).
    Mutations proven RED: M1 neutered warn arm → warn test RED; M2 reintroduced mode-b guard → forward-A test
    RED. Spine AD-30 amended in place; deferred-work "Epic-3 widening" entry resolved.

- [x] **Task 6 (AC: 4) — Netty pipelines + `SmartLifecycle` acceptor (AD-1/AD-2/AD-16).** *(T6 substrate landed
  2026-08-15 — subtasks 2–5 complete; subtask 1 stayed open BY OWNER DECISION until T8 landed the handler
  entries — CLOSED 2026-08-16: the T8 `RelayHandler` entries are wired on BOTH legs (ingress
  `framer → codec → BindInterceptor → RelayHandler`, egress `framer → codec → RelayHandler`), pinned by
  `RelayPipelineInitializersTest` (exactly-4 / exactly-3 user handlers, order, per-channel instances).)*
  - [x] `ServerBootstrap`/`Bootstrap` driven directly (NO Spring messaging integration). Ingress pipeline `SmppFrameDecoder → SmppCodec → BindInterceptor → RelayHandler`; egress `SmppFrameDecoder → SmppCodec → RelayHandler`. One `SmppFrameDecoder` instance per channel (CODEC-014).
    **[2026-08-15 owner decision — codec-only prefix + attachment points (no placeholder handler classes):** T6 wires `SmppFrameDecoder → SmppCodec` on BOTH legs — per-channel instances (CODEC-014), pinned by `RelayPipelineInitializersTest` (order, exactly-2-user-handlers, distinct instances per channel, no `SslHandler`) — with the `BindInterceptor` (T7) and `RelayHandler` (T8, both legs) `addLast` entries appended at the attachment points documented in `RelayIngressInitializer`/`RelayEgressInitializer`. **This checkbox closes when those entries land (T7 ingress interceptor; T8 both relay-handler legs).** The per-bind egress `Bootstrap` (grouped on the ingress channel's event loop, HexDumpProxy-style) is assembled by T7 from the landed substrate (`RelayEgressInitializer` + `RelayChannelOptions.applyToEgress`); T6 ships no `connect()` — nothing to connect to until the bind interceptor exists.**]**
  - [x] Shared event loop (platform threads — virtual threads never carry the data-plane splice, AD-1). `AUTO_READ=false` + write-completes-gates-read + explicit low-water re-arm (AD-2/AD-30). Per-channel inbound queue bounded. *(Substrate: the ONE `MultiThreadIoEventLoopGroup` bean (named `companion-relay-*` platform threads — AD-1 pinned by test), `AUTO_READ=false` + explicit `WriteBufferWaterMark` — low = one `SmppFrame.MAX_COMMAND_LENGTH` frame, high = `max-inbound-depth` frames = the per-channel inbound bound in bytes — on BOTH legs via `RelayChannelOptions`. The read-demand BEHAVIOR (arm read on write-complete / low-water re-arm) is T8's `RelayHandler`, as AC4's "backpressure substrate" scopes.)*
  - [x] `SmartLifecycle` bean: start = bind acceptor + wire egress; `stop(Runnable)` invokes the callback in `finally` (mirror `ProxyCompanionLifecycle`). **Explicit `getPhase()`** so the relay lifecycle and `ProxyCompanionLifecycle` stop in the right order (deferred-work.md 2nd-SmartLifecycle item; full AD-22 drain is Epic 4). *(`RelayServerLifecycle`: mode-b-scoped start (this slice's cell — every other cell stays not-running, no port bind), SYNC bind (occupied port → throws through start() → AD-17 fail-fast, proven), stop = close acceptor → `shutdownGracefully` awaited (deterministic port release within the 30s phase window), callback in `finally`. Phases: `RELAY_ACCEPTOR_PHASE = APP_PHASE + 1000` — acceptor stops FIRST (AD-22 step 1); `ProxyCompanionLifecycle` gained explicit `APP_PHASE = 0`. "Wire egress" = the egress substrate above; the per-bind assembly is T7.)*
  - [x] Config source: `companion.bind.port` (listener) + `companion.reverse.mode-b.{smsc, acknowledged:true}` (the single egress + plaintext opt-in) + `companion.memory.*` (T5) + `companion.tls.*` (AD-34 defaults). Read via `ProxyCompanionProperties` (Story 1.3). **ZERO new config field — `reverse.mode-b` already carries `smsc` + `acknowledged`; NO change to `ProxyCompanionProperties.java`.** *(T6 reads `bind.port` (acceptor bind) + `memory.max-inbound-depth` (watermark high) through the existing record — ZERO new fields, ZERO `ProxyCompanionProperties` change. `reverse.mode-b.smsc` is CONSUMED at T7's connect site (the egress target — nothing connects in T6); `acknowledged` + `tls.*` stay Story-1.3's validation/yml surface — a plaintext slice consumes no TLS settings.)*
  *(Amended 2026-08-17, review F3: "ZERO new config field / NO change to `ProxyCompanionProperties.java`" held for T6 only — T5b later added `companion.memory.budget-check` + the `BudgetCheck` enum (AC8 amendment, sanctioned) and T7 added `Bind.adjudicationDeadline` with its positivity guard (owner-FIXME round, sanctioned). No `companion.relay.*`/`companion.egress.*` key was ever added.)*
  - [x] **No `SslHandler` on either leg.** *(pinned per-leg by `RelayPipelineInitializersTest`; TLS is Epic 3.)*

- [x] **Task 7 (AC: 2) — `BindInterceptor`: bind-family verifier gating + AD-33 collapse + caller-owned zeroize (AD-7/AD-15/AD-25/AD-27/AD-33).**
  - [x] On decoded `SmppBindRequest`: consume `SmppCommandIds.BIND_FAMILY` (no local redefine). **Route EVERY bind to the single configured egress (`companion.reverse.mode-b.smsc`) — NO `system_id` allow-list, NO routing table (AD-29 is forward-role, inapplicable here).**
  - [x] **Verifier `Deny*` → AD-33 deny:** synthesize the matching `bind_*_resp` with ONE generic bind-failure `command_status` (header-only 16-octet construct built directly — AD-32 forbids re-serializing via `SmppBindEncoder` on the hot path; the deny `bind_resp` is the ONE place the relay builds a PDU). Exact code: **open question Q2 (reopened — left for the dev to ratify at T7 impl):** the prior `ESME_RINVSYSAUTH 0x0000000E` pin was tied to routing-miss AND is a non-existent SMPP 3.4 code name pinned to the wrong hex (`0x0E` = `ESME_RINVPASWD`); with routing-miss gone the collapse covers verifier-`Deny*` + egress-establishment-fail only, and AD-33's anti-enumeration purpose favors a GENERIC code (e.g. `ESME_RSYSERR 0x00000008`) over a credential-specific one. Ratify the chosen generic code vs SMPP 3.4 §5.1.3 at T7 impl. *(Q2 RATIFIED at T7 impl: **`ESME_RBINDFAIL 0x0000000D`** — verified against the repo's own `docs/SMPP_v3_4_Issue1_2.pdf` §5.1.3 ("Bind Failed"; `RSYSERR 0x08`, `RINVPASWD 0x0E`, `RINVSYSID 0x0F` around it). §5.1.3's LITERAL generic bind-failure code; zero credential-validity information; identical across BOTH collapse arms (a prober cannot distinguish verifier-reject from unreachable-SMSC); reads definitive rather than retry-worthy, so naive clients don't retry-storm the way `RSYSERR`'s "System Error" conventionally invites. The story's illustrative `RSYSERR` was considered and set aside (see Debug Log). Tests pin the LITERAL `0x0000000D` independent of the production constant.)*
  - [x] Invoke `BindCredentialVerifier.verify(BindCredential, ScopedValue<RequestContext>)`; construct `BindCredential(new SystemId(req.systemId()), new Password(req.password()))` and the `RequestContext(systemId, channelId, deadline)` bound via `ScopedValue` (AD-5; never `ThreadLocal`). Await `VerdictRequest.future()`.
  - [x] On `Allow`: open egress (T6), forward `req.originalFrame()` to the SMSC verbatim (AD-14), `release()` after. On `Deny*`: AD-33 deny `bind_resp` + `onBindReject(systemId, verdict)` (AD-19: no labeled `system_id` values; reject counter unlabeled full-stop). **Egress-establishment-fail (no SMSC response PDU) collapses to the SAME generic deny code (AD-33)** — a prober cannot distinguish verifier-reject from unreachable-SMSC; SMSC-originated non-ROK `bind_*_resp` is forwarded verbatim (AD-32 case 4, RELAY-002c — NOT collapsed).
  - [x] On decoded `bind_*_resp` from egress: forward to the legacy client (the AD-25 forwarder split — BindInterceptor owns bind-family forward; RelayHandler reads read-only to flip).
  - [x] **Caller-owned zeroize:** `cred.password().zeroize()` in `finally` on EVERY path (Allow/Deny/cancelHttp/timeout/exception). This resolves the open 2.1 review finding (deferred-work.md §AlwaysAllow-zeroization) — `AlwaysAllow` does not inspect the secret, so the relay owns the wipe.
  - [x] Tests: RELAY-004 (retry-bind while adjudication in-flight → deterministic reject/teardown, no second pair, no registry corruption — fake verifier with `CountDownLatch`-held verdict, configurable `Allow` OR `Deny`). **AD-33 collapse test (slice-scoped):** verifier-`Deny` (fake `Deny`-verifier) → the generic failure code; egress-establishment-fail (no SMSC response) → the SAME generic code (collapse holds); SMSC-originated non-ROK `bind_*_resp` forwarded verbatim, NOT collapsed (RELAY-002c). **The AD-33 routing-miss collapse half CANNOT run in 2.2 (no routing table) and DEFERS to Epic 3 forward-role**; the verifier-`Deny` collapse half stays (fake verifier) + RELAY-002c.
  - [x] RED-on-neuter for the verifier-`Deny` collapse (fake `Deny`-verifier: neuter the deny-synthesis → the bind wrongly ROKs / hangs instead of denying) and the zeroize-in-finally.

- [x] **Task 8 (AC: 3, 7) — `RelayHandler`: AD-25 single-flip + AD-32 bare-close + REL-1 splice + SpliceObserver triggers (AD-2/AD-3/AD-25/AD-27/AD-32).**
  - [x] **The ONLY flipper:** on the ingress event loop, on decoded `bind_*_resp` where `SmppBindResponse.isOk()`, flip the entry's flag; fire `onBindAccept(systemId)` exactly at the flip (NOT at the verdict). Non-ROK → do NOT flip; tear down.
  - [x] **Race-free re-check:** before flipping (Allow path) AND in the Deny callback, re-check the `ConnectionRegistry` entry — if absent or `tearing-down`, the callback is a no-op (AD-25 gate-fix).
  - [x] **Post-flip opaque splice:** framed-`ByteBuf` forward both directions; `SmppCodec` object-decode dormant post-couple (AD-2). **No live `pipeline.remove()`** — the coupling is a flag flip, not a pipeline mutation.
  - [x] **AD-32 bare-close (final spine):** pre-flip, on EITHER leg — bind-family cooperative; egress `generic_nack`/non-ROK `bind_resp` forwarded verbatim (case 4); **everything else → NO response, close**. `command_id` read only to confirm "not bind-family" (`ByteBuf.getInt(4)`, no codec helper — AD-19); TRACE-gated only. Race-free teardown: same event loop, remove entry + mark `tearing-down` BEFORE close → `cancelHttp()` + `zeroize()` → close.
  - [x] **SpliceObserver triggers:** `onFramedPdu(Direction)` per framed PDU; `onConnectionClosed(Direction, CloseReason)` **exactly-once** (CAS on the channel attribute) at the `channelInactive` teardown site; the violation handler only stashes `CloseReason`, never calls `onConnectionClosed` directly.
  - [x] Tests (drive the REAL pipeline — gate-must-run-in-`check` trap; do NOT call handler methods directly): RELAY-001 (single-flipper — flips ONLY on decoded ROK `bind_resp`; no flip on non-ROK/peeked-id/Allow-without-bind_resp), RELAY-002 (ingress pre-couple non-bind → bare close, no egress PDU), RELAY-003 (egress pre-couple `deliver_sm` not leaked), RELAY-002c (SMSC `generic_nack`/non-ROK forwarded verbatim). REL-1: RELAY-008 (half-close propagates + drains/drops cleanly, sequence integrity), RELAY-009 (in-flight write racing `channelInvalid` → zero or exactly one complete frame on the wire), RELAY-010 (RST → both legs + registry, teardown OBSERVED). **CODEC-021 sibling of RELAY-001 (Risk Note 2 second vector):** feed a 0-byte-body (header-only) `bind_resp` → `SmppCodec` throws `DecoderException` before `SmppBindResponse` is built, so `isOk()` is NEVER reached — assert the `channelInvalid` teardown (`CloseReason`/counter fires), NOT `isOk()==false` (distinct from RELAY-001's decoded non-ROK branch).
  - [x] RecordingAllocator-bypass trap: any allocator/leak assertion feeds input in MULTIPLE chunks via `ctx.alloc()` wrapped in `RecordingAllocator` (one `writeInbound(Unpooled.buffer())` is tautological — Epic-1 retro).
  - [x] RED-on-neuter for the single-flipper, the AD-32 bare-close, the flip re-check, exactly-once `onConnectionClosed`, AND the non-ROK teardown guard (AC9 enumerates "non-ROK teardown" but T8's checklist omits it — neuter the "Non-ROK → do NOT flip; tear down" arm → a non-ROK `bind_resp` wrongly flips / fails to tear down).

- [x] **Task 9 (AC: 6, 7) — In-JVM mock SMSC + A-1 mechanics smoke (RELAY-011) + REL-1 roundtrip + A-1 ops-plan docs (AD-24/AD-9).**
  - [x] In-JVM mock SMSC: embedded Netty server in `proxy/src/test` using the PRODUCTION codec (`SmppFrameDecoder` + `SmppCodec`) — NOT a jSMPP harness. Programs: ≥N concurrent binds under one `system_id` → ROK each; `deliver_sm` on the SMSC socket that received the bind (carrier affinity emulation); injectable delay/stall; captures forwarded PDUs for byte-exact assertion. **Never an oracle for A-1 or codec correctness** (shares the codec's bugs + assumes A-1) — document this in the fixture's javadoc. *(Landed as `MockSmsc`: one accepted connection = one `Session` with byte-exact bind/PDU captures + `deliver`/`deliverAll` injection on that session's socket; injectable delay (`start(long millis)`, scheduled via `CompletableFuture.delayedExecutor` — never an event-loop block) + stall (`stallBinds()`/`releaseBinds()` on a future-gate); the oracle disclaimer is the class javadoc's opening bold.)*
  - [x] **RELAY-011 (load-bearing):** ≥2 concurrent `bind_transceiver` under the SAME `system_id`, distinct ingress Channels; inject a uniquely-tagged `deliver_sm` per egress; assert each tag arrives on exactly its originating ingress (capturing `SpliceObserver` per Channel; AssertJ on tag→Channel). Zero cross-bleed. *(Both binds written to the two sockets BEFORE either response is read — genuinely concurrent handshakes; pair identity matched by bind-frame CONTENT (`sessionBoundWith(bindA)`), which is itself the AD-14 byte-exact assertion through two real sockets. The socket-level read IS the tag→Channel assertion — see the Debug Log entry on the channel-blind seam.)*
  - [x] REL-1 roundtrip: `submit_sm` (legacy→SMSC) + `deliver_sm` (SMSC→legacy) across a coupled pair — no drop/dup/corrupt; PDU boundaries preserved (golden-vector-driven where wire bytes are needed — load `codec/src/test/resources/golden-vectors/`). *(Bind = the `bind_transceiver_request_all_fields` golden vector parsed from its `raw-hex:` token; 4 submit_sm in ONE coalesced socket write → exactly 4 complete framed captures at the mock; 3 deliver_sm in ONE mock-side write → exactly 3 byte-exact frames at the legacy socket; `onFramedPdu` count/order pinned. Plus the real-socket teardown arms T8 deferred to T9 — see Debug Log.)*
  - [x] **A-1 ops-plan docs (OBS-035/036/037):** author `docs/` A-1 real-carrier test plan with explicit PASS criterion (≥2 concurrent binds, same `system_id`, both ROK on the real carrier), explicit FAIL criterion + DLR-affinity assertion (submit on bind A → `deliver_sm` on bind A's socket, not B), and naming the real carrier/conformance SMSC as the oracle (explicitly excluding the in-JVM mock). Docs-gate tests scan for the criterion shape (regex/AssertJ presence). *(Landed as `docs/a-1-carrier-test-plan.md` + `A1CarrierPlanDocsTest` — 3 gate tests, one per OBS id; normalized lowercased/backtick-stripped/whitespace-collapsed text so prose tweaks never false-RED; the doc's existence is asserted FIRST and loudly.)*
  - [x] RED-on-neuter: neuter the coupling (e.g. forward `deliver_sm` to the wrong ingress) → RELAY-011 goes RED. *(N1: splice forwarded to `self` instead of the peer → RELAY-011 RED on `SocketTimeoutException` (the tagged deliver_sm never reaches client A) AND REL-1 RED (`awaitPdus` unreached — the submits echo back); the teardown test correctly stayed GREEN (no spliced PDUs). N2: blanked ops-plan doc → all 3 docs-gate tests RED. Both restored byte-exact from `/tmp/t9-backups`; full `clean build` GREEN after.)*

- [x] **Task 10 (AC: 6) — jSMPP independent A-1 conformance oracle (OBS-038).**
  - [x] Add `org.jsmpp:jsmpp:3.0.2` to `proxy` testImplementation (test-only — never the production codec; mirror the codec module's coordinate, `codec/build.gradle.kts:38`). *(Mirrored verbatim in `proxy/build.gradle.kts` with the CODEC-031-style comment; stays off the main compile/runtime classpaths so OBS-013/SEC-099 gates are unaffected.)*
  - [x] Build a **jSMPP 3.0.2 server-side mock** as the SMSC — the independent oracle (shares NEITHER the production codec's bugs NOR its A-1 assumption). Server-side API: `org.jsmpp.session.SMPPServerSessionListener` (bind to a port; `accept()` yields one `SMPPServerSession` per TCP connection, each delivering a `BindRequest` to a `ServerMessageReceiverListener` — see `org.jsmpp.examples.SMPPServerSimulator`). SMPP is one-bind-per-connection by spec, so the affinity scenario is N separate connections sharing one `system_id` (exactly AC6): the mock accepts N concurrent connections and ROKs each `bind_transceiver` regardless of `system_id`, then emits `deliver_sm` on the session that received the bind (carrier-side affinity). *(Landed as `JsmppSmscServer`: blocking daemon accept loop → per-session handler on a daemon worker pool (`waitForBind(10s)` → `accept("jsmpp-smpp", IF_34)` ROK regardless of `system_id`); `onAcceptSubmitSm` captures the (session, short_message) pair and AUTO-delivers a tagged DLR on THAT SAME session via `deliverShortMessage` — scheduled on the fixture worker, never jSMPP's PDU-reader thread (`deliverShortMessage` blocks for the `deliver_sm_resp`); `anomalies()` queue asserts a healthy run explains away nothing. Two jSMPP portability facts baked into the fixture + javadoc: `getPort()` returns the CONFIGURED port not the bound one (probe-first — see Debug Log), and quiet timers (`enquire_link` 60s / transaction 5s) so no proactive SMSC `enquire_link` races the zero-cross-bleed assertions.)*
  - [x] **OBS-038 (load-bearing):** ≥2 concurrent binds under ONE `system_id` through the relay to the jSMPP server mock → both `bind_*_resp` ROK; `submit_sm` on bind A → the resulting `deliver_sm` (DLR) arrives on bind A's coupled channel, NOT bind B (capturing `SpliceObserver` per ingress; AssertJ). The strongest CI approximation of A-1 (test-coverage-scenarios.md:1267–1271). *(Landed as `JsmppA1OracleTest` on the REAL acceptor via the T9 `ModeBRelayHarness` (egress → the oracle's port): two binds written to both sockets before either response is read, both `bind_resp` ROK with matching sequences; the oracle's own view of A-1's premise asserted (two `BoundSession`s under the ONE `system_id`); submit on A → `submit_sm_resp` (ROK, sequence-integrity through the relay) + the DLR `deliver_sm` on A ONLY (classified — the resp/DLR wire order per pair is a fixture-internal race), then the symmetric leg for B; zero cross-bleed asserted on the OTHER socket each time; the well-behaved `deliver_sm_resp` answer completes the DLR roundtrip through the splice; observer pins 2× `onBindAccept` under one `SystemId` + 8 `onFramedPdu` (4 INGRESS / 4 EGRESS, counts-not-order) + 0 rejects; registry stays 2; `anomalies()` empty. The oracle bit the test TWICE during development — malformed §4.4.1 submit_sm and a wrong `deliver_sm` command_id literal — see the Debug Log; both are exactly the independence AC6(b) buys.)*
  - [x] Optional reuse: a jSMPP alternate-ESME client can also drive the RELAY-002/008 sequence-integrity paths — not required for AC6. *(NOT exercised — this subtask's own text marks it optional / not-required-for-AC6; the plain-socket clients + the jSMPP server-side oracle carry AC6. Recorded here so the checkbox is not mistaken for work done.)*
  - [x] RED-on-neuter: neuter the coupling → OBS-038 goes RED (the DLR lands on the wrong bind). *(N1: `RelayHandler.splice()` write redirected to `self` instead of the peer → OBS-038 RED at the A-leg DLR read (`SocketTimeoutException` — the submit echoes back toward the SMSC, client A never receives the DLR; the bind stage correctly stayed GREEN — binds do not traverse `splice`); restored byte-exact from `/tmp/t10-backups`, marker-grep clean, full `clean build` GREEN after. See Debug Log.)*

- [x] **Task 11 (AC: 9) — RED-on-neuter mutation pass + green build (AI-1).**
  - [x] For every guard listed in AC9: neuter (comment out / invert) → run the matching test → confirm RED → revert → confirm GREEN. Record each in the Completion Notes (cite the test). Assertion bodies that can throw release latches/`EmbeddedChannel` resources in `finally`. *(35 mutations on integrated HEAD — the 4 AC9-named guards (AD-32 bare-close, non-ROK teardown, AD-30 self-check, AD-25 flip re-check) + the flipper + exactly-once CAS first-hand inline; the remaining 29 guards via a worktree-isolated agent sweep. Full ledger in Completion Notes.)*
  - [x] `./gradlew clean build` green on JDK 25 + `--enable-preview`. No test `@Disabled`/removed to pass. ArchUnit RELAY-025 + RELAY-026 stay green. *(BUILD SUCCESSFUL — 296 tests, 0 failures, 0 errors, 0 skipped, XML-aggregated == T10's count; zero `@Disabled` in codec+proxy sources; RELAY-025/026 run green in-suite.)*
  - [x] jqwik trap: any `@Property` carries NO Jupiter annotations (`@DisplayName`/`@Tag`) — class-level only (silent-skip → green-build hazard, Epic-1 retro). *(Verified: 10 `@Property` methods across the 3 codec property classes, zero method-level Jupiter annotations; none in proxy.)*

## Dev Notes

### Architecture compliance (MUST follow)

- **AD-1 (event-loop relay):** Netty event loops own the steady-state byte splice; virtual threads own the control plane (bind adjudication, AD-5). VTs never carry steady-state bytes; the data-plane splice uses NO preview API.
- **AD-2 (coupling + framed-ByteBuf splice):** HexDumpProxy pattern — shared event loop both legs, `AUTO_READ=false`, write-completes-gates-read. **Forward framed-PDU `ByteBuf`s, not raw stream bytes** — each PDU forwarded exactly once, boundaries preserved. `SmppFrameDecoder` stays active on both legs post-couple; `SmppCodec` object-decode dormant. **No live pipeline surgery.** Flag flip (AD-25), not pipeline mutation.
- **AD-3 (hybrid PDU model):** inspect/handle ONLY bind-family pre-couple; post-couple EVERY PDU (incl. `unbind`) is opaque framed bytes. AD-3 opacity is about the PDU **body**; AD-32 reads only the fixed header (`command_id` octets 4–7, `sequence_number` 12–15).
- **AD-8 (state-ownership):** the ONLY mutable runtime state is the `ConnectionRegistry` (per-bind pair state) + monotonic counters. `message_id`→`system_id` NEVER exists (RELAY-025).
- **AD-9 (stateless on A-1):** socket-pairing state only; DLRs ride the coupled pair — NO `message_id` correlation, NO routing lookup. The SMSC/mock decides which socket a `deliver_sm` lands on; the proxy forwards on the paired ingress.
- **AD-11 (fail-closed):** every auth-adjacent decision denies on indeterminate. (The "routing-miss → deny (no default route)" clause is forward-role — AD-29 allow-list — and inapplicable to this reverse.mode-b slice, which has no routing table; it defers to Epic 3.)
- **AD-12 (the port relay calls):** inject `BindCredentialVerifier` (default bean = `AlwaysAllowBindCredentialVerifier`). Call `verify(...)`, await `future()`, call `cancelHttp()` on AD-32 case-3 teardown. Port is **immutable henceforth** (2.1 AC8).
- **AD-14 (identity forwarded):** forward `SmppBindRequest.originalFrame()` verbatim — legacy `system_id` == carrier `system_id`; never re-encode, never remap.
- **AD-15 (no local password check):** delegate password validation entirely to `BindCredentialVerifier`. No local credential store. (The "route on `system_id`" half is forward-role — AD-29 allow-list — and inapplicable to this reverse.mode-b slice; the verifier-gating half IS the model here.)
- **AD-16 (Spring Boot + Netty direct):** own `ServerBootstrap`/`Bootstrap` in a `SmartLifecycle` bean; NO WebFlux/Reactor. `spring.main.web-application-type: none`.
- **AD-19 (metrics cardinality):** NO `system_id`/`command_id`/`ChannelId` label on ANY close/reject counter. `system_id` labels ONLY routing-table values — reverse.mode-b has NO routing table, so the labeled set is empty by construction (every reject/teardown counter is unlabeled full-stop, vacuously satisfying the cardinality bound). Reading `command_id` for logic is always OK; emitting it is TRACE-gated.
- **AD-21 (one allocator):** ONE shared `PooledByteBufAllocator` across all channels.
- **AD-24 (test toolchain):** in-JVM mock SMSC on the production codec (RELAY-011) AND the jSMPP 3.0.2 server-side independent oracle (OBS-038, T10 — test-only). Concurrency proofs (jcstress + race-soak) are nightly/exit-gates, not this story.
- **AD-25 (bind→splice state machine — THE CORE):** exactly one flipper = `RelayHandler` on decoded `bind_*_resp.isOk()`. `BindInterceptor` forwards `bind_*_resp`; `RelayHandler` reads read-only + flips, never forwards it. First spliced PDU = first PDU AFTER `bind_*_resp`. Race-free re-check at both Allow-flip and Deny-callback.
- **AD-27 (ownership seams + SpliceObserver):** consume `SmppCommandIds.BIND_FAMILY` (no local redefine); seed `SpliceObserver` (4 methods) + `Direction` + `CloseReason` (16 values) + noop impl. Pinned triggers + exactly-once `onConnectionClosed`. Codec never emits metrics.
- **AD-29 (routing v1 = 1:1, FORWARD-ROLE):** one instance fronts one carrier egress; routing table = `system_id` allow-list → the single egress target. **Inapplicable to this reverse.mode-b slice** (no routing table — the egress is the single configured `reverse.mode-b.smsc`, gated by the verifier, not an allow-list); stays binding for production / Epic 3 forward-role.
- **AD-30 (frame/budget):** `SmppFrameDecoder` enforces max 65536 / min 16; per-channel inbound queue bounded; `MaxDirectMemorySize` formula via ONE constant + live self-check (T5).
- **AD-32 (pre-couple policy, FINAL):** uniform bare-close — no `_resp` synthesis, no carve-outs (dropped at gate-fix). Race-free teardown: remove+mark-tearing-down → `cancelHttp()` + zeroize → close.
- **AD-33 (bind-denial collapse):** ALLOW→ROK; ALL proxy-side denials → ONE generic bind-failure code. **In this reverse.mode-b slice the denial arms are verifier `Deny*` + egress-establishment-fail (no SMSC response) ONLY — the routing-miss arm is forward-role (AD-29) and inapplicable / deferred to Epic 3.** SMSC-originated non-ROK forwarded verbatim (AD-32 case 4), NOT collapsed.
- **AD-35 (null-safety):** `@NullMarked` does NOT propagate — `relay/` and `observability/` already have `package-info.java`; any NEW sub-package gets its own.

### Library / framework specifics

- **JDK 25 + `--enable-preview`** process-wide (`smpp.java-conventions.gradle.kts:22–34`) — STS (JEP 505, 5th preview) + `ScopedValue` (JEP 506, final). Confine STS to the control plane (`security/`+`bootstrap/`); the relay data-plane splice stays pure-stable API.
- **Netty 4.2.16.Final** via `netty-bom` (overrides SB 4.1's 4.2.15) — `proxy/build.gradle.kts:17`. APIs in use (`LengthFieldBasedFrameDecoder`, `MessageToMessageDecoder`, `ChannelPipeline`, `channelInactive`, `ChannelId`/`AttributeKey`, `PooledByteBufAllocator`, `AsciiString`) are stable across 4.x and already exercised by the codec. `org.jsmpp:jsmpp:3.0.2` is added to `proxy` testImplementation (T10) — the independent A-1 oracle; test-only, never the production codec.
- **Spring Boot 4.1.0** — DI (`@Component`/`@Bean`/`@Configuration`), `SmartLifecycle`, `@ConfigurationProperties("companion")` (Story 1.3). No web server.
- **JSpecify 1.0.0 + NullAway 0.13.8** — ERROR on `compileJava` only (NOT `compileTestJava`); `AnnotatedPackages=smpp.companion`, `JSpecifyMode=true`.
- **Test stack:** JUnit Platform 6.0.3, AssertJ 3.27.7, jqwik 1.10.1, ArchUnit 1.4.2, Testcontainers 2.x (`disabledWithoutDocker = true` — environment gate, not a disable-to-pass dodge). JMH 1.37 is nightly-only (not in `check`).
- **No format gate** (Spotless/checkstyle/gjf) — match hand style; do NOT auto-reformat edits (MEMORY `no-format-gate-match-hand-style`). Codec uses Lombok `@UtilityClass` for utility types; records for data.

### Seeded contract surfaces the relay WIRES (verify exact signatures in code before use)

```java
// proxy/security/ — IMMUTABLE HENCEFORTH (2.1 AC8)
interface BindCredentialVerifier { VerdictRequest verify(BindCredential cred, ScopedValue<RequestContext> ctx); }
sealed interface Verdict permits Verdict.Allow, Verdict.DenyInvalid, Verdict.DenyIndeterminate { ... } // 3 payload-less records
interface VerdictRequest { CompletableFuture<Verdict> future(); void cancelHttp(); }   // cancelHttp aborts the HTTP call, not just the future
record BindCredential(SystemId systemId, Password password) { ... }                    // compact-ctor null-guards; redacting toString
record SystemId(AsciiString value)  { /* MAX_LENGTH=15 */ }
record Password(AsciiString value)  { /* MAX_LENGTH=8; void zeroize(); redacting toString */ }
record RequestContext(SystemId systemId, ChannelId channelId, Instant deadline) { }    // ScopedValue-bound, never ThreadLocal
@Component final class AlwaysAllowBindCredentialVerifier implements BindCredentialVerifier { /* completed-Allow, no-op cancelHttp */ }
```

### Codec surface the relay CONSUMES (REUSE — do NOT re-author)

```java
// codec/framer/
SmppFrame.HEADER_LENGTH=16; MIN_COMMAND_LENGTH=16; MAX_COMMAND_LENGTH=65536   // the RELAY-026 single source — reference THIS, never a literal
SmppFrameDecoder extends LengthFieldBasedFrameDecoder   // no-arg ctor; lengthAdjustment=-4; stays active both legs; drop+close on exception
// codec/bind/
SmppCodec extends MessageToMessageDecoder<ByteBuf>      // bind-family -> SmppBindPdu; else out.add(buf.retain()) (opaque, zero-copy)
SmppBindPdu permits SmppBindRequest, SmppBindResponse   // commandId()/commandStatus()/sequenceNumber()/originalFrame() (retained, consumer-owned; ESME_ROK=0)
SmppBindRequest{...,systemId() AsciiString, password() AsciiString,...,originalFrame()}   // the credential handoff
SmppBindResponse{commandId,commandStatus,sequenceNumber,systemId,originalFrame; boolean isOk()}  // isOk() == the AD-25 flip trigger
SmppBindEncoder                                          // OFFLINE-ONLY (NOT a hot-path outbound handler; AD-32 forbids re-serialize)
// codec/command/
SmppCommandIds.BIND_FAMILY (6 ids) / isBindFamily(int) / isResponse(int) / requestIdOf(int)  // BindInterceptor MUST consume (no local redefine)
```
**Codec→relay handoff:** `SmppFrameDecoder` emits one framed `ByteBuf` per PDU → `SmppCodec` reads `command_id` (`skipBytes(4)+readInt()`), dispatches typed `SmppBindPdu` (bind family) or `buf.retain()` (opaque forward). Post-couple, `SmppCodec` is dormant; the splice forwards framed `ByteBuf`s.

### Previous-story intelligence (Story 2.1 — patterns to continue)

- **`@Component`/`SmartLifecycle` conventions:** `AlwaysAllowBindCredentialVerifier` and `ProxyCompanionLifecycle` are the templates. `@ConfigurationPropertiesScan` is on `ProxyCompanionApplication`. The relay's Netty acceptor + allocator + noop observer + registry are Spring-managed beans.
- **2nd `SmartLifecycle` phase ordering:** `ProxyCompanionLifecycle` is a stub today; 2.2 introduces the relay lifecycle — set explicit `getPhase()` (default `MAX_VALUE` stops first — wrong for AD-22 drain ordering; deferred-work.md flags this). Full AD-22 7-step body is Epic 4.
- **Testcontainers/embedded pattern:** `KeycloakContainer` (custom `GenericContainer` + `AbstractWaitStrategy`, `disabledWithoutDocker`). The in-JVM mock SMSC follows the embedded-Netty-in-test-JVM pattern (NOT Testcontainers — it is in-JVM).
- **RED-on-neuter discipline (AI-1):** every 2.1 task ran a mutation pass; it caught real harness flaws (the `finally`-latch hang). Bake into every relay guard. MEMORY: a RED-on-neuter test whose assertion can throw MUST release resources in `finally`.
- **`SpliceObserver` was NOT seeded by 2.1** — 2.1's "Out of scope" (`2-1-...md:244–245`) explicitly defers it. `observability/` = `package-info.java` only. T2 authors it; do not assume it exists.
- **Password seam already fixed:** the fragile `AsciiString→char[]` conversion is ELIMINATED (2.1's 2026-08-09 revision). `new Password(bindRequest.password())` wraps the same backing array. What remains is the `toString()` hazard (T3) + caller-owned zeroize (T7).
- **The one 2.1 review finding touching the relay:** `AlwaysAllowBindCredentialVerifier` does not zeroize (never inspects the secret) → the relay (caller) must own `cred.password().zeroize()` in `finally` (T7). The other 5/6 LOW findings are test-tier `RopcSlice`, Epic-3-owned, zero relay touch.

### Out of scope (explicitly — do NOT expand into these)

- **Full FR-TRANSIT-3 conformance-suite breadth** (exhaustive PDU/edge-frame coverage, both legs, beyond the A-1 affinity scenario) → Story 2.3. (The jSMPP A-1 oracle OBS-038 IS in this story — T10; only the broader sweep defers.)
- **jcstress (RELAY-007), race-soak (RELAY-024), PARANOID leak matrix (RELAY-017), BlockHound (RELAY-018/019)** → nightly hardening story / Epic-2 exit gates (handoff names them exit-gates, not first-story gates).
- **Perf: direct-memory soak (RELAY-013/015), backpressure tuning** → Epic 6. (The `AUTO_READ=false` *mechanism* is IN — T6; proving it under soak is Epic 6.)
- **R32 post-ALLOW failure paths (RELAY-020/021), egress-flap stale-DLR (RELAY-012), AUTO_READ unit (RELAY-014), shutdown drain (RELAY-022/023), E2E-001 two-real-proxy** → later Epic-2 story / Epic 4.
- **TLS on either leg, real ROPC adjudication, production ROPC adapter** → Epic 3. 2.2 = plaintext + `AlwaysAllow`.
- **Production `SpliceObserver` impl (Micrometer `/metrics`), JSON-lines ops logging impl, full AD-22 7-step drain** → Epic 4. 2.2 ships the noop seed.
- **`bind_resp`→OIDC-outcome mapping (AD-33 deferred item), per-egress cipher intersection (AD-34)** → Epic 3 (needs real adjudication / `SSLContext`s).
- **Multi-carrier routing** → post-v1 (AD-29: v1 forward-role = 1:1). **Note: even the v1 1:1 routing TABLE is forward-role — this story's reverse.mode-b slice has NO routing table at all (single fixed egress, verifier-gated); the allow-list itself returns in Epic 3 forward-role.**

### Risk notes (carried from the analysis)

1. **AD-25 flip race + AD-32 case-3 teardown** — the relay's hardest invariant. Both Allow-flip and Deny-callback must re-check the registry entry; teardown removes+marks-tearing-down BEFORE close. The jcstress/race-soak proof is nightly — so the PR-tier tests (RELAY-001/005/006) must at least pin the observable contract. Pair with the exception-safety `finally` lesson.
2. **Header-only non-ROK `bind_resp` — DECIDED, not open (Story 1.2 T3-review 2026-07-29 locked "strict reject").** Ground truth: `SmppCodec.decodeResponse` UNCONDITIONALLY calls `SmppBytes.readAscii(body, "system_id")` (`codec/.../SmppCodec.java:80` → `SmppBytes.readNullTerminated`); the outcome splits on the body byte count — do **NOT conflate "bare denial" with "0-byte body"**:
   - **system_id present, OR empty-system_id (≥1 byte — the NUL terminator)** — the *usual* real-SMSC "bare denial" shape (an empty `system_id` is a single `0x00`). `readAscii` returns (possibly `EMPTY_STRING`), `SmppBindResponse` is built (`:82`), and `isOk()` **IS reached** → `false` for non-ROK (CODEC-019/020-style clean decode). Relay observes the decoded non-ROK `bind_resp` → no-flip + teardown (RELAY-001).
   - **truly header-only (0 bytes — no NUL terminator at all)** — the rarer malformed / SMSC-bug case. `bytesBefore((byte)0)` returns `-1` → `DecoderException` → `SmppCodec.exceptionCaught` fires the reject downstream then `ctx.close()` (`SmppCodec.java:95–97`) BEFORE `SmppBindResponse` is built — so `isOk()` is **NEVER reached** (CODEC-021 path). Relay observes the `channelInactive` teardown.
   Both shapes are fail-closed-correct (a non-ROK `bind_resp` tears down per AC3 regardless; no splice ever flips) — they just surface on different observables. **T9/mock must cover BOTH vectors:** empty/present-system_id non-ROK → assert `isOk()==false` + no-flip (RELAY-001); 0-byte header-only → assert the `channelInactive` teardown (CloseReason/counter), NOT `isOk()`. Do NOT widen T3's codec-touch scope to make `decodeResponse` body-optional — that would re-open a Story-1.2-locked decision AND violate the T3-only codec-touch discipline (Project Structure Notes).
3. **AD-32 is the FINAL uniform-bare-close version** (case-3 reversed to bare-close `.memlog.md:101`; `unbind`/`enquire_link` carve-outs dropped `:103`; case-4 SMSC non-ROK verbatim-forwarding `:104`) — NOT the intermediate header-only-`_resp` version (`:94–96`, itself superseded) nor the earlier SMPP-conformant-`_resp` draft (`:81`). No `_resp` synthesis for non-bind violations; no `unbind`/`enquire_link` carve-outs.
4. **Same-model author+review risk** — glm-5.2 authored/reviewed every Epic 1/2.1 story; the relay is the most concurrency-sensitive code yet. Run the 3-layer adversarial code review (Blind Hunter + Edge Case Hunter + Acceptance Auditor) fresh-context, as 2.1 did.
5. **A-1 is proven in CI here** (mechanics via RELAY-011 + independent jSMPP oracle via OBS-038) but NOT yet on a real carrier — the non-CI ops plan (OBS-035/036/037) completes it. Be honest in the Completion Record.

### Project Structure Notes

- **New main types:** `proxy/observability/{SpliceObserver,Direction,CloseReason,NoopSpliceObserver}.java`; `proxy/relay/{ConnectionRegistry,BindInterceptor,RelayHandler}` + the Netty lifecycle/allocator beans (suggested: a `relay/` sub-package for the bootstrap, e.g. `relay/netty/` — give it its own `@NullMarked package-info`). `relay/package-info.java` + `observability/package-info.java` already exist with `@NullMarked`.
- **Modified main types:** `proxy/bootstrap/ProxyCompanionLifecycle.java` (phase coordination, or a sibling lifecycle bean) — read it fully before touching (T6). **NO new `companion.relay.*`/`companion.egress.*` config key and NO change to `ProxyCompanionProperties.java` — the egress is the existing `companion.reverse.mode-b.smsc` field (already declared with `acknowledged`), read via the Story-1.3 properties record; `application.yml` only binds the selected `reverse.mode-b` branch.** *(Amended 2026-08-17, review F3: `ProxyCompanionProperties.java` DID change after T6, by owner sanction — T5b's `companion.memory.budget-check`/`BudgetCheck` (AC8 amendment) + T7's `Bind.adjudicationDeadline` (the adjudication budget). Still no `relay.*`/`egress.*` key. And `application.yml` binds only the mode-b-relevant keys (`companion.bind.adjudication-deadline`, `companion.memory.budget-check`); the role×mode template blocks (yml :61-94) stay commented, operator-supplied.)*
- **Codec touch (T3 only):** `SmppBindRequest.toString()` override + the static scan. Minimal; do not touch the framer/parser hot path.
- **Tests:** mirror main layout under `proxy/src/test/java/smpp/companion/proxy/{relay,observability}/`. Mock SMSC + capturing `SpliceObserver` fake + fake `BindCredentialVerifier` (latched/already-allow) live in `proxy/src/test`.

### References

- Epic + scope: `_bmad-output/planning-artifacts/epics.md` (Epic 2 :358–367; FR-TRANSIT-1/2/3 :42–44; AD list :364).
- Architecture (binding): `_bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/ARCHITECTURE-SPINE.md` (AD-1/2/3/8/9/12/14/15/16/19/21/24/25/27/29/30/32/33/35); `.memlog.md:87,96` (AD-27 gate-fixes); `.memlog.md:101,103,104` (AD-32 FINAL gate-fixes); `walkthrough.md` §5 bind→splice sequence.
- Test design: `_bmad-output/test-artifacts/test-design/smpp-companions-handoff.md` (E2 guidance); `test-coverage-scenarios.md` (RELAY-001..026 :317–475; OBS A-1 plan :1247–1271; A-1 unfalsifiable note :1646); `test-design-architecture.md` (mock-SMC oracle gap :200–215); `test-design-qa.md` (mock SMSC + jSMPP harness :125–129).
- Prior story: `_bmad-output/implementation-artifacts/2-1-security-port-contract-validation-slice.md` (seeded port; review findings; RED-on-neuter discipline).
- Retro + traps + gates: `_bmad-output/implementation-artifacts/epic-1-retro-2026-08-08.md` (4 traps :83–92, :167–179; relay carry-forward :154–180; AI-1..AI-8).
- Gates ledger: `_bmad-output/implementation-artifacts/deferred-work.md` (AI-5/AI-6/AI-8; AD-30 split; AlwaysAllow zeroization); `sprint-status.yaml` (action_items AI-1/AI-5/AI-6/AI-7/AI-8).
- Seeded contract (main): `proxy/src/main/java/smpp/companion/proxy/security/*.java`.
- Codec surface (main): `codec/src/main/java/smpp/companion/codec/{framer,bind,command}/*.java`.
- Config/bootstrap (main): `proxy/src/main/java/smpp/companion/proxy/{config,bootstrap}/*.java`; `proxy/src/main/resources/application.yml`.
- Build pins: `buildSrc/src/main/kotlin/smpp.{java-conventions,null-safety}.gradle.kts`; `proxy/build.gradle.kts`; `codec/build.gradle.kts`.
- Existing test patterns: `proxy/src/test/java/smpp/companion/proxy/{config/Relay026ConstantContractTest,bootstrap/EnablePreviewArgTest,security/KeycloakContainer}.java`; `codec/src/test/java/smpp/companion/codec/framer/SmppFrameDecoderTest.java` (RecordingAllocator).

## Dev Agent Record

### Agent Model Used

glm-5.2[1m] (Tasks 1–8 — bootstrap gate + observability contract seed + password hygiene/CODEC-024 P2 + ConnectionRegistry/AD-8 + shared allocator/AD-30 (T5/T5b) + Netty pipelines/SmartLifecycle substrate (T6) + BindInterceptor/AC2 (T7) + RelayHandler/AC3+AC7 (T8); Task 9 — the in-JVM mock SMSC + RELAY-011 A-1 smoke + REL-1 roundtrip + OBS-035/036/037 ops-plan docs; Task 10 — the jSMPP 3.0.2 independent A-1 conformance oracle OBS-038 + the owner-FIXME 3-agent investigation; Task 11 — the consolidated 35-mutation RED-on-neuter pass + green build: 6 guards first-hand inline + 29 worktree-isolated verifier agents, workflow `wf_529b1174-f33`).

### Debug Log References

- **T1 design REVISION (source-scan → compiler-enforced gate; owner decision 2026-08-11).** T1 was first
  implemented as a static source-scan of `smpp.java-conventions.gradle.kts` (3 assertions over the
  `JavaCompile`/`Test`/`JavaExec` blocks, mirroring `Relay026ConstantContractTest`). The owner redirected
  to a compiler-enforced gate — a test source that USES a JEP 505 preview API, so the compiler/JVM enforce
  the wiring directly (no source-scan). Rationale: a compile/exec gate is un-maskable (a runtime file read
  can be Gradle-UP-TO-DATE-skipped on incremental runs) and has no regex to maintain. Trade-off accepted by
  the owner: the RUN (`bootRun`) wiring is not reachable by any build/test task, so it is intentionally
  ungated (see the AC9 deviation in Completion Notes). The static source-scan was removed;
  `EnablePreviewArgTest` was restored to its committed (live-method-only) form.
- **T1 RED-on-neuter (compiler-enforced gate) — COMPILE neuter:** removed the `JavaCompile`
  `--enable-preview` arg → `:proxy:compileTestJava` FAILED; errors include
  `PreviewFeatureCompileGateTest.java:3: error: StructuredTaskScope is a preview API and is disabled by
  default` (alongside `RpcSlice`'s STS usage) → restored → GREEN. The gate test is an independent biter
  (it would fail `compileTestJava` even if `RpcSlice` stopped using STS).
- **T1 RED-on-neuter (compiler-enforced gate) — TEST neuter:** removed the `Test` `jvmArgs("--enable-preview")`
  → `:proxy:test --tests *EnablePreviewArgTest` FAILED cleanly: `EnablePreviewArgTest >
  jvmLaunchedWithEnablePreview() FAILED` (line 26 — the test JVM launched without the flag) → restored →
  GREEN. (TEST is doubly enforced: that live assertion AND the preview-marked gate class refusing to load
  without the flag.)
- **T1 `join()` checked exception:** `StructuredTaskScope.join()` throws `InterruptedException`; the gate
  test declares `throws InterruptedException` (JUnit permits checked exceptions on `@Test` methods).
- **T2 ArchUnit rule scoping (design decision).** The first draft of `ObservabilityLayerRulesTest` used
  `noClasses().that().resideInAPackage("..observability..").should().dependOnClassesThat().resideInAPackage("io.netty..")`
  — sweeping the WHOLE package. Caught before run: `@AnalyzeClasses(packages = "...observability")` scans
  the MERGED test classpath, which includes the test helpers (`CapturingSpliceObserver`, the `*Test`
  classes); those legitimately build a `SystemId` via Netty `AsciiString`, so the broad rule would have
  false-failed. Scoped the rule by FQN to the 4 seeded MAIN contract types
  (`SpliceObserver`/`Direction`/`CloseReason`/`NoopSpliceObserver`, referenced via `class.getName()` so a
  rename refactors both sides) — the precise expression of "no Netty type on the seam" (AD-19/AD-27).
  Dropped the second tautological "reside in package" rule (things-in-package-are-in-package = noise).
- **T2 REVISION — `onByteTransfer` dropped; PDU count via `onFramedPdu` (owner decision 2026-08-11).** Owner
  redirected mid-story: observe PDU count, not bytes. Since `onFramedPdu(Direction)` already fires once per
  framed PDU, PDU count is derivable from its fires — the dedicated byte-count slot was redundant, so the
  owner chose to DROP `onByteTransfer(Direction, long)` entirely (4-method seam) over repurposing it. Blast
  radius: the signature was in the BINDING `ARCHITECTURE-SPINE.md` AD-27:224, `epics.md`:225/388,
  `test-coverage-scenarios.md` OBS-010, and the readiness-report — owner authorized amending all of them
  (not code+story only). A 4-finder workflow audit (`wsu4qjy9u`) enumerated every `onByteTransfer` /
  `5-method` / `byte-count` reference; applied: spine + epics + TEA amended in place; readiness-report
  finding #2 annotated SUPERSEDED (dated point-in-time report, not rewritten); architecture `.memlog.md`
  appended as the canonical decision log; `reviews/review-adversarial.md` left verbatim (point-in-time
  history). Code: `SpliceObserver`/`NoopSpliceObserver` trimmed; `CapturingSpliceObserver` dropped
  `ByteTransfer` + `byteTransfers` + `totalBytes`; `SpliceObserverShapeTest` `hasSize(5)`→`4` +
  `onByteTransferSignature` deleted (10→9); `CapturingSpliceObserverTest` `byteTotalAccumulates` deleted
  (2→1). OBS-010 reworded to `onFramedPdu`-only (kept as a runtime wiring check; the `/metrics`
  sentinel-scrape-absence stays the load-bearing privacy gate — the `onFramedPdu`-only assertion is
  near-tautological on content, but still proves the relay wired the observer at runtime).
- **T3 scan-design — explicit `.toString()` scope, honest gap.** The source scan mirrors `Relay026ConstantContractTest`
  (comment-strip then regex over CODE) and forbids an EXPLICIT `.toString()` on a password-typed expression via two
  rules: Rule 1 — a `.password()` chain (`req.password().toString()`, `cred.password().value().toString()`,
  `cred.password().toString()`); Rule 2 — a `Password`-typed variable's `.value()` chain (`Password p = …;
  p.value().toString()`). Rule 1 covers the dominant documented hazard (the codec/port accessors); Rule 2 covers the
  inner `AsciiString` reached via a `Password` local/param. Both proven to bite (see T3 RED-on-neuter below). The scan
  does NOT chase IMPLICIT String materialization (string concat, `String.valueOf`, passing the raw `AsciiString`
  straight to a logger) — `String.valueOf(req.password())` is feasible but the `[^)]*`-across-nested-parens regex is
  fragile, so the implicit case is left to the relay-logging DISCIPLINE rule (subtask 3: "log `SystemId` only"),
  recorded on `SmppBindRequest.toString()`. This is the same lighter-weight-than-AST trade-off `Relay026` documents;
  the override + the redacting `Password`/`BindCredential` toString already kill the auto-toString leak vector, so the
  scan's job is keeping FUTURE explicit calls honest, not re-proving the override.
- **T3 scan scoping — three named packages, NOT all of proxy main.** The scan walks `../codec/src/main/java` (sibling
  module; `:proxy:test` CWD = proxy module) + `src/main/java/smpp/companion/proxy/security` + `…/proxy/relay`.
  Scoping to these three (not all of proxy main) is load-bearing: `CompanionConfigValidator` (proxy/config) calls
  `trustStore.password()` — a DIFFERENT password (a Spring `String`, the TLS truststore secret), and a blanket
  `.password()` ban would false-fire on it. The three roots are asserted to exist so a CWD/path drift fails LOUDLY
  (a missing root → empty walk → offenders-empty → silent false-green is the failure mode the existence asserts close).
- **T3 golden-string test — digit-collision fix.** First draft used a digit password `"57013579"` (mirroring
  `PasswordTest`'s "digits absent from the redacted form" technique). That FAILED: `Password.toString()` is
  `"Password[***]"` (zero digits, so any digit works), but `SmppBindRequest.toString()` renders numeric fields
  (`commandId=0x9`, `interfaceVersion=0x34`, `addrTon=0`, …) whose digits collide with the password's — the per-char
  `doesNotContain("0")` fired on the legit `0x9`/`addrTon=0`. Fix: draw the password from digits the redacted form
  NEVER renders. The golden uses only `{0,1,2,3,4,9}` (verified from the override output), so the password is
  restricted to `{5,6,7,8}` (`"56785678"`) — collision-free. (The `isEqualTo` golden is asserted FIRST and is
  independent of the password value — `password` always renders `***` — so the per-char check only runs once the
  exact golden matches, guaranteeing no legit digit trips it.)
- **T3 RED-on-neuter — `:proxy:test --tests '*Class:method'` filter matched ZERO tests.** Mid-mutation, the
  `--tests '*NoStringFromPasswordTest:noStringFromPassword'` invocation returned `BUILD SUCCESSFUL in 3s` (vacuous —
  no test ran); the `Class:method` filter form is not how Gradle's `--tests` matches here. Re-ran with the class
  filter `--tests '*NoStringFromPasswordTest'` → the expected RED. Lesson logged: use the class filter (or
  `--tests '*ClassName.methodName'` with a dot, not a colon) for single-method source-scan mutations.
- **T3 RED-on-neuter — all FOUR guards proven (codec override dropped + golden; scan Rule 1; scan Rule 2).** (1) Drop
  the `SmppBindRequest.toString()` override (record reverts to auto-toString) → `SmppBindRequestTest` RED at the
  `isEqualTo` (line 48 — auto-toString renders the password) AND `NoStringFromPasswordTest
  .smppBindRequestDeclaresToStringOverride` RED (no `String toString()` decl in CODE). (2) Throwaway probe
  `r.password().toString()` in codec main → `noStringFromPassword` RED (Rule 1, offender named). (3) Throwaway probe
  `Password p; p.value().toString()` in proxy/security → `noStringFromPassword` RED (Rule 2, offender named). All
  reverted → full `:codec:test :proxy:test` GREEN. Probes deleted; codec/proxy main back to the T3-committed shape.
- **T4 design — two-layer idempotency (attribute-clear + CAS).** `ConnectionRegistry.beginTeardown(channel)`
  reads the cached `Channel` attribute first; if absent → `null` (single-threaded double-teardown fast path:
  the winner's `clearAttributes` nulled both legs' attrs, so the loser's `channelInactive` reads absent and
  no-ops BEFORE it ever reaches the CAS). The `ConnectionEntry.beginTearingDown()` CAS is the race-free
  guarantee for the window where BOTH legs' attributes are still set (two event loops + the AD-25 Deny-callback
  race). This split is load-bearing for the RED-on-neuter story (see next entry): the deterministic
  `beginTearingDownIsCasOnce` test bites the CAS directly; the two-leg race test is a non-deterministic
  supplement whose GREEN/RED under a neutered CAS depends on the interleaving (the attr-clear path can still
  serialize the two threads). The statistical proof of the race invariant is RELAY-007 (jcstress, DEFERRED —
  see Completion Notes).
- **T4 EmbeddedChannel singleton-id trap.** Netty's no-arg `EmbeddedChannel()` ctor shares a singleton
  `EmbeddedChannelId.INSTANCE`; since the registry keys by ingress `ChannelId` (AD-8), two `new
  EmbeddedChannel()` ingress channels would COLLIDE on one map key (the second overwriting the first — fatal
  for RELAY-011's ≥2 concurrent binds). Verified via `javap` on `netty-transport-4.2.16.Final.jar`
  (`io/netty/channel/embedded/EmbeddedChannelId.class` is the singleton; the `EmbeddedChannel(ChannelId)` ctor
  exists). Fix: every test channel is `new EmbeddedChannel(DefaultChannelId.newInstance())` — unique ids,
  deterministic, independent of the default-ctor behavior. Pinned by `distinctIngressChannelsAreDistinctKeys`.
- **T4 RELAY-025 mechanism — source-scan, NOT ArchUnit (idiom match).** The scenario names "ArchUnit +
  source/field-type scan"; the repo's established idiom for IDENTIFIER/VALUE-structural invariants is the
  comment-stripped source-scan (`Relay026ConstantContractTest`, `NoStringFromPasswordTest`), while ArchUnit
  is reserved for DEPENDENCY/layer rules (`ObservabilityLayerRulesTest`, `NoRolledCryptoArchitectureTest`).
  RELAY-025 is a "no `message_id`-keyed map / identifier" invariant — identifier-shaped, so source-scan is
  the idiomatic, robust choice (ArchUnit's `JavaParameterizedType` type-argument introspection is fiddlier
  for the key-type check). Scan walks `src/main/java/.../relay/`: forbids the `message_id`/`messageId`
  identifier + any `Map`/`HashMap`/`ConcurrentHashMap`/`ConcurrentMap`/`NavigableMap`/`TreeMap` keyed by
  `String`/`Long`/`Integer` (the message_id / sequence-number key types — `ChannelId` cannot match); positive
  rule asserts `ConnectionRegistry` declares `ConcurrentHashMap<ChannelId` so dropping the registry cannot
  pass by silent false-green. Honest gap documented in the test javadoc: an opaque-wrapper-keyed
  `Map<SomeDomainKey, SystemId>` is not regex-caught — code review + behavioral RELAY-011 cover it.
- **T4 RED-on-neuter — idempotent-teardown CAS guard PROVEN (AC9 AI-1).** Neutered
  `ConnectionEntry.beginTearingDown()` to `tearingDown.set(true); return true;` (always-win, no CAS) →
  `ConnectionRegistryTest.beginTearingDownIsCasOnce()` FAILED cleanly at line 133 (second call returned `true`
  not `false`). Reverted → GREEN. (The two-leg race test stayed GREEN under the neuter that run because the
  attribute-clear path serialized the threads — see the design note above; that is the expected, honest
  outcome and exactly why RELAY-007 jcstress is the statistical proof, not a single-shot race.)
- **T4 RED-on-neuter — RELAY-025 scan PROVEN.** Injected a throwaway
  `private final Map<String, SystemId> messageIdIndex = new HashMap<>();` into `ConnectionEntry` →
  `Relay025StatelessnessScanTest` FAILED (the forbid-rules matched both the `messageId` identifier AND the
  `Map<String,` key type) → reverted → full `:proxy:test` GREEN. Probe had ZERO net change.
- **T5 module-open — `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED`, NOT `--add-opens`.**
  `jdk.internal.misc.VM` is a PUBLIC class and `maxDirectMemory()` a PUBLIC static method, so DIRECT
  (compile-time) access needs only `--add-exports` (exports the package → public API reachable), not
  `--add-opens` (which is for reflective deep access to non-public members). Verified empirically: without
  the flag `javac` fails `package jdk.internal.misc is not visible`; with `--add-exports` both compile
  and `VM.maxDirectMemory()` run resolve. Added to `smpp.java-conventions.gradle.kts` (SHARED, alongside
  `--enable-preview`) on `JavaCompile` + `Test` + `JavaExec` — consistent with the preview pin's placement,
  and harmless for modules that never reference the package (codec/buildSrc). The `ManagementFactory`
  arg-parsing fallback is NOT used: it only sees an EXPLICIT `-XX:MaxDirectMemorySize`, missing the
  common `-Xmx`-default case, whereas `VM.maxDirectMemory()` returns the true live ceiling in both cases
  (measured: == `Runtime.maxMemory()` when `-XX:MaxDirectMemorySize` is unset). Error Prone 2.50.0 +
  NullAway do NOT flag it (`VM.maxDirectMemory()` is `native`, not `@Restricted`; returns primitive `long`).
- **T5 self-check SCOPING — runtime mode-b guard, NOT an unconditional startup bean (load-bearing).**
  **[SUPERSEDED 2026-08-15 — T5b (operator decision) made the check UNCONDITIONAL: the mode-b guard is gone,
  `companion.memory.budget-check` now governs over-budget severity (default `fail` = the behavior this entry
  describes), and the full-context tests this entry worried about are accommodated by minimal-budget overrides
  (`TestCompanionConfigs.common()` + the two forward-A yml-backed boots). See the T5b Dev Notes entry. The text
  below is kept for the record.]**
  Measured the test JVM's live ceiling: `VM.maxDirectMemory()` == `Runtime.maxMemory()`, which under a
  capped test JVM (Gradle test worker: 512 MiB) is FAR below the default AD-30 budget
  (`64 × 1024 × 1.5 × SmppFrame.MAX_COMMAND_LENGTH` ≈ 6 GiB). An UNCONDITIONAL self-check would therefore
  trip on EVERY full-context boot that carries the default `companion.memory.*` — including the Story-1.3
  `BootstrapLifecycleTest` (forward) and `CompanionConfigMatrixTest` SEC-052 (mode-b) — on any CI-sized
  JVM, i.e. flaky-by-environment. The self-check is a RELAY data-plane concern that "mounts with the relay"
  (AC8), so `DirectMemoryBudgetStartupCheck.afterPropertiesSet()` guards on
  `properties.reverse() != null && reverse.modeB() != null` and is a no-op for every other cell. This is
  slice-correct (this story wires the relay for reverse.mode-b ONLY; forward + reverse.mode-a/c relays +
  their budget checks are Epic 3 — widen the guard then). The forward-context tests (no mode-b) are
  immune by construction; the mode-b matrix test needed a separate, smaller accommodation (next entry).
- **T5 `io.netty.allocator.type=pooled` — superseded by the explicit pooled bean (honest deviation).**
  The subtask names the Netty system property, but it is read ONCE at Netty static init
  (`ByteBufAllocator.DEFAULT` selection) — setting it programmatically at bean-creation is too late and
  unreliable (Netty is already class-loaded by the codec). `RelayNettyConfig.pooledByteBufAllocator()`
  instead returns `PooledByteBufAllocator.DEFAULT` — pooled BY CONSTRUCTION — which T6 wires to every
  channel via `ChannelOption.ALLOCATOR`. That bean is the authoritative pooling guarantee for the relay
  data plane; the system property is redundant for channels wired to it. Setting it as a JVM arg
  (`-Dio.netty.allocator.type=pooled`) is a deploy concern (Epic 5), not code. Flagged for review.
- **T5 `SpringApplicationBuilder.properties()` precedence trap — default props lose to application.yml.**
  First fail-fast-context-test draft supplied `companion.memory.*` overrides via
  `builder.properties(...)`; it GREEN-tripped on the DEFAULT 6 GiB budget (the override was ignored).
  Cause: `SpringApplicationBuilder.properties(String...)` → `SpringApplication.setDefaultProperties` →
  LOWEST-precedence property source (Spring Boot externalized-config order: default props < application.yml).
  `BootstrapLifecycleTest` works this way only because its forward.mode-a branch has NO application.yml
  entry (commented out), so the default prop is the only source. Fix: pass the memory overrides as
  COMMAND-LINE ARGS to `run(String...)` (HIGHEST precedence) — they beat application.yml's live
  `companion.memory.*` defaults. The mode-b branch props stay in `.properties()` (no competing yml entry).
- **T5 mode-b matrix test accommodation — `reverseB()` uses a minimal budget.** The Story-1.3
  `CompanionConfigMatrixTest.sec052_reverseModeBWithAckWarnsAndStarts` boots the FULL
  `ProxyCompanionApplication` for a valid mode-b cell (to fire the `CompanionModeBWarning` banner); with
  the self-check now active for mode-b, its default 6 GiB budget (set explicitly in
  `TestCompanionConfigs.common()`) exceeded the test JVM's 512 MiB ceiling → `DirectMemoryBudgetException`.
  This is the self-check doing its correct job (a 6 GiB budget on a 512 MiB-ceiling JVM IS under-provisioned).
  Fix: `TestCompanionConfigs.reverseB()` overrides `companion.memory.*` to a minimal budget (1/1/1.0 →
  65536 bytes) after `common()`, with a comment that a mode-b boot now carries the AD-30 self-check. The
  self-check still RUNS for every `reverseB()` boot; only the budget is sized to the test JVM. No test
  asserts on `reverseB()`'s memory values, so this is safe. (The no-ack SEC-052 test uses the slice runner
  — no `@Component` load — and the bad-port test fails `@Max` validation BEFORE the self-check bean inits,
  so neither is affected.) This is a legitimate adjustment to satisfy a new startup invariant, NOT a
  disable-to-pass dodge (AC9): no test was `@Disabled`/removed.
- **T5 RED-on-neuter — PROVEN on BOTH the unit and the context biter (AC9 AI-1).** Neutered
  `DirectMemoryBudgetValidator.validate()` (`if (budget > liveCeiling)` → `if (false)`) →
  `DirectMemoryBudgetValidatorTest.budgetExceedingCeilingThrows()` RED (line 27 — `assertThatThrownBy`
  got no throw) AND `DirectMemoryBudgetStartupCheckTest.modeBBudgetExceedingLiveCeilingRefusesToStart()`
  RED (line 65 — the under-budget mode-b context STARTED instead of throwing) → reverted → full `:proxy:test`
  GREEN. The context biter is exception-safe (closes the unexpectedly-started context on the neutered path
  so it cannot outlive the assertion failure — MEMORY `mutation-pass-needs-exception-safe-test-cleanup`).
- **T6 design — owner fork resolved: codec-only pipeline prefix + attachment points.** T6's subtask-1
  pipeline names `BindInterceptor`/`RelayHandler`, but those classes are authored by T7/T8 — and their
  per-channel constructor SHAPES (verifier/registry/observer/egress deps, ingress-vs-egress direction)
  are T7/T8's design decisions, so shipping T6 placeholder shells would have front-run them. Asked the
  owner (2026-08-15); they chose "codec-only + attachment point": T6 wires `SmppFrameDecoder → SmppCodec`
  on both legs with the two handler slots as documented `addLast` attachment points (comments in the
  initializers); NO placeholder main classes. Consequence honestly recorded: subtask 1's checkbox stays
  open until the handler entries land (T7 ingress `BindInterceptor`; T8 `RelayHandler` on both legs) —
  an explicit owner instruction overriding the strict task-completion ordering for this subtask only.
- **T6 Netty 4.2 discovery — `NioEventLoopGroup` is CLASS-deprecated in 4.2.16.** First draft used the
  classic `new NioEventLoopGroup(0, factory)`; the build flagged deprecation, and `javap` confirmed the
  class-level `@Deprecated` (the 4.2 IoHandle refactor). Swapped to the 4.2 idiom:
  `new MultiThreadIoEventLoopGroup(0, new DefaultThreadFactory("companion-relay"), NioIoHandler.newFactory())`
  — build warning-free. `NioServerSocketChannel` is NOT class-deprecated (its hit was member-level) and
  serves the new group unchanged.
- **T6 watermark math — the AD-30 per-channel inbound bound in BYTES, tied to the budget input.** Low
  water = one `SmppFrame.MAX_COMMAND_LENGTH` frame (the "explicit low-water mark to re-arm read" —
  writability flips back once less than a max frame is queued); high water = `MAX_COMMAND_LENGTH ×
  memory.maxInboundDepth()` (at most `max-inbound-depth` max-sized framed PDUs queued per channel —
  the SAME depth the `MemoryBudget.compute` formula multiplies, so per-channel bound and JVM budget
  cannot drift). Long-multiplication clamped to `Integer.MAX_VALUE` — a pathological depth must not
  wrap the int-typed `WriteBufferWaterMark` (mutation M-D proves the clamp bites). `low == high`
  (depth 1, the minimal test budget) is legal.
- **T6 test-shape gotchas.** (1) `WriteBufferWaterMark` implements NO `equals` — the first draft's
  `isEqualTo(new WriteBufferWaterMark(...))` failed on identity; assert the `low()`/`high()` accessors.
  (2) `ChannelPipeline.names()` INCLUDES Netty's internal `TailContext` (but not Head) — the
  exactly-the-codec-prefix assertion filters `DefaultChannelPipeline$*` names. (3) ErrorProne
  `FutureReturnValueIgnored` fires on bare `EmbeddedChannel.close()` in tests — class-level
  `@SuppressWarnings` with a reason (house pattern). (4) `new Socket("127.0.0.1", port)` trips
  `AddressSelection` — use `InetAddress.getLoopbackAddress()`.
- **T6 existing-boot accommodations — mode-b full boots now BIND a port (not disable-to-pass).** With
  the acceptor live, every VALID mode-b full-app boot binds `companion.bind.port`. Two accommodations:
  `TestCompanionConfigs.common()` now probes a FREE EPHEMERAL port per config instance (was the fixed
  2775 — deterministic against a locally-listening SMPP tool and other tests; the sec052 matrix boot
  consumes it via `reverseB().args()`); `DirectMemoryBudgetStartupCheckTest` passes a shared
  `--companion.bind.port=<free>` run-arg on its three boots that reach the lifecycle phase (run-arg =
  HIGHEST precedence, beats yml's 2775 — the T5 `.properties()`-loses-to-yml lesson; the two refusal
  boots fail at refresh before any bind and need none). Forward-cell boots never bind (the lifecycle is
  mode-b-scoped — pinned by `forwardCellLeavesAcceptorUnstarted`, RED under the guard-removal mutation
  M-A).
- **T7 design — Q2 ratified: `ESME_RBINDFAIL 0x0000000D`, NOT the story's illustrative `ESME_RSYSERR`.**
  Ratified against the primary source IN THE REPO (`pdftotext docs/SMPP_v3_4_Issue1_2.pdf` §5.1.3:
  `ESME_RSYSERR 0x00000008 System Error`, `ESME_RBINDFAIL 0x0000000D Bind Failed`,
  `ESME_RINVPASWD 0x0000000E Invalid Password`, `ESME_RINVSYSID 0x0000000F Invalid System ID` — also
  independently confirming the story's claim that the prior `0x0E` pin was `RINVPASWD`, not
  `RINVSYSAUTH`). Why RBINDFAIL over RSYSERR: (1) it is §5.1.3's LITERAL generic bind-failure status —
  the exact semantic slot of "ONE generic bind-failure `command_status` answering a `bind_*` request";
  (2) anti-enumeration is a TIE (both carry zero credential information), but RSYSERR conventionally
  signals a TRANSIENT system error — naive legacy clients retry-storm on it — while RBINDFAIL reads
  definitive, which mildly ANTI-amplifies probing under the collapse; (3) honest for BOTH arms
  (verifier-deny AND egress-unreachable are both "the bind failed"). The production constant
  (`BindInterceptor.AD_33_GENERIC_BIND_FAILURE_STATUS`) is pinned in tests by the LITERAL `0x0000000D`
  (plus the §5.1.3-verified neighbor codes in the test javadoc), so re-pointing the constant cannot
  silently re-point the wire contract.
- **T7 design — the egress `bind_resp` forwarder: a nested `BindInterceptor.EgressLeg`, resolving the
  AC4/RELAY-003 "egress has no BindInterceptor" vs AD-25 "BindInterceptor forwards the bind_resp"
  tension.** The egress leg's fixed initializer keeps its documented shape (`framer → codec` + the T8
  slot — untouched by T7); the per-bind connect assembly (inside `BindInterceptor`, HexDumpProxy-style)
  appends a per-pair `EgressLeg` inner handler AFTER that prefix: `framer → codec → RelayHandler(T8,
  from the initializer) → EgressLeg(T7, from the assembly)`. Two load-bearing consequences: (a) the
  `addLast` happens in the connect-success listener BEFORE any read is armed (`AUTO_READ=false` — no
  PDU can precede it; registration precedes connect, so the initializer's handlers are already in
  place), which is NOT the AD-2-forbidden "live pipeline surgery" (that ban is `pipeline.remove()` on a
  live channel — removing); (b) `EgressLeg` is the bind family's LAST consumer (forwards the SMSC's
  `bind_resp` bytes verbatim to the ingress, releases the decoded PDU, propagates nothing) — a contract
  that stays STABLE when T8's `RelayHandler` inserts earlier in the pipeline: T8's handler observes the
  decoded `bind_resp` first (flips, read-only) and PROPAGATES bind-family PDUs so the forwarder still
  sees them; opaque PDUs are consumed by whichever handler handles them first. At T7-time (no
  RelayHandler yet) `EgressLeg` directly follows `SmppCodec` — same contract.
- **T7 design — zeroize TIMING: at adjudication settlement + at teardown, NOT at `verify()`-return.**
  The subtask says "`zeroize()` in a `finally` on EVERY path"; the finally that matters is the VERDICT
  CONTINUATION's (plus every teardown path): the Epic-3 ROPC adapter reads the password ASYNCHRONOUSLY
  while its future is pending (the ROPC token request carries the credential), so a wipe at
  `verify()`-return would hand the adapter zeroed bytes. Wipe sites: the continuation's `finally`
  (Allow/Deny/exceptional — the Allow arm is the only one no teardown covers, and it has a dedicated
  biter), `cancelAndWipePending()` on every teardown arm (retry-bind, ingress/egress death, violation —
  idempotent, RELAY-005 double-zeroize safe), and the sync-throw catch. Verified SAFE for the AD-14
  forward: `SmppBytes.readNullTerminated` COPIES each C-octet field into a fresh `byte[]`, so the
  password's backing array is never the forwarded frame's memory — the wipe cannot corrupt the bind the
  SMSC receives (a real jshell-free read of the codec source; the forwarded frame keeps the cleartext
  until its buffer is released, which is the codec's documented model).
- **T7 design — `EgressConnector` seam (package-private ctor param), and it CLOSES the T6-review
  deferred wiring pin.** RELAY-006's technique note sanctions "an injected failing ChannelFuture"; the
  seam takes the fully-assembled `Bootstrap` + host/port and returns the `ChannelFuture` (production:
  `bootstrap.connect(host, port)`). Beyond the injectable failure, the tests capture the Bootstrap and
  pin what the T6 review deferred to T7 ("dropping `.childHandler`/`applyToEgress` keeps the suite
  GREEN"): group == the ingress event loop (HexDumpProxy same-loop coupling), handler == the
  `RelayEgressInitializer` bean, `ALLOCATOR`/`AUTO_READ=false`/watermark options present — mutations
  N3/N4 prove both bites. The 6-arg public ctor (used by `RelayIngressInitializer`) delegates with the
  DEFAULT connector; only the 7-arg package-private ctor exposes the seam (tests live in the same
  package).
- **T7 test-harness gotchas (three).** (1) **`EmbeddedChannel.eventLoop().execute()` after `close()`
  QUEUES the task instead of running it** (empirically probed via jshell: the task never ran; a real
  event loop always drains its queue) — the late-verdict tests must call `ingress.runPendingTasks()`
  after completing the held future, else the continuation silently never runs and the no-op/re lease
  asserts are VACUOUS (the original RELAY-004 late-verdict arm passed vacuously before the pump was
  added). (2) **`readOutbound()` hands the reader ownership** — the refCnt-reaching-zero proof requires
  releasing the read buffer first (the deny-synth buffer is independent, but the AD-14 forwarded frame
  shares the underlying buffer with the test's wrapped input). (3) The RED-phase run's Gradle console
  said "15 tests completed, 9 failed" while the class XML says `tests="9" failures="9"` — trust the XML
  (the console line aggregates other bookkeeping); the RED phase was 9/9 behavioral failures against a
  compiling no-op stub.
- **T7 RED-on-neuter — all FIVE guards PROVEN (AC9 AI-1; each reverted from a unique
  `/tmp/t7-backups` path, main diff-verified byte-exact after restore).** **N1** deny synthesis neutered
  (`writeAndFlush(deny)+CLOSE` → bare `close()`) → exactly the 5 deny-dependent tests RED (verifier-deny,
  bind-type matching, egress-death, egress-establishment-fail, RELAY-004 retry-reject — no deny on the
  wire). **N2** the continuation's `finally`-zeroize removed → exactly the ALLOW-path test RED (its
  zeroize assert is the only arm no teardown wipe covers — added precisely so N2 has a biter; the deny
  tests' wipes come from the teardown arm and stay green under N2, correctly so). **N3**
  `channelOptions.applyToEgress(bootstrap)` dropped → the wiring-pin test RED (options absent). **N4**
  `.handler(egressInitializer)` dropped → the wiring-pin test RED (handler absent). **N5** the AD-25
  race-free re-check removed → both late-verdict no-op tests RED (the late Allow wrongly opens an
  egress).
- **T7 owner-FIXME round (2026-08-15, post-T7 — the owner left 6 in-code FIXMEs; addressed same-day,
  the T5b pattern).** (1) **Adjudication deadline → config:** `companion.bind.adjudication-deadline`
  (`Bind` record's 2nd component, `Duration`, `@NotNull` + compact-ctor POSITIVITY guard — zero/negative
  refuse, AD-17), default **4s** in application.yml (was a hardcoded 30s constant; the owner's FIXME
  named the 4s default). Follows the T5b house pattern exactly — the default ships in yml, deliberately
  NO `@DefaultValue`, and `TestCompanionConfigs.common()` states the key explicitly because the matrix
  boots run on `ApplicationContextRunner`, which does NOT load application.yml (a bare `@NotNull`
  without that would null-fail all 53 matrix tests — the load-bearing trap of this round). 6 direct
  `new Bind(...)` sites gained the arg (`RelayTestFixtures` exports `DEFAULT_ADJUDICATION_DEADLINE`).
  New bite: `nonPositiveAdjudicationDeadlineRefuses` (0s/-5s/PT0S — the INVALID value is bound, not the
  key removed) + an end-to-end flow assert (the latched verifier captures `ctx.get().deadline()` inside
  the ScopedValue-bound verify; asserted ≈ now+4s) + a yml-default pin in `CompanionTlsBindingTest`
  (that boot sets NO `companion.bind.*` property — mirror of the T5b `budgetCheck==FAIL` end-to-end
  pin). Mutation **N6** (guard → `if (false)`) RED on exactly the 3 new parameters. (2) The
  spliced-passthrough arm's comment now DESCRIBES the mechanism (post-flip a bind-family PDU still
  DECODES — SmppCodec is structural, "dormant" means downstream ignores it — so the arm sees a decoded
  `SmppBindRequest`, fires it downstream untouched, T8's RelayHandler owns the frame). (3) `assert
  pendingVerdict == null && pendingPassword == null` at `adjudicate` entry — a single-event-loop
  invariant (every entry-clearing path also clears the pending handles on the same loop), `assert` not
  throw so the production bind path pays nothing without `-ea`; probe-proven live (a temporary
  `assert false` failed 2 tests — Gradle test workers run `-ea`; **N7** probe, reverted exactly).
  (4) The sync-throw catch's redundant `pendingPassword` assignment REMOVED (nothing was stored to
  track; `cancelAndWipePending` finding nothing is correct; the explicit `zeroize()` below is that
  arm's single wipe). (5) `EgressLeg` → Lombok `@RequiredArgsConstructor` (house style). (6) "Prove
  non-blocking": the verify() call site documents the proof (the call only hands off; the await is the
  `whenComplete` chain; a blocking-inside-verify verifier violates the PORT contract, AD-28) and
  `BindInterceptorTest` gained a class-level `@Timeout(10)` — a blocking regression now FAILS a test
  instead of hanging the suite (RELAY-004's mid-flight second write already proves the pipeline stays
  live deterministically). ErrorProne `UnusedVariable` on the continuation's `error` param resolved by
  making the fail-closed arm read it explicitly (`error == null && verdict instanceof Allow` /
  `error == null && verdict != null` — behavior identical under the `whenComplete` contract).
  Post-round `./gradlew clean build` GREEN — **277 tests, 0 failures, 0 skipped** (matrix +3).
- **T8 design — the flip site is the EGRESS-leg `RelayHandler`, resolving "RelayHandler on the ingress
  event loop" (AC3/AD-25).** The `bind_*_resp` arrives FROM the SMSC on the EGRESS channel; that channel
  rides the INGRESS channel's event loop (T7's HexDumpProxy same-loop coupling, AD-2), so the flip runs
  "on the ingress event loop" in the spine's sense while physically sitting in the egress pipeline
  (`framer → codec → RelayHandler → EgressLeg`). The ingress-leg `RelayHandler` can never see a decoded
  `SmppBindResponse` at all: T7's interceptor consumes bind-family pre-flip and its post-flip passthrough
  fires REQUESTS only — so the single-flipper property is STRUCTURAL (one branch in one handler on one
  leg), not merely conventional. `RelayHandler` is one class, one per-channel instance per LEG
  (`Direction` is the only per-instance state beyond the shared registry/observer beans).
- **T8 design — the AD-32 ingress-violation teardown is DELEGATED to `BindInterceptor` (a new
  package-private seam `teardownForPreCoupleViolation(Channel)`), because the pending-adjudication
  handles live there.** AC3's pinned ordering (remove + mark tearing-down BEFORE close → `cancelHttp()`
  + `zeroize()` → close) needs the `pendingVerdict`/`pendingPassword` fields, which are per-channel
  interceptor state; a `RelayHandler`-owned teardown could not cancel the ROPC (the interceptor's
  `channelInactive` only fires its cancel arm when IT wins `beginTeardown` — a RelayHandler-won teardown
  clears the attrs first and the cancel would be skipped). The seam does exactly the T7
  `denyAndTeardown` sequence minus the deny write (bare close — AD-32 case 3 emits NOTHING), and
  RelayHandler reaches it via `channel.pipeline().get(BindInterceptor.class)` (same package). The EGRESS
  leg's violations need no delegation: closing the egress is enough — `EgressLeg.channelInactive`
  (answered==false) collapses the dead bind via AD-33 (RELAY-003's propagation), and a RelayHandler-won
  `beginTeardown` makes that arm lose the race cleanly (the post-egress ingress violation test pins
  exactly this: NO deny, both legs closed).
- **T8 design — `CloseReason` stashes + the exactly-once CAS; which values fire this slice (honest
  coverage).** Only `channelInactive` calls `onConnectionClosed` (CAS on a channel attribute set at
  `handlerAdded`); every other path (violations, teardowns, `exceptionCaught`) merely STASHES a reason
  on the channel. Unstashed defaults: `PEER_HALF_CLOSE` for a spliced pair (the RELAY-008 contract),
  `OTHER` for a pre-flip leg (the handshake planes — T7's deny/violation closes — left no T8 stash);
  teardown propagation copies its reason onto the peer it closes. `exceptionCaught` classifies
  `DecoderException → DECODE_ERROR` (the CODEC-021 sibling lands here — `isOk()` is never reached) and
  `IOException → PEER_RST` (how a reset surfaces pre-inactive). Fired this slice:
  `PRE_COUPLE_NON_BIND_PDU`, `BIND_FAILED_NON_ROK`, `GENERIC_NACK_PRE_BIND`, `DECODE_ERROR`,
  `PEER_HALF_CLOSE`, `PEER_RST`, `OTHER`. NOT fired (closed-set stability, not a must-fire list):
  `UNKNOWN_COMMAND_ID` (the relay classifies non-bind uniformly — maintaining a known-id set in
  `relay/` would duplicate codec knowledge AD-27 forbids; unknown ids are a subset of non-bind),
  `CLEAN_UNBIND_HANDSHAKE` (detecting it needs post-flip command_id peeking AD-3/AD-32 scope to the
  pre-flip window; a post-flip unbind is opaque and its close reports `PEER_HALF_CLOSE` — correct but
  coarser), `OVERSIZED_FRAME`/`UNDERSIZED_FRAME` (the framer's rejects classify as `DECODE_ERROR` via
  their `DecoderException`/`TooLongFrameException` types), and the TLS/shutdown values (Epic 3/4).
- **T8 design — `generic_nack` classification constant.** AD-32 case 4 is the ONE pre-couple opaque
  case that must be distinguished (SMSC-originated answer → forward verbatim). `SmppCommandIds` does
  not export it — AD-27 declares `generic_nack` opaque-spliced, NOT bind-family, and the codec-touch
  discipline is T3-only — so `RelayHandler` carries a private `GENERIC_NACK = 0x80000000` (documented
  as a classification constant, NOT a redefinition of the bind set; `SmppCommandIds.requestIdOf`'s own
  javadoc names the same literal). The read is the AD-32-prescribed bare `getInt(4)` (no codec helper,
  AD-19), on the EGRESS leg only; the INGRESS violation path reads NO header at all (non-bind is
  already structural there — the codec emitted it opaque because it is not bind-family).
- **T8 test-harness gotchas (three, empirically grounded).** (1) **`writeInbound` on a CLOSED
  `EmbeddedChannel` throws `ClosedChannelException`** — the RED phase surfaced it on the first
  `lateBindResp` draft. Any "delivery racing teardown" scenario must keep the channel OPEN and clear
  the pair state directly: `registry.beginTeardown(...)` leaves the CLOSES to the caller (the T4 split),
  and `ConnectionEntry.beginTearingDown()` is the CAS without the attr clear — together they
  deterministically fabricate BOTH halves of the AD-25 re-check window (entry absent / entry cached but
  tearing-down). (2) **`EmbeddedChannel.close()` tears the pipeline down** — after close,
  `pipeline().get(RelayHandler.class)` returns null and a manual `fireChannelInactive()` propagates
  through an EMPTY pipeline (probe-verified: a post-close duplicate is a NO-OP, not a biter). The
  exactly-once biter therefore delivers its duplicate inactive PRE-close, while the handler is
  installed; the initial post-close shape passed VACUOUSLY under the neutered CAS and was restructured
  (the mutation pass caught its own false-green — the exact failure mode the Epic-1 gate exists for).
  (3) **`BindInterceptorTest`'s ingress pipeline predated T8** (framer→codec→interceptor, no
  `RelayHandler`) — the non-ROK close-events assertion failed on the missing INGRESS event until the
  real production pipeline (4 handlers) was retrofitted into its `@BeforeEach` + the throwing-verifier
  sub-channel.
- **T8 RED phase genuine — 12/12 behavioral failures against a compiling no-op stub** (XML-verified;
  the console's "18 completed" aggregates other bookkeeping — trust the XML, the T7 lesson). Two test
  reshapes followed from the gotchas above BEFORE the implementation: the re-check biter (both halves)
  and the RELAY-009 dead-pair phase (registry-direct teardown instead of close-then-write).
- **T8 RED-on-neuter — all FIVE guards PROVEN (AC9 AI-1; unique `/tmp/t8-backups` masters, restored
  byte-exact, `grep -c MUTATION` = 0, full `clean build` GREEN after).** **N1** flipper neutered
  (`if (entry.flipSpliced())` → `if (false)`) → 5 flip-dependent tests RED (the named biter:
  `flipsOnlyOnDecodedRokBindRespThenSplicesOpaquely` — `onBindAccept` never fired). **N2** the AD-32
  bare-close seam neutered (`teardownForPreCoupleViolation` → immediate return) → exactly the 2
  RELAY-002 tests RED (no close, no `cancelHttp`, no zeroize). **N3** the `tearingDown` re-check
  conjunct dropped → exactly the re-check biter RED (the late bind_resp wrongly FLIPS on the cached
  tearing-down entry). **N4** the exactly-once CAS neutered (always fire) → RED ONLY AFTER the biter
  restructure (the post-close duplicate was a no-op; the pre-close duplicate double-fires →
  `connectionClosedFiresExactlyOncePerChannel` RED at `hasSize(2)`). **N5** the non-ROK teardown
  dropped (forward only) → exactly the 2 non-ROK tests RED (RelayHandlerTest's + the T7-evolved
  BindInterceptorTest one: pair stays registered, legs open).
- **T9 design — direct-construction REAL-acceptor harness (`RelayTestFixtures.ModeBRelayHarness`), NOT a
  full Spring boot.** The A-1 smoke needs a CAPTURING `SpliceObserver` wired into the REAL
  initializers, but a component-scanned `ProxyCompanionApplication` boot resolves the `@Component`
  `NoopSpliceObserver` by type (registering a second observer bean creates injection ambiguity; the
  noop is the seeded default by design). The harness instead builds the exact production constructor
  graph — `RelayIngressInitializer(verifier, registry, observer, properties, egressInitializer,
  channelOptions)` + the shared `RelayEgressInitializer` — behind the REAL `RelayServerLifecycle`
  acceptor, with the production-default `AlwaysAllowBindCredentialVerifier` (AC6's wired verifier)
  and the egress target pointed at the mock (`modeBProperties(bindPort, depth, smscHost, smscPort)`,
  the new 4-arg overload; the 2-arg form delegates unchanged). This discharges the T6-review
  DEFERRED wiring pin in full: real PDUs now flow through the acceptor, so a dropped
  `.childHandler(ingressInitializer)` / initializer-wiring line fails RELAY-011/REL-1 outright.
- **T9 design — the socket-level read IS the tag→Channel assertion (the subtask's "capturing
  SpliceObserver per Channel" phrasing).** AC5's seam is deliberately channel-BLIND
  (`onFramedPdu(Direction)` carries no channel identity — AD-19's cardinality posture), so a
  per-channel observer capture is unconstructible through the contract. The legacy TCP connection
  IS the ingress channel identity: asserting "client A's socket reads exactly the bytes injected on
  pair A's SMSC socket (and then times out)" is the tag→Channel mapping, at the wire, with no seam
  change. The shared `CapturingSpliceObserver` still pins the trigger contract: 2× `onBindAccept`
  under ONE `SystemId` (A-1's premise observed at the relay), one `onFramedPdu` per spliced PDU on
  the leg it was read from, zero `onBindReject`.
- **T9 design — mock sessions matched by bind-frame CONTENT, not accept order.** Two concurrent
  binds' egress connects race in principle (verdict continuations hop through the shared event
  loop); `sessionBoundWith(bindA)` matches the session whose captured bind bytes equal client A's
  bind — removing the order dependence AND independently proving "each bind couples to its own
  egress pair" (two distinct sessions, each carrying the exact original bind — AD-14 through two
  real sockets + the framer, byte-exact).
- **T9 design — the real-socket teardown arms T8 deferred here are IN the smoke class (AC7's
  half-close/RST text).** FIN = client `shutdownOutput()` (true half-close, read side kept); RST =
  `setSoLinger(true, 0)` + `close()` (loopback). Both assert the SMSC-side socket goes inactive,
  `registry.size()==0`, and observed `onConnectionClosed` in BOTH directions. The FIN arm pins
  `PEER_HALF_CLOSE` on both legs exactly; the RST arm asserts reasons ⊆
  {PEER_RST, PEER_HALF_CLOSE, OTHER} honestly (which arm fires depends on whether a read was armed
  at the reset instant — an armed read surfaces the `IOException`/PEER_RST path, a bare inactive
  takes the default — both are the observed fail-closed teardown RELAY-010 requires). These tests
  are ALSO the live proof of the AD-2 read-demand substrate T8 could not observe on
  `EmbeddedChannel`s: under `AUTO_READ=false` not one byte of RELAY-011/REL-1 would cross without
  the handlers' arming — every observed byte flowed through write-completes-gates-read.
- **T9 gotchas (three).** (1) **Golden vectors are NOT on proxy's test classpath** — they live in
  codec's TEST source set (`codec/src/test/resources`), so the smoke loads them by FILE PATH
  (`../codec/src/test/resources/golden-vectors`, the `NoStringFromPasswordTest` sibling-module
  idiom; the corpus root is asserted to exist loudly), parsing the single-line provenance header's
  `raw-hex:` token via `HexFormat` — hand-authored-from-spec bytes, codec-independent. (2)
  **Markdown backticks broke the docs-gate regex** on the first run (`2 concurrent
  `bind_transceiver`` carries a backtick between "concurrent" and "bind") — the gate's normalizer
  now strips backticks (formatting noise, like whitespace); wording/markdown tweaks must never
  false-RED a falsifiability gate. (3) **ErrorProne `UnnamedVariable`** flags the lambda param in
  `thenCompose(unused -> bindGate)` — the JDK 22+ unnamed-variable `_` is the clean fix (and reads
  as intent: the delay future's value is deliberately dropped).
- **T9 RED-on-neuter — both mutations PROVEN (unique `/tmp/t9-backups` masters, restored
  diff-verified byte-exact, `grep T9-MUTATION` = 0, full `clean build` GREEN after the restores).**
  **N1** (the checklist's named coupling neuter): `splice()` forwarded to `self` instead of the
  peer → RELAY-011 RED on `SocketTimeoutException` (the tagged deliver_sm echoes back to the mock —
  client A reads nothing) AND REL-1 RED (`awaitPdus(4)` unreached — the submits echo back to the
  legacy client); the real-socket teardown test stayed GREEN, correctly (its scenario carries no
  spliced PDUs). **N2**: the ops-plan doc blanked → all 3 `A1CarrierPlanDocsTest` tests RED (the
  existence-first assert plus every shape assert).
  `forwardCellLeavesAcceptorUnstarted` RED (the forward boot took the port → the test's own bind of it
  failed); M-B `callback.run()` removed → `stopInvokesCallbackAndReleasesPort` RED; M-C `AUTO_READ`
  childOption removed → `ingressChildOptionsCarryTheSharedSubstrate` RED; M-D watermark clamp removed →
  `watermarkHighClampsAtIntegerMaxValueOnPathologicalDepth` RED; M-E `getPhase()` override removed →
  `relayAcceptorStopsBeforeTheAppLifecycle` RED; M-F `ALLOCATOR` childOption removed → same options
  biter RED; M-G bind de-synced (`.syncUninterruptibly()` dropped) → `bindFailureFailsStartupFailFast`
  RED (no throw on the occupied port; the async bind also broke the full-boot socket connect — the
  port was not yet bound when `run()` returned). Each reverted → masters diff-verified zero residue →
  full `./gradlew clean build` GREEN (182 proxy tests, 0 failures; only the 3 pre-existing RpcSlice
  warnings).

- **T10 jSMPP portability facts (bytecode-verified, `javap` on the cached 3.0.2 jar).** (1) **`SMPPServerSessionListener.getPort()`
  returns the CONFIGURED port, not the live bound one** — `new SMPPServerSessionListener(0)` binds an ephemeral
  port yet keeps reporting 0, so the fixture's first draft pointed the relay's egress at port 0 → refused connect →
  the AD-33 egress-establishment-fail collapse (the client read a SYNTHESIZED `ESME_RBINDFAIL 0x0000000D`
  `bind_resp` — which is ALSO the relay's own AD-33 code, initially misread as a jSMPP rejection; a jar-wide scan
  found ZERO jSMPP references to `STAT_ESME_RBINDFAIL`). Fix: `RelayTestFixtures.freePort()` probe-first (the
  documented TOCTOU-accepted practice). (2) **The initiation `SO_TIMEOUT=5000` (set by `accept()`) is overwritten
  INSIDE the `SMPPServerSession` constructor** — `BoundSessionStateListener.onStateChange` fires at the
  CLOSED→OPEN transition and re-applies `setSoTimeout(enquireLinkTimer)`; with the fixture's 60s timer a bound
  session's read idles for a minute, and a read timeout only triggers an `enquire_link` (no close). The "5s
  initiation-timer kills the session" theory is refuted (also empirically: repro E6 held a bind 6s past the
  window — late ROK, healthy submit).
- **T10 — the oracle bit the test TWICE (the AC6(b) independence, working as designed).** (1) **The hand-authored
  `submit_sm` was malformed:** the §4.4.1 body needs `schedule_delivery_time` + `validity_period` (empty C-octets)
  and `replace_if_present_flag` — the first draft omitted all three AND double-counted `sm_length` in the length
  formula (52 bytes where 54 belong). jSMPP's strict `DefaultDecomposer.submitSm` walked its field cursor into
  `short_message` territory: it read `sm_length` at offset 40 = ASCII `'B'` (0x42=66) of `"SUBMIT-FROM-A"`, then
  `System.arraycopy(41, 66)` → **`last source index 107 out of bounds for byte[52]`** (41+66=107 — the JVM message
  matches the arithmetic exactly). The uncaught AIOOBE killed jSMPP's `PDUProcessServerTask` BEFORE any
  `submit_sm_resp` — no response, no close — so the client's 4s read timed out. `MockSmsc` could NEVER catch this:
  it splices submits opaquely (T9's REL-1 "submits" were also wire-shape-agnostic). (2) **The `DELIVER_SM` literal
  was wrong:** the test pinned `0x00000105` (a NON-EXISTENT id); the spec's actual `deliver_sm = 0x00000005`
  (§5.1.2.1, verified against the repo PDF — `deliver_sm_resp = 0x80000005`). jSMPP's CONSTRUCTED DLR arrived with
  `0x00000005` and the assertion found 0 matches. T9 never caught this either — its "deliver_sm" frames are opaque
  tag-carriers where any non-bind id works. **Note for the record:** `RelayA1SmokeTest` still carries the
  `0x00000105` literal as an opaque tag id — harmless in its scope (never parsed, no contract asserted on the id),
  left untouched (T9 is closed); the corrected literals + the §4.4.1 field walk live in `JsmppA1OracleTest` with
  javadoc naming both traps.
- **T10 — the owner FIXME ("concurrent bindB closes bindA's socket before bind_resp") — investigated and RESOLVED
  as non-reproducing on HEAD.** A 3-agent adversarial workflow (jSMPP-internals bytecode analysis + relay
  close-path enumeration + a 6-experiment standalone repro matrix through the REAL relay) converged, all
  high-confidence: (a) jSMPP 3.0.2 has NO sub-10s self-close path for an idle OPEN session (see the portability
  facts above); (b) the relay has NO cross-pair close path — every pre-`bind_resp` egress close is keyed to THIS
  pair's ingress (registry `ChannelId` keys, per-channel handlers, per-pair `EgressLeg`) — and NO timer at all
  (`adjudicationDeadline` is only stamped into `RequestContext`, never read back); (c) the repro matrix: real
  relay + real fixture, 3/3 concurrent AND sequential binds ROK in ~90ms; the only HEAD mechanism with the
  observed wire shape is the **AD-32 pre-couple bare-close when a non-bind PDU hits an ingress leg pre-flip**
  (repro E5c: bind+submit coalesced pre-flip → bare EOF, SMSC-side socket dead ~7ms in — the relay's DESIGNED
  response, not a defect). Reconciliation of the original observation: it matches the pre-port-fix state (egress →
  port 0 → refused connect → AD-33 deny + close, jSMPP never seeing a socket) or an E5c-shaped interleaving from
  the debugging session. The FIXME is removed; 9 consecutive green runs + the workflow's matrix back the
  non-reproduction.
- **T10 RED-on-neuter — N1 PROVEN (unique `/tmp/t10-backups` master, restored byte-exact, marker-grep = 0, full
  `clean build` GREEN after the restore).** `RelayHandler.splice()`'s write redirected to `self` instead of the
  peer → `JsmppA1OracleTest` RED at the A-leg DLR read (`SocketTimeoutException` — A's submit echoes back toward
  the SMSC, the DLR never reaches client A; the bind stage correctly stayed GREEN: binds do not traverse
  `splice`). Full `./gradlew clean build` GREEN — **296 tests, 0 failures, 0 skipped** (proxy 214 = 213 + 1;
  codec 82 unchanged).

- **T11 design — the consolidated pass ran as TWO complementary sweeps on integrated HEAD d0ea8ac (35 mutations
  total).** (a) SIX first-hand inline mutations in the main tree (the load-bearing AC3/AC8 guards): T8-N1 flipper,
  T8-N2 AD-32 bare-close seam, T8-N3 flip re-check conjunct, T8-N4 exactly-once CAS, T8-N5 non-ROK teardown, T5a
  `validate()` guard — each with the house discipline (unique `/tmp/t11-backups` master → neuter → RED → restore →
  `git diff` empty → GREEN re-run). (b) TWENTY-NINE worktree-isolated agents (workflow `wf_529b1174-f33`, batches of
  6, 29 agents / 0 errors): every remaining guard from T1–T10 re-proved on the FINAL integrated code — T7's N1–N6
  had last run against the pre-T8 `BindInterceptor`; T5's against the pre-T5b shape; the T6-review M-A…M-H2 set had
  been execution-verified per-task but never re-run together on the integrated tree. Each agent: fresh git worktree →
  apply the specified neuter → run the biter class → capture RED evidence (failing methods + key lines) →
  `git checkout --` revert (`git status --short` empty) → GREEN re-run → structured report. All 29 reported
  RED + GREEN-confirmed, 0 problems; all worktrees auto-cleaned (`git worktree list` = main tree only); the main
  tree stayed byte-identical to HEAD throughout (verified after every inline restore and again at the end).
- **T11 honest deltas vs the per-task records (fresh counts on integrated HEAD).** (1) **T7-N1** (deny synthesis
  neutered to bare `close()`) now kills SIX deny-dependent tests, not the T7-era five — the verifier-EXCEPTION
  fail-closed test is also deny-synthesis-dependent and correctly joins the biter set. (2) **T1b** (Test-JVM
  `--enable-preview` removed) REDs via the preview-marked CLASS-LOAD failure ("Preview features are not enabled …
  class file version 69.65535") aborting the test executor during discovery — `EnablePreviewArgTest
  .jvmLaunchedWithEnablePreview` never records its own assertion failure because `compileTestJava` still flags the
  whole test compilation preview-marked; this is exactly the second kill mechanism the gate's javadoc documents, and
  the post-revert GREEN re-run executes BOTH gate tests (1/1 each, XML-verified). (3) **T5a-context** kills FOUR
  tests (the mode-b/forward/null-cell refusals + the warn-banner test, which needs the gate's exception to banner).
  (4) **T2's** mutation drops `SHUTDOWN_DRAIN` (zero main references — verified by grep), NOT the T2-era `OTHER`
  (referenced 5× by `RelayHandler`): deleting a referenced constant would break compilation instead of biting the
  shape test. (5) **T6-M-C / T6-M-F / T6-M-H1** share the options-substrate biter — each option's absence REDs the
  same `ingressChildOptions…` pin, which asserts ALL the substrate options at once.
- **T11 jqwik/@Disabled static checks (subtask 3).** Zero `@Disabled`/removed tests (grep across codec+proxy
  sources; the XML-aggregated suite count 296 == T10's). Ten `@Property` methods across the 3 codec property
  classes (`SmppCodecOpaquePropertyTest` 3, `SmppCodecForwardingPropertyTest` 3, `SmppFrameDecoderPropertyTest` 4) —
  ZERO method-level Jupiter annotations (class-level `@Tag`/`@DisplayName` only, the allowed pattern; the gotcha is
  javadoc'd in-file, and `SmppFrameDecoderPropertyTest` carries the explicit "omitted here for that reason" note);
  zero `@Property` in proxy.

### Completion Notes List

- **T1 DONE — AI-8 `--enable-preview` bootstrap gate via compiler enforcement (owner-approved alternative
  to the subtask-1 source-scan).** NEW `PreviewFeatureCompileGateTest` opens a JEP 505
  `StructuredTaskScope` and forks/joins a trivial task. It IS the gate: (a) **COMPILE wiring** — the class
  compiles iff `compileTestJava` carries `--enable-preview` (drop it → `compileTestJava` fails on the
  preview API); (b) **TEST wiring** — the compiled class is preview-marked, so the test JVM loads it iff
  launched with `--enable-preview`. `EnablePreviewArgTest` is kept UNCHANGED (its live
  `jvmLaunchedWithEnablePreview()` remains the explicit TEST-JVM proof). Full `:proxy:test` GREEN, no
  regressions. (Subtask 1 literally specified a `Files.walk`/regex source-scan; the owner chose this
  compiler-enforced mechanism instead — recorded here for transparency.)
- **T1 RED-on-neuter — PROVEN (AC9 standing gate AI-1):** COMPILE neuter → `:proxy:compileTestJava` RED
  (gate test is a named biter); TEST neuter → `jvmLaunchedWithEnablePreview` RED (clean, line 26). Both
  restored → GREEN.
- **T1 AC9 deviation — RUN (`bootRun`) wiring INTENTIONALLY UNGATED (owner-approved, FLAGGED for review).**
  No `build`/`test` task starts the app, so `bootRun`'s `--enable-preview` is only exercised when an
  operator runs it; the compiler-enforced gate cannot reach it, and the source-scan that used to cover it
  was removed per the owner decision. AC9 names "COMPILE **and RUN**" — the RUN half is deliberately
  dropped. **Revisit if:** an operator hits a `bootRun` preview-API failure, OR a regression shows bootRun
  needs guarding — at which point re-add a minimal `JavaExec`-block source-scan or a `bootRun` smoke. (The
  reviewer may wish to lift this to `deferred-work.md` / the AD-12 accepted-risk register.)
- **T1 STS-preview-dependence (maintenance note).** The gate bites iff `StructuredTaskScope` stays a
  PREVIEW feature. It is JEP 505 (5th preview) on the pinned JDK 25; if a future JDK graduates STS to a
  stable API, `PreviewFeatureCompileGateTest` stops requiring `--enable-preview` and the gate goes silently
  inert — reintroduce a static wiring scan (or pivot to another preview feature the codebase uses) then.
  (A source-scan does not have this dependence; that is the trade-off the owner accepted.)
- **T1 Q1 (JDK 25 vendor pin) — FLAGGED, not implemented (per subtask).**
  `smpp.java-conventions.gradle.kts` header documents the deliberate NO-vendor-pin decision (relaxed
  2026-07-25 from an Eclipse-Temurin-only pin + foojay auto-provisioning); the JDK is an environment
  precondition (DEPLOY-014 / SEC-085). No `.github/workflows` exists yet, so there is no CI setup step to
  amend. **Action for when CI lands:** pin a JDK 25 setup-step IMAGE (e.g. `actions/setup-java` with an
  explicit vendor/distribution) — the build itself must NOT auto-provision or vendor-pin (kept relaxed by
  design). Q1 stays open until the CI lane is authored.
- **T1 STS-confinement (AD-5) — noted as discipline for T6–T8, not a T1 test.** The preview wiring guards
  the control plane (`security/`+`bootstrap/`, where `StructuredTaskScope`/`ScopedValue` live). The relay
  data-plane splice (T6–T8) MUST use NO preview API — pure stable Netty/JDK. Enforced by code review at
  T6–T8; not gated by a T1 test (out of T1 scope).
- **T2 DONE — AD-27 `observability/` contract seed authored.** Four main types in
  `proxy/observability/`: (a) `SpliceObserver` interface — EXACTLY the 4 pinned triggers
  (`onFramedPdu(Direction)`, `onBindAccept(SystemId)`, `onBindReject(SystemId, Verdict)`,
  `onConnectionClosed(Direction, CloseReason)`); no PDU type, no
  content (AD-19/AD-27); `onBindReject` imports `proxy.security.Verdict` as specified. (b) `Direction`
  enum — closed 2-value set `{INGRESS, EGRESS}`. (c) `CloseReason` enum — the 16-value exhaustive set
  verbatim (AC5 / gate-fix `.memlog.md:96`), javadoc-documenting exhaustiveness over the spine's close
  paths; the 2 TLS values are present now for set-stability across the Epic-3 boundary (fired only once
  TLS lands). (d) `NoopSpliceObserver` — `@Component final` default bean, every method a no-op (mirrors
  `AlwaysAllowBindCredentialVerifier`). `observability/package-info.java` confirmed `@NullMarked` (AD-35).
- **T2 tests (11, 0 skipped/failed):** `SpliceObserverShapeTest` (9) — reflection shape pin mirroring
  `VerdictShapeTest`/`SecurityPortShapeTest`: exact 4-method count + per-method signature (param/return
  types by class), Direction `{INGRESS,EGRESS}`, CloseReason `hasSize(16)` + `containsExactlyInAnyOrder`
  of all 16 names, package `@NullMarked`, `NoopSpliceObserver` `@Component`+final+implements-seam.
  `ObservabilityLayerRulesTest` (1 ArchUnit `@ArchTest`) — the 4 seeded main contract types must not
  depend on `io.netty..` (AD-19/AD-27 seam purity; scoped by FQN, not package — see Debug Log).
  `CapturingSpliceObserverTest` (1) — smoke-proofs the thread-safe capturing fake records all 4 triggers
  + `clear()`.
- **T2 capturing-fake for T7/T9 (`CapturingSpliceObserver`):** thread-safe (lock-free
  `ConcurrentLinkedQueue` per trigger) because the relay's flip/teardown paths
  race (AD-25); snapshot accessors return immutable `List.copyOf` so assertions are stable once the relay
  test has observed quiescence (the relay test owns the await/latch, not the fake). Record subtypes
  `BindReject`/`ConnectionClose` carry the multi-arg captures.
- **T2 RED-on-neuter — PROVEN (spot-check; formal consolidated pass is T11):** dropped the `OTHER`
  `CloseReason` value → `SpliceObserverShapeTest.closeReasonIsClosedSixteenValueSet()` FAILED at the
  `hasSize(16)` assertion (line 115) → restored → GREEN. The shape test bites by construction (exact
  counts + named values + compile-coupled class refs); the per-method signature tests add
  `NoSuchMethodException`-on-rename/drop as a second bite. The full `:proxy:test` suite stays GREEN (no
  regressions).
- **T2 "ArchUnit/shape test" subtask — reflection chosen as primary (consistency note).** The subtask
  says "ArchUnit/shape test"; the codebase's established idiom for pinning a CONTRACT SHAPE is pure
  reflection + AssertJ (`VerdictShapeTest`, `SecurityPortShapeTest` — the closest analogs). That is the
  primary guard here; ArchUnit is added for the cross-cutting Netty-free layer rule (its idiomatic use in
  this repo is dependency rules, per `JmhIsolationArchitectureTest`). Both mechanisms land.
- **T2 forward note for T8 (exactly-once `onConnectionClosed` enforcement).** AC5 pins
  `onConnectionClosed` exactly-once-per-channel, CAS-guarded at the `channelInactive` site — that is the
  RELAY's responsibility (T8), not the seam's. The seam provides the trigger; `CapturingSpliceObserver`
  records duplicates so T8 can assert "exactly one `ConnectionClose` per channel". No T2 action beyond
  seeding the capability.
- **T3 DONE — CODEC-024 P2 / AI-5 password hygiene: codec `SmppBindRequest.toString()` redaction + no-String-from-
  password static gate.** (a) **Codec override** — `SmppBindRequest` (a record) now declares `toString()`: renders
  `password=***`, omits the secret-bearing `originalFrame` (its bytes embed the cleartext password — a `ByteBuf`
  summary carries no content, but the secret is kept off the debug/log surface regardless); renders the non-secret
  identifying/bind fields (`commandId`/`sequenceNumber`/`systemId`/`systemType`/`interfaceVersion`/`addrTon`/`addrNpi`/
  `addressRange`); never calls `AsciiString.toString()` on the password. Mirrors `Password.toString()` /
  `BindCredential.toString()` (both already redacted). Closes the deferred-work finding (1-2 T3 code review,
  `deferred-work.md:64–72`) that the record's auto-toString would render + cache the password. (b) **RELAY logging
  rule (subtask 3, dev note)** — recorded ON the override's javadoc: relay/logging code logs `SystemId` ONLY; NEVER
  logs `SmppBindRequest`/`Password`/`BindCredential` objects nor the raw `password()` `AsciiString` (the override
  redacts, but a raw `AsciiString` handed to a logger bypasses it and caches the cleartext). This is the human-
  discipline backstop for the implicit-String-materialization case the scan does not chase (see Debug Log). Forward
  guidance for T7/T8 (relay logging). (c) **Source-scan gate** — new `NoStringFromPasswordTest` (proxy/security test;
  mirrors `Relay026ConstantContractTest`'s comment-stripped source-scan): forbids an explicit `.toString()` on a
  password-typed expression across codec + proxy/security + proxy/relay — Rule 1 (`.password()` chain) + Rule 2
  (`Password`-var `.value()` chain) + a positive override-existence check on `SmppBindRequest`. Honest scope: explicit
  `.toString()` only; implicit concat/`valueOf` left to the discipline rule (Debug Log). (d) **Golden-string test** —
  new `SmppBindRequestTest` (codec bind test): `isEqualTo` the exact redacted golden + per-char `doesNotContain` over a
  `{5,6,7,8}`-digit password (collision-free vs the redacted form's `{0,1,2,3,4,9}` digits).
- **T3 RED-on-neuter — PROVEN on all four guards (AC9 standing gate AI-1).** Drop the codec override → golden test
  RED (`isEqualTo`, line 48) AND scan override-existence RED; inject `r.password().toString()` (codec probe) → scan
  Rule 1 RED; inject `Password-var.value().toString()` (proxy/security probe) → scan Rule 2 RED. Each reverted →
  full `:codec:test :proxy:test` GREEN (no regressions). See Debug Log for the full mutation trace + the two design
  gotchas (digit collision; `--tests Class:method` filter).
- **T3 regression — full `:codec:test :proxy:test` GREEN.** The `SmppBindRequest` override is the only production
  change; NullAway (`compileJava`) clean on it; no codec/proxy test depended on the record's auto-toString
  (`SmppBindEncoderTest` uses recursive-comparison ignoring `originalFrame`, not toString). ArchUnit RELAY-025/026
  unaffected (no relay code touched).
- **T3 forward notes for T7/T8.** (1) The RELAY logging rule (log `SystemId` only) is enforced by CODE REVIEW at the
  relay handlers, NOT by a T3 test (the scan catches explicit `.toString()`; the implicit concat/logger case is
  discipline — see the override javadoc). (2) The scan covers `proxy/relay` already (today just `package-info.java`);
  once relay code lands in T6–T8 it is automatically in scope. (3) Caller-owned zeroize (`cred.password().zeroize()`
  in `finally`) is T7's job, not T3 — T3 only ensures the password is never STRING-materialized.
- **T4 DONE — AC1 `ConnectionRegistry` (AD-8) authored.** Two main types in `proxy/relay/`:
  (a) `ConnectionEntry` — the ephemeral per-bind state holding EXACTLY the four AD-8 fields: the peer-egress
  `Channel` (`@Nullable volatile`, absent until the egress connect succeeds — optimistic creation per
  RELAY-006), the AD-25 splice flip-flag (`AtomicBoolean` CAS-once via `flipSpliced()`), ephemeral session
  metadata (`SystemId` + the ingress `ChannelId` that keys the registry), and the tearing-down mark
  (`AtomicBoolean` CAS-once via `beginTearingDown()`). NO `message_id` field/correlation (REL-4 / RELAY-025).
  Relay-internal; never crosses a package boundary. (b) `ConnectionRegistry` — the singleton `@Component`
  `ConcurrentHashMap<ChannelId, ConnectionEntry>`; `register(ingress, systemId)` creates optimistically +
  caches the entry on the ingress attribute; `attachEgress(ingressId, egress)` sets the egress + caches on
  the egress attribute (no-op if the ingress already tore down during the handshake); `entryFor(channel)`
  is the O(1) attribute read from either leg; `beginTeardown(channel)` is the idempotent race-free teardown
  (attribute-read → CAS-once `beginTearingDown` → `remove` + clear both legs' attrs → hand the entry to the
  caller to close/`cancelHttp`/`zeroize`). The teardown SIDE-EFFECTS (close both legs, `cancelHttp`,
  `zeroize`) are intentionally NOT in the registry — the caller (T7/T8 handlers) owns them; the registry owns
  only the state + the idempotent transition (AD-8/AD-32 split).
- **T4 tests (13, 0 skipped/failed):** `ConnectionRegistryTest` (11) — register/AD-8-fields, distinct-keys
  (no ChannelId collision), attachEgress-both-legs, attachEgress-no-op-when-gone, `flipSpliced` CAS-once,
  `beginTearingDown` CAS-once (the deterministic RED-on-neuter biter), RELAY-005 single-threaded idempotent
  double-teardown, RELAY-005 egress-leg teardown, RELAY-005 caller-side double-zeroize-safe (R8 slice),
  RELAY-005 two-leg concurrent race (exactly-one-wins), RELAY-006 no-orphan-on-egress-connect-fail.
  `Relay025StatelessnessScanTest` (2) — RELAY-025 structural statelessness (no `message_id` identifier /
  message_id-keyed Map) + positive ConnectionRegistry-declares-ChannelId-keyed-map rule.
- **T4 RELAY-007 (jcstress) DEFERRED — honest scoping.** The `ConnectionRegistry` concurrent-lifecycle
  stress (RELAY-007, "no-lost-entry / no-orphan / no-double-add under all thread interleavings") is DEFERRED
  to the nightly hardening story per the T4 checklist and the story's Out-of-scope list ("jcstress
  (RELAY-007), race-soak (RELAY-024) → nightly hardening story / Epic-2 exit gates"). The single-shot
  two-leg race test here pins the observable contract ONCE; it is NOT the statistical proof. Open question
  Q2 (jcstress adoption as a build target vs a JUnit-based stress harness) remains — owned by the nightly
  story, not this task. The `ConnectionRegistry` is `ConcurrentHashMap`-backed (the scenario's prescribed
  implementation), so the nightly jcstress harness targets it unchanged.
- **T4 forward notes for T7/T8.** (1) The teardown side-effects the registry RETURNS the entry for are the
  handlers' job: `BindInterceptor` (T7) owns egress-establishment-fail teardown + the AD-33 deny + the
  `finally`-owned `zeroize`; `RelayHandler` (T8) owns the AD-25 flip (`entry.flipSpliced()`), the AD-32
  bare-close teardown, and the exactly-once `onConnectionClosed` (the registry hands the entry once; the
  observer fires once). (2) `attachEgress` is the single egress-attachment seam — T7's egress-connect
  success path calls it (caches the entry on the egress leg so T8's egress-side `entryFor` resolves). (3) The
  `ConnectionEntry` API (`flipSpliced`/`spliced`/`beginTearingDown`/`tearingDown`/`egress`/`ingress`) is the
  complete state surface T7/T8 read; no further registry changes are anticipated for T7/T8 (only NEW handler
  classes consuming it).
- **T4 regression — full `:proxy:test` GREEN + `./gradlew clean build` GREEN (AC9).** NullAway clean on the
  two new `@Component`/`final` main types (the `@Nullable Channel egress` field/getter + the two
  `@Nullable`-returning registry methods are the only nullable surfaces). ArchUnit RELAY-025 (new) +
  RELAY-026 unaffected; no existing test touched.
- **T5 DONE — AC8 shared `PooledByteBufAllocator` (AD-21) + AD-30 live direct-memory self-check (AI-6).**
  Five main types in the new `proxy/relay/netty/` sub-package (its own `@NullMarked package-info` — AD-35;
  the relay data-plane splice stays pure-stable API, AD-5): (a) `DirectMemoryBudgetValidator` — pure
  statics: `validate(long budget, long liveCeiling)` (throws iff `budget > liveCeiling`; budget == ceiling
  permitted — inclusive) + `liveDirectMemoryCeiling()` → `jdk.internal.misc.VM.maxDirectMemory()` (the live
  ceiling, NOT `ByteBufAllocatorMetric`'s usage-only `usedDirectMemory()`). (b) `DirectMemoryBudgetException`
  — the AD-17 fail-fast signal (budget + ceiling in the message + accessors; unchecked — crosses the Spring
  lifecycle boundary). (c) `RelayNettyConfig` (`@Configuration`) — `@Bean PooledByteBufAllocator` →
  `PooledByteBufAllocator.DEFAULT` (the ONE shared pooled allocator; T6 wires every channel to it via
  `ChannelOption.ALLOCATOR`). (d) `DirectMemoryBudgetStartupCheck` (`@Component` `InitializingBean`) — on
  refresh, computes the budget via `MemoryBudget.compute(memory.maxInboundDepth(), .concurrentPairs(),
  .safetyFactor())` and validates it against the live ceiling; **mode-b-scoped** (no-op for other cells —
  the relay mounts mode-b this slice; forward/mode-a/c relays + their checks are Epic 3). The sizing
  references `SmppFrame.MAX_COMMAND_LENGTH` ONLY transitively (via `MemoryBudget`) — no `65536` literal
  anywhere in `relay/netty/` (RELAY-026 stays green).
- **T5 build-convention change — `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED`.** Added to
  `smpp.java-conventions.gradle.kts` (`JavaCompile` + `Test` + `JavaExec`, shared alongside
  `--enable-preview`) so `jdk.internal.misc.VM.maxDirectMemory()` resolves at compile + run. `--add-exports`
  (not `--add-opens`) — direct access to a public static method. Harmless for modules that never reference
  the package. The `ManagementFactory` arg-parsing fallback is NOT wired (the export is clean + the live API
  handles the `-Xmx`-default case the fallback misses).
- **T5 tests (7, 0 skipped/failed):** `DirectMemoryBudgetValidatorTest` (5, unit) — budget>ceiling throws
  (AD-30 message); budget==ceiling boundary passes; budget<ceiling passes; exception accessors;
  `liveDirectMemoryCeiling()` > 0 (smoke-proves the export at run time). `DirectMemoryBudgetStartupCheckTest`
  (2, full `ProxyCompanionApplication` context) — mode-b + minimal budget (65536 B) starts, the AD-21
  allocator bean is `PooledByteBufAllocator.DEFAULT`, the self-check bean ran; mode-b + huge
  `concurrent-pairs=1000000` (budget ≈ 6.3 TiB, a valid long) → context fails, root cause
  `DirectMemoryBudgetException` (null-vs-blank trap: the huge value is BOUND as a command-line arg, not the
  memory key removed). Memory overrides are command-line args (highest precedence); the mode-b branch is
  `.properties()` (lowest precedence, but the only source — application.yml has the branches commented).
- **T5 existing-test accommodation (AC9 — NOT a disable-to-pass).** `TestCompanionConfigs.reverseB()` now
  overrides `companion.memory.*` to a minimal budget (1/1/1.0) so a valid mode-b full-context boot fits
  under the test JVM's (small) direct-memory ceiling — the self-check is a new startup invariant for mode-b
  contexts, so a mode-b test config must satisfy it (same as it satisfies the config validator). The
  self-check still runs for every `reverseB()` boot. No test was `@Disabled`/removed; full
  `:codec:test :proxy:test` GREEN (162 proxy tests).
- **T5 RED-on-neuter — PROVEN (AC9 standing gate AI-1).** Neutered `validate()`'s `budget > liveCeiling`
  guard → the unit biter (`budgetExceedingCeilingThrows`, line 27) AND the context biter
  (`modeBBudgetExceedingLiveCeilingRefusesToStart`, line 65 — the under-budget context STARTED instead of
  throwing) both went RED → reverted → GREEN. The context biter closes the unexpectedly-started context on
  the neutered path (exception-safety).
- **T5 regression — full `./gradlew clean build` GREEN (AC9).** NullAway clean on the 4 new main types
  (the two `@Nullable` `reverse()`/`modeB()` derefs are guarded; no other nullable surfaces). ArchUnit
  RELAY-025/026 unaffected (no `65536` literal, no `message_id` map in `relay/netty/`). The 3 build
  warnings are pre-existing (`RpcSlice.java` `JavaUtilDate`/`ArrayRecordComponent`, unrelated).
- **T5 forward notes for T6.** (1) The shared `PooledByteBufAllocator` bean exists and is
  `PooledByteBufAllocator.DEFAULT` — T6 wires it to BOTH legs via `ChannelOption.ALLOCATOR` on the
  `ServerBootstrap`/`Bootstrap` (`.option`/`.childOption`/`.handler`); do NOT create a per-channel
  allocator (AD-21). (2) The AD-30 self-check runs at refresh for mode-b; T6's relay acceptor lifecycle
  (the 2nd `SmartLifecycle`, explicit `getPhase()`) lands on top of it. (3) The `--add-exports` is in the
  shared convention — no per-module wiring needed. (4) Any NEW mode-b full-context test (T9's in-JVM mock)
  must use a memory budget that fits its test JVM (mirror `reverseB()`'s minimal override, or the self-check
  fail-fasts) — this is correct behavior, not a workaround.
- **T5 `io.netty.allocator.type=pooled` deviation — FLAGGED for review.** The Netty system property is read
  once at static init (unreliable to set in code); the explicit `PooledByteBufAllocator.DEFAULT` bean is the
  authoritative pooling guarantee for relay-wired channels. Setting it as a JVM arg is a deploy concern
  (Epic 5). The reviewer may prefer to ALSO set it best-effort or lift it to the deploy/ops plan.
- **T5b DONE (2026-08-15, operator decision) — self-check made UNCONDITIONAL + `companion.memory.budget-check`
  policy (AD-30 amended in place; see the `.memlog.md` 2026-08-15 entry).** (1) The mode-b guard is GONE:
  `DirectMemoryBudgetStartupCheck.afterPropertiesSet()` now computes + compares on EVERY boot — every
  role×mode cell relays (forward relays ESME→reverse), and the AD-17 constructor guarantees exactly one cell
  per deployment, so per-cell scoping was slice-incremental, not architectural; Epic 3 never needs to widen
  anything (resolves the Review-Defer "Epic-3 widening" item + the deferred-work tracker entry — the forward
  cell is now mechanically bitten by `forwardAWithHugeBudgetRefusesToStart`, proven RED when the guard was
  reintroduced). (2) New key `companion.memory.budget-check: fail | warn` (4th `Memory` component — a POLICY,
  not a budget-formula input): `fail` = default incl. absent/null (fail-closed — `@Nullable` component, null
  behaves as FAIL at the single use site; deliberately NOT `@DefaultValue("FAIL")`, which could change the
  whole-record-null-when-node-absent semantics that the omitted-memory-block refusal test pins); `warn` =
  loud starred `System.err` accepted-risk banner (`OVER_BUDGET_WARNING`, the `CompanionModeBWarning` /
  SEC-052 Mode B pattern; reuses `DirectMemoryBudgetException.describe`, now package-private) + start; NO
  value skips the check itself; an invalid enum token fails the bind (matrix-tested). `validate()` stays the
  single throw site (unit-tested); the warn arm short-circuits only on `budget > ceiling && WARN`.
  (3) Test accommodations (the exact boots the T5 scoping protected — minimal-budget overrides, NOT
  disable-to-pass): minimal budget (1/1/1.0) moved from `reverseB()` into `TestCompanionConfigs.common()`
  (every full-context boot now carries the check), + run-arg overrides added to the two forward-A yml-backed
  full boots (`BootstrapLifecycleTest.MINIMAL_MEMORY`, `CompanionTlsBindingTest` first test). (4) Tests:
  `DirectMemoryBudgetStartupCheckTest` now 4 — happy (starts, allocator==DEFAULT, NO banner under ceiling),
  mode-b default refusal, **forward.mode-a unconditionality refusal**, **warn boots + banner** (CapturedOutput);
  matrix gains the invalid-enum refusal (53 total). 5 direct `Memory(...)` constructions gained the 4th
  `null` arg. (5) Mutations proven RED: M1 warn-arm neutered (`== WARN` → `false`) → warn test RED; M2
  mode-b guard reintroduced → forward-A test RED; restore → full `:proxy:test` GREEN.
- **T6 DONE (substrate; subtask 1's handler entries land T7/T8 by owner decision) — AC4 Netty pipelines +
  `SmartLifecycle` acceptor (AD-1/AD-2/AD-16).** Four new main types in `proxy/relay/netty/`:
  (a) `RelayChannelOptions` — the shared per-channel substrate applied to BOTH legs: AD-21 allocator,
  AD-2 `AUTO_READ=false`, AD-30 `WriteBufferWaterMark` (low = one `SmppFrame.MAX_COMMAND_LENGTH` frame,
  high = `max-inbound-depth` frames, long-clamped at `Integer.MAX_VALUE`; RELAY-026-clean — the constant,
  never a literal). (b) `RelayIngressInitializer` + (c) `RelayEgressInitializer` — the codec prefix
  (`SmppFrameDecoder → SmppCodec`, per-channel instances CODEC-014, no `SslHandler`) with documented
  T7/T8 `addLast` attachment points (owner decision: codec-only, no placeholder handler classes).
  (d) `RelayServerLifecycle` (`SmartLifecycle`, 2nd in the app): mode-b-scoped start (SYNC bind —
  occupied port throws through `start()` → AD-17 fail-fast), `stop(Runnable)` with the callback in
  `finally` (mirror `ProxyCompanionLifecycle`), close-acceptor-then-`shutdownGracefully` (awaited —
  deterministic port release), explicit `RELAY_ACCEPTOR_PHASE = ProxyCompanionLifecycle.APP_PHASE + 1000`
  (acceptor STOPS first, AD-22 step 1 — `ProxyCompanionLifecycle` gained the explicit `APP_PHASE`,
  resolving the deferred-work 2nd-SmartLifecycle item). `RelayNettyConfig` gained the ONE shared
  event-loop bean (`MultiThreadIoEventLoopGroup` + `NioIoHandler.newFactory()` — Netty 4.2's idiom,
  NOT the class-deprecated `NioEventLoopGroup`; named `companion-relay-*` PLATFORM threads, AD-1).
  ZERO new config fields; NO `ProxyCompanionProperties` change. Tests (12, 0 skipped/failed):
  `RelayChannelOptionsTest` (4 — both legs' option maps via real bootstrap configs, clamp, depth-1),
  `RelayPipelineInitializersTest` (3 — order/exactly-the-prefix/no-SslHandler per leg + CODEC-014
  distinct instances), `RelayServerLifecycleTest` (5 — mode-b full-app boot binds+serves TCP+releases on
  stop + AD-1 named-platform-thread pin; forward cell inert + port never taken; occupied-port fail-fast;
  stop callback + idempotence; phase pins). Existing-boot accommodations (NOT disable-to-pass):
  `TestCompanionConfigs.common()` binds a free ephemeral port; the 3 starting mode-b boots in
  `DirectMemoryBudgetStartupCheckTest` pass a shared free-port run-arg. Seven RED-on-neuter mutations
  proven (M-A guard, M-B callback, M-C AUTO_READ, M-D clamp, M-E phase, M-F allocator, M-G sync-bind)
  — see Debug Log. Full `./gradlew clean build` GREEN (182 proxy tests). Forward notes for T7:
  assemble the per-bind egress `Bootstrap` as `.group(ingressChannel.eventLoop())` (HexDumpProxy
  same-thread coupling) with `RelayEgressInitializer` + `RelayChannelOptions.applyToEgress`, then
  `.connect(smsc.host(), smsc.port())`; the initial ingress read is ARMED by the handlers (nothing
  reads under `AUTO_READ=false` until then — by design).

- **T7 DONE — AC2 `BindInterceptor` (bind-family verifier gating + AD-33 collapse + caller-owned
  zeroize; AD-7/AD-12/AD-14/AD-15/AD-25/AD-27/AD-33).** NEW `proxy/relay/BindInterceptor.java` — the
  per-channel ingress handler + nested `EgressLeg` (the egress-side `bind_resp` forwarder, the AD-25
  forwarder split's egress arm; see the Debug Log placement decision) + the package-private
  `EgressConnector` seam (RELAY-006's injected future; closes the T6-review-deferred bootstrap-wiring
  pin). Behavior: first bind → optimistic `registry.register` (RELAY-006) → `BindCredential` +
  `ScopedValue`-bound `RequestContext` → `verify` (never blocks the loop, never spawns a VT — AD-28) →
  continuation hopped to the ingress event loop with the AD-25 race-free re-check; `Allow` → per-bind
  egress `Bootstrap` on the ingress event loop (T6 `RelayEgressInitializer` + `applyToEgress`) →
  AD-14 verbatim `originalFrame` forward (write = the release) + `read()` arming; `Deny*` →
  `onBindReject` (Verdicts only) + the AD-33 header-only deny (`ESME_RBINDFAIL 0x0000000D`, Q2
  ratified vs §5.1.3) + `ChannelFutureListener.CLOSE` (walkthrough §5 "bind_resp error, then close");
  egress-establishment-fail (refused connect OR SMSC death pre-`bind_resp`) collapses to the SAME code
  with NO `onBindReject`; SMSC non-ROK `bind_resp` forwarded VERBATIM (RELAY-002c); verifier
  exception/absent verdict → fail-closed deny, no observer trigger (AD-11/AD-27); RELAY-004 retry-bind
  → generic deny answering the RETRY's sequence + `cancelHttp` + teardown (the in-flight predicate is
  the registry entry, per AD-32); caller-owned `zeroize` at settlement + every teardown arm (see the
  Debug Log timing decision); teardown ordering per AC3 (`beginTeardown` → cancel+wipe → deny+close;
  losing racers no-op). `RelayIngressInitializer` appends the T7 `addLast` entry (T6 subtask 1's
  ingress half CLOSED — its checkbox stays open for T8's two RelayHandler legs). Tests (10, 0
  skipped/failed): `BindInterceptorTest` (RELAY-004, AD-33 deny collapse + bind-type matching +
  egress-fail indistinguishability, AD-14 verbatim + bootstrap wiring pin, RELAY-002c non-ROK verbatim,
  ROK verbatim, egress pre-bind_resp death, ingress-vanish-mid-adjudication + late-verdict no-op,
  verifier-exception fail-closed both arms) + `LatchedBindCredentialVerifier` (latch-held-verdict fake,
  reusable by T8/T9); `RelayPipelineInitializersTest` ingress pin evolved to exactly-3 user handlers
  (+ per-channel interceptor distinctness); `RelayServerLifecycleTest` rewired via the new shared
  `RelayTestFixtures.modeBIngressInitializer` fixture. RED phase genuine (9/9 RED against a compiling
  no-op stub, XML-verified); 5 RED-on-neuter mutations (N1–N5) each RED on exactly their named biters.
  Full `./gradlew clean build` GREEN — 274 tests, 0 failures, 0 skipped (proxy 191; was 182 at T6).
  Honest scope notes: (a) the ingress leg's pre-couple NON-bind policy (AD-32 case-3 bare-close) is
  T8's — at T7 opaque ingress PDUs pass to the tail and are released, no leak, no policy yet;
  (b) post-ROK teardown (non-ROK `bind_resp` / post-flip lifecycle) is T8's — T7 forwards only;
  (c) no relay-side verdict TIMEOUT arm (RELAY-020 deferred) — the `RequestContext` deadline (30s,
  mirroring the 2.1 slice's clamp default) is the verifier's budget; (d) `onConnectionClosed` triggers
  stay T8's (T7 fires only `onBindReject`).

- **T8 DONE — AC3+AC7 `RelayHandler` (AD-25 single-flip + AD-32 bare-close + REL-1 splice +
  SpliceObserver triggers; AD-2/AD-3/AD-25/AD-27/AD-32).** NEW `proxy/relay/RelayHandler.java` — one
  class, one per-channel instance per LEG (Direction-carrying; the flip site is the EGRESS-leg instance,
  which rides the ingress event loop — AD-2 same-loop coupling; see Debug Log). Behavior: channelRead
  re-checks the entry (absent/tearing-down → consume + fail-closed close — the AD-25 race-free
  re-check, both halves test-fabricated deterministically); pre-flip decoded `SmppBindResponse` → ROK
  flips via `entry.flipSpliced()` (the ONLY flip call site in the relay) + `onBindAccept` exactly at
  the flip + arms both legs' post-couple reads, then PROPAGATES to `EgressLeg` (the AD-25 forwarder
  split — RelayHandler never forwards the bind_resp); non-ROK propagates FIRST (verbatim per AD-32
  case 4) then `teardownPair(BIND_FAILED_NON_ROK)`; pre-flip `SmppBindRequest` propagates (the
  interceptor plane owns bind-family); pre-flip opaque on EGRESS → the one case-4 check
  (`getInt(4) == generic_nack` → verbatim forward + `GENERIC_NACK_PRE_BIND` teardown) else violation
  (release + stash + close → `EgressLeg` collapses via AD-33 — RELAY-003); pre-flip opaque on INGRESS
  → release + stash + `BindInterceptor.teardownForPreCoupleViolation` (the new package-private seam
  running AC3's literal ordering: `beginTeardown` → `cancelHttp`+`zeroize` → close both — bare, no
  deny; RELAY-002); post-flip EVERY PDU (incl. `unbind`, incl. a stray bind-family decode via
  `originalFrame()`) splices opaquely to the peer with one `onFramedPdu(direction)` fire, dead-peer
  guard (release + teardown, RELAY-009), write-completes-gates-read listener (re-arm only while the
  peer is writable) + `channelWritabilityChanged` low-water re-arm (the AD-2/AD-30 backpressure
  behavior — embedded channels cannot observe read-arming; T9's real sockets prove it live);
  `channelInactive` tears a SPLICED pair down (either leg — RELAY-008/010) and fires
  `onConnectionClosed` EXACTLY-ONCE per channel (CAS on the channel attribute; violations only ever
  STASH a CloseReason); `exceptionCaught` classifies `DecoderException`→`DECODE_ERROR` (the CODEC-021
  sibling — `isOk()` never reached) / `IOException`→`PEER_RST`, tears a spliced pair, closes.
  `BindInterceptor` gained the `teardownForPreCoupleViolation` seam + a post-flip
  `exceptionCaught` propagation arm (spliced → `fireExceptionCaught` so RelayHandler stashes
  PEER_RST/DECODE_ERROR — pre-flip arms unchanged). `RelayIngressInitializer` appends the ingress
  `RelayHandler` (T6 subtask-1's last slot — checkbox CLOSED); `RelayEgressInitializer` became
  constructor-carrying (shared registry/observer) and appends the egress `RelayHandler`. Tests: NEW
  `RelayHandlerTest` (12 — RELAY-001a/b/e + the re-check both halves, RELAY-002 mid-adjudication +
  post-egress (the Q1 no-deny race), RELAY-003 no-leak, RELAY-002c generic_nack verbatim+teardown,
  CODEC-021 sibling, RELAY-008 half-close propagation + whole-PDU drain, RELAY-009 zero-or-one
  complete frame + raced-frame release, RELAY-010 RST observed, AC5 exactly-once with a PRE-close
  duplicate inactive; multi-chunk feed per the RecordingAllocator-bypass trap; `@Timeout(SEPARATE_THREAD)`).
  `BindInterceptorTest` retrofitted to the real 4-handler ingress pipeline + its non-ROK test evolved
  to the T8 teardown contract (the T7 comment had pinned exactly this deferred arm).
  `RelayPipelineInitializersTest` pins exactly-4/exactly-3 user handlers + per-channel RelayHandler
  distinctness. RED phase genuine (12/12 vs the no-op stub); FIVE RED-on-neuter mutations (N1–N5) each
  RED on exactly their named biters — N4's FIRST biter shape was a false-green (post-close duplicate
  never reaches the torn-down pipeline; probe-verified) and was restructured pre-close — the mutation
  pass caught its own vacuous test. Full `./gradlew clean build` GREEN — **289 tests, 0 failures,
  0 skipped** (proxy 207 = 195+12; codec 82 unchanged). Honest scope notes: (a) read-ARMING is
  unobservable on EmbeddedChannel — T9's real sockets carry the live proof; (b) RST is simulated as
  the pipeline-fired IOException (exactly how a live NIO channel surfaces it) — the real-socket RST
  injection is T9's; (c) the CloseReason values NOT fired this slice (UNKNOWN_COMMAND_ID,
  CLEAN_UNBIND_HANDSHAKE, OVERSIZED/UNDERSIZED_FRAME, TLS, SHUTDOWN_DRAIN) — see the Debug Log
  coverage entry; (d) RELAY-001(c) (a "raw frame whose command_id matches bind_resp but not decoded")
  is unconstructible through the real pipeline — `SmppCodec` decodes bind-family structurally and a
  malformed one becomes a `DecoderException` (the CODEC-021 sibling covers that arm); the flip keys on
  the decoded type, so the peeked-id shortcut is structurally absent.

- **T9 DONE — AC6(a)+AC7 socket-level smoke: in-JVM mock SMSC (RELAY-011's A-1 mechanics + the REL-1
  roundtrip + T8's deferred real-socket teardown arms) + the OBS-035/036/037 ops-plan docs + their
  docs gate.** NEW `MockSmsc` (test fixture): embedded Netty server on the PRODUCTION codec
  (`SmppFrameDecoder → SmppCodec`, per-channel CODEC-014, own single-thread `mock-smsc` group) —
  every `SmppBindRequest` answered a hand-authored ROK `bind_*_resp` (matching response id + the
  request's sequence) behind the injectable delay (`start(long)`, `delayedExecutor`-scheduled) /
  stall (`stallBinds()`/`releaseBinds()` future-gate — never an event-loop block); one accepted
  connection = one `Session` (byte-exact `bindFrame()` + `received()` captures, `deliver`/
  `deliverAll` injection on THAT session's socket = the carrier-affinity emulation). The
  oracle-honesty disclaimer (never an oracle for A-1 or codec correctness — shares the codec's bugs,
  assumes A-1) is the fixture javadoc's opening. NEW `RelayA1SmokeTest` (3 tests, real sockets
  through the REAL acceptor via the new `ModeBRelayHarness`): (1) **RELAY-011** — two concurrent
  `bind_transceiver` under ONE `system_id` (both written before either response is read) both ROK;
  two distinct mock sessions each carrying the byte-exact original bind (own egress pair per
  ingress, AD-14 through two real sockets); tagged `deliver_sm` per egress socket lands on EXACTLY
  its originating legacy socket byte-exact, then both sockets time out clean (zero cross-bleed, no
  duplicates); observer pins 2× `onBindAccept` under one `SystemId` + 2× `onFramedPdu(EGRESS)`.
  (2) **REL-1 roundtrip** — the golden-vector `bind_transceiver_request_all_fields` crosses both
  sockets byte-exact; 4 submit_sm in ONE coalesced write → exactly 4 complete framed captures at
  the mock (no drop/dup/corrupt, order + boundaries preserved); 3 deliver_sm in ONE mock-side
  write → exactly 3 byte-exact frames at the legacy socket; `onFramedPdu` fires 4× INGRESS + 3×
  EGRESS in order. (3) **real-socket teardown** — FIN (`shutdownOutput`) propagates to BOTH legs +
  registry, observed, `PEER_HALF_CLOSE`×2; RST (`SO_LINGER 0`) tears both legs down, observed —
  the T8-deferred live proofs, and with them the live proof of the AD-2 read-demand substrate
  (nothing crosses under `AUTO_READ=false` without the handlers' arming). NEW
  `docs/a-1-carrier-test-plan.md` + `A1CarrierPlanDocsTest` (3 gates — explicit numeric PASS
  criterion [2 concurrent binds, same system_id, ESME_ROK, on the real carrier], explicit FAIL
  criterion + the DLR-affinity procedure [submit on bind A → deliver_sm on bind A's socket, NOT
  bind B's], oracle = real target carrier / conformance SMSC with the in-JVM mock EXPLICITLY
  excluded); normalized (lowercase/backtick-strip/whitespace-collapse) so prose tweaks never
  false-RED; doc existence asserted FIRST and loudly. `RelayTestFixtures` gained the egress-targeted
  `modeBProperties` overload + the `ModeBRelayHarness` record. RED-on-neuter: N1 (splice → wrong
  leg) RED on RELAY-011 + REL-1; N2 (blanked doc) RED on all 3 gates — see Debug Log. Full
  `./gradlew clean build` GREEN — **295 tests, 0 failures, 0 skipped** (proxy 213 = 207 + 6 new;
  codec 82 unchanged). Honest scope: (a) the in-JVM mock trivially affirms A-1 — that is exactly why
  the jSMPP independent oracle (T10) is mandatory next, and the genuine falsification remains the
  non-CI carrier plan just authored; (b) the mock never answers `submit_sm` with a
  `submit_sm_resp` (the splice scenarios need one-way flows; conformance breadth is Story 2.3);
  (c) session→client mapping is content-matched (bind bytes), not accept-order — see Debug Log.

- **T10 DONE — AC6(b) OBS-038: the jSMPP independent A-1 conformance oracle.** `org.jsmpp:jsmpp:3.0.2`
  added to `proxy` testImplementation (the codec module's CODEC-031 coordinate mirrored; test-only, main
  purity gates unaffected). NEW `JsmppSmscServer` (test fixture): the jSMPP 3.0.2 server-side mock —
  `SMPPServerSessionListener` accept loop (daemon), per-session `waitForBind` → `accept(..., IF_34)` ROK
  **regardless of `system_id`** (A-1's premise accepted by the independent stack), `onAcceptSubmitSm`
  capture + AUTO `deliverShortMessage` DLR on the SAME session (carrier-side affinity; emitted from the
  fixture worker, never the PDU-reader thread), quiet 60s/5s timers, an `anomalies()` queue the test
  asserts empty. NEW `JsmppA1OracleTest` (1 test, REAL sockets through the REAL acceptor via the T9
  `ModeBRelayHarness`): two CONCURRENT binds under ONE `system_id` both ROK (the oracle PARSED the relay's
  AD-14-forwards — independence from the production codec); submit on A → `submit_sm_resp` (ROK, sequence
  integrity through the relay) + the jSMPP-CONSTRUCTED DLR on A's channel ONLY, symmetric leg for B, zero
  cross-bleed each way, well-behaved `deliver_sm_resp` answers riding the splice back; observer pins
  (2× `onBindAccept` one `SystemId`, 8 `onFramedPdu` — 4/4 INGRESS/EGRESS counts, 0 rejects), registry 2
  throughout, `anomalies()` empty. The oracle bit the test twice mid-development (malformed §4.4.1
  submit_sm → jSMPP decomposer AIOOBE; wrong `deliver_sm` literal `0x00000105` vs the spec's `0x00000005`)
  — both are precisely the independent-stack bites AC6(b) exists for and are javadoc'd at the corrected
  builders; `MockSmsc`'s opaque path can never catch either. The optional jSMPP alternate-ESME-client
  reuse subtask was NOT exercised (explicitly not-required-for-AC6). RED-on-neuter N1 (splice→self) RED
  at the DLR read, restored byte-exact. Owner FIXME (concurrent-binds bind-stage close) investigated via
  a 3-agent adversarial workflow + 6-experiment repro matrix — NOT reproducible on HEAD (relay/jSMPP both
  exonerated; the only matching HEAD mechanism is the DESIGNED AD-32 pre-couple bare-close, E5c);
  FIXME removed. Full `./gradlew clean build` GREEN — **296 tests, 0 failures, 0 skipped** (proxy 214 =
  213 + 1). **AC6 is now complete in CI on both proofs: RELAY-011 mechanics (T9) + the OBS-038
  independent oracle (T10); the genuine real-carrier falsification remains the non-CI plan
  (`docs/a-1-carrier-test-plan.md`).** (T11 remains open — story stays in-progress.)

- **T11 DONE — AC9 consolidated RED-on-neuter mutation pass + green build (standing gate AI-1). 35 mutations on
  integrated HEAD d0ea8ac, every one RED under neuter on its named biter(s) → reverted → GREEN after restore;
  `./gradlew clean build` GREEN — 296 tests, 0 failures, 0 errors, 0 skipped (proxy 214 + codec 82,
  XML-aggregated, == T10's count — no test added/removed/`@Disabled`); RELAY-025/026 scans green in-suite; jqwik
  `@Property` trap verified clean (class-level Jupiter annotations only). The full ledger (guard → biter(s)):**

  **Inline, first-hand in the main tree (`/tmp/t11-backups` masters; restore diff-verified, GREEN re-run each):**
  1. **T8-N1 single-flipper** (`if (entry.flipSpliced())` → `if (false)`) → `RelayHandlerTest` ×5 — the
     RELAY-001a/e named biter (`flipsOnlyOnDecodedRokBindResp…`) + RELAY-008/009/010 + the AC5 exactly-once test
     (all require a spliced pair).
  2. **T8-N2 AD-32 bare-close seam** (`teardownForPreCoupleViolation` immediate-return) → exactly the 2 RELAY-002
     tests (mid-adjudication + post-egress) — no close, no cancelHttp, no zeroize.
  3. **T8-N3 AD-25 flip re-check conjunct dropped** (`entry == null || entry.tearingDown()` → `entry == null`) →
     exactly the re-check biter (a late `bind_resp` on a cached tearing-down entry wrongly FLIPS).
  4. **T8-N4 exactly-once CAS neutered** (always fire) → exactly `connectionClosedFiresExactlyOncePerChannel`.
  5. **T8-N5 non-ROK teardown dropped** (forward only) → exactly 2 tests (RelayHandlerTest's RELAY-001b/AC3 guard +
     BindInterceptorTest's evolved RELAY-002c).
  6. **T5a AD-30 `validate()` guard** (`if (false)`) → `DirectMemoryBudgetValidatorTest` "budget strictly above the
     ceiling throws DirectMemoryBudgetException".

  **Worktree-isolated sweep (workflow `wf_529b1174-f33`; 29 agents, 0 errors; each neuter → RED → revert → GREEN):**
  7. **T1a** COMPILE preview wiring removed → `:proxy:compileTestJava` BUILD FAILED, 13 preview-API errors across
     `PreviewFeatureCompileGateTest` + `RopcSlice` (compile-gate RED; GREEN = compile succeeds after restore).
  8. **T1b** TEST preview wiring removed → `:proxy:test` FAILED at the preview-marked class-load
     (class file version 69.65535), executor aborted during discovery (see Debug Log delta).
  9. **T2** `SHUTDOWN_DRAIN` dropped → `SpliceObserverShapeTest.closeReasonIsClosedSixteenValueSet` (hasSize 16→15).
  10. **T3a** codec toString override deleted → `SmppBindRequestTest.toStringRedactsPassword` (codec) +
      `NoStringFromPasswordTest.smppBindRequestDeclaresToStringOverride` (proxy) — both modules RED.
  11. **T3b** Rule-1 probe (`req.password().toString()`) → `NoStringFromPasswordTest.noStringFromPassword`.
  12. **T3c** Rule-2 probe (`Password p; p.value().toString()`) → the same scan RED.
  13. **T4** `beginTearingDown()` CAS neutered (always-win) → `ConnectionRegistryTest.beginTearingDownIsCasOnce`.
  14. **T4/RELAY-025** probe (`Map<String, SystemId> messageIdIndex` injected) →
      `Relay025StatelessnessScanTest` RED (both forbid-rules).
  15. **T5a-context** (same validate neuter, context biters) → 4 RED: the mode-b / forward-A / null-cell refusals +
      the warn-banner test (no exception → no banner).
  16. **T5b-M2** mode-b guard reintroduced → `forwardAWithHugeBudgetRefusesToStart` (unconditionality bites).
  17. **T5b-M3a** (`== WARN` → `!= FAIL`) → exactly `nullBudgetCheckBehavesAsFailOnOverCeilingBudget`.
  18. **T5b-M3b** (`== WARN` → `== FAIL`) → 3 RED (the warn-banner boots test + both FAIL-path refusals).
  19. **T6-M-A** forward-cell guard deleted → `forwardCellLeavesAcceptorUnstarted`.
  20. **T6-M-B** stop callback removed → `stopInvokesCallbackAndReleasesPort`.
  21. **T6-M-C** AUTO_READ childOption removed → `ingressChildOptionsCarryTheSubstrate`.
  22. **T6-M-D** watermark clamp removed (`(int) high`) → `watermarkHighClampsAtIntegerMaxValueOnPathologicalDepth`.
  23. **T6-M-E** phase → `Integer.MAX_VALUE` → `relayAcceptorStopsBeforeTheAppLifecycle`.
  24. **T6-M-F** ALLOCATOR childOption removed → the options-substrate pin.
  25. **T6-M-G** sync-bind dropped → `bindFailureFailsStartupFailFast`.
  26. **T6-M-H1** SO_REUSEADDR removed → the ingress SO_REUSEADDR pin.
  27. **T6-M-H2** stop() body emptied → the full-boot `isRunning` pin + the direct stop test.
  28. **T7-N1** deny synthesis → bare `close()` → SIX deny-dependent tests (the T7-era five + the
      verifier-exception fail-closed test — Debug Log delta).
  29. **T7-N2** continuation `finally`-zeroize removed → the ALLOW-path zeroize biter
      (`allowForwardsTheOriginalFrameVerbatimToTheConfiguredEgress`).
  30. **T7-N3** `applyToEgress` dropped → the egress-bootstrap wiring pin.
  31. **T7-N4** `.handler(egressInitializer)` dropped → the same wiring pin.
  32. **T7-N5** verdict re-check removed (`if (false)`) → both late-verdict no-op tests
      (`ingressVanishingMidAdjudication…` + `retriedBindWhileAdjudicationInFlight…`).
  33. **T7-N6** adjudication-deadline positivity guard → `if (false)` → the 3 matrix refusal cells
      (`0s`/`-5s`/`PT0S`).
  34. **T9/T10 splice coupling** (`peer.writeAndFlush` → `self`) → `RelayA1SmokeTest` (RELAY-011
      `SocketTimeoutException` + REL-1) AND `JsmppA1OracleTest` (OBS-038 DLR read timeout) — both RED, bind stages
      correctly GREEN.
  35. **T9 docs plan blanked** → all 3 `A1CarrierPlanDocsTest` gates RED (the existence assert first).

  Zero residue: `grep T11-MUTATION` = 0 across codec/proxy/buildSrc/docs; all agent worktrees auto-cleaned; the
  main tree byte-identical to HEAD before the final `clean build` (`git diff` empty). **With T11 closed, ALL
  tasks are complete — story status → review.**

### File List

- `proxy/src/test/java/smpp/companion/proxy/bootstrap/PreviewFeatureCompileGateTest.java` — **added**: the
  compiler-enforced `--enable-preview` gate (uses JEP 505 `StructuredTaskScope` → compile-fail w/o COMPILE
  flag, load-fail w/o TEST flag); covers the COMPILE and TEST wirings.
- `proxy/src/test/java/smpp/companion/proxy/bootstrap/EnablePreviewArgTest.java` — **unchanged** (restored
  to its committed HEAD form: the T1 source-scan was added then removed per the owner-approved compile-gate
  redesign; the original live `jvmLaunchedWithEnablePreview()` TEST-JVM assertion stays).
- *(mutation-pass only, ZERO net change — not listed as modified):*
  `buildSrc/src/main/kotlin/smpp.java-conventions.gradle.kts` — temporarily neutered (COMPILE block, then
  TEST block) during the RED-on-neuter pass, then fully restored to its committed state.
- `proxy/src/main/java/smpp/companion/proxy/observability/SpliceObserver.java` — **added** (T2): the AD-27
  observability seam; exactly the 4 pinned triggers (no PDU type, no content); `onBindReject` imports
  `proxy.security.Verdict`.
- `proxy/src/main/java/smpp/companion/proxy/observability/Direction.java` — **added** (T2): closed 2-value
  enum `{INGRESS, EGRESS}`.
- `proxy/src/main/java/smpp/companion/proxy/observability/CloseReason.java` — **added** (T2): the closed
  16-value exhaustive set over the spine's close paths (AC5 / gate-fix `.memlog.md:96`).
- `proxy/src/main/java/smpp/companion/proxy/observability/NoopSpliceObserver.java` — **added** (T2): the
  `@Component final` seeded default bean (mirrors `AlwaysAllowBindCredentialVerifier`); Epic 4 swaps the
  impl only.
- `proxy/src/test/java/smpp/companion/proxy/observability/SpliceObserverShapeTest.java` — **added** (T2):
  reflection shape pin (9 tests) — 4-method count + per-method signatures + Direction(2) + CloseReason(16)
  + package `@NullMarked` + `NoopSpliceObserver` `@Component`/final/seam.
- `proxy/src/test/java/smpp/companion/proxy/observability/ObservabilityLayerRulesTest.java` — **added**
  (T2): ArchUnit `@ArchTest` — the 4 seeded main contract types must not depend on `io.netty..`
  (AD-19/AD-27 seam purity).
- `proxy/src/test/java/smpp/companion/proxy/observability/CapturingSpliceObserver.java` — **added** (T2):
  thread-safe capturing fake for T7/T9 relay tests (lock-free queues; `List.copyOf`
  snapshots; `BindReject`/`ConnectionClose` record subtypes).
- `proxy/src/test/java/smpp/companion/proxy/observability/CapturingSpliceObserverTest.java` — **added**
  (T2): smoke-proofs the fake records all 4 triggers + `clear()` (1 test).
- `codec/src/main/java/smpp/companion/codec/bind/SmppBindRequest.java` — **modified** (T3): adds the
  `toString()` override (renders `password=***`, omits the secret-bearing `originalFrame`) — closes the CODEC-024 P2
  record-auto-toString leak (`deferred-work.md:64–72`); the existing class javadoc's "callers must avoid toString()
  on the password" sentence updated to note it is now statically enforced + redacted by the override. Carries the
  RELAY-logging-rule dev note (subtask 3).
- `codec/src/test/java/smpp/companion/codec/bind/SmppBindRequestTest.java` — **added** (T3): golden-string test for
  the override — `isEqualTo` the exact redacted form + per-char `doesNotContain` over a `{5,6,7,8}`-digit password
  (RED-on-neuter: drop the override → auto-toString leaks the digits).
- `proxy/src/test/java/smpp/companion/proxy/security/NoStringFromPasswordTest.java` — **added** (T3): the
  CODEC-024 P2 / AI-5 static gate — source-scan (mirrors `Relay026ConstantContractTest`) forbidding `.toString()` on
  a `.password()` chain (Rule 1) or a `Password`-var `.value()` chain (Rule 2) across codec + proxy/security +
  proxy/relay, plus a positive override-existence check on `SmppBindRequest` (2 tests).
- *(mutation-pass only, ZERO net change — not listed as modified):* `codec/.../SmppBindRequest.java` (override
  dropped + restored) and throwaway probes `_T3MutationProbeChain.java` (codec) / `_T3MutationProbeVar.java`
  (proxy/security) — created + deleted during the T3 RED-on-neuter pass.
- `proxy/src/main/java/smpp/companion/proxy/relay/ConnectionEntry.java` — **added** (T4): the ephemeral
  per-bind state — the four AD-8 fields (peer-egress `@Nullable Channel`, `AtomicBoolean` splice flip-flag,
  `SystemId`+ingress `ChannelId` session metadata, `AtomicBoolean` tearing-down mark); CAS-once
  `flipSpliced()` / `beginTearingDown()`. No `message_id` correlation (REL-4 / RELAY-025).
- `proxy/src/main/java/smpp/companion/proxy/relay/ConnectionRegistry.java` — **added** (T4): the singleton
  `@Component` `ConcurrentHashMap<ChannelId, ConnectionEntry>` — `register` / `attachEgress` / `entryFor` /
  `beginTeardown` (idempotent race-free); `AttributeKey` cache on both legs for O(1) event-loop access.
- `proxy/src/test/java/smpp/companion/proxy/relay/ConnectionRegistryTest.java` — **added** (T4): RELAY-005
  (idempotent double-teardown, egress-leg teardown, double-zeroize-safe, CAS-once, two-leg concurrent race)
  + RELAY-006 (no-orphan-on-egress-connect-fail) + AD-8 field/attribute assertions (11 tests).
- `proxy/src/test/java/smpp/companion/proxy/relay/Relay025StatelessnessScanTest.java` — **added** (T4): the
  REL-4 / RELAY-025 structural statelessness source-scan — forbids `message_id`/`messageId` identifiers +
  String/Long/Integer-keyed Maps in `relay/`; positive rule asserts the registry's `ChannelId`-keyed map (2 tests).
- *(mutation-pass only, ZERO net change — not listed as modified):* `proxy/.../relay/ConnectionEntry.java` —
  `beginTearingDown()` CAS neutered (then restored) for the idempotent-teardown RED-on-neuter; a throwaway
  `Map<String, SystemId> messageIdIndex` probe injected (then removed) for the RELAY-025 RED-on-neuter.
- `buildSrc/src/main/kotlin/smpp.java-conventions.gradle.kts` — **unchanged vs HEAD** *(corrected
  2026-08-15, review round 2 — the T5-era entry below falsely claimed a "modified" state; the
  `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED` was added in T5 and then REMOVED by Review
  Decision A, which switched the ceiling read to `ManagementFactory`/`Runtime.maxMemory()`; the file
  carries only `--enable-preview`. Kept for the record:)* T5 briefly added
  `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED` to `JavaCompile` + `Test` + `JavaExec`.
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/package-info.java` — **added** (T5): the
  `relay/netty/` sub-package `@NullMarked` (AD-35 — nullness does not propagate to sub-packages); home for
  the Netty bootstrap beans (allocator + self-check now; acceptor + pipelines in T6).
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/DirectMemoryBudgetValidator.java` — **added** (T5,
  **modified** T5b review round 2): pure statics `validate(long budget, long liveCeiling)` (throws iff
  budget > liveCeiling) + `liveDirectMemoryCeiling()` *(corrected 2026-08-15: reads the LAST explicit
  `-XX:MaxDirectMemorySize` via `ManagementFactory` input args — HotSpot duplicate-flag last-wins — else
  `Runtime.maxMemory()`; NOT `jdk.internal.misc.VM.maxDirectMemory()`, which Review Decision A removed
  with its `--add-exports`. NOT `ByteBufAllocatorMetric` usage.)*. Round 2 also added: `parseSize` accepts
  HotSpot's `t`/`T` suffix (a valid `-XX:MaxDirectMemorySize=1t` previously died as a raw
  `NumberFormatException`) and wraps unparseable tokens in an error naming the flag; the last-wins scan
  is the pure `lastMaxDirectMemorySizeToken(List)`. Unit-testable logic isolated from the JVM surface.
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/DirectMemoryBudgetException.java` — **added** (T5):
  the AD-17 fail-fast `RuntimeException` (budget + ceiling in the message + accessors).
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayNettyConfig.java` — **added** (T5):
  `@Configuration` with `@Bean PooledByteBufAllocator` → `PooledByteBufAllocator.DEFAULT` (AD-21 one shared
  pooled allocator; T6 wires every channel to it).
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/DirectMemoryBudgetStartupCheck.java` — **added**
  (T5): `@Component` `InitializingBean` — computes the budget via `MemoryBudget.compute(...)` from
  `companion.memory.*` and validates against the live ceiling at refresh; **mode-b-scoped** (no-op for
  other cells this slice; widen for forward/mode-a/c in Epic 3).
- `proxy/src/test/java/smpp/companion/proxy/relay/netty/DirectMemoryBudgetValidatorTest.java` — **added**
  (T5): pure unit tests *(5 at T5; 8 after the Decision A rework + T5b round 2 — suffix decode incl. `t`,
  error-message content, last-wins flag scan)* — budget>ceiling throws; budget==ceiling boundary;
  budget<ceiling; exception accessors; `liveDirectMemoryCeiling()` > 0 (smoke-proves the read).
- `proxy/src/test/java/smpp/companion/proxy/relay/netty/DirectMemoryBudgetStartupCheckTest.java` — **added**
  (T5): full `ProxyCompanionApplication` context tests (2) — mode-b + minimal budget starts (allocator bean
  == `PooledByteBufAllocator.DEFAULT`, self-check ran); mode-b + huge `concurrent-pairs` → context fails
  (root cause `DirectMemoryBudgetException`). Memory overrides via command-line args; mode-b branch via
  `.properties()`. Fail-fast biter is exception-safe (closes the unexpectedly-started context when neutered).
- `proxy/src/test/java/smpp/companion/proxy/config/TestCompanionConfigs.java` — **modified** (T5):
  `reverseB()` overrides `companion.memory.*` to a minimal budget (1/1/1.0) after `common()` so a valid
  mode-b full-context boot fits the test JVM's direct-memory ceiling (the self-check is a new mode-b
  startup invariant). Comment explains why; no test asserts on reverseB() memory.
- *(mutation-pass only, ZERO net change — not listed as modified):*
  `proxy/.../relay/netty/DirectMemoryBudgetValidator.java` — the `budget > liveCeiling` guard neutered to
  `if (false)` (then restored) for the T5 RED-on-neuter pass.
- `proxy/src/main/java/smpp/companion/proxy/config/ProxyCompanionProperties.java` — **modified** (T5b): the
  `Memory` record gains its 4th component `BudgetCheck budgetCheck`
  (`companion.memory.budget-check` — non-null; the FAIL default ships in application.yml; owner FIXME
  resolved 2026-08-15) + the nested `BudgetCheck { FAIL, WARN }` enum (policy, not a formula
  input; see the T5b Dev Notes entry for why `@DefaultValue` was rejected).
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/DirectMemoryBudgetStartupCheck.java` — **modified**
  (T5b): mode-b guard REMOVED (unconditional — every role×mode cell); warn arm emits `OVER_BUDGET_WARNING`
  (starred `System.err` banner) + returns; `validate()` stays the single throw site.
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/DirectMemoryBudgetException.java` — **modified**
  (T5b): remediation text names the `budget-check=warn` opt-in; `describe(...)` package-private (banner reuse).
- `proxy/src/main/resources/application.yml` — **modified** (T5b): `companion.memory.budget-check: fail`
  + policy comment (not a formula input; no skip value).
- `proxy/src/test/java/smpp/companion/proxy/relay/netty/DirectMemoryBudgetStartupCheckTest.java` —
  **modified** (T5b): 2 → 4 tests — + forward-A unconditionality refusal (full `ProxyCompanionApplication`
  boot), + warn boots-with-banner (CapturedOutput); happy test gains the no-banner-under-ceiling negative;
  `@ExtendWith(OutputCaptureExtension.class)`.
- `proxy/src/test/java/smpp/companion/proxy/config/TestCompanionConfigs.java` — **modified** (T5b): minimal
  budget moved `reverseB()` → `common()` (the check is unconditional — every full-context boot needs it).
- `proxy/src/test/java/smpp/companion/proxy/bootstrap/BootstrapLifecycleTest.java` — **modified** (T5b):
  `MINIMAL_MEMORY` run-args on both forward-A boots (yml's realistic ≈ 6 GiB budget trips the check under a
  capped test JVM).
- `proxy/src/test/java/smpp/companion/proxy/config/CompanionTlsBindingTest.java` — **modified** (T5b):
  minimal-memory run-args on the yml-backed forward-A boot (same reason); TLS-from-yml assertion unchanged.
- `proxy/src/test/java/smpp/companion/proxy/config/CompanionConfigMatrixTest.java` — **modified** (T5b):
  + invalid `budget-check` token refusal test (53 tests); 3 direct `Memory(...)` constructions gain `null`.
- `proxy/src/test/java/smpp/companion/proxy/config/CompanionRoleFailFastTest.java` — **modified** (T5b):
  2 direct `Memory(...)` constructions gain `null`.
- *(mutation-pass only, ZERO net change — not listed as modified):*
  `proxy/.../relay/netty/DirectMemoryBudgetStartupCheck.java` — M1 (warn-arm comparison → `false`) + M2
  (mode-b guard reintroduced) neutered then restored for the T5b RED-on-neuter pass.
- `_bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/ARCHITECTURE-SPINE.md`
  — **modified** (T5b): AD-30 rule amended in place (unconditional self-check + `budget-check` policy) +
  dated amendment note.
- `_bmad-output/planning-artifacts/architecture/architecture-smpp-companions-2026-07-19/.memlog.md` —
  **appended** (T5b): the 2026-08-15 amendment entry.
- `_bmad-output/implementation-artifacts/deferred-work.md` — **modified** (T5b): "no mechanical guard forces
  the Epic-3 widening" entry → ✅ RESOLVED.
- *(T5b review round 2, 2026-08-15)* `proxy/.../relay/netty/DirectMemoryBudgetValidator.java` —
  **modified again**: `t`/`T` suffix + flag-naming parse errors + LAST-wins
  `lastMaxDirectMemorySizeToken(List)` scan (see the round-2 Review Findings).
- *(T5b review round 2)* `proxy/.../relay/netty/DirectMemoryBudgetValidatorTest.java` — **modified again**:
  8 tests (suffix incl. `t`, error content, last-wins scan).
- *(T5b review round 2)* `proxy/.../relay/netty/DirectMemoryBudgetStartupCheckTest.java` — **modified
  again**: 6 tests (+ null⇒FAIL direct-construction cell, + warn-under-ceiling no-banner cell; T2/T3
  banner-absence asserts; T2 comment corrected).
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayChannelOptions.java` — **added** (T6): the
  shared per-channel option substrate for BOTH legs — AD-21 allocator, AD-2 `AUTO_READ=false`, AD-30
  `WriteBufferWaterMark` (low = 1 frame, high = `max-inbound-depth` frames, long-clamped); T7's egress
  `Bootstrap` consumes `applyToEgress`.
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayIngressInitializer.java` — **added** (T6):
  ingress codec prefix (`SmppFrameDecoder → SmppCodec`, per-channel CODEC-014) + the documented T7
  (`BindInterceptor`) / T8 (`RelayHandler`) attachment points (owner decision — codec-only prefix).
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayEgressInitializer.java` — **added** (T6):
  the SAME codec prefix for the egress leg + the T8 `RelayHandler` attachment point; no `SslHandler`
  (plaintext slice).
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayServerLifecycle.java` — **added** (T6):
  the 2nd `SmartLifecycle` — mode-b-scoped SYNC bind (AD-17 fail-fast), `stop(Runnable)` callback in
  `finally`, acceptor-close→graceful-shutdown awaited, explicit `RELAY_ACCEPTOR_PHASE` (stops FIRST,
  AD-22 step 1).
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayNettyConfig.java` — **modified** (T6): +
  the ONE shared event-loop bean (`MultiThreadIoEventLoopGroup` + `NioIoHandler.newFactory()` — Netty
  4.2 idiom, NOT the class-deprecated `NioEventLoopGroup`; named `companion-relay-*` platform threads,
  AD-1; `destroyMethod="shutdownGracefully"` as the never-started-cell backstop).
- `proxy/src/main/java/smpp/companion/proxy/bootstrap/ProxyCompanionLifecycle.java` — **modified** (T6):
  + explicit `APP_PHASE = 0` + `getPhase()` (the deferred-work 2nd-SmartLifecycle ordering item —
  `RELAY_ACCEPTOR_PHASE` is deliberately `APP_PHASE + 1000` so the acceptor stops first).
- `proxy/src/test/java/smpp/companion/proxy/relay/netty/RelayChannelOptionsTest.java` — **added** (T6):
  4 unit tests — both legs' option maps read off real bootstrap configs (allocator/AUTO_READ/watermark),
  the int-overflow clamp, the depth-1 minimal-budget legality.
- `proxy/src/test/java/smpp/companion/proxy/relay/netty/RelayPipelineInitializersTest.java` — **added**
  (T6): 3 unit tests — framer→codec order + exactly-the-codec-prefix + no `SslHandler` per leg, and
  CODEC-014 per-channel instance distinctness.
- `proxy/src/test/java/smpp/companion/proxy/relay/netty/RelayServerLifecycleTest.java` — **added** (T6):
  5 tests — mode-b full-app boot (binds, serves TCP, AD-1 named-platform-thread pin, stop releases
  port + group), forward-cell inertness (port never taken), occupied-port fail-fast, stop(Runnable)
  callback + idempotence, phase pins. Ephemeral-port discipline + exception-safe group release.
- `proxy/src/test/java/smpp/companion/proxy/config/TestCompanionConfigs.java` — **modified** (T6):
  `common()` binds a FREE EPHEMERAL port per config instance (was fixed 2775) — valid mode-b full boots
  now bind the port (relay acceptor); deterministic against local listeners/other tests.
- `proxy/src/test/java/smpp/companion/proxy/relay/netty/DirectMemoryBudgetStartupCheckTest.java` —
  **modified** (T6): + shared `BIND_PORT` free-port run-arg on the three boots that reach the lifecycle
  phase (the two refusal boots fail at refresh before any bind).
- *(mutation-pass only, ZERO net change — not listed as modified):*
  `proxy/.../relay/netty/RelayServerLifecycle.java` (mode-b guard, callback, getPhase, sync-bind
  neutered then restored) and `proxy/.../relay/netty/RelayChannelOptions.java` (AUTO_READ / clamp /
  ALLOCATOR neutered then restored) — the seven T6 RED-on-neuter mutations; masters diff-verified.
- `proxy/src/main/java/smpp/companion/proxy/relay/BindInterceptor.java` — **added** (T7): the AC2
  bind-handshake interceptor — per-channel ingress handler (verifier gating via `ScopedValue`-bound
  `RequestContext`, AD-33 `ESME_RBINDFAIL` header-only deny synth, RELAY-004 retry-guard, caller-owned
  zeroize at settlement + teardown) + nested `EgressLeg` (the AD-25 egress-arm `bind_resp` forwarder,
  appended by the per-bind connect assembly) + the package-private `EgressConnector` seam
  (RELAY-006's injected future; production default = `bootstrap.connect(host, port)`).
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayIngressInitializer.java` — **modified**
  (T7): the documented T7 `addLast` attachment point LANDED (`new BindInterceptor(...)` per accepted
  channel after the codec prefix; 6 constructor-injected beans). T6 subtask 1's ingress half is closed;
  the T8 `RelayHandler` slot remains.
- `proxy/src/test/java/smpp/companion/proxy/relay/BindInterceptorTest.java` — **added** (T7): 10 tests —
  RELAY-004 retry-bind, AD-33 deny collapse (literal `0x0000000D` pin), bind-type resp matching,
  egress-establishment-fail collapse, AD-14 verbatim forward + the egress-bootstrap wiring pin,
  RELAY-002c non-ROK verbatim, ROK verbatim, egress pre-`bind_resp` death, ingress-vanish +
  late-verdict no-op, verifier-exception fail-closed (both arms).
- `proxy/src/test/java/smpp/companion/proxy/relay/LatchedBindCredentialVerifier.java` — **added** (T7):
  the latch-held-verdict fake (captures credentials for the zeroize asserts + `cancelHttp` calls);
  reusable by T8/T9.
- `proxy/src/test/java/smpp/companion/proxy/relay/netty/RelayPipelineInitializersTest.java` —
  **modified** (T7): the ingress pin evolved to exactly-3 user handlers
  (`framer → codec → BindInterceptor`, order pinned) + per-channel interceptor distinctness in the
  CODEC-014 test; the egress pin stays exactly-2 (T8's slot).
- `proxy/src/test/java/smpp/companion/proxy/relay/netty/RelayServerLifecycleTest.java` — **modified**
  (T7): the three `new RelayIngressInitializer()` sites rewired through the shared fixture (the
  initializer became constructor-carrying).
- `proxy/src/test/java/smpp/companion/proxy/testsupport/RelayTestFixtures.java` — **modified** (T7): +
  `modeBIngressInitializer(bindPort)` — the shared real-wiring factory (same consolidation rationale as
  the T6 review's fixture finding).
- *(mutation-pass only, ZERO net change — not listed as modified):*
  `proxy/.../relay/BindInterceptor.java` — the five T7 mutations (N1 deny synthesis, N2 finally-zeroize,
  N3 `applyToEgress`, N4 egress initializer handler, N5 the AD-25 re-check) neutered then restored from
  `/tmp/t7-backups`; the restored file diff-verified byte-exact before the final `clean build`. The
  owner-FIXME round added N6 (the `Bind` positivity guard, in
  `proxy/.../config/ProxyCompanionProperties.java` — reverted byte-exact) and the N7 `assert false`
  probe (assertions-enabled proof, reverted exactly).
- *(T7 owner-FIXME round, 2026-08-16)* `proxy/src/main/java/smpp/companion/proxy/config/ProxyCompanionProperties.java`
  — **modified again**: the `Bind` record gains its 2nd component `Duration adjudicationDeadline`
  (`companion.bind.adjudication-deadline`; `@NotNull` + compact-ctor positivity guard, AD-17) +
  `java.time.Duration`/`java.util.Objects` imports.
- *(T7 owner-FIXME round)* `proxy/src/main/resources/application.yml` — **modified again**:
  `companion.bind.adjudication-deadline: 4s` + the budget/ownership comment.
- *(T7 owner-FIXME round)* `proxy/src/main/java/smpp/companion/proxy/relay/BindInterceptor.java` —
  **modified again**: the deadline read from `properties.bind().adjudicationDeadline()` (30s constant
  deleted), the spliced-passthrough comment rewritten, the adjudicate-entry `assert`, the sync-throw
  catch simplified, `EgressLeg` → `@RequiredArgsConstructor`, the non-blocking-proof comment at the
  `verify()` call, and the fail-closed arm made to read `error` explicitly (ErrorProne
  `UnusedVariable`).
- *(T7 owner-FIXME round)* `proxy/src/test/java/smpp/companion/proxy/config/TestCompanionConfigs.java`
  — **modified again**: `common()` sets `companion.bind.adjudication-deadline=4s` (the
  `ApplicationContextRunner` boots load no yml — the round's load-bearing trap).
- *(T7 owner-FIXME round)* `proxy/src/test/java/smpp/companion/proxy/config/CompanionConfigMatrixTest.java`
  — **modified again**: + `nonPositiveAdjudicationDeadlineRefuses` (0s/-5s/PT0S; N6's biter) + the 3
  direct `Bind` constructions gained the duration.
- *(T7 owner-FIXME round)* `proxy/src/test/java/smpp/companion/proxy/config/CompanionTlsBindingTest.java`
  — **modified again**: the yml-default pin (`adjudicationDeadline == 4s` from application.yml in the
  boot that sets no `companion.bind.*` property).
- *(T7 owner-FIXME round)* `proxy/src/test/java/smpp/companion/proxy/config/CompanionRoleFailFastTest.java` /
  `proxy/src/test/java/smpp/companion/proxy/relay/netty/DirectMemoryBudgetStartupCheckTest.java` /
  `proxy/src/test/java/smpp/companion/proxy/testsupport/RelayTestFixtures.java` — **modified again**:
  direct `Bind` constructions gained the duration (`RelayTestFixtures` exports
  `DEFAULT_ADJUDICATION_DEADLINE`).
- *(T7 owner-FIXME round)* `proxy/src/test/java/smpp/companion/proxy/relay/BindInterceptorTest.java` —
  **modified again**: class-level `@Timeout(10, SEPARATE_THREAD)` + the deadline-flow assert;
  `LatchedBindCredentialVerifier` captures the ScopedValue-bound deadlines.
- `proxy/src/main/java/smpp/companion/proxy/relay/RelayHandler.java` — **added** (T8): the AC3+AC7
  data-plane handler — AD-25 single flipper (the egress-leg instance, riding the ingress event loop),
  AD-32 pre-couple bare-close (ingress via the interceptor seam, egress via close+EgressLeg collapse,
  generic_nack case-4 verbatim), post-flip opaque splice + write-completes-gates-read + low-water
  re-arm, `channelInactive` pair teardown + exactly-once `onConnectionClosed` (CAS),
  `exceptionCaught` classification (DECODE_ERROR/PEER_RST/OTHER).
- `proxy/src/main/java/smpp/companion/proxy/relay/BindInterceptor.java` — **modified** (T8): +
  package-private `teardownForPreCoupleViolation(Channel)` (the AD-32 case-3 ingress seam running the
  pinned AC3 ordering: beginTeardown → cancelHttp+zeroize → close both, NO deny) + the post-flip
  `exceptionCaught` propagation arm (spliced → `fireExceptionCaught` so RelayHandler stashes the
  reason and owns the pair teardown); pre-flip arms byte-identical to T7.
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayIngressInitializer.java` — **modified**
  (T8): the T8 `addLast` entry LANDED (`new RelayHandler(registry, observer, Direction.INGRESS)` after
  `BindInterceptor`) — T6 subtask 1's ingress slot closed; the full AC4 pipeline is wired.
- `proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayEgressInitializer.java` — **modified**
  (T8): constructor-carrying (`@RequiredArgsConstructor` on the shared `ConnectionRegistry` +
  `SpliceObserver` — Spring wires the same singletons into both initializers) + the T8 `addLast` entry
  (`Direction.EGRESS` after the codec prefix).
- `proxy/src/test/java/smpp/companion/proxy/relay/RelayHandlerTest.java` — **added** (T8): 12 tests —
  RELAY-001a/b/e + flip-re-check (both halves), RELAY-002 (mid-adjudication + post-egress), RELAY-003,
  RELAY-002c (generic_nack), CODEC-021 sibling, RELAY-008, RELAY-009, RELAY-010, AC5 exactly-once
  (PRE-close duplicate delivery); multi-chunk feed; hand-authored PDU builders incl. opaque non-bind
  PDUs + a local `FakeEgressConnector`.
- `proxy/src/test/java/smpp/companion/proxy/relay/BindInterceptorTest.java` — **modified** (T8): the
  ingress pipelines (@BeforeEach + the throwing-verifier sub-channel) retrofitted to the REAL
  4-handler production shape (RelayHandler added); the non-ROK verbatim test evolved to the T8
  teardown contract (registry 0, both legs closed, `BIND_FAILED_NON_ROK` close events — the T7 comment
  had pinned this exact deferred arm); `RelayEgressInitializer` construction now shares the
  registry/observer.
- `proxy/src/test/java/smpp/companion/proxy/relay/netty/RelayPipelineInitializersTest.java` —
  **modified** (T8): ingress pin evolved to exactly-4 user handlers
  (`framer → codec → BindInterceptor → RelayHandler`, order pinned), egress to exactly-3
  (`framer → codec → RelayHandler`), + per-channel `RelayHandler` distinctness on both legs; the
  egress initializer factory shares a registry/observer pair.
- `proxy/src/test/java/smpp/companion/proxy/testsupport/RelayTestFixtures.java` — **modified** (T8):
  `modeBIngressInitializer` now builds ONE shared `ConnectionRegistry` + observer instance and hands
  the same pair to the ingress initializer and the (now constructor-carrying)
  `RelayEgressInitializer` — mirroring Spring's singleton wiring, required for the egress-leg flipper
  to resolve the pair the ingress interceptor registered.
- *(mutation-pass only, ZERO net change — not listed as modified):*
  `proxy/.../relay/RelayHandler.java` (N1 flipper, N3 re-check conjunct, N4 exactly-once CAS, N5
  non-ROK teardown) and `proxy/.../relay/BindInterceptor.java` (N2 bare-close seam) — neutered then
  restored from unique `/tmp/t8-backups` masters; restored files `grep MUTATION`-verified clean and
  the final `clean build` ran AFTER the restores. A throwaway `ProbeN4Test` (the closed-pipeline
  diagnosis) was created and deleted within the round.
- `proxy/src/test/java/smpp/companion/proxy/relay/MockSmsc.java` — **added** (T9): the in-JVM mock
  SMSC on the PRODUCTION codec — per-connection `Session` (byte-exact bind/PDU captures +
  per-socket `deliver`/`deliverAll` injection), ROK bind answering behind the injectable
  delay/stall gate; javadoc opens with the NEVER-an-oracle disclaimer (AD-24/RELAY-011).
- `proxy/src/test/java/smpp/companion/proxy/relay/RelayA1SmokeTest.java` — **added** (T9): the
  real-socket A-1 smoke — RELAY-011 (concurrent same-`system_id` binds, zero DLR cross-bleed),
  the REL-1 golden-vector roundtrip (no drop/dup/corrupt, boundaries preserved), and the
  real-socket FIN/RST teardown arms T8 deferred; plain blocking loopback clients + hand-authored
  PDU builders.
- `proxy/src/test/java/smpp/companion/proxy/relay/A1CarrierPlanDocsTest.java` — **added** (T9): the
  OBS-035/036/037 docs-falsifiability gate (3 tests — PASS criterion shape, FAIL + DLR-affinity
  shape, oracle naming + in-JVM-mock exclusion).
- `docs/a-1-carrier-test-plan.md` — **added** (T9): the A-1 real-carrier test plan — oracle
  (real carrier / conformance SMSC, mock explicitly excluded), preconditions, explicit PASS/FAIL
  criteria, the DLR-affinity assertion procedure, evidence + escalation on FAIL.
- `proxy/src/test/java/smpp/companion/proxy/testsupport/RelayTestFixtures.java` — **modified**
  (T9): + the egress-targeted `modeBProperties(bindPort, depth, smscHost, smscPort)` overload
  (2-arg form delegates unchanged) + the `ModeBRelayHarness` record +
  `modeBRelayHarness(properties)` (the real constructor graph with a capturing observer + the
  registry handle for the socket smoke tests).
- *(mutation-pass only, ZERO net change — not listed as modified):*
  `proxy/.../relay/RelayHandler.java` (N1: the splice forwarded to the wrong leg) and
  `docs/a-1-carrier-test-plan.md` (N2: blanked) — neutered then restored from unique
  `/tmp/t9-backups` masters; restored files diff-verified byte-exact, `grep T9-MUTATION` = 0, and
  the full `clean build` ran AFTER the restores.

- `proxy/build.gradle.kts` — **modified** (T4 + T10): + `id("io.freefair.lombok") version "9.5.0"` (T4 — the
  relay main types' `@RequiredArgsConstructor`/`@Slf4j`, mirroring `codec/build.gradle.kts:9`; documented
  retroactively 2026-08-17, review F4) + `testImplementation("org.jsmpp:jsmpp:3.0.2")` — the
  OBS-038 independent A-1 oracle, test-only (the mirror of `codec/build.gradle.kts:38`, CODEC-031's
  interop-oracle coordinate); off the main compile/runtime classpaths, so OBS-013 runtime purity /
  SEC-099 floors are unaffected. (2026-08-17, review F17: the `test` task also gained
  `inputs.file("../docs/a-1-carrier-test-plan.md")` so the docs-reading A1CarrierPlanDocsTest cannot be
  UP-TO-DATE-skipped on a docs-only incremental build.)
- `proxy/src/test/java/smpp/companion/proxy/relay/JsmppSmscServer.java` — **added** (T10): the jSMPP
  3.0.2 server-side mock SMSC — the INDEPENDENT oracle (parses everything the relay splices onto the
  egress sockets, constructs everything the legacy clients read back); accept loop + per-session
  ROK-any-`system_id` bind answering, submit capture + tagged-DLR auto-emission on the SAME session
  (carrier-side affinity), quiet timers, `anomalies()` bookkeeping; javadoc carries the honest-scope
  caveat (CI approximation of A-1, not the real-carrier falsification) + the jSMPP portability facts.
- `proxy/src/test/java/smpp/companion/proxy/relay/JsmppA1OracleTest.java` — **added** (T10): the
  OBS-038 load-bearing test — two concurrent binds under one `system_id` through the REAL relay to the
  oracle, both ROK; submit→resp+DLR on the owning bind ONLY (both legs exercised, zero cross-bleed);
  hand-authored §4.4.1-complete bind/submit builders + the corrected `deliver_sm`/`deliver_sm_resp`
  command-id literals (0x00000005/0x80000005, §5.1.2.1) with javadoc naming the two oracle-bite traps;
  observer + registry + `anomalies()` pins.
- *(mutation-pass only, ZERO net change — not listed as modified):*
  `proxy/.../relay/RelayHandler.java` — `splice()`'s write redirected to `self` (T10-MUTATION N1: the
  coupling neuter) then restored byte-exact from the unique `/tmp/t10-backups` master; marker-grep
  clean and the full `clean build` ran AFTER the restore.

- *(T11 mutation pass — ZERO net change; NO file added/modified/deleted):* the 6 inline main-tree mutations
  (`RelayHandler.java` ×4 sites, `BindInterceptor.java` ×1, `DirectMemoryBudgetValidator.java` ×1) were applied
  against unique `/tmp/t11-backups` masters and restored byte-exact (`git diff` empty; `grep T11-MUTATION` = 0);
  the 29 sweep mutations ran in throwaway git worktrees (workflow `wf_529b1174-f33`, all auto-cleaned). T11's
  only artifact is this story file (Tasks/Dev Agent Record/Change Log/Status).

## Change Log

- 2026-08-11 — **Story 2.2 Task 1:** AI-8 `--enable-preview` bootstrap gate. Initially implemented as a
  static source-scan of `smpp.java-conventions.gradle.kts` (COMPILE+TEST+RUN); **REVISED per owner decision**
  to a compiler-enforced gate — NEW `PreviewFeatureCompileGateTest` (JEP 505 `StructuredTaskScope`) covers
  COMPILE+TEST; `EnablePreviewArgTest` restored to its original live-method form. **RUN/bootRun coverage
  intentionally dropped (AC9 deviation, flagged for review).** RED-on-neuter proven for COMPILE+TEST; Q1
  (JDK vendor pin) flagged; STS-confinement (AD-5) noted for T6–T8. (T2–T11 remain open — story stays
  in-progress.)
- 2026-08-11 — **Story 2.2 Task 2:** AD-27 `observability/` contract seed — `SpliceObserver` (4 pinned
  triggers, no PDU type/content), `Direction{INGRESS,EGRESS}`, `CloseReason` (16-value exhaustive set),
  `NoopSpliceObserver` (`@Component final` default bean). Tests: reflection shape pin
  (`SpliceObserverShapeTest`, 9) + ArchUnit Netty-free seam rule (`ObservabilityLayerRulesTest`, 1,
  scoped by FQN to the 4 main contract types — see Debug Log) + capturing-fake smoke
  (`CapturingSpliceObserverTest`, 1); thread-safe `CapturingSpliceObserver` seeded for T7/T9. RED-on-neuter
  spot-check PROVEN (drop `OTHER` → shape test RED at `hasSize(16)` → restore → GREEN); full `:proxy:test`
  GREEN, no regressions. (T3–T11 remain open — story stays in-progress.)
- 2026-08-11 — **Story 2.2 Task 2 REVISION (owner decision):** `SpliceObserver` drops
  `onByteTransfer(Direction, long)` — 5→4 method seam. PDU count now comes from counting
  `onFramedPdu(Direction)` fires; the seam carries no byte-volume signal. Rationale: the byte-count slot was
  redundant with `onFramedPdu` for PDU counting; owner prefers observing PDU count over bytes. Propagated to
  ALL binding artifacts (owner-authorized scope): `ARCHITECTURE-SPINE.md` AD-27:224, `epics.md`:225/388,
  `test-coverage-scenarios.md` OBS-010 (observer-level assertion rewrote to `onFramedPdu`-only;
  sentinel-scrape-absence stays load-bearing), `implementation-readiness-report` finding #2 annotated
  SUPERSEDED, architecture `.memlog.md` amendment appended. Code: `SpliceObserverShapeTest` `hasSize(5)`→`4`
  (10→9 tests; RED-on-neuter preserved), `CapturingSpliceObserver` trimmed (`ByteTransfer`/`totalBytes`
  dropped; 2→1 test). `:proxy:test` GREEN, no regressions. See Debug Log for the full audit/propagation
  trace. (T3–T11 remain open — story stays in-progress.)
- 2026-08-11 — **Story 2.2 Task 3:** CODEC-024 P2 / AI-5 password hygiene. (a) Codec `SmppBindRequest.toString()`
  override — renders `password=***`, omits the secret-bearing `originalFrame`; closes the deferred 1-2 code-review
  finding (record auto-toString leaking the password `AsciiString`). (b) New `NoStringFromPasswordTest` static gate
  (proxy/security test; mirrors `Relay026ConstantContractTest`): forbids `.toString()` on a `.password()` chain
  (Rule 1) or a `Password`-var `.value()` chain (Rule 2) across codec + proxy/security + proxy/relay, + a positive
  override-existence check. Honest scope: explicit `.toString()` only — implicit concat/`valueOf` left to the relay-
  logging discipline rule (subtask 3), recorded on the override javadoc. (c) New `SmppBindRequestTest` golden-string
  test (codec bind). RED-on-neuter PROVEN on all four guards (drop override → golden + scan override-existence RED;
  inject `.password().toString()` → Rule 1 RED; inject `Password-var.value().toString()` → Rule 2 RED); each reverted.
  Full `:codec:test :proxy:test` GREEN, no regressions; NullAway clean on the override. (T4–T11 remain open — story
  stays in-progress.)
- 2026-08-11 — **Story 2.2 Task 4:** AC1 `ConnectionRegistry` (AD-8). NEW `ConnectionEntry` (the four AD-8
  fields: peer-egress `@Nullable Channel`, `AtomicBoolean` splice flip-flag, `SystemId`+ingress `ChannelId`
  session metadata, `AtomicBoolean` tearing-down mark — no `message_id` correlation, REL-4) + NEW
  `ConnectionRegistry` (singleton `@Component` `ConcurrentHashMap<ChannelId, ConnectionEntry>`; `register` /
  `attachEgress` / `entryFor` / `beginTeardown`; `AttributeKey` cache on both legs for O(1)). Two-layer
  idempotency: attribute-clear (single-threaded double-teardown fast path) + CAS-once `beginTearingDown`
  (race-free for the two-leg/AD-25-Deny-callback window). Tests: `ConnectionRegistryTest` (11) covering
  RELAY-005 (idempotent double-teardown, egress-leg teardown, double-zeroize-safe R8 slice, CAS-once,
  two-leg concurrent race — exactly-one-wins) + RELAY-006 (no-orphan-on-egress-connect-fail); NEW
  `Relay025StatelessnessScanTest` (2) — the REL-4 structural statelessness source-scan (no `message_id`
  identifier / String/Long/Integer-keyed Map; positive ChannelId-keyed-map rule). RED-on-neuter PROVEN for
  the idempotent-teardown CAS (neuter → `beginTearingDownIsCasOnce` RED at line 133) AND the RELAY-025 scan
  (inject `Map<String, SystemId> messageIdIndex` → scan RED); each reverted. **RELAY-007 (jcstress) DEFERRED
  to the nightly hardening story** (per T4 checklist + Out-of-scope); the single-shot race test pins the
  observable contract once but is not the statistical proof (Q2 jcstress-adoption open for the nightly story).
  EmbeddedChannel singleton-id trap handled (every test channel uses `DefaultChannelId.newInstance()`).
  Full `:proxy:test` GREEN + `./gradlew clean build` GREEN (AC9); NullAway clean. (T5–T11 remain open —
  story stays in-progress.)
- 2026-08-12 — **Story 2.2 Task 5:** AC8 shared `PooledByteBufAllocator` (AD-21) + AD-30 live direct-memory
  self-check (AI-6). NEW `proxy/relay/netty/` sub-package (`@NullMarked`): `DirectMemoryBudgetValidator`
  (pure statics — `validate(budget, liveCeiling)` throws iff budget > liveCeiling; `liveDirectMemoryCeiling()`
  → `jdk.internal.misc.VM.maxDirectMemory()`, the live ceiling NOT `ByteBufAllocatorMetric`'s usage),
  `DirectMemoryBudgetException` (AD-17 fail-fast), `RelayNettyConfig` (`@Bean PooledByteBufAllocator` →
  `PooledByteBufAllocator.DEFAULT` — the one shared pooled allocator), `DirectMemoryBudgetStartupCheck`
  (`@Component` `InitializingBean`; computes the budget via `MemoryBudget.compute(...)` and validates at
  refresh; **mode-b-scoped** — no-op for other cells this slice). Build-convention change:
  `--add-exports=java.base/jdk.internal.misc=ALL-UNNAMED` added to `smpp.java-conventions.gradle.kts`
  (`JavaCompile`+`Test`+`JavaExec`, shared alongside `--enable-preview`) — `--add-exports` (direct public-API
  access, not `--add-opens`); `ManagementFactory` fallback not wired (the export is clean + the live API
  handles the `-Xmx`-default case). Tests (7): `DirectMemoryBudgetValidatorTest` (5 unit) +
  `DirectMemoryBudgetStartupCheckTest` (2 full-context — minimal-budget happy path + huge-budget fail-fast;
  memory overrides via command-line args since `.properties()` is lowest-precedence and loses to
  application.yml). Existing-test accommodation: `TestCompanionConfigs.reverseB()` uses a minimal memory
  budget so a valid mode-b full-context boot fits the test JVM's 512 MiB ceiling (the self-check is a new
  mode-b startup invariant; NOT a disable-to-pass — no test `@Disabled`/removed). RED-on-neuter PROVEN on
  BOTH the unit and the context biter (neuter `validate()`'s guard → both RED → restore → GREEN). Honest
  deviation FLAGGED: `io.netty.allocator.type=pooled` system property is superseded by the explicit pooled
  bean (the property is read once at Netty static init, unreliable to set in code; JVM-arg is deploy/Epic 5).
  `./gradlew clean build` GREEN (AC9); NullAway clean; RELAY-025/026 unaffected. (T6–T11 remain open —
  story stays in-progress.)

- 2026-08-15 — **Story 2.2 Task 5b (operator decision):** AD-30 self-check made UNCONDITIONAL (mode-b guard
  removed — runs for every role×mode cell; Epic 3 will never need to widen it) + new
  `companion.memory.budget-check: fail | warn` over-ceiling policy (`fail` default incl. absent — prior
  behavior; `warn` = loud accepted-risk banner + start, the Mode B pattern; no skip value). Binding spine
  AD-30 amended in place + `.memlog.md` entry appended; deferred-work "Epic-3 widening" entry resolved.
  Tests: startup-check suite 2 → 4 (forward-A unconditionality refusal; warn boots + banner; no-banner
  negative); invalid-enum matrix refusal; minimal-budget accommodations in `common()` + the two forward-A
  yml-backed boots. Mutations M1 (warn arm) + M2 (reintroduced guard) proven RED; `:proxy:test` GREEN
  after restore.

- 2026-08-15 — **Story 2.2 T5b review round 2 (adversarial workflow, 4 lenses → per-finding refutation):**
  13 raw findings → 9 confirmed (1 HIGH: the absent/null `budget-check`⇒FAIL cell had NO biting test —
  yml's explicit `fail` masked it; the `!= FAIL` mutation survived the whole suite) → all 9 fixed + 1
  parent-verified extra (duplicate-flag last-wins). Validator now accepts HotSpot's `t` suffix (a valid
  `-XX:MaxDirectMemorySize=1t` previously crashed every boot with a raw NFE — reproduced on the real
  jar), names the flag in parse errors, and reads the LAST duplicate flag occurrence. Startup-check
  tests 2→6: + null⇒FAIL direct-construction cell, + (warn, under-ceiling) no-banner cell, + FAIL-path
  banner-absence asserts. Stale T5-era File List/AC8 mechanism claims corrected (buildSrc is UNCHANGED vs
  HEAD — Decision A removed the `--add-exports`). Mutations M3/M4/M5 each RED on exactly their test;
  full `clean build` GREEN (6/6 + 8/8). Refuted-but-real `spring.main.lazy-initialization` bypass
  recorded as a deferred-work app-wide posture item.

## Review Findings

### Review 2026-08-12 — Story 2.2 T5 (AD-30 direct-memory self-check)

Reviewed by: adversarial 3-layer workflow (Blind Hunter + Edge Case Hunter + Acceptance Auditor) + per-finding REFUTE verification, then human triage. Scope: uncommitted changes vs HEAD (11 files, +545/−7). Stack: Netty 4.2.16.Final, Spring Boot 4.1.0 / Spring 7.0.8, JDK 25. Result: **3 decision-needed, 5 patch, 2 defer, 2 dismissed.**

**Resolutions (applied 2026-08-12, all verified):**
- **[Decision A → ManagementFactory fallback]** (user choice). `DirectMemoryBudgetValidator.liveDirectMemoryCeiling()` now reads an explicit `-XX:MaxDirectMemorySize` via `ManagementFactory`, else falls back to `Runtime.maxMemory()` (the `-Xmx` default) — no `jdk.internal.misc`. The `--add-exports` was **removed** from `smpp.java-conventions.gradle.kts`, which **also resolves [Patch B]** (the codec purity surface is gone — no module receives the export). New `parseSize()` helper + unit tests. Verified: `java -jar proxy.jar` with **no flags** boots cleanly on the happy path (`Started ProxyCompanionApplication`) and fails-fast with `DirectMemoryBudgetException` (not `IllegalAccessError`) on the over-budget path; `./gradlew clean build` GREEN.
- **[Decision G → leave as-is]** (spec-conformant; `safety-factor` default 1.5 is the documented headroom knob).
- **[Decision H → skip]** (the `compute`-throws arm is already unit-bitten by `MemoryBudgetTest`; `afterPropertiesSet` propagates both throws identically).
- **[Patches C/D/E/F → applied]**: spine AD-30/AD-21 amended in place + `.memlog.md` entry (C); TiB→TB comment (D); `toMiB()`→`describe()` (E — visible in the verified fail-fast message: "6000000 MiB / 7716 MiB"); `@Bean(destroyMethod="")` on the allocator (F).
- **[Defer I/J]** → appended to `deferred-work.md`.

**Decision-needed (resolve first):**

- [x] [Review][Decision] **[HIGH] Production `java -jar proxy.jar` crashes with `IllegalAccessError` on the AD-30 self-check.** `--add-exports=java.base/jdk.internal.misc=ALL-UNNAMED` is wired only into `JavaCompile`/`Test`/`JavaExec` (`smpp.java-conventions.gradle.kts:29,35,41`); the Spring Boot `bootJar` is a `Jar` task, so the produced jar's manifest carries NO `Add-Exports` (verified — manifest has only `Main-Class`/`Start-Class`). A production mode-b boot (`java -jar proxy.jar`) therefore hits `IllegalAccessError: ... module java.base does not export jdk.internal.misc to unnamed module` at `DirectMemoryBudgetValidator.liveDirectMemoryCeiling()` *before* the budget comparison runs — the self-check fails with the WRONG exception (a `LinkageError`, not `DirectMemoryBudgetException`), defeating AD-30/AD-17 intent. `./gradlew clean build` stays GREEN only because the Test JVM carries the export, so AC9's gate cannot see it. Options: (a) add `Add-Exports: java.base/jdk.internal.misc ALL-UNNAMED` to the bootJar manifest (keep the accurate `VM.maxDirectMemory()`); (b) fall back to `ManagementFactory` arg-parsing (no internal API, but misses the `-Xmx`-default case the author chose `VM.maxDirectMemory()` for); (c) defer to Epic 5 deploy (leaves `java -jar` broken until then). Empirically reproduced by the verify layer (crash, then clean boot with `--add-exports`). [buildSrc/.../smpp.java-conventions.gradle.kts:29-41; proxy/build.gradle.kts; proxy/.../DirectMemoryBudgetValidator.java:36]
- [x] [Review][Decision] **Inclusive-ceiling leaves zero direct-memory headroom when `safety-factor=1.0`.** `validate()` throws only on `budget > liveCeiling` (equality passes — spec-mandated by AD-30 "≥ the computed budget" / AC8 strict "live ceiling < budget"). With `safety-factor=1.0` and depth×pairs tuned to the ceiling, the self-check passes yet leaves no JVM-wide headroom for non-relay direct allocations. Code is spec-conformant; the question is whether AD-30/AC8 should be tightened to enforce minimum headroom (e.g. `@DecimalMin("1.1")` on `safety-factor`, or reserve headroom in the comparison). Policy call for the architect. [proxy/.../DirectMemoryBudgetValidator.java:48-52; proxy/.../ProxyCompanionProperties.java:285]
- [x] [Review][Decision] **No Spring-level test for the `MemoryBudget.compute`-throws arm.** The integration test covers only the `validate()` arm (`budget > ceiling`). Binding `safety-factor=Infinity` (passes `@DecimalMin("1.0")`) or near-`Integer.MAX_VALUE` depth×pairs makes `compute()` throw `IllegalArgumentException` → `BeanCreationException` — a distinct, reachable fail-fast path through the bean, unexercised at the Spring level. (The guard IS unit-bitten by the pre-existing `MemoryBudgetTest`, Story 1.3, and `afterPropertiesSet` propagates both throws identically; AC9 names the `validate()` arm specifically.) Worth an extra context-level biter? [proxy/.../DirectMemoryBudgetStartupCheckTest.java]

**Patch:**

- [x] [Review][Patch] **[MEDIUM] Shared `--add-exports` grants the codec silent access to `jdk.internal.misc`, breaching its purity posture (AD-7).** The export lives in the SHARED convention, so the purity-gated codec inherits it; before this change `import jdk.internal.misc.VM` was a compile error in codec, now it compiles+runs, and no ArchUnit/CODEC-040 rule forbids `jdk.internal.**` reach. Fix: scope the export to the proxy module only (move to `proxy/build.gradle.kts`); optionally add a `ForbiddenApis`/ArchUnit rule forbidding `jdk.internal.**`/`sun.misc.**` outside `DirectMemoryBudgetValidator`. [buildSrc/.../smpp.java-conventions.gradle.kts:29]
- [x] [Review][Patch] **Binding spine AD-30/AD-21 not amended — still says "read/exposed via ByteBufAllocatorMetric".** The impl justifiably reads `VM.maxDirectMemory()` (`ByteBufAllocatorMetric` exposes only `usedDirectMemory()` — usage, not the ceiling), and the story spec was amended, but the BINDING `ARCHITECTURE-SPINE.md` AD-30 (line 239) + AD-21 (line 194) were not. Per the contract-amendment discipline, amend the spine in place + append an `.memlog.md` entry. (Exact text depends on the Decision above — keep `VM.maxDirectMemory()` vs fallback.) [_bmad-output/.../ARCHITECTURE-SPINE.md:194,239]
- [x] [Review][Patch] **Fail-fast test comment has the wrong unit (TiB vs TB).** `65536 × 64 × 1e6 × 1.5 = 6.29e12 bytes = 5.72 TiB = 6.29 TB`; the comment says "≈ 6.3 TiB" (6.3 is the decimal-TB figure). Pure comment, zero runtime effect. [proxy/.../DirectMemoryBudgetStartupCheckTest.java:22,25,61]
- [x] [Review][Patch] **`toMiB()` integer division renders "0 MiB" for sub-mebibyte budgets.** `bytes / (1024L*1024L)` yields 0 below 1 MiB, so a sub-MiB trip's message reads e.g. "65536 bytes / 0 MiB". Only pathological (`-XX:MaxDirectMemorySize=<sub-MiB>`); the precise byte count is always shown too. Format with a decimal, or omit the MiB portion when < 1 MiB. [proxy/.../DirectMemoryBudgetException.java:43-45]
- [x] [Review][Patch] **`@Bean PooledByteBufAllocator` has no explicit `destroyMethod = ""` (defensive).** Returns the JVM-global `PooledByteBufAllocator.DEFAULT`. Verified via `javap`: Netty 4.2.16's allocator exposes NO `close()`/`shutdown()`/`AutoCloseable`, so Spring infers nothing today — **no current bug**. Add `@Bean(destroyMethod = "")` to pin intent against a future Netty bump that could add a lifecycle method (which would corrupt the shared singleton at context close). Optional defense-in-depth. [proxy/.../RelayNettyConfig.java:32-35]

**Defer:**

- [x] [Review][Defer] **`validate()` silently passes negative-equal inputs** (e.g. `validate(-1,-1)`) — latent: the sole caller feeds a non-negative budget from `MemoryBudget.compute` (which guards `product < 0`) and a positive ceiling from `VM.maxDirectMemory()`. A `budget < 0 || liveCeiling <= 0` precondition would convert the silent pass into a fail-fast. Upstream-guarded today. [proxy/.../DirectMemoryBudgetValidator.java:48-52] — deferred, latent/upstream-guarded
- [x] [Review][Defer] **No mechanical guard forces the Epic-3 widening of the mode-b self-check.** The `reverse()==null || modeB()==null` no-op branch is slice-correct, and the widening requirement is on the load-bearing Javadoc/dev-notes, but nothing bites if Epic 3 wires a forward/mode-a/c relay without widening it. Proposed ArchUnit guards were unsound (the allocator `@Bean` is unconditional). Track via a sprint-status `action_item` for Epic 3. [proxy/.../DirectMemoryBudgetStartupCheck.java:34-44] — deferred, forward (Epic 3)
  **[RESOLVED 2026-08-15 (T5b, operator decision — not by deferral): the guard is gone entirely; the check is
  unconditional and the forward cell is mechanically bitten by
  `DirectMemoryBudgetStartupCheckTest.forwardAWithHugeBudgetRefusesToStart` (proven RED when the mode-b guard
  was reintroduced — mutation M2). Deferred-work tracker entry resolved in kind.]**

**Dismissed (2):** weak `liveDirectMemoryCeilingIsPositive()` smoke test (REFUTED — proposed `isEqualTo(Runtime.maxMemory())` fix is self-defeating: on a stock JVM `VM.maxDirectMemory() == Runtime.maxMemory()` by definition); `DirectMemoryBudgetValidator` methods "over-exposed" as public (matches house style `CompanionConfigValidator`, no reachable external consumer in the 2-module repo).

### Review 2026-08-15 — Story 2.2 T5b (adversarial workflow: 4 lenses → per-finding refutation; 13 raw, 9 confirmed, 4 refuted)

**Confirmed and FIXED in this round:**

- [x] **[HIGH] The absent/null `budget-check` ⇒ FAIL cell had no biting test** — every full-app boot loads
  application.yml, which now ships an EXPLICIT `budget-check: fail`, so `budgetCheck()` was never null at
  the guard; the round-1 mode-b refusal test's comment overclaimed ("the default (fail) is what this test
  bites" — it bit yml's explicit value). The verifier's `!= FAIL` mutation survived the entire suite.
  FIX: `nullBudgetCheckBehavesAsFailOnOverCeilingBudget` — direct construction (`Memory(64, 1_000_000,
  1.5, null)`, no Spring) → `afterPropertiesSet()` MUST throw; T2's comment corrected. Mutation M3
  (`== WARN` → `!= FAIL`) now RED on exactly this test.
- [x] **[MEDIUM] The (warn, under-ceiling) matrix cell was untested** — dropping the `budget > ceiling &&`
  conjunct (banner on every warn boot regardless of provisioning) passed the whole suite. FIX:
  `budgetCheckWarnUnderCeilingStartsWithoutBanner` (starts + NO banner). Mutation M4 (conjunct dropped)
  RED on exactly this test.
- [x] **[MEDIUM] `parseSize` rejected HotSpot's valid `t`/`T` suffix** — a healthy
  `-XX:MaxDirectMemorySize=1t` deployment died on every cell with a raw `NumberFormatException` naming
  neither the flag nor AD-30 (verifier reproduced end-to-end on the real boot jar: `512g` boots, `1t`
  crashes). FIX: `t` branch added (1024⁴); unparseable tokens now throw an error naming
  `-XX:MaxDirectMemorySize` and the token; tests pin `1t`/`2T` + the error content.
- [x] **[MEDIUM] Story File List/AC8 still pinned the pre-Decision-A mechanism** — the File List claimed
  buildSrc was "modified" to add `--add-exports` (it is UNCHANGED vs HEAD; Decision A removed the export),
  and living entries still described the ceiling as `VM.maxDirectMemory()`. FIX: buildSrc entry corrected
  to net state; Validator/ValidatorTest entries corrected (ManagementFactory/Runtime.maxMemory; 5→8
  tests); AC8 amendment now notes the Decision A mechanism replacement.
- [x] **[LOW] FAIL-path tests never asserted banner absence** — a hoisted `println` (banner + refusal)
  passed the suite, telling the operator the risk was "opted in" when it was not. FIX: T2/T3 gained
  `CapturedOutput` + `doesNotContain("AD-30 DIRECT-MEMORY BUDGET")`. Mutation M5 (hoisted banner) RED on
  exactly both.
- [x] **[LOW] deferred-work `validate()` entry cited the superseded `VM.maxDirectMemory()` + a stale
  `:48-52` anchor** (stale-on-arrival: shipped in the same diff that removed the mechanism). FIX: entry
  corrected (`liveDirectMemoryCeiling()` via ManagementFactory/Runtime.maxMemory; explicit `=0` can now
  yield a 0 ceiling, which STRENGTHENS the proposed guard; anchor = the `validate(long, long)` method).
- [x] **[LOW] sprint-status `last_updated` (2026-08-12) predated the T5b content (2026-08-15) in the same
  edit set.** FIX: stamped 2026-08-15.

**Refuted (4):** sprint-status stamp (dupe of the above — refuter argued commit-time bookkeeping, fixed
anyway as zero-risk); `spring.main.lazy-initialization=true` bypasses the check (mechanism REAL and
reproduced — Spring defers all eager beans, so both the self-check AND the AD-17 zero-branch refusal
silently pass — but app-wide, pre-existing, and out of T5b's scope; recorded as a deferred-work app-wide
posture item, not a T5b defect); "living sections still instruct Epic-3 widening" (append-only history
convention; the File List carries the T5b supersession 20 lines below and mutation M2 kills any
reintroduced guard); duplicate `-XX:MaxDirectMemorySize` first-vs-last match (the finding was REAL — see
the fix below — but its verifier died on a 429; parent-verified against HotSpot last-wins semantics and
fixed with the finding's own recommendation).

**Fixed additionally (from the unverified-due-to-429 finding, parent-verified):**

- [x] **`liveDirectMemoryCeiling()` took the FIRST `-XX:MaxDirectMemorySize` match; HotSpot applies
  duplicate command-line flags last-wins** — first-match under-reports the ceiling and falsely refuses a
  healthy deployment. FIX: the read now takes the LAST occurrence via the pure
  `lastMaxDirectMemorySizeToken(List)` (unit-tested: `[...,=1g,...,=8g] → 8g`; absent → null →
  `Runtime.maxMemory()` fallback).

**Verification after the round:** mutations M3/M4/M5 each RED on exactly their new test (M1/M2 from
round 1 unchanged); full `./gradlew clean build` GREEN; `DirectMemoryBudgetStartupCheckTest` 6/6,
`DirectMemoryBudgetValidatorTest` 8/8.

**Operational note (honest record):** during the workflow, a verifier's mutation-restore collided with
the parent's `/tmp` backup path and transiently reverted `DirectMemoryBudgetStartupCheck.java` on disk to
the staged T5 version; detected via the workflow's caveat, rewritten to the ratified T5b content, and the
full clean build + mutation passes above ran AFTER that restoration. All round-2 mutations used unique
backup paths.

- 2026-08-15 — **Story 2.2 T5b owner refinement (post-review):** the warn arm restructured per owner
  in-code FIXMEs — `validate()` is now the single comparison AND throw site (the owner: "use validation
  gate instead of condition"): `afterPropertiesSet()` calls the gate in a try/catch, and the policy is
  applied to the gate's VERDICT — `WARN` prints the starred banner carrying the caught exception's own
  message ("log warning using exception message" — one source of truth for budget/ceiling/remediation,
  banner and failure cannot drift) and boots; `FAIL`/null rethrows. Behavior identical (all 6
  startup-check tests + 8 validator tests GREEN unchanged); mutations re-proven in the gate shape
  (`== WARN`→`!= FAIL` → null-cell test RED; swallow→always-rethrow → warn test RED). The
  `describe(...)` package-private widening was reverted (no longer needed — the banner reuses the
  message). `./gradlew clean build` GREEN.

- 2026-08-15 — **Story 2.2 T5b owner FIXMEs addressed (2):** (1) `Memory.budgetCheck` is now NON-null —
  the FAIL default ships in `application.yml` (no `@DefaultValue`, which could construct a half-defaulted
  record when the whole memory node is absent); the check's `== WARN` comparison stays null-safe, so even
  a yml-less bind delivering null fails closed. The 5 "don't-care" direct constructions now pass explicit
  `FAIL`; the deliberately-null defensive pin REMAINS (NullAway is main-only) and still bites the
  `!= FAIL` mutation (re-proven RED). New pin: the full-app happy boot asserts
  `memory().budgetCheck() == FAIL` — the yml default is now load-bearing, so it is pinned end-to-end.
  (2) The warn banner now goes through SLF4J (`log.warn(OVER_BUDGET_WARNING, e.getMessage())` — one `{}`
  placeholder, no pre-formatting) instead of `System.err.println` — the FIRST logger in proxy main;
  `CompanionModeBWarning` still uses the System.err banner (out of this change's scope). Tests unchanged
  in shape: Logback console output is captured by `CapturedOutput` (warn test GREEN proves the path).
  Mutations re-proven in the final shape: `== WARN`→`!= FAIL` → null-cell test RED; `== WARN`→`== FAIL`
  → 3 tests RED (warn loses banner+start; both FAIL-paths banner+swallow instead of refuse). Full
  `./gradlew clean build` GREEN; no FIXMEs remain in main.

- 2026-08-15 — **Story 2.2 T5b owner FIXME (3rd): logger via Lombok** — the manual
  `LoggerFactory.getLogger` field became `@Slf4j` (first `@Slf4j` in the proxy module; the
  `io.freefair.lombok` plugin was already applied). Behavior identical (same generated field, same WARN
  banner through Logback — the warn-banner test stays GREEN). Full `./gradlew clean build` GREEN; no
  FIXMEs remain in main.

- 2026-08-15 — **Story 2.2 Task 6 (substrate):** AC4 Netty pipelines + `SmartLifecycle` acceptor
  (AD-1/AD-2/AD-16). **Owner fork resolved first:** T6's pipeline names `BindInterceptor`/`RelayHandler`
  (T7/T8's classes) — owner chose **codec-only prefix + attachment points** (no placeholder handler
  classes; subtask 1's checkbox closes when the handler `addLast` entries land T7/T8). NEW
  `relay/netty/`: `RelayChannelOptions` (AD-21 allocator + AD-2 `AUTO_READ=false` + AD-30 watermark —
  low = one `SmppFrame.MAX_COMMAND_LENGTH` frame, high = `max-inbound-depth` frames, clamped), the two
  codec-prefix initializers (per-channel CODEC-014, no `SslHandler`), `RelayServerLifecycle`
  (mode-b-scoped SYNC bind / stop-callback-in-`finally` / acceptor-stops-first explicit phase;
  `ProxyCompanionLifecycle` gained `APP_PHASE` — the deferred-work 2nd-SmartLifecycle item resolved),
  + the ONE shared event-loop bean (`MultiThreadIoEventLoopGroup` + `NioIoHandler.newFactory()` —
  Netty 4.2's idiom; `NioEventLoopGroup` is class-deprecated in 4.2.16; named platform threads, AD-1).
  ZERO new config fields. Tests +12 (options 4, initializers 3, lifecycle 5 — full-app boots, AD-1
  platform-thread pin, occupied-port fail-fast, phase pins); accommodations: `common()` free ephemeral
  port + shared `BIND_PORT` run-arg on the 3 starting mode-b boots in the startup-check suite. Seven
  RED-on-neuter mutations proven (guard/callback/AUTO_READ/clamp/phase/allocator/sync-bind). Full
  `./gradlew clean build` GREEN — 182 proxy tests, 0 failures. (T7–T11 remain open — story stays
  in-progress; T6 subtask 1's handler entries land with T7/T8.)

### Review 2026-08-15 — Story 2.2 T6 (adversarial 3-layer workflow + empirical verification; 14 raw, 9 kept, 5 dismissed)

Reviewed by: Blind Hunter + Edge Case Hunter + Acceptance Auditor (parallel, blind), then per-finding code-read
triage with two empirical checks: (a) a jshell probe proved Netty 4.2.16 event loops start threads LAZILY
(`THREADS_BEFORE_ANY_TASK=0` — the "eager selectors / leaked non-daemon threads / phase-test leak" cluster is
refuted: an unused group spins nothing); (b) `./gradlew :proxy:cleanTest :proxy:test` re-ran the full suite —
**182 tests, 0 failures, 0 errors, 0 skipped** (the T6 DONE execution claim VERIFIED by run; the seven
RED-on-neuter mutations remain structurally-verified only — every named biter exists at the right seam; T11's
consolidated pass re-proves them). Auditor verdict: no AC/spec violations; all 16 T6 claims MATCH the code
(including independent javap confirmation of the Netty 4.2 class-deprecation claims). Result: **1
decision-needed, 5 patch, 3 defer, 5 dismissed.**

- [x] [Review][Defer→Epic 3] Wildcard listener posture — `bind(port)` listens on `0.0.0.0` (all interfaces) with no
  bind-host config key (`Bind` record is port-only), no connection cap, no idle timeout; accepted channels are
  inert-but-never-reaped until T7/T8 (`AUTO_READ=false`, no handler) — an unauthenticated, unbounded socket sink
  on every interface for any real mode-b boot. **Owner decision 2026-08-15: defer to Epic 3** — the slice is
  in-JVM/loopback until then; Epic 3 adds bind-host + hardening (incl. the connection-cap question) when it
  wires the production acceptors. [RelayServerLifecycle.java:89; ProxyCompanionProperties.java:220-222]
- [x] [Review][Patch] No `SO_REUSEADDR` on the acceptor — a crash/OOM-kill with established children leaves
  TIME_WAIT sockets; the restart then hits `BindException` → AD-17 fail-fast boot-loops until kernel state
  clears (~60s) for a listener whose job is to come back. Fix: `.option(ChannelOption.SO_REUSEADDR, true)` on
  the `ServerBootstrap` (a SERVER option, not child; fail-fast on an ACTIVE listener is preserved — only
  TIME_WAIT is bypassed). [RelayServerLifecycle.java:84-89]
- [x] [Review][Patch] Watermark javadoc misstates direction — "the high water mark is the per-channel inbound
  queue ceiling" describes the EMERGENT bound (T8's write-completes-gates-read on the peer leg);
  `WriteBufferWaterMark` trips on the channel's OUTBOUND write buffer. A T8 implementer trusting the javadoc
  could double-guard inbound or skip the actual `isWritable()` gate. Fix: reword to outbound-buffer truth +
  emergent inbound bound (javadoc only; no code change). [RelayChannelOptions.java:26-27]
- [x] [Review][Patch] Full-boot stop-discipline asserts are neuterable — with `stop()` emptied, the group bean's
  `destroyMethod="shutdownGracefully"` still closes the server channel at context close, so both post-close
  asserts (`group.isShutdown()`, port-reclaim bind) pass under the neuter (the stop BODY is pinned only by the
  direct-construction `stopInvokesCallbackAndReleasesPort`). Fix: add
  `assertThat(relay.isRunning()).isFalse()` after context close — `running` never flips if `stop()` was skipped
  or emptied → RED. [RelayServerLifecycleTest.java:83-88]
- [x] [Review][Patch] Vacuous asserts — `esme.isConnected()` / `reclaimed.isBound()` / `neverTaken.isBound()`
  can never return false (the `Socket`/`ServerSocket` constructors THROW on failure — the ctor is the real,
  biting guard). Delete the accessor asserts so nothing masquerades as a pin the repo's AC9 bar would reject.
  [RelayServerLifecycleTest.java:69, 100-102, 150-151]
- [x] [Review][Patch] Fixture duplication with drift — `freePort()` ×3 (`TestCompanionConfigs`,
  `DirectMemoryBudgetStartupCheckTest`, `RelayServerLifecycleTest`) + two near-identical 12-line
  `ProxyCompanionProperties` builders that gratuitously differ (`Bind(2775)` hardcoded vs parameterized port).
  The next field added to the record breaks five scattered fixtures. Consolidate (one `freePort` helper; one
  shared mode-b properties builder). [TestCompanionConfigs.java:145; DirectMemoryBudgetStartupCheckTest.java:196-202; RelayServerLifecycleTest.java:225-243, 245-251]
- [x] [Review][Defer] Wiring seam has no RED-on-neuter pin — dropping `.childHandler(ingressInitializer)` or
  `channelOptions.applyToIngress(bootstrap)` from `start()` keeps the whole suite GREEN: the full-boot test's
  TCP-connect probe cannot see an empty pipeline, `AUTO_READ=false` means nothing reads pre-T8, and the
  `ServerBootstrap` is a local variable (no structural pin either). Deferred to T7/T9: T7's `BindInterceptor`
  and the T9 A-1 smoke drive real PDUs through the acceptor and will bite on a dropped wiring line; T7 review
  must confirm. [RelayServerLifecycle.java:87-88]
- [x] [Review][Defer] `stop()` quiesces the shared event loop at acceptor phase — from T7 every egress leg
  registers on the SAME group, so acceptor-stop terminates all established legs before any app-phase drain
  could run; Epic 4's AD-22 7-step drain will re-author this stop body. Spec-mandated today (the T6 checkbox
  pins exactly this stop), and `shutdownGracefully` is graceful (quiet window lets in-flight complete) —
  recorded so T7 review + Epic 4 own it consciously. [RelayServerLifecycle.java:113-115]
- [x] [Review][Defer] `shutdownGracefully()` default 2s quiet period — every mode-b context close blocks ≥2s
  (~+8-10s across the suite's boots; full suite 47s). A documented, deliberate choice (javadoc cites "Netty's
  defaults (2s quiet / 15s cap)"); becomes a mini-drain feature once in-flight PDUs exist. Revisit with the
  Epic-4 drain work (or pass an explicit 0-quiet then). [RelayServerLifecycle.java:115]

Dismissed (5): eager-group/leaked-thread cluster (empirically refuted — lazy thread start, unused group spins
zero threads); ephemeral-port TOCTOU ×3 (accepted, documented test practice; no parallel execution configured);
`stop()` close-failure aborts group quiesce (theoretical — NIO server-channel close ~never fails, callback runs
in `finally`, destroy backstop bounds it); start-after-stop on a dead group (single-shot app; Netty rejects
tasks on a shutdown group → loud fail-fast through `start()`, no hang); `applyToEgress` has no production
caller (by-design T7 substrate, spec-documented — T7 review confirms consumption).

**Patches applied + verified (2026-08-15, post-triage; owner chose "apply all 5" after a walkthrough):**
(a) `SO_REUSEADDR` now set by `applyToIngress` (server-socket option, ingress-only — `applyToEgress` javadoc
pins its deliberate absence), pinned BOTH ways in `RelayChannelOptionsTest` (ingress `isEqualTo(true)` off
`config().options()`; egress `isNull()`); (b) watermark javadoc reworded to the outbound-buffer truth + the
emergent T8 inbound bound (class + method javadoc); (c) full-boot test hoists the `relay` bean ref and asserts
`isRunning()` false after close; (d) all four vacuous accessor asserts removed (ctor-throw documented as the
probe); (e) new `proxy/…/testsupport/RelayTestFixtures` (`freePort()` + `modeBProperties(bindPort, depth)`)
consolidates the three `freePort()` copies and both 12-line properties builders (`RelayChannelOptionsTest`,
`RelayServerLifecycleTest`, `TestCompanionConfigs`, `DirectMemoryBudgetStartupCheckTest` rewired; the
null-budgetCheck direct record in the startup-check suite is purpose-built and stays). RED-on-neuter for the
two NEW pins, per the AC9 AI-1 bar: **M-H1** (dropped `SO_REUSEADDR` line) → `RelayChannelOptionsTest` RED on
exactly the ingress pin; **M-H2** (`stop()` body emptied) → `RelayServerLifecycleTest` RED (the new full-boot
`isRunning` pin + the direct stop test). Both restored byte-exact; final `:proxy:cleanTest :proxy:test` GREEN —
**182 tests, 0 failures, 0 errors, 0 skipped**. Review mutation set grows to M-A…M-G (T6) + M-H1/M-H2 (this
review) — T11's consolidated pass re-runs all.

- 2026-08-15 — **Story 2.2 Task 7:** AC2 `BindInterceptor` — bind-family verifier gating + AD-33
  collapse + caller-owned zeroize (AD-7/AD-12/AD-14/AD-15/AD-25/AD-27/AD-33). NEW
  `proxy/relay/BindInterceptor.java` (per-channel ingress handler + nested `EgressLeg` egress-arm
  `bind_resp` forwarder + `EgressConnector` seam) + the T7 `addLast` entry in `RelayIngressInitializer`
  (T6 subtask 1's ingress half closed). **Q2 RATIFIED: the AD-33 generic bind-failure code is
  `ESME_RBINDFAIL 0x0000000D`** (§5.1.3 "Bind Failed", verified against the repo's own spec PDF; the
  story's illustrative `ESME_RSYSERR` considered and set aside — §5.1.3-literal, definitive-not-
  retry-worthy, identical across both collapse arms; pinned in tests by the LITERAL, independent of the
  production constant). Zeroize timing decided: at adjudication settlement + every teardown arm (NOT at
  `verify()`-return — the Epic-3 ROPC adapter reads the secret async; `SmppBytes` copies C-octet fields
  so the wipe can never corrupt the AD-14 forward). Tests +11 (10 `BindInterceptorTest` +
  `LatchedBindCredentialVerifier`; ingress pipeline pin evolved to 3 handlers; `RelayTestFixtures`
  gained the shared initializer factory). RED phase genuine (9/9 vs a compiling stub); FIVE
  RED-on-neuter mutations (N1 deny synth, N2 finally-zeroize, N3/N4 the T6-review-DEFERRED
  egress-bootstrap wiring pins, N5 the AD-25 re-check) each RED on exactly their named biters. Full
  `./gradlew clean build` GREEN — 274 tests, 0 failures, 0 skipped (proxy 191). (T8–T11 remain open —
  story stays in-progress.)

- 2026-08-16 — **Story 2.2 T7 owner-FIXME round (6 in-code FIXMEs, addressed same-day):** (1) the
  adjudication deadline extracted to config — `companion.bind.adjudication-deadline: 4s`
  (`ProxyCompanionProperties.Bind` 2nd component, `@NotNull` + compact-ctor positivity guard
  zero/negative→refuse; the T5b house pattern: default in application.yml, no `@DefaultValue`,
  `TestCompanionConfigs.common()` states it because the `ApplicationContextRunner` matrix boots load NO
  yml — the round's load-bearing trap). New bite: matrix refusal 0s/-5s/PT0S (mutation N6 RED on
  exactly those 3) + an end-to-end flow assert (the latched verifier captures the ScopedValue-bound
  deadline ≈ now+4s) + the yml-default pin in `CompanionTlsBindingTest` (mirror of the T5b
  `budgetCheck==FAIL` pin). (2) Spliced-passthrough comment rewritten to describe the mechanism.
  (3) `assert pendingVerdict/pendingPassword == null` at adjudicate entry — a single-event-loop
  invariant, probe-proven live under Gradle's `-ea` (N7). (4) The redundant `pendingPassword`
  assignment removed from the sync-throw catch (the explicit zeroize is that arm's single wipe).
  (5) `EgressLeg` → Lombok `@RequiredArgsConstructor`. (6) "Prove non-blocking": call-site comment +
  class-level `@Timeout(10, SEPARATE_THREAD)` on `BindInterceptorTest` — SEPARATE_THREAD is
  load-bearing (the default SAME_THREAD can only observe a timeout AFTER a method returns; the
  separate thread INTERRUPTS an interruptible block — the realistic blocking-verifier regression —
  into a test failure). ErrorProne `UnusedVariable` on the continuation's `error` param resolved by
  making the fail-closed arm read it explicitly (behavior identical under the `whenComplete`
  contract). Full `./gradlew clean build` GREEN — 277 tests, 0 failures, 0 skipped.
  **Verification note (honest record):** the post-round adversarial 4-lens workflow died vacuously —
  all 4 finder agents hit the account's 429 usage limit (resets 2026-08-16 03:39), so its empty
  findings carry no evidence; the round was instead PARENT-VERIFIED inline (the T5b 429 precedent).
  The inline pass caught and fixed one real defect (the `@Timeout` SAME_THREAD overclaim above) and
  grounded the rest: every boot path binds the deadline (the green suite's `@NotNull` paths are the
  empirical proof; the record-arity change makes any missed direct construction a compile error),
  the Duration tokens all parse (N6's RED-under-neuter proves 0s/-5s/PT0S reached the guard as parsed
  values), no planning artifact pins a deadline number or names the zero-new-config constraint (grep —
  story-text only; the owner override is recorded here), and no unresolved FIXME remains in main.
  Re-run the workflow after the limit resets if a second opinion is wanted.

- 2026-08-16 — **Story 2.2 Task 8:** AC3+AC7 `RelayHandler` — the AD-25 single-flip + AD-32 bare-close +
  REL-1 opaque splice + pinned SpliceObserver triggers (AD-2/AD-3/AD-25/AD-27/AD-32). NEW
  `proxy/relay/RelayHandler.java` (per-leg instances; the flip site is the EGRESS-leg handler riding the
  ingress event loop — structural single-flipper: the ingress leg can never see a decoded bind_resp);
  `BindInterceptor` gained the `teardownForPreCoupleViolation` seam (AC3's literal ordering — the
  pending cancelHttp/zeroize handles live in the interceptor) + a post-flip exceptionCaught propagation
  arm; both initializers wire their `RelayHandler` entries (T6 subtask 1's checkbox CLOSED — the AC4
  pipelines are complete). Tests +12 (`RelayHandlerTest`: RELAY-001a/b/e + re-check both halves,
  RELAY-002 ×2, RELAY-003, RELAY-002c generic_nack, CODEC-021 sibling, RELAY-008/009/010, AC5
  exactly-once with a PRE-close duplicate); `BindInterceptorTest` retrofitted to the real 4-handler
  ingress pipeline + its non-ROK test evolved to the T8 teardown contract; pipeline pins 4/3 handlers.
  RED phase genuine (12/12 vs a no-op stub); FIVE RED-on-neuter mutations proven (N1 flipper, N2
  bare-close seam, N3 tearing-down re-check, N4 exactly-once CAS — whose first biter shape was a
  false-green caught by the mutation pass itself (post-close duplicates never reach the torn-down
  embedded pipeline; restructured pre-close), N5 non-ROK teardown). Full `./gradlew clean build` GREEN —
  289 tests, 0 failures, 0 skipped (proxy 207; was 195). Honest scope: read-arming unobservable on
  embedded channels (T9's real sockets), RST simulated as the pipeline-fired IOException (real-socket
  injection is T9's), 7 of 16 CloseReason values fire this slice (coverage map in the Debug Log).
  (T9–T11 remain open — story stays in-progress.)

- 2026-08-16 — **Story 2.2 Task 9:** AC6(a)+AC7 socket-level smoke + the A-1 ops plan. NEW
  `MockSmsc` (in-JVM mock SMSC on the PRODUCTION codec — ROK bind answering behind an injectable
  delay/stall gate, per-session byte-exact captures, per-socket `deliver_sm` injection = the
  carrier-affinity emulation; NEVER an oracle — javadoc opens with the disclaimer) + NEW
  `RelayA1SmokeTest` (3 tests on REAL sockets through the REAL acceptor via the new
  `ModeBRelayHarness`): RELAY-011 — two concurrent binds under one `system_id` both ROK, each
  coupled to its own egress pair (content-matched bind bytes), tagged `deliver_sm` per egress lands
  on EXACTLY its originating legacy socket — zero cross-bleed; REL-1 — the golden-vector bind +
  4-submit/3-deliver coalesced-write chains, no drop/dup/corrupt, boundaries preserved; real-socket
  FIN/RST teardown arms (the T8-deferred live proofs + the live AD-2 read-demand proof). NEW
  `docs/a-1-carrier-test-plan.md` (OBS-035/036/037: explicit numeric PASS criterion, explicit FAIL
  criterion + the DLR-affinity procedure, real-carrier/conformance-SMSC oracle with the in-JVM mock
  explicitly excluded) + `A1CarrierPlanDocsTest` (3 falsifiability gates, normalization-tolerant,
  doc existence asserted loudly). `RelayTestFixtures` gained the egress-targeted properties
  overload + the harness record. RED-on-neuter: N1 (splice → wrong leg) RED on RELAY-011
  (`SocketTimeoutException`) + REL-1; N2 (blanked doc) RED on all 3 gates; both restored
  byte-exact. Full `./gradlew clean build` GREEN — 295 tests, 0 failures, 0 skipped (proxy 213 =
  207 + 6). (T10–T11 remain open — story stays in-progress.)

- 2026-08-16 — **Story 2.2 Task 10:** AC6(b) OBS-038 — the jSMPP 3.0.2 independent A-1 conformance
  oracle. `org.jsmpp:jsmpp:3.0.2` on `proxy` testImplementation (test-only, the codec's CODEC-031
  coordinate mirrored); NEW `JsmppSmscServer` (server-side mock: ROK-any-`system_id` binds,
  submit-triggered tagged DLR on the SAME session = carrier-side affinity, `anomalies()` bookkeeping)
  + NEW `JsmppA1OracleTest` (two CONCURRENT binds under ONE `system_id` through the REAL relay → both
  ROK; submit → `submit_sm_resp` + DLR on the owning bind ONLY, symmetric leg for B, zero cross-bleed;
  observer/registry/anomalies pins). **The oracle bit the test twice mid-flight** (malformed §4.4.1
  `submit_sm` → jSMPP decomposer AIOOBE with zero response; wrong `deliver_sm` literal `0x00000105` vs
  the spec's `0x00000005` §5.1.2.1) — the exact independence AC6(b) buys; `MockSmsc`'s opaque path
  cannot catch either. Owner FIXME (concurrent-binds bind-stage close) investigated via a 3-agent
  adversarial workflow + 6-experiment repro matrix — NOT reproducible on HEAD (jSMPP + relay both
  exonerated; bytecode: the initiation SO_TIMEOUT is overwritten by `enquireLinkTimer` in the session
  ctor, and a read timeout only enquire_links; relay: no cross-pair close path, no timer at all; the
  only matching HEAD mechanism is the DESIGNED AD-32 pre-couple bare-close — E5c); FIXME removed.
  jSMPP portability fact baked into the fixture: `getPort()` returns the CONFIGURED port (probe-first,
  else the egress aims at port 0 → AD-33 deny). RED-on-neuter N1 (splice→self) RED at the DLR read,
  restored byte-exact. Full `./gradlew clean build` GREEN — **296 tests, 0 failures, 0 skipped**
  (proxy 214 = 213 + 1). AC6 now complete in CI on both proofs (RELAY-011 + OBS-038); real-carrier
  falsification stays the non-CI plan. (T11 remains open — story stays in-progress.)

- 2026-08-16 — **Story 2.2 Task 11 (AC9 / standing gate AI-1): the consolidated RED-on-neuter mutation pass +
  green build.** 35 mutations on integrated HEAD d0ea8ac — the 6 load-bearing AC3/AC8 guards first-hand in the
  main tree (`/tmp/t11-backups` discipline; AC9's named four — AD-32 bare-close, non-ROK teardown, AD-25 flip
  re-check, AD-30 self-check — plus the single-flipper and the exactly-once CAS) + the 29 remaining guards
  T1–T10 introduced via a worktree-isolated agent sweep (workflow `wf_529b1174-f33`; 29 agents, 0 errors; every
  mutation: neuter → RED on its named biter(s) → revert → GREEN; full ledger in Completion Notes). Fresh-count
  deltas vs the per-task records logged honestly (T7-N1 → 6 biters; T1b's class-load kill mechanism; T5a-context
  → 4). jqwik `@Property` trap verified clean (class-level Jupiter annotations only, 10 methods / 3 codec
  classes); zero `@Disabled`/removed tests. `./gradlew clean build` GREEN — **296 tests, 0 failures, 0 errors,
  0 skipped** (proxy 214 + codec 82); RELAY-025/026 green; zero marker residue (`grep T11-MUTATION` = 0);
  worktrees auto-cleaned; main tree byte-identical to HEAD. **ALL TASKS COMPLETE — story status → review.**

### Review 2026-08-17 — Story 2.2 full-story code review (3 adversarial layers + 5-verifier triage; 28 raw → 21 deduped → decisions resolved same-day → 8 patch / 8 defer / 5 dismissed)

Scope: full story diff `b7927b2..HEAD` (59 files, +9,605/−33). Method: Blind Hunter (cynical adversarial)
+ Edge Case Hunter + Acceptance Auditor run fresh-context in parallel; 21 deduped findings then
adversarially re-verified against the working tree by 5 independent verifiers (CONFIRM/PARTIAL/REFUTE +
tracked-where audit; the one raw HIGH — runtime pair cap — fell to PARTIAL: explicitly owner-deferred to
Epic 3, deferred-work.md:244-249). Deferred-work RESOLVED spot-check: **no false-RESOLVED — all 3 markers
backed by cited biting tests.** AC scoreboard: AC1/2/4/5/6/7/8 SATISFIED; AC3 PARTIAL (F1); AC9 PARTIAL (F2).

**Decision needed — RESOLVED by owner 2026-08-17 (F1/F7/F10/F9/F11 → defer, F16/F2 → defer + ledger, F5 → dismiss):**

- [x] [Review][Decision→Defer] **[F1|medium] Ingress-leg `bind_*_resp` silently dropped — not bare-closed pre-flip, not spliced post-flip** — `BindInterceptor.java:188-197` else-arm releases the frame and returns. Post-flip non-splice is an unambiguous deviation (spine :80 "once coupled, every PDU … forwarded like any other"; AC7 :136 "never a silent drop"). Pre-flip the spine is arguable (AD-32 bullet 1 vs bullet 3) — and the current drop accidentally blocks a client-forged ROK flipping the pair without SMSC consent (`RelayHandler.channelRead:126-137` would flip on a forwarded resp), so the correct pre-flip fix is bare-close, not forward. No test covers ingress `bind_*_resp` in either window; tracked nowhere. **Owner (2026-08-17): defer** — drop kept (it incidentally seals the forged-ROK flip window); the AD-32 letter + post-flip splice question rides with RELAY-020/021 in the later Epic-2 story.
- [x] [Review][Decision→Defer] **[F7|medium] Cancelled-but-never-settling verdict leaks the original bind frame (pooled direct buffer)** — `BindInterceptor.java:271-274` `whenComplete` is the only releaser of the in-flight `req.originalFrame()`; all four teardown arms call `cancelAndWipePending` (:336-347), which never releases it. The ratified port (`VerdictRequest.java:26-30`) does not promise `future()` completes on `cancelHttp()`. Latent today (AlwaysAllow pre-completes); goes live with Epic 3 ROPC. Fix fork: (a) amend the ratified-immutable port (AC8) to promise settlement on cancel, or (b) relay-side frame-ownership transfer with a CAS/flag to avoid double-release against the onVerdict racer arm (:289). **Owner (2026-08-17): defer to Epic 3** — latent under AlwaysAllow (pre-completed future); decide port-amendment vs relay-side ownership when Epic 3's ROPC adapter can actually strand a future.
- [x] [Review][Decision→Defer] **[F10|medium] Egress `Bootstrap` has no `CONNECT_TIMEOUT_MILLIS` — blackholed SMSC hangs legacy sockets ~30s vs the 4s budget** — `BindInterceptor.java:400-406` + `RelayChannelOptions.java:80-84`; Netty default 30s (verified in pinned 4.2.16.Final); PERF-3's 2-5s fail-closed budget never bounds TCP establishment; RELAY-020-as-written (connect-refused, RST fails fast) passes without the option, so the blackhole case has no named owner. Fix fork: one-line Bootstrap option (value = adjudication-deadline? PERF-3 window? new key — this slice's notes forbid new companion.* keys) vs a scheduled deadline-task deny matching RELAY-020's injectable-clock design. **Owner (2026-08-17): defer** — blackhole-establishment bounding folds into the deferred RELAY-020/021 timeout arm; ~30s worst case accepted for this plaintext test-tier slice.
- [x] [Review][Decision→Defer] **[F9|low] `EGRESS_CONNECT_FAILED`/`BIND_REJECTED` never fire — deny/connect-fail closes surface as `OTHER`** — 5 of the 7 unreachable `CloseReason` values are documented not-fired-by-design (Debug Log :742-757, "closed-set stability, not a must-fire list"), but these two are absent from BOTH the fired and not-fired lists: `denyAndTeardown` (`BindInterceptor.java:321-333`) stashes no reason and `ConnectionRegistry` clears the entry attr before close, so `channelInactive` fires `OTHER`. Epic 4 metrics inherits the mis-bucketing. Fix needs hoisting the RelayHandler-private CLOSE_REASON key (`RelayHandler.java:83-84`) + a deny-variant→value mapping + possibly amending the ratified not-a-must-fire-list contract. **Owner (2026-08-17): defer to Epic 4** — firing semantics decided by Epic 4 when the metrics observer consumes the taxonomy.
- [x] [Review][Decision→Defer] **[F11|low] `onFramedPdu` never fires pre-couple despite seam contract "pre- or post-couple"** — sole fire site `RelayHandler.java:197` (post-flip only); the AD-14 verbatim bind forward (`BindInterceptor.java:427`) and the `bind_resp` forward (:511) cross uncounted (deny-synthesis + generic_nack forward likewise). Firing at the handshakes would flip three pinned tests RED (`RelayHandlerTest:176-179`, `RelayA1SmokeTest:191/243`, `JsmppA1OracleTest`); the alternative is amending `SpliceObserver.java:31` — decides Epic-4 PDU-count metric semantics. **Owner (2026-08-17): defer to Epic 4** — contract-vs-firing folds into Epic 4's PDU-count metric semantics; javadoc amended then if post-couple-only is ratified.
- [x] [Review][Decision→Defer] **[F16|low] Backpressure writability condition + low-water handler body have no behavioral test (RELAY-014 deferred)** — correction to the raw finding: the forward at `RelayHandler.java:198` is unconditional; `peer.isWritable()` gates only the read re-arm (:200), and the re-arm happy path IS covered on real sockets (multi-roundtrip traffic needs it). Uncovered: the writability CONDITION and `channelWritabilityChanged` (:219-231). RELAY-014 (test-coverage-scenarios.md:405-409) is the owner-scoped deferral — decide: pull it forward into 2.2 or re-affirm. **Owner (2026-08-17): re-affirm the RELAY-014 deferral + ledger it** — recorded in deferred-work.md (2026-08-17) so it stops living only in the story's Out-of-scope.
- [x] [Review][Decision→Defer] **[F2|low] AC9/AI-8 RUN-half (`bootRun`/JavaExec) `--enable-preview` gate deviation is unledgered** — owner-approved + flagged (`PreviewFeatureCompileGateTest.java:29-33`; story :961-967, proposing a lift to deferred-work/accepted-risk) but no ledger entry was created, AC9 text unamended, and `deferred-work.md:14` is a stale pre-2.2 line never refreshed. Choose the home: deferred-work.md vs AD-12 accepted-risk register vs AC9 amendment (+ ledger cleanup). **Owner (2026-08-17): ledger in deferred-work.md** — entry written (2026-08-17) + the stale pre-2.2 line refreshed.
- [x] [Review][Decision→Dismiss] **[F5|low] AC2 letter: `SmppCommandIds.BIND_FAMILY` is never referenced** — intent holds (typed decode, no local redefinition; `BindInterceptor.java:372-377` javadoc says "consumed, never redefined" while the switch enumerates the 3 request ids + their `*_RESP`). Fix fork: amend AC2/Dev-Notes wording vs add a pin test (deny-switch request ids = the request half of `BIND_FAMILY`). **Owner (2026-08-17): dismiss** — letter-only; the intent (typed decode, no local redefinition) holds.

**Patch (unambiguous):**

- [x] [Review][Patch→Dismiss] **[F8|medium] `parseSize` rejects valid HotSpot hex tokens → false boot refusal** [proxy/src/main/java/smpp/companion/proxy/relay/netty/DirectMemoryBudgetValidator.java:81-119] — accept `0x`/`0X` prefix (`Long.parseLong(hex, 16)`) before the multiplier, mirroring the merged t-suffix fix; pin with test `0x40000000 → 1073741824`. (Raw-IAE-for-malformed-tokens is deliberate T5b design — don't change.) **Owner (2026-08-17): dismiss** — non-decimal size tokens are considered invalid by owner decision; the existing descriptive IAE (which names the flag and the rejected token) is the accepted behavior for `0x…`.
- [x] [Review][Patch] **[F12|low] Null-returning `verify()` leaks the bind frame (NPE outside the try)** [proxy/src/main/java/smpp/companion/proxy/relay/BindInterceptor.java:269-274] — null-check `verdictRequest` and reuse the adjacent catch arm verbatim (release + denyAndTeardown + `cred.password().zeroize()`); fail-closed semantics already ratified ten lines above. **Applied 2026-08-17** — the null arm mirrors the catch (release + deny + zeroize + return); pinned by `nullReturningVerifierFailsClosedAndReleasesTheFrame` (deny code + no `onBindReject` + closed + registry empty + zeroized + `refCnt == 0`).
- [x] [Review][Patch] **[F21|low] Channel-options javadoc overclaims the per-channel bound** [proxy/src/main/java/smpp/companion/proxy/relay/netty/RelayChannelOptions.java] — Netty `read()` under AUTO_READ=false is an idempotent interest-arm (arms coalesce; `AbstractNioChannel.doBeginRead` sets readPending once), so "at most max-inbound-depth" is stronger than the mechanism; reword to the actual guarantee (steady-state buffered bytes ≈ high mark + one read cycle). **Applied 2026-08-17** — class javadoc + `writeBufferWaterMark()` javadoc reworded to the steady-state bound (high mark + one read cycle; arms coalesce).
- [x] [Review][Patch] **[F13-doc|low] Deferred-work "wildcard listener" rationale is stale post-T7/T8** [_bmad-output/implementation-artifacts/deferred-work.md:244-249] — entry was authored when accepted channels were "inert-but-never-reaped"; uncapped accepts now create live coupled pairs + egress connections. Refresh the wording (docs-only); the connection-cap decision itself stays deferred to Epic 3 (owner 2026-08-15). **Applied 2026-08-17** — dated `↳` refresh note appended (deferral stands; weight sharpened to coupled-pair memory residency).
- [x] [Review][Patch] **[F17|low] `A1CarrierPlanDocsTest` can false-green on incremental builds** [proxy/build.gradle.kts] — declare the non-build-graph read as a test input: `tasks.named("test") { inputs.file(layout.projectDirectory.file("../docs/a-1-carrier-test-plan.md")) }`. (The two source-scan gates are effectively covered transitively via compiled-class inputs; `PreviewFeatureCompileGateTest` is the compiler-enforced replacement, not an instance of the trap.) **Applied 2026-08-17** — `inputs.file(...)` added to the `test` task with the trap comment.
- [x] [Review][Patch] **[F3|low] Unamended constraint text contradicts the diff** [story :217, :359] — "NO change to `ProxyCompanionProperties.java` / ZERO new config field" vs the sanctioned `adjudication-deadline` + `budget-check` additions. Add dated amendment notes mirroring the AC8 amendment pattern; also fix the "application.yml only binds the selected reverse.mode-b branch" sentence (blocks are at application.yml:61-94, all commented). **Applied 2026-08-17** — dated amendment notes added at both spots (Task-6 subtask + Project Structure Notes).
- [x] [Review][Patch] **[F4|low] `io.freefair.lombok` 9.5.0 plugin addition undocumented** [proxy/build.gradle.kts:13] — extend the File List entry to record the T4 plugin addition (mirrors codec/build.gradle.kts:9); relay main types rely on it (`@RequiredArgsConstructor`, `@Slf4j`). **Applied 2026-08-17** — File List entry now reads "modified (T4 + T10)" with the plugin line + the F17 note.
- [x] [Review][Patch] **[F6|low] `NoStringFromPasswordTest` soft-skips a missing `proxy/relay` root** [proxy/src/test/java/smpp/companion/proxy/security/NoStringFromPasswordTest.java:88-90] — relay code has landed; promote `PROXY_RELAY` to the hard existence assert mirroring :84-85, delete the `continue` (and fix the story Debug Log :447-448 "three roots asserted" claim). **Applied 2026-08-17** — hard assert added, `continue` deleted; the Debug Log's "three roots asserted" claim is now literally true.

**Deferred (owner already decided):**

- [x] [Review][Defer] **[F14|low] Relay-side adjudication-deadline enforcement (verdict-timeout arm)** [proxy/src/main/java/smpp/companion/proxy/relay/BindInterceptor.java:127-133,242-244] — deferred, owner-approved (story T7 honest-scope note (c), :1243; Out of scope :339). The 4s key ships but nothing arms a timeout: a never-settling verifier pins the entry + frame + client socket. Ledgered under its own name in deferred-work.md because the catalog RELAY-020 tag names a different, already-implemented scenario (post-Allow connect-refused no-hang).

**Dismissed (6):** F20 pending-adjudication `assert` (documented probe-verified tradeoff; sanctioned state-machine refactor already at deferred-work.md:253-271) · F15 zero relay logging (ratified Epic-4 deferral — AD-19/AD-33, story Out of scope :341; AC3's "TRACE logs" phrasing presupposes the Epic-4 sink) · F19 non-ROK close-vs-pending-write race (theoretical — pre-couple non-ROK `bind_resp` is the first-ever outbound write, kernel send buffer empty) · F18 scan blind spots (self-documented honest scope; typed `Password.toString()` redacts, so the cited logger example doesn't leak; raw-AsciiString vectors remain covered by the RELAY logging discipline rule) · F5 `BIND_FAMILY` letter (owner 2026-08-17: letter-only, intent holds) · F8 hex size tokens (owner 2026-08-17: non-decimal tokens are considered invalid; the descriptive IAE naming flag + token is the accepted behavior).

**Applied round (2026-08-17, same day):** 7 patches applied — F12 (+ the
`nullReturningVerifierFailsClosedAndReleasesTheFrame` biter), F21, F13-doc, F17, F3, F4, F6; F8 dismissed
by owner (non-decimal size tokens considered invalid). Verification: `./gradlew clean build` GREEN —
**297 tests, 0 failures, 0 errors, 0 skipped** (proxy 215 = 214 + 1 new; codec 82). Story status → done.
