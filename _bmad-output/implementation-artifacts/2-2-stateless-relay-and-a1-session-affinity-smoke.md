---
baseline_commit: b7927b2
epic: 2
story: 2
story_key: 2-2-stateless-relay-and-a1-session-affinity-smoke
status: in-progress
---

# Story 2.2: Stateless Relay Splice + A-1 Session-Affinity Smoke (plaintext, always-allow adjudication)

Status: in-progress

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
   AI-6.)*

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

- [ ] **Task 4 (AC: 1) — `ConnectionRegistry` (AD-8).**
  - [ ] Concurrent bean keyed by ingress `ChannelId` (`ConcurrentHashMap`). Entry: `{ peer-egress Channel, splice flip-flag (volatile/AtomicBoolean), session metadata, tearing-down mark }`.
  - [ ] `Channel` attribute (`AttributeKey`) caching the entry for O(1) on the event loop.
  - [ ] `channelInactive` on either leg removes the entry (idempotent — RELAY-005); egress-connect-failure-after-entry removes it + tears down ingress (RELAY-006).
  - [ ] **No `message_id`→`system_id` map anywhere** — RELAY-025 ArchUnit scan forbids it (statelessness, REL-4).
  - [ ] Tests: RELAY-005 (idempotent double-teardown, double-zeroize safe), RELAY-006 (no orphaned entry on egress-connect-fail). jcstress (RELAY-007) is DEFERRED to the nightly hardening story — note in Completion Record.
  - [ ] RED-on-neuter for the idempotent-teardown guard.

- [ ] **Task 5 (AC: 8) — Shared `PooledByteBufAllocator` + AD-30 live self-check (AD-21/AD-30, AI-6).**
  - [ ] `@Bean PooledByteBufAllocator` (ONE shared, wired to every channel ingress+egress — NOT per-channel). `io.netty.allocator.type=pooled`.
  - [ ] Startup self-check: read the JVM's live direct-memory ceiling via `jdk.internal.misc.VM.maxDirectMemory()` (mind the `jdk.internal.misc` module-open on JDK 25; `ManagementFactory` arg-parsing is a fallback), compare to `MemoryBudget.compute(maxInboundDepth, concurrentPairs, safetyFactor)` (inputs from `companion.memory.*`), **fail-fast** if under budget. (`ByteBufAllocatorMetric` exposes only `usedDirectMemory()`/`usedHeapMemory()` — current usage, NOT the ceiling.)
  - [ ] Reference `SmppFrame.MAX_COMMAND_LENGTH` directly in any sizing (keep `Relay026ConstantContractTest` green — no magic `65536`).
  - [ ] Test: bind `companion.memory.*` to values that exceed a deliberately-small live budget → assert fail-fast (null-vs-blank trap: bind the specific value, do not remove the key).
  - [ ] RED-on-neuter: removing the self-check → the under-budget startup goes GREEN when it must fail.

- [ ] **Task 6 (AC: 4) — Netty pipelines + `SmartLifecycle` acceptor (AD-1/AD-2/AD-16).**
  - [ ] `ServerBootstrap`/`Bootstrap` driven directly (NO Spring messaging integration). Ingress pipeline `SmppFrameDecoder → SmppCodec → BindInterceptor → RelayHandler`; egress `SmppFrameDecoder → SmppCodec → RelayHandler`. One `SmppFrameDecoder` instance per channel (CODEC-014).
  - [ ] Shared event loop (platform threads — virtual threads never carry the data-plane splice, AD-1). `AUTO_READ=false` + write-completes-gates-read + explicit low-water re-arm (AD-2/AD-30). Per-channel inbound queue bounded.
  - [ ] `SmartLifecycle` bean: start = bind acceptor + wire egress; `stop(Runnable)` invokes the callback in `finally` (mirror `ProxyCompanionLifecycle`). **Explicit `getPhase()`** so the relay lifecycle and `ProxyCompanionLifecycle` stop in the right order (deferred-work.md 2nd-SmartLifecycle item; full AD-22 drain is Epic 4).
  - [ ] Config source: `companion.bind.port` (listener) + `companion.reverse.mode-b.{smsc, acknowledged:true}` (the single egress + plaintext opt-in) + `companion.memory.*` (T5) + `companion.tls.*` (AD-34 defaults). Read via `ProxyCompanionProperties` (Story 1.3). **ZERO new config field — `reverse.mode-b` already carries `smsc` + `acknowledged`; NO change to `ProxyCompanionProperties.java`.**
  - [ ] **No `SslHandler` on either leg.**

- [ ] **Task 7 (AC: 2) — `BindInterceptor`: bind-family verifier gating + AD-33 collapse + caller-owned zeroize (AD-7/AD-15/AD-25/AD-27/AD-33).**
  - [ ] On decoded `SmppBindRequest`: consume `SmppCommandIds.BIND_FAMILY` (no local redefine). **Route EVERY bind to the single configured egress (`companion.reverse.mode-b.smsc`) — NO `system_id` allow-list, NO routing table (AD-29 is forward-role, inapplicable here).**
  - [ ] **Verifier `Deny*` → AD-33 deny:** synthesize the matching `bind_*_resp` with ONE generic bind-failure `command_status` (header-only 16-octet construct built directly — AD-32 forbids re-serializing via `SmppBindEncoder` on the hot path; the deny `bind_resp` is the ONE place the relay builds a PDU). Exact code: **open question Q2 (reopened — left for the dev to ratify at T7 impl):** the prior `ESME_RINVSYSAUTH 0x0000000E` pin was tied to routing-miss AND is a non-existent SMPP 3.4 code name pinned to the wrong hex (`0x0E` = `ESME_RINVPASWD`); with routing-miss gone the collapse covers verifier-`Deny*` + egress-establishment-fail only, and AD-33's anti-enumeration purpose favors a GENERIC code (e.g. `ESME_RSYSERR 0x00000008`) over a credential-specific one. Ratify the chosen generic code vs SMPP 3.4 §5.1.3 at T7 impl.
  - [ ] Invoke `BindCredentialVerifier.verify(BindCredential, ScopedValue<RequestContext>)`; construct `BindCredential(new SystemId(req.systemId()), new Password(req.password()))` and the `RequestContext(systemId, channelId, deadline)` bound via `ScopedValue` (AD-5; never `ThreadLocal`). Await `VerdictRequest.future()`.
  - [ ] On `Allow`: open egress (T6), forward `req.originalFrame()` to the SMSC verbatim (AD-14), `release()` after. On `Deny*`: AD-33 deny `bind_resp` + `onBindReject(systemId, verdict)` (AD-19: no labeled `system_id` values; reject counter unlabeled full-stop). **Egress-establishment-fail (no SMSC response PDU) collapses to the SAME generic deny code (AD-33)** — a prober cannot distinguish verifier-reject from unreachable-SMSC; SMSC-originated non-ROK `bind_*_resp` is forwarded verbatim (AD-32 case 4, RELAY-002c — NOT collapsed).
  - [ ] On decoded `bind_*_resp` from egress: forward to the legacy client (the AD-25 forwarder split — BindInterceptor owns bind-family forward; RelayHandler reads read-only to flip).
  - [ ] **Caller-owned zeroize:** `cred.password().zeroize()` in `finally` on EVERY path (Allow/Deny/cancelHttp/timeout/exception). This resolves the open 2.1 review finding (deferred-work.md §AlwaysAllow-zeroization) — `AlwaysAllow` does not inspect the secret, so the relay owns the wipe.
  - [ ] Tests: RELAY-004 (retry-bind while adjudication in-flight → deterministic reject/teardown, no second pair, no registry corruption — fake verifier with `CountDownLatch`-held verdict, configurable `Allow` OR `Deny`). **AD-33 collapse test (slice-scoped):** verifier-`Deny` (fake `Deny`-verifier) → the generic failure code; egress-establishment-fail (no SMSC response) → the SAME generic code (collapse holds); SMSC-originated non-ROK `bind_*_resp` forwarded verbatim, NOT collapsed (RELAY-002c). **The AD-33 routing-miss collapse half CANNOT run in 2.2 (no routing table) and DEFERS to Epic 3 forward-role**; the verifier-`Deny` collapse half stays (fake verifier) + RELAY-002c.
  - [ ] RED-on-neuter for the verifier-`Deny` collapse (fake `Deny`-verifier: neuter the deny-synthesis → the bind wrongly ROKs / hangs instead of denying) and the zeroize-in-finally.

- [ ] **Task 8 (AC: 3, 7) — `RelayHandler`: AD-25 single-flip + AD-32 bare-close + REL-1 splice + SpliceObserver triggers (AD-2/AD-3/AD-25/AD-27/AD-32).**
  - [ ] **The ONLY flipper:** on the ingress event loop, on decoded `bind_*_resp` where `SmppBindResponse.isOk()`, flip the entry's flag; fire `onBindAccept(systemId)` exactly at the flip (NOT at the verdict). Non-ROK → do NOT flip; tear down.
  - [ ] **Race-free re-check:** before flipping (Allow path) AND in the Deny callback, re-check the `ConnectionRegistry` entry — if absent or `tearing-down`, the callback is a no-op (AD-25 gate-fix).
  - [ ] **Post-flip opaque splice:** framed-`ByteBuf` forward both directions; `SmppCodec` object-decode dormant post-couple (AD-2). **No live `pipeline.remove()`** — the coupling is a flag flip, not a pipeline mutation.
  - [ ] **AD-32 bare-close (final spine):** pre-flip, on EITHER leg — bind-family cooperative; egress `generic_nack`/non-ROK `bind_resp` forwarded verbatim (case 4); **everything else → NO response, close**. `command_id` read only to confirm "not bind-family" (`ByteBuf.getInt(4)`, no codec helper — AD-19); TRACE-gated only. Race-free teardown: same event loop, remove entry + mark `tearing-down` BEFORE close → `cancelHttp()` + `zeroize()` → close.
  - [ ] **SpliceObserver triggers:** `onFramedPdu(Direction)` per framed PDU; `onConnectionClosed(Direction, CloseReason)` **exactly-once** (CAS on the channel attribute) at the `channelInactive` teardown site; the violation handler only stashes `CloseReason`, never calls `onConnectionClosed` directly.
  - [ ] Tests (drive the REAL pipeline — gate-must-run-in-`check` trap; do NOT call handler methods directly): RELAY-001 (single-flipper — flips ONLY on decoded ROK `bind_resp`; no flip on non-ROK/peeked-id/Allow-without-bind_resp), RELAY-002 (ingress pre-couple non-bind → bare close, no egress PDU), RELAY-003 (egress pre-couple `deliver_sm` not leaked), RELAY-002c (SMSC `generic_nack`/non-ROK forwarded verbatim). REL-1: RELAY-008 (half-close propagates + drains/drops cleanly, sequence integrity), RELAY-009 (in-flight write racing `channelInvalid` → zero or exactly one complete frame on the wire), RELAY-010 (RST → both legs + registry, teardown OBSERVED). **CODEC-021 sibling of RELAY-001 (Risk Note 2 second vector):** feed a 0-byte-body (header-only) `bind_resp` → `SmppCodec` throws `DecoderException` before `SmppBindResponse` is built, so `isOk()` is NEVER reached — assert the `channelInvalid` teardown (`CloseReason`/counter fires), NOT `isOk()==false` (distinct from RELAY-001's decoded non-ROK branch).
  - [ ] RecordingAllocator-bypass trap: any allocator/leak assertion feeds input in MULTIPLE chunks via `ctx.alloc()` wrapped in `RecordingAllocator` (one `writeInbound(Unpooled.buffer())` is tautological — Epic-1 retro).
  - [ ] RED-on-neuter for the single-flipper, the AD-32 bare-close, the flip re-check, exactly-once `onConnectionClosed`, AND the non-ROK teardown guard (AC9 enumerates "non-ROK teardown" but T8's checklist omits it — neuter the "Non-ROK → do NOT flip; tear down" arm → a non-ROK `bind_resp` wrongly flips / fails to tear down).

- [ ] **Task 9 (AC: 6, 7) — In-JVM mock SMSC + A-1 mechanics smoke (RELAY-011) + REL-1 roundtrip + A-1 ops-plan docs (AD-24/AD-9).**
  - [ ] In-JVM mock SMSC: embedded Netty server in `proxy/src/test` using the PRODUCTION codec (`SmppFrameDecoder` + `SmppCodec`) — NOT a jSMPP harness. Programs: ≥N concurrent binds under one `system_id` → ROK each; `deliver_sm` on the SMSC socket that received the bind (carrier affinity emulation); injectable delay/stall; captures forwarded PDUs for byte-exact assertion. **Never an oracle for A-1 or codec correctness** (shares the codec's bugs + assumes A-1) — document this in the fixture's javadoc.
  - [ ] **RELAY-011 (load-bearing):** ≥2 concurrent `bind_transceiver` under the SAME `system_id`, distinct ingress Channels; inject a uniquely-tagged `deliver_sm` per egress; assert each tag arrives on exactly its originating ingress (capturing `SpliceObserver` per Channel; AssertJ on tag→Channel). Zero cross-bleed.
  - [ ] REL-1 roundtrip: `submit_sm` (legacy→SMSC) + `deliver_sm` (SMSC→legacy) across a coupled pair — no drop/dup/corrupt; PDU boundaries preserved (golden-vector-driven where wire bytes are needed — load `codec/src/test/resources/golden-vectors/`).
  - [ ] **A-1 ops-plan docs (OBS-035/036/037):** author `docs/` A-1 real-carrier test plan with explicit PASS criterion (≥2 concurrent binds, same `system_id`, both ROK on the real carrier), explicit FAIL criterion + DLR-affinity assertion (submit on bind A → `deliver_sm` on bind A's socket, not B), and naming the real carrier/conformance SMSC as the oracle (explicitly excluding the in-JVM mock). Docs-gate tests scan for the criterion shape (regex/AssertJ presence).
  - [ ] RED-on-neuter: neuter the coupling (e.g. forward `deliver_sm` to the wrong ingress) → RELAY-011 goes RED.

- [ ] **Task 10 (AC: 6) — jSMPP independent A-1 conformance oracle (OBS-038).**
  - [ ] Add `org.jsmpp:jsmpp:3.0.2` to `proxy` testImplementation (test-only — never the production codec; mirror the codec module's coordinate, `codec/build.gradle.kts:38`).
  - [ ] Build a **jSMPP 3.0.2 server-side mock** as the SMSC — the independent oracle (shares NEITHER the production codec's bugs NOR its A-1 assumption). Server-side API: `org.jsmpp.session.SMPPServerSessionListener` (bind to a port; `accept()` yields one `SMPPServerSession` per TCP connection, each delivering a `BindRequest` to a `ServerMessageReceiverListener` — see `org.jsmpp.examples.SMPPServerSimulator`). SMPP is one-bind-per-connection by spec, so the affinity scenario is N separate connections sharing one `system_id` (exactly AC6): the mock accepts N concurrent connections and ROKs each `bind_transceiver` regardless of `system_id`, then emits `deliver_sm` on the session that received the bind (carrier-side affinity).
  - [ ] **OBS-038 (load-bearing):** ≥2 concurrent binds under ONE `system_id` through the relay to the jSMPP server mock → both `bind_*_resp` ROK; `submit_sm` on bind A → the resulting `deliver_sm` (DLR) arrives on bind A's coupled channel, NOT bind B (capturing `SpliceObserver` per ingress; AssertJ). The strongest CI approximation of A-1 (test-coverage-scenarios.md:1267–1271).
  - [ ] Optional reuse: a jSMPP alternate-ESME client can also drive the RELAY-002/008 sequence-integrity paths — not required for AC6.
  - [ ] RED-on-neuter: neuter the coupling → OBS-038 goes RED (the DLR lands on the wrong bind).

- [ ] **Task 11 (AC: 9) — RED-on-neuter mutation pass + green build (AI-1).**
  - [ ] For every guard listed in AC9: neuter (comment out / invert) → run the matching test → confirm RED → revert → confirm GREEN. Record each in the Completion Notes (cite the test). Assertion bodies that can throw release latches/`EmbeddedChannel` resources in `finally`.
  - [ ] `./gradlew clean build` green on JDK 25 + `--enable-preview`. No test `@Disabled`/removed to pass. ArchUnit RELAY-025 + RELAY-026 stay green.
  - [ ] jqwik trap: any `@Property` carries NO Jupiter annotations (`@DisplayName`/`@Tag`) — class-level only (silent-skip → green-build hazard, Epic-1 retro).

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
- **Modified main types:** `proxy/bootstrap/ProxyCompanionLifecycle.java` (phase coordination, or a sibling lifecycle bean) — read it fully before touching (T6). **NO new `companion.relay.*`/`companion.egress.*` config key and NO change to `ProxyCompanionProperties.java` — the egress is the existing `companion.reverse.mode-b.smsc` field (already declared with `acknowledged`), read via the Story-1.3 properties record; `application.yml` only binds the selected `reverse.mode-b` branch.**
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

glm-5.2[1m] (Tasks 1–3 — bootstrap gate + observability contract seed + password hygiene/CODEC-024 P2; T4–T11 pending).

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

## Review Findings

_(filled at code review)_
