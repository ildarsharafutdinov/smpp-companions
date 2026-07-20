---
review: adversarial re-review (post-revision verification)
target: ARCHITECTURE-SPINE.md (Companions v1, status: draft, revised 2026-07-19, 31 ADs)
reviewer: adversarial
prior: reviews/review-adversarial.md (findings F-1..F-9, verdict FAIL)
created: 2026-07-19
method:
  - (1) CLOSURE: for each prior finding F-1..F-9, verify the closing AD(s) actually fix the two-unit divergence, not just name it.
  - (2) NEW DIVERGENCE: hunt for NEW pairs of units (epics/stories) that each obey every AD yet build incompatibly, INTRODUCED by the revision (AD-25..31 + ~14 tightenings).
---

# Adversarial Re-Review — Companions v1 Architecture Spine (Revised)

## Verdict

**PASS-WITH-FINDINGS.** All nine prior findings (F-1..F-9) are **CLOSED** — the closing ADs fix the named divergences, not merely label them. The four first-sprint blockers that drove the prior FAIL (F-1 flip/teardown, F-2 verifier contract, F-3 role×mode matrix, F-4 intra-proxy ownership) are genuinely resolved: the relay, security, and config epics can now be scoped against the spine. The internal two-flipper contradiction is gone (the line-59 diagram now shows `RelayHandler` flipping on decoded `bind_*_resp` ROK, matching AD-2/AD-25).

The revision **introduces five new seams** (NF-1..NF-5) where two AD-compliant units would still build incompatibly. None is a first-sprint scoping blocker; all are fixable with targeted tightenings. The most serious is NF-1, a literal ordering contradiction between AD-22 and AD-28 on JWKS-refresh-vs-cache-close shutdown ordering. The rest are trigger-event / ownership ambiguities created by the new transition (AD-25) and observability (AD-27) ADs interacting with the tightened cardinality (AD-19) and executor (AD-28) rules.

---

## Part 1 — Closure of Prior Findings (F-1 .. F-9)

| # | Prior finding (severity) | Status | Closed by | Verification |
| --- | --- | --- | --- | --- |
| F-1 | Two flippers + silent post-couple `unbind` (CRITICAL) | **CLOSED** | AD-25 + tightened AD-2 + tightened AD-3 + reconciled line-59 diagram | AD-25 names exactly one flipper (data-plane `RelayHandler`), one trigger (decoded `bind_*_resp` with `command_status == ESME_ROK`), and fixes the post-couple path (`unbind`/`unbind_resp` are opaque framed bytes; session ends on TCP half/close). AD-3 was rewritten to match ("Once coupled … every PDU — including `unbind`/`unbind_resp` — is an opaque framed byte stream"). The diagram (line 59) now reads `RelayHandler flips flag`, killing the second flipper. The non-ROK `bind_resp` case is settled (`→ do not flip; tear down`). |
| F-2 | `BindCredentialVerifier` port contract undefined (CRITICAL) | **CLOSED** | AD-12 (port-contract block) + AD-17 (role/mode) + AD-28 (executor) | AD-12 now fixes: owning package (`io.companions.proxy.security.BindCredentialVerifier`), signature verbatim (`CompletableFuture<Verdict> verify(BindCredential cred, ScopedValue<RequestContext> ctx)`), sealed verdict (`permits Allow, DenyInvalid, DenyIndeterminate`, no Throwable/Nimbus crosses), executor (hand-managed VT pool, never `@Async`), and canonical role ("the ingress role performs OIDC verification; the egress role trusts … over the internet leg"). The `relay → security` edge is the only permitted direction. |
| F-3 | role×mode matrix + Mode A egress trust (CRITICAL) | **CLOSED** | AD-17 (2×3 matrix + Mode B posture) + broadened AD-13 + NEW AD-26 | AD-17 publishes the full required/optional/forbidden matrix per cell, makes Mode B egress-only with loud-warning-and-ack posture, and names Mode A egress's "client trust store for P1/SMSC server cert (AD-26, never `cacerts`)". AD-13 broadened to "every peer-certificate validation path, not only Mode C". AD-26 makes egress trust anchoring explicit. Single-side adoption no longer trips a cross-role check. |
| F-4 | Intra-`proxy` ownership (HIGH) | **CLOSED** | NEW AD-27 | AD-27 makes `companions-codec` the single owner of `SmppCommandIds.BIND_FAMILY`, declares `outbind`/`generic_nack` opaque-spliced (not bind-family), and puts the `SpliceObserver` interface in `observability/` with a fixed method list (`RelayHandler` holds an injected reference; codec never emits metrics). One counter source. |
| F-5 | Executor assignment (HIGH) | **CLOSED** | NEW AD-28 + tightened AD-4 | AD-28 fixes the `SslHandler` delegating executor as ONE hand-managed fixed platform-thread pool (not VT, not Spring `ThreadPoolTaskExecutor`), shared ingress+egress, abort-on-saturation; JWKS refresh as a hand-rolled VT on a `ScheduledExecutorService` (not `@Scheduled`); and restricts `spring.threads.virtual.enabled` to Spring's own internals. AD-4 defers to AD-28. |
| F-6 | Per-bind state home (HIGH) | **CLOSED** | tightened AD-8 + tightened AD-22 | AD-8 fixes the home: a single concurrent `ConnectionRegistry` bean keyed by ingress `ChannelId` (holds peer-egress `Channel`, flip-flag, ephemeral metadata) + a `Channel` attribute for O(1); teardown via `channelInactive`. JWKS cache shape fixed as `AtomicReference<JwkSet>` swapped whole, with `close()` for drain. AD-22's drain now enumerates the registry. |
| F-7 | `/metrics` event loop (HIGH) | **CLOSED** | tightened AD-19 | AD-19 now mandates "a DEDICATED, hand-managed Netty event loop group … never shares the SMPP relay event loop group", started/stopped via `SmartLifecycle`. The scrape cannot stall a splice. |
| F-8 | Routing value schema (MEDIUM) | **CLOSED** | NEW AD-29 + AD-13/AD-17 FR-AUTH-3 wording | AD-29 fixes the value schema (`{host, port, tlsContextId?}`) and Mode C cert scope ("per-instance by default; per-target cert IDs permitted via `tlsContextId` + an explicit `tls.contexts` map"). AD-13 confirms per-instance. |
| F-9 | Frame size + memory budget (MEDIUM) | **CLOSED** | NEW AD-30 + tightened AD-21 | AD-30 pins max `command_length` = 65 536 octets, per-channel inbound depth bounded via `AUTO_READ=false` low-water-mark, and one named derivation formula `MaxDirectMemorySize = max_frame × max_inbound_depth × concurrent_pairs × safety_factor`. Added (beyond the prior ask): reject declared length < 16 and guard length-arithmetic overflow before allocation. AD-21 cross-references the derivation. |

**All nine closed.** No prior finding survives.

---

## Part 2 — New Divergence Findings (introduced by the revision)

Same method as the prior review: two concrete epics/stories one level down, each obeying every AD to the letter, that build incompatibly. Ranked most-severe first. Every finding is **new** — it depends on AD-25..31 or a tightened AD and could not have existed in the prior spine.

---

### NF-1 [HIGH] — AD-22 and AD-28 prescribe opposite shutdown orderings for JWKS-refresh-stop vs JWKS-cache-close

**Introduced by:** AD-28 (new) interacting with the rewritten AD-22 drain sequence.

#### The two units

- **E-BOOTSTRAP-LIFECYCLE — "Graceful drain driver," in `bootstrap/`.** Reads AD-22's listed sequence as authoritative: `stop acceptor → DENY in-flight adjudications → drain splices → close the JWKS cache → VT control-plane drain → exit`. Implements it literally: calls `jwkCache.close()` in step 4, then drains VTs (including the JWKS refresh VT) in step 5.
- **E-SECURITY-OIDC — "JWKS cache + refresh," in `security/`.** Reads AD-28(2): "JWKS refresh is a hand-rolled virtual thread on a `ScheduledExecutorService` owned by `security/` … so SIGTERM stops refresh **before** the JWKS cache closes." Implements it: on SIGTERM, `ScheduledExecutorService.shutdownNow()` + `awaitTermination(...)` THEN `jwkCache.close()`.

#### The gap

AD-22 places "close the JWKS cache" (step 4) **before** "VT control-plane drain" (step 5), where the refresh VT lives. AD-28(2) states the refresh "stops **before** the JWKS cache closes." These two orderings are mutually exclusive. AD-28's "registered with the bootstrap graceful-drain (AD-22)" does not resolve it — if the refresh VT is drained in the AD-22 VT-drain step, it stops **after** the cache closes, contradicting AD-28; if it stops before the cache closes, that step is absent from AD-22's list.

**Incompatibility, concretely:** a SIGTERM that lands during a scheduled JWKS refresh. E-BOOTSTRAP-LIFECYCLE's build calls `AtomicReference<JwkSet>.close()` (or nulls/swaps the cache to a closed sentinel) while the refresh VT is mid-`set(...)` — the refresh VT either throws inside the closed cache, silently loses a key rotation, or races `close()` on the `ScheduledExecutorService` itself. E-SECURITY-OIDC's build quiesces the refresh VT first and closes a quiescent cache. Both pass AD-22 (the listed order is followed by Team 1) and AD-28 (the before-close requirement is followed by Team 2). On a merged build the two shutdown hooks fight.

#### Closing AD

**TIGHTEN AD-22 — insert an explicit "stop JWKS refresh" step immediately before "close the JWKS cache".** New sequence: `… drain splices → stop JWKS refresh (`ScheduledExecutorService` shutdown + await, AD-28) → close the JWKS cache → VT control-plane drain → exit`. Alternatively, move "close the JWKS cache" to after "VT control-plane drain" — but the cleaner fix is the inserted step, because the cache's producer (refresh) must stop before its consumer (the cache) is torn down. State in AD-28(2) that the refresh VT is drained in this inserted step, NOT in the general VT-drain step.

---

### NF-2 [MEDIUM] — AD-27 names `SpliceObserver` methods but not their trigger events; `onBindAccept`/`onBindReject` fire at different points, and one path silently re-opens the AD-19 cardinality leak

**Introduced by:** AD-27 (new `SpliceObserver`) interacting with AD-25 (new flip trigger), AD-11 (enumerated denies), and the tightened AD-19 cardinality rule.

#### The two units

- **E-SECURITY-BIND — "BindInterceptor + verifier wiring," in `relay/`.** Fires `onBindAccept(systemId)` the moment `BindCredentialVerifier` returns `Allow` (the verdict), and fires `onBindReject(systemId, verdict)` for **every** AD-11 deny — including a routing-table miss, for which it synthesizes a `DenyIndeterminate` verdict so the reject is attributable.
- **E-RELAY-SPLICE — "RelayHandler + splice observer calls," in `relay/`.** Fires `onBindAccept(systemId)` only at the AD-25 flip (decoded `bind_*_resp` ROK — actual session establishment), and fires `onBindReject(systemId, verdict)` only for verifier-returned `Deny*`. A routing-miss bind never reaches the verifier; it increments AD-19's unlabeled counter `binds.rejected.unknown_system_id` and is **not** passed to `onBindReject`.

#### The gap

AD-27 fixes the `SpliceObserver` method **names and signatures** but not the **trigger event** for any of them. AD-25 fixes the flip trigger but does not say the flip is also the accept-metric trigger. AD-11 enumerates deny sources but does not say which feed `onBindReject`. AD-19 forbids "free-form `system_id` … ever a label" and routes unknown `system_id` to an unlabeled counter — but AD-27's `onBindReject(SystemId, Verdict)` takes a `SystemId` with no rule that the impl must suppress it when the value is not in the routing table.

**Incompatibility, concretely:**
- *Accept metric measures different things.* A bind whose OIDC verdict is `Allow` but whose `bind_resp` from the SMSC is non-ROK (rejected downstream) increments `binds.accepted` on E-SECURITY-BIND's build (verdict was Allow) and does **not** on E-RELAY-SPLICE's (no flip happened). Published PERF/SM-3 numbers differ.
- *Cardinality leak through the new seam.* A bind with `system_id="foo"` not in the routing table: E-SECURITY-BIND calls `onBindReject("foo", DenyIndeterminate)` → the Micrometer impl tags `binds.rejected{system_id="foo"}` → **violates AD-19** (free-form `system_id` as a label, unbounded cardinality). E-RELAY-SPLICE routes it to the unlabeled counter. Both obey AD-27 (the method exists and takes `SystemId`) and AD-19 (which Team 2 honors and Team 1 unknowingly defeats *through* the seam AD-27 added). Team 1's build is a walking AD-19 violation that no single AD forbids at the call site.

#### Closing AD

**TIGHTEN AD-27 — pin the trigger events and the cardinality obligation at the seam.**
1. `onBindAccept` fires **exactly at the AD-25 flip** (decoded `bind_*_resp` ROK), not at the verdict.
2. `onBindReject` is called **only for `Verdict` values returned by `BindCredentialVerifier`** (DenyInvalid / DenyIndeterminate). Routing-miss, `kid`-miss, and startup/config denies do **not** call `onBindReject`; they increment AD-19's unlabeled counter directly.
3. The `SpliceObserver` implementation MUST apply AD-19's cardinality rule: a `SystemId` not present in the routing table is never emitted as a label and is routed to the unlabeled counter. State this in AD-27 so the seam cannot be the vector for an AD-19 violation.

---

### NF-3 [MEDIUM] — AD-12's "relay's hand-managed VT pool" references an executor that AD-28 never defines; the adjudication threading shape is unpinned

**Introduced by:** AD-28 (new, but enumerates only SslHandler + JWKS executors) interacting with AD-12's tightened executor clause.

#### The two units

- **E-SECURITY-OIDC — "BindCredentialVerifier + ROPC adapter," in `security/`.** Reads AD-12's "Runs on the relay's hand-managed VT pool (AD-6/AD-28)" and the memlog intent ("a shared VT service for bind adjudication"). Builds a single bounded `ExecutorService` of virtual threads (per JEP 444 try-with-resources), sized via config, owned by `security/`. Backpressure on saturation = queue-bounded + fail-closed reject (AD-11).
- **E-RELAY-BIND — "BindInterceptor dispatch," in `relay/`.** Reads AD-28 as the **exhaustive** executor specification (it fixes SslHandler's pool, JWKS refresh, and `spring.threads.virtual.enabled` — three items, adjudication not among them). Concludes there is no shared adjudication pool; spawns one ad-hoc VT per bind (`Thread.ofVirtual().start(...)`) tracked only via AD-8's `ConnectionRegistry`. No bound, no backpressure.

#### The gap

AD-6 model 2 ("hand-managed virtual threads (control plane)") is generic; AD-28 was written to fix F-5's *specific* executors (SslHandler delegated tasks, JWKS refresh) and is silent on adjudication. AD-12 cross-references "AD-6/AD-28" for a pool that neither pins down to a shape. The memlog's "shared VT service" intent did not make it into an AD.

**Incompatibility, concretely:** under a bind-storm, E-RELAY-BIND's build creates an unbounded number of adjudication VTs (one per bind) — direct-memory/thread-table pressure with no fail-closed; E-SECURITY-OIDC's build bounds them and rejects on saturation. AD-22's "DENY in-flight bind adjudications" is a one-line `executor.shutdownNow()` for Team 1 and a registry walk for Team 2. Both obey AD-6 (hand-managed VTs) and AD-28 (which is silent). The two `BindInterceptor` wirings are not interchangeable.

#### Closing AD

**EXTEND AD-28 (or AD-12) — pin the adjudication executor.** Add to AD-28: "(4) bind adjudication runs on a single bounded hand-managed VT `ExecutorService` (JEP 444) owned by `security/`, shared across all binds, sized via config, fail-closed on saturation (AD-11); registered with the AD-22 drain (DENY-in-flight = `shutdownNow()` + await). Spawning one VT per bind outside this pool is forbidden." This makes AD-12's cross-reference resolve.

---

### NF-4 [MEDIUM] — The decoded `bind_*_resp` that triggers the AD-25 flip has no named forwarder; BindInterceptor (AD-3) and RelayHandler (AD-25) both legitimately touch it

**Introduced by:** AD-25 pinning the flip trigger to the **decoded** `bind_*_resp` (a specific PDU in the pipeline), which is also the transition PDU owned by AD-3's bind-family handler.

#### The two units

- **E-SECURITY-BIND — "BindInterceptor owns the whole bind family pre-couple," in `relay/`.** Per AD-3 ("inspect/handle ONLY the bind family … pre-couple") consumes the decoded `bind_*_resp`, writes it to the legacy client (codec re-encodes), then sets the flip flag on the ingress event loop. RelayHandler never sees or forwards the `bind_*_resp`; its first spliced PDU is the one **after** the `bind_resp`.
- **E-RELAY-SPLICE — "RelayHandler owns the transition," in `relay/`.** Per AD-25 ("RelayHandler flips on receipt of the decoded `bind_*_resp` ROK") treats the `bind_*_resp` as the transition PDU: detects ROK, flips, and forwards the `bind_*_resp` itself as the first spliced frame. BindInterceptor passes bind-family through without consuming once the verdict is obtained.

#### The gap

AD-25 made the decoded `bind_*_resp` simultaneously (a) the bind-family PDU AD-3 assigns to `BindInterceptor` and (b) the flip trigger AD-25 assigns to `RelayHandler`. Neither AD names who **forwards** it to the legacy client. AD-2's "forwarded exactly once" is satisfied by either unit individually, but not by both together.

**Incompatibility, concretely:** on a merged build the legacy client receives **two** `bind_*_resp` frames (one from BindInterceptor, one from RelayHandler). Even unmerged, the observable metrics differ — E-RELAY-SPLICE's `SpliceObserver.onFramedPdu` fires for the `bind_resp` (it was a spliced frame), E-SECURITY-BIND's does not (it was a decoded object handled by the interceptor). The wire bytes can also differ if the codec re-encodes non-canonically (field order, trailing padding) on Team 1's path versus byte-pass-through on Team 2's.

#### Closing AD

**TIGHTEN AD-25 — name the `bind_*_resp` forwarder explicitly.** Recommended: `BindInterceptor` forwards the `bind_*_resp` to the legacy client (it owns bind-family pre-couple per AD-3); `RelayHandler` observes the decoded `bind_*_resp` **read-only** to flip the flag and never forwards it. The first spliced PDU is the first PDU **after** the `bind_*_resp`. Add a sentence to AD-25 stating this so the transition PDU has exactly one owner.

---

### NF-5 [LOW] — AD-26 "the Mode B pattern" makes the `cacerts`/public-PKI opt-in scope ambiguous across modes

**Introduced by:** AD-26 (new) — specifically the parenthetical "(the Mode B pattern)".

#### The two units

- **E-CONFIG-ROLE-EGRESS (reading A) — "`cacerts` opt-in is Mode-B-only."** Reads "(the Mode B pattern)" as scope: public-PKI/`cacerts` SMSC trust is permitted **only** in Mode B. In Mode A egress, no operator trust store → refuse to start (AD-26 default is operator trust store, never `cacerts`).
- **E-CONFIG-ROLE-EGRESS (reading B) — "`cacerts` opt-in mechanism is the Mode-B-style opt-in, available in any mode."** Reads "(the Mode B pattern)" as naming the **mechanism** (loud warning + explicit ack), available in Mode A egress too. In Mode A egress, no operator trust store + `cacerts` opt-in flag → starts with a warning.

#### The gap

AD-26's "it is an explicit opt-in with a loud startup warning (the Mode B pattern) — never the default" does not say whether the opt-in is **available** in non-Mode-B egress or **restricted** to Mode B. AD-17's matrix forbids ingress+Mode-B and lists Mode A egress as requiring a client trust store (AD-26), but does not mention a `cacerts` opt-in flag for Mode A egress.

**Incompatibility, concretely:** the same config — Mode A egress, `companions.egress.trust=cacerts` opt-in set, no operator trust store mounted — refuses to start on reading A and starts (with warning) on reading B. Both obey AD-13/AD-26 (default is operator trust store) and AD-17 (matrix is silent on the opt-in).

#### Closing AD

**TIGHTEN AD-26 — state explicitly whether the `cacerts`/public-PKI opt-in is permitted only in Mode B or in any egress mode.** Recommended (matching the security posture): the opt-in is permitted in **any egress mode** with the Mode-B-style loud warning + ack (the threat is identical — trusting a public root for the SMSC peer); state this so reading B is canonical and reading A is foreclosed.

---

## Summary

### Closure

**9/9 prior findings CLOSED.** The revision's 7 new ADs + ~14 tightenings land where the prior review asked. The spine is now a build substrate for the first sprint (relay, security, config epics are all scopable).

### New findings introduced by the revision

| # | Severity | Seam | Closing action |
| --- | --- | --- | --- |
| NF-1 | HIGH | AD-22 vs AD-28 shutdown ordering (refresh-vs-cache-close) | TIGHTEN AD-22 — insert "stop JWKS refresh" before "close JWKS cache" |
| NF-2 | MEDIUM | AD-27 SpliceObserver trigger events vs AD-25/AD-11/AD-19 | TIGHTEN AD-27 — pin onBindAccept=flip, onBindReject=verifier-only, cardinality rule at the seam |
| NF-3 | MEDIUM | AD-12 "relay VT pool" not defined by AD-28 | EXTEND AD-28 (or AD-12) — pin adjudication executor (bounded shared VT pool) |
| NF-4 | MEDIUM | AD-25 transition PDU (`bind_*_resp`) has no named forwarder | TIGHTEN AD-25 — BindInterceptor forwards it; RelayHandler observes read-only to flip |
| NF-5 | LOW | AD-26 "the Mode B pattern" scope ambiguity | TIGHTEN AD-26 — state whether `cacerts` opt-in is Mode-B-only or any egress mode |

NF-1 should be fixed before the bootstrap/security epics split (it is a literal AD-vs-AD ordering contradiction). NF-2/NF-3/NF-4 should be fixed before the relay and security epics split (they affect the bind-path contract those epics will implement). NF-5 can land with the config epic.
