---
review: rubric-walker (UPDATE pass)
target: ARCHITECTURE-SPINE.md — UPDATE 2026-07-23 (AD-32/33/34 + amendments AD-27/3/25/19/30/24 + register)
role: judges the UPDATE against the good-spine checklist
baseline: spine PASSED the 2-round 8+2-lens gate on 2026-07-19 (see sibling reviews); this pass judges ONLY the 2026-07-23 UPDATE that resolved test-design blockers Q1–Q7
verdict: pass-with-findings
reviewer: rubric-walker
date: 2026-07-23
---

# Rubric-Walker Review — UPDATE (Q1–Q7 resolution)

> Scope discipline: the spine (AD-1..AD-31, stack, structural seed, capability map) was already gated and PASSED. This pass does NOT re-walk the inherited spine. It judges ONLY the delta: three new ADs (32/33/34), six amendments (27/3/25/19/30/24), the two register additions, and whether the delta is internally consistent, enforceable, and leaves no new divergence surface for the level below (epics/stories). The six checklist questions posed for this UPDATE structure the walk.

## Pre-walk — what the UPDATE changed

- **AD-32 (new, Q1)** — pre-couple non-bind PDU policy: 5-case dispatch (unbind handshake / enquire_link keepalive / any-other-well-formed → synthesize matching `_resp` + `ESME_RINVBNDSTS` + close + teardown / egress `generic_nack` pre-`bind_resp` = bind-failure propagation / `generic_nack` reserved for unresolvable frames). Fail-closed, zero knobs. Decisive — turns RELAY-002 from a determinism-only test into a property test.
- **AD-33 (new, Q7)** — bind-denial wire collapse: ALLOW→ROK; every denial → one generic `bind_*_resp` failure code; rich OIDC outcome logs + bounded counters only.
- **AD-34 (new, Q3)** — TLS cipher/protocol allowlist default pinned; empty provider-intersect → fail-fast. Closes the prior F3 (no shipped default).
- **AD-27 amended** — `onConnectionClosed(Direction, CloseReason)` + closed `CloseReason` enum; backs `relay_connections_closed_total{direction,reason}`; replaces latent RELAY-010 assumption.
- **AD-3 amended** — corollary carving unbind (handshake) and enquire_link (keepalive) out of the "non-bind = violation" rule.
- **AD-25 amended** — note that close-on-violation is above-spec fail-closed, always on.
- **AD-19 amended** — NO `system_id`/`command_id`/`ChannelId` label on ANY pre-flip counter; `command_id` only in TRACE via `ByteBuf.getInt(4)`, no codec helper.
- **AD-30 amended (Q5)** — shared-constant ArchUnit assertion + startup `ByteBufAllocatorMetric` self-check.
- **AD-24 amended (Q2/Q4)** — jcstress (cross-thread, nightly) + delay-injection soak; two-real-instance forward↔reverse E2E (weekly, validates DEP-1).
- **Register** — sharpened "no-rate-limit" (IdP amplification via abandoned in-flight ROPC; operator IdP rate-limiting REQUIRED) + new "pipelining ESMEs / short-bind-timeout clients closed".

The UPDATE is high-signal: every one of the 7 blockers landed as a concrete, enforceable Rule rather than a deferral, and the Deferred surface actually shrank (cipher allowlist and `bind_resp` collapse both moved from deferred to fixed). Findings below are refinements, not blockers.

---

## Checklist walk

### 1. Do the new ADs fix REAL divergence points (or are they over-/under-specified)?  **YES, with two under-specified seams.**

- **AD-32** fixes the single most load-bearing relay divergence (the pre-couple window). The 5-case dispatch, the exact `command_status` (`ESME_RINVBNDSTS` 0x4), the `command_id` response-bit formula (`offender | 0x80000000`), the carve-outs, and "zero knobs" are all at the right altitude — two relay stories cannot diverge on the wire bytes. Verified against SMPP 3.4: `ESME_RINVBNDSTS`=0x00000004 and `ESME_RINVCMDID`=0x00000003 are correct; the response-bit-set (0x80000000) convention is correct (§3.2); `generic_nack` reservation for unresolvable frames with `seq=0` is correct (§4.3).
- **AD-33** fixes a real oracle divergence (distinct denial codes → enumeration). The binary collapse is the right invariant; deferring only the exact status code to one owning story is correct (collapse is the invariant, code is low-blast-radius wire detail).
- **AD-34** closes the prior F3 cleanly.
- **AD-30 (Q5)** — the two-layer guard (ArchUnit compile-time + startup runtime self-check) is exactly the belt-and-braces needed; each closes a gap the other cannot reach.

**Under-specified seams (findings F2, F3 below):**

- The `command_id → response-body-requirement` lookup (AD-32 case 3) is named but its **ownership is not pinned**. AD-7 puts non-bind PDU shapes out of `codec`'s owned scope ("every non-bind PDU… never parsed into a typed object"), so the lookup is neither clearly codec (protocol shape knowledge) nor clearly relay (policy). Two stories could place it differently. AD-19 already established the principle for `command_id` ("proxy-side `ByteBuf.getInt(4)`, never a codec helper"); AD-32 should extend the same ownership statement to the body-requirement lookup.
- AD-32 case 3's enumeration lists specific `command_id`s but is silent on **`outbind` (0x0B)**, which AD-27 declares opaque-spliced. `outbind` has no `_resp` in SMPP 3.4, so the case-3 formula `offender | 0x80000000` fabricates an undefined `0x8000000B`. A minor over-specification; needs an explicit exception.

### 2. Is every new AD's Rule ENFORCEABLE and does it prevent its stated divergence?  **YES.**

- AD-32: each case is independently testable (RELAY-002/002a/002b/002c map 1:1). "Zero config knobs" is enforceable by a config-key scan. The teardown assertions (ROPC cancelled, password zeroized, registry entry removed) are observable via the fake verifier + capturing observer. The `writeAndFlush+CLOSE` flush-before-FIN ordering is wire-assertable.
- AD-33: the binary wire contract is enforceable by asserting no denial path emits a code other than ROK or the one generic failure code; rich outcome appears only in log/counter sinks.
- AD-34: the startup intersect + fail-fast is a deterministic startup test.
- AD-30: both the ArchUnit reference scan and the `ByteBufAllocatorMetric` ≥-budget assertion are deterministic.
- AD-24: jcstress + delay-soak + two-instance E2E are concrete tiers.

One enforceability nuance (not a finding, recorded for the owning story): AD-32 case 3 mandates "cancel the ROPC call at the HTTP-client layer (not only the VT scope)", but the **HTTP client itself is unnamed in the Stack**. Any modern Java HTTP client supports request cancellation, so this is not a divergence today, but the cancellation requirement makes the HTTP-client choice more load-bearing than it was before the UPDATE.

### 3. Does anything now under Deferred still let two units diverge?  **NO — the Deferred surface is clean and shrank.**

Re-walked every Deferred entry. The UPDATE moved two items from deferred to fixed (cipher allowlist → AD-34; `bind_resp` collapse → AD-33) and left nothing ambiguous. Multi-carrier routing remains deferred but v1 cardinality is pinned at 1:1 (AD-29), so no divergence. The exact `bind_resp` failure code is single-story-owned by explicit statement. The one latent item the UPDATE *introduced* without docking — the response-body-requirement lookup — is NOT in Deferred and NOT pinned (F2).

### 4. Does AD-32 weaken or contradict any inherited AD?  **ONE consistency tension (F1).**

- **AD-9 (statelessness):** consistent and reinforcing — AD-32's "no buffer mode, close on violation" is explicitly chosen to avoid pre-couple buffering state, preserving statelessness.
- **AD-25 (flip):** consistent — AD-32 operates strictly pre-flip and never touches the single-flipper mechanism; AD-25's note correctly frames close-on-violation as implicitly failing any in-flight bind (acceptable per AD-11).
- **AD-27 (seams):** consistent — the `CloseReason` enum is the telemetry seam for AD-32's close path. One completeness gap on the enum (F4).
- **AD-11 (fail-closed):** consistent and stronger — close-on-violation is an above-spec fail-closed policy; teardown cancels the in-flight bind. No accept-on-indeterminate introduced.
- **AD-3 (hybrid PDU model) — TENSION (F1):** AD-3's main Rule says "inspect/handle ONLY the bind family + unbind(+resp) pre-couple… All other PDUs are opaque framed bytes, never inspected." AD-32 case 3 reads `command_id` + `sequence_number` from the **header of every well-formed non-bind PDU** pre-couple (to synthesize the matching `_resp`). The amended AD-3 corollary carves out `unbind` and `enquire_link` but is **silent on case 3's header read**. So an implementer reading AD-3 literally ("inspect/handle ONLY bind family + unbind") would NOT read a non-bind PDU's header, while AD-32 requires it. The body is never parsed (opacity principle holds), but the literal AD-3 wording is now narrower than what AD-32 requires. A one-line extension of the AD-3 corollary (acknowledging case 3 reads header fields `command_id`/`sequence_number` without parsing the body) reconciles them.

### 5. Is the close-on-violation / teardown path consistent with AD-22 + AD-8?  **YES, with one ordering nuance (F5).**

- **AD-8 (ConnectionRegistry teardown):** consistent — AD-32's "remove the ConnectionRegistry entry" is achieved via the close → `channelInactive` → registry-remove path AD-8 defines. Zeroize-on-teardown aligns with AD-12. The per-connection teardown and AD-22's shutdown drain compose correctly (an entry removed by AD-32 before SIGTERM is simply absent from the drain enumeration).
- **AD-22 (graceful shutdown):** the two cancellation scopes are distinct and coherent — AD-32 is per-connection (cancel one ROPC at the HTTP layer during normal operation); AD-22 step 2 + AD-28(4) is pool-wide (`shutdownNow()` during SIGTERM). They do not conflict.
- **Ordering nuance (F5):** AD-32 case 3 lists the steps as `writeAndFlush(_resp).addListener(CLOSE)` **then** "cancel the ROPC call". If the cancel is sequenced after the write scheduling, there is a window — widened by PERF-3's deliberately large bind latency — in which the in-flight ROPC returns `Allow`, the BindInterceptor attempts to flip + couple on a channel that is closing/closed. AD-8's `channelInactive` teardown should catch the stray couple, but the safer, race-free ordering is to cancel the ROPC **first / atomically with violation detection**, before the `_resp` write. The literal clause order invites a implementer to cancel-last. Worth pinning explicitly so the race-soak (RELAY-024) can assert cancel-wins.

### 6. Any whole dimension the UPDATE touched left silent?  **NO whole dimension; two sub-seams.**

Wire behavior, denial contract, TLS allowlist, telemetry cardinality, test toolchain, and memory budget are all covered for the dimensions the UPDATE touched. The accepted-risk register was correctly extended (IdP amplification, pipelining-ESME closure). The two sub-seams left silent are the response-body-requirement lookup ownership (F2) and `CloseReason` enum completeness for pre-SMPP closes (F4). No whole dimension (security/trust, observability, error handling, concurrency) was left silent by the delta.

---

## Findings (most-severe first)

| # | Severity | AD / location | Summary | Suggested fix |
|---|---|---|---|---|
| F1 | medium | AD-33 (line 259) vs AD-27 (line 223) | The wire-collapse enumeration lists only adjudication outcomes (invalid-credential/indeterminate/`kid`-miss/JWT-fail/cert-fail/introspection-fail). **Routing-miss and config-deny** — which AD-27 routes to the unlabeled counter and explicitly excludes from `onBindReject` — are NOT in the AD-33 collapse. Their wire shape (which `bind_resp` code, or whether a `bind_resp` is emitted at all vs a bare close) is undefined. An attacker on the trusted network (or spoofing a `system_id`, an accepted risk) can therefore distinguish "system_id not routed" from "credential rejected" — exactly the enumeration oracle AD-33's `Prevents` claims to close. A residual timing differential also remains (routing-miss is instant; adjudicated denial waits on IdP RTT/timeout). | Amend AD-33 to state explicitly that **ALL** bind denials — including routing-miss and config-deny — collapse to the SAME generic `bind_*_resp` failure code (same wire shape: emit the `bind_resp`, then close), so no code-shape oracle exists. Acknowledge the timing differential as a residual accepted risk (or mandate uniform deny timing if operators require it). |
| F2 | low-medium | AD-3 (line 80) vs AD-32 case 3 (line 251) | AD-3 says "inspect/handle ONLY the bind family + unbind(+resp) pre-couple"; the amended corollary carves out `unbind` + `enquire_link` but is **silent on case 3**, which reads `command_id` + `sequence_number` from every well-formed non-bind PDU header. Literal AD-3 now contradicts AD-32 (body opacity holds, but header inspection of non-bind PDUs is new). | Extend the AD-3 corollary by one clause: "case 3 reads only the header fields (`command_id`, `sequence_number`) of a non-bind PDU to synthesize the matching `_resp`; the body is never parsed — AD-3 opacity holds." |
| F3 | low-medium | AD-32 case 3 (line 251) | The `command_id → response-body-requirement` lookup is named but its **owner is not pinned**. AD-7 puts non-bind PDU shapes outside `codec`'s owned scope, leaving the lookup in a codec-vs-relay seam ambiguity. | Add to AD-32: "the lookup is a proxy-side (`relay/`) constant — not a codec helper — consistent with AD-19's `ByteBuf.getInt(4)` principle and AD-7 inward-only." |
| F4 | low-medium | AD-27 `CloseReason` enum (line 223) | The new closed enum lacks a bucket for **pre-SMPP TLS-handshake-failure** closes (ingress Mode C cert fail per AD-11; egress TLS handshake fail per RELAY-021) — `channelInactive` still fires in `RelayHandler` on a TLS failure, but no reason fits. The **case-5 unresolvable-frame** close (unknown `command_id` → `generic_nack`) is also ambiguously bucketed vs `PRE_COUPLE_NON_BIND_PDU`/`DECODE_ERROR`, so two implementers could emit different `reason` labels. | Either add `TLS_HANDSHAKE_FAILED` (or explicitly scope `relay_connections_closed_total` to post-TLS-establishment only) and pin which enum value the case-5 unknown-`command_id` close carries. |
| F5 | low | AD-32 case 3 teardown ordering (line 251) | "cancel the ROPC call" is listed AFTER `writeAndFlush(_resp).addListener(CLOSE)`. Sequenced literally, this leaves a window (widened by PERF-3) in which an in-flight `Allow` completes and attempts to couple on a closing channel. | Re-order / clarify: the ROPC cancellation is **first or atomic** with violation detection, before the `_resp` write, so cancel-wins is assertable by RELAY-024. |

### Notes (not findings — for the owning story / walkthrough)

- **outbind (0x0B) exception.** AD-32 case 3's `offender | 0x80000000` formula assumes every command has a `_resp`; `outbind` has none in SMPP 3.4, so the formula fabricates `0x8000000B`. Fold into F3's amendment: list `outbind` as a case-5 exception (`generic_nack` + close, or bare close). Edge case (outbind pre-couple from the wrong direction is malformed behavior regardless), but the spec should not imply a non-existent `_resp`.
- **Timing oracle on AD-33.** Even with F1 fixed (uniform code), routing-miss responds instantly while adjudicated denials wait on IdP RTT/timeout. Closing a timing oracle fully is expensive (pad all denials to worst-case). Most products accept it; recommend an explicit register entry rather than silent acceptance.
- **HTTP-client unnamed.** AD-32's "cancel at the HTTP-client layer" makes the ROPC HTTP-client choice load-bearing for resource hygiene; the Stack still does not name it. Not introduced by this UPDATE; flag for the ROPC-adapter story.

---

## Verdict: **pass-with-findings**

The UPDATE resolves all seven test-design blockers with concrete, enforceable Rules and shrank the Deferred surface rather than enlarging it. Every new AD's Rule prevents its stated divergence; the new ADs do not weaken the inherited fail-closed / stateless / opacity invariants (AD-11/9/3) and compose cleanly with AD-22/AD-8 teardown. The stack and SMPP 3.4 references are accurate.

Five findings survive, none critical and none blocking the walk-down to epics/stories. The most significant is F1 (AD-33's wire collapse omits routing-miss / config-deny, leaving a `system_id`-enumeration oracle that undermines AD-33's stated `Prevents`) — this should be closed in the spine before the bind-adjudication stories are authored, because it changes what those stories must emit on the wire. F2 (AD-3 corollary vs AD-32 case-3 header read) is a consistency fix that should land alongside F1. F3/F4/F5 are low-cost clarifications (lookup ownership, enum completeness, teardown ordering) that can be folded into the owning stories or a small spine amendment at finalize.

Recommended finalize actions: close **F1 + F2** in the spine (AD-33 collapse extension + AD-3 corollary clause); assign **F3/F4/F5** to the AD-32-owning relay story and the AD-27-owning observability story as explicit acceptance criteria.
