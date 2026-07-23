---
review: adversarial (one-level-down divergence) — UPDATE only
target: ARCHITECTURE-SPINE.md (Companions v1, status: final) — UPDATE 2026-07-23 (AD-32/33/34 + AD-27/3/25/19/30/24 amendments)
reviewer: adversarial
prior: reviews/review-adversarial.md (F-1..F-9, FAIL) + reviews/verify-adversarial.md (NF-1..NF-5, PASS-WITH-FINDINGS, all closed in-spine)
created: 2026-07-23
method: Construct pairs of units ONE LEVEL DOWN (epics / stories) that each obey every AD to the letter and still build incompatibly. Scope is the UPDATE only — the spine AD-1..AD-31 already PASSED the 2-round 8+2-lens gate and is NOT re-reviewed here. Every pair below is introduced by AD-32/33/34 or an amended AD and could not have existed in the prior spine.
---

# Adversarial Review — Companions v1 UPDATE (2026-07-23: Q1–Q7 resolution)

## Verdict

**PASS-WITH-FINDINGS.** The UPDATE lands where the test-design blockers asked: AD-32 gives Q1 a fail-closed, zero-knob, SMPP-3.4-conformant policy; AD-33 gives Q7 a clean wire collapse; AD-34 pins Q3's cipher default; the amendments close the testability seams Q2/Q4/Q5 named. The spine remains a build substrate and the Q1–Q7 exits are unblocked.

But the UPDATE introduces **seven new seams (UF-1..UF-7)** where two AD-compliant units one level down still build incompatibly. None re-opens a prior finding, and none is a first-sprint scoping blocker the prior gate already covered — they are all NEW, created by AD-32/33/34 or an amended AD. The two most serious are both HIGH and both live inside AD-32:

- **UF-1**: AD-32 case-3 response synthesis authorizes a `command_id → response-body-requirement` lookup and a `command_id | 0x80000000` transform without saying WHO owns the lookup (codec vs proxy) or that the offender must be a REQUEST-direction PDU — so it collides with AD-7 (inward-only) / AD-19 (no codec helper) / AD-3 (never parsed), and silently mis-handles response/alert offenders.
- **UF-2**: AD-32 case-3 teardown is a per-bind concurrent operation (cancel ROPC + zeroize + registry remove) with no ordering pinned against the AD-25 flip, the AD-12 ROPC verdict callback, or the AD-8 `channelInactive` teardown — and `onConnectionClosed` exactly-once is not guaranteed.

UF-3..UF-7 are MEDIUM/LOW and fixable with targeted tightenings. Findings are ranked most-severe first; each names two concrete units, the gap, and the closing AD.

---

## UF-1 [HIGH] — AD-32 case-3 response synthesis has no owner and assumes a request-direction offender; collides with AD-7/AD-19/AD-3 and mis-handles response/alert PDUs

**AD-32 case 3 prescribes synthesis of a "matching `_resp`" — `command_id = offender.command_id | 0x80000000`, plus a "spec-conformant body synthesized from a `command_id → response-body-requirement` lookup" — but does not say which unit owns that lookup, and the `| 0x80000000` transform silently assumes the offender is a request PDU (bit 31 clear). Both omissions open a divergence.**

### The two units

- **E-CODEC — "pure SMPP protocol layer," in `codec/`.** Reads AD-7 (codec owns "PDU model + bind-family framing" and "the single source of truth for which `command_id`s are parsed vs opaque-spliced") and concludes the `command_id → response-body-requirement` table is SMPP protocol knowledge → lives in `codec`. Exposes a `NonBindRespSynthesizer.synthesize(int offenderCommandId, int seq) → ByteBuf`. Argues this is "response synthesis, not request parsing," so AD-3 opacity holds.
- **E-RELAY — "RelayHandler pre-couple violation handling," in `relay/`.** Reads AD-19's explicit "The offending `command_id` is permitted ONLY in TRACE logs, sourced via a proxy-side `ByteBuf.getInt(4)` read on the opaque framed buffer — **never via a codec helper** (preserves AD-7 inward-only + 'codec never emits metrics')" and AD-3's "every non-bind PDU … is an opaque framed `ByteBuf`, never parsed into a typed object." Concludes codec must NOT be asked to synthesize a non-bind `_resp` (that is a codec helper on a non-bind PDU). Builds the lookup table locally in `relay/` as a static `Map<Integer, RespBodyTemplate>`.

### The gap — three facets

1. **Owner of the lookup is undefined; the two readings are mutually exclusive.** If codec owns it (E-CODEC), the proxy gains a NEW `proxy → codec` inward edge for NON-bind PDUs — exactly the edge AD-7 scopes away ("every non-bind PDU … is an opaque framed `ByteBuf`") and AD-19 forbids ("never via a codec helper"). If proxy owns it (E-RELAY), SMPP protocol semantics (which `command_id` carries which `_resp` body — `submit_sm_resp.message_id` C-octet, `query_sm_resp.{message_id, final_date, message_state, error_code}`, `submit_multi_resp` multi-`message_id`, `data_sm_resp` TLV-ignore, …) live OUTSIDE the pure codec layer, duplicating the protocol knowledge AD-7 centralized. CODEC-026/027/028 lock "the 6-id bind family is the parsed surface" but say nothing about "the non-bind response-body table," so two independently-built tables WILL disagree on an edge case (`submit_multi_resp` vs `submit_sm_resp` body shape; `alert_notification` which has NO `_resp` in SMPP 3.4). On a merged build the wire bytes for the same offender differ.

2. **The offender-direction assumption is unstated; response/alert offenders fall through every case.** AD-32 case 3 lists only request-direction examples (`submit_sm`, `data_sm`, `query_sm`, `replace_sm`, `cancel_sm`, `submit_multi`, `deliver_sm`, `alert_notification`) and uses `command_id | 0x80000000`, which is a **no-op** for an offender whose bit 31 is already set (any `_resp` PDU: `deliver_sm_resp` 0x80000005, `submit_sm_resp` 0x80000004, `data_sm_resp`, `query_sm_resp`, `replace_sm_resp`, `cancel_sm_resp`, `submit_multi_resp`). "Synthesize the matching `_resp`" of a `_resp` is malformed (a resp-to-a-resp). And `alert_notification` (0x00000102) has **no response PDU** in SMPP 3.4 at all — the lookup has no entry. These well-formed, known `command_id`s in the wrong state are NOT case 5 ("generic_nack RESERVED for unresolvable frames: unknown `command_id`/corrupt length" — explicitly "Never use `generic_nack` for a well-formed PDU merely in the wrong state"). So a pre-flip `deliver_sm_resp` / `submit_sm_resp` / `alert_notification` is **unhandled by AD-32's case list**. E-CODEC synthesizes a header-only resp with a duplicated command_id (malformed); E-RELAY escalates to case-5 `generic_nack` (contradicting case 5's own rule). Both pass every AD; the wire differs.

3. **"command_id only in TRACE" (AD-19) vs AD-32's need to read command_id for logic.** AD-32 case selection AND synthesis both require reading the offender `command_id` on the hot path pre-flip — not just for a TRACE log. AD-19's "permitted ONLY in TRACE logs" is about *emission*, but its absolute wording lets a unit refuse to read `command_id` for logic at default log level. E-RELAY reads it for classification; an over-literal E-CODEC-companion unit treats reading-for-logic as an AD-19 violation.

### Incompatibility, concretely

A legacy ESME sends `deliver_sm_resp` (a misbehaving client responding to a DLR it never got) pre-`bind_resp`. E-CODEC's build calls `NonBindRespSynthesizer.synthesize(0x80000005, seq)` → emits a PDU with `command_id = 0x80000005 | 0x80000000 = 0x80000005` (a second `deliver_sm_resp`) with `ESME_RINVBNDSTS` — a resp-to-a-resp on the wire. E-RELAY's build, finding no request-direction match, escalates to `generic_nack(ESME_RINVCMDID)` + close — which AD-32 case 5 *forbids* for a well-formed wrong-state PDU. Same input, two wire outputs, both teams pass every AD. Even for the nominal request case, E-CODEC's `submit_multi_resp` body (C-octet `message_id` list) and E-RELAY's hand-rolled table disagree on whether to emit one `message_id` or a count-prefixed list.

### Closing AD

**TIGHTEN AD-32 (and reconcile with AD-7/AD-19/AD-3).** Add a paragraph to AD-32 case 3:
1. **Owner:** the `command_id → response-body-requirement` lookup lives in **`proxy/relay`** as a static, codec-independent table. Response synthesis from a known integer `command_id` is NOT request parsing (the offender body is never read), so AD-3 opacity and AD-7 inward-only hold; the codec gains NO non-bind helper. State this explicitly so AD-19's "never via a codec helper" is honored.
2. **Direction:** case 3 applies ONLY to REQUEST-direction non-bind PDUs (bit 31 clear). Add an explicit case for "well-formed non-bind PDU whose `command_id` already has bit 31 set (`*_resp`) or that has no `_resp` defined in SMPP 3.4 (`alert_notification`)" → close + AD-32 teardown, emitting NO synthetic resp (or `generic_nack` — but if `generic_nack`, strike the case-5 sentence "Never use `generic_nack` for a well-formed PDU merely in the wrong state" or carve this sub-case).
3. **Reading-for-logic is authorized:** clarify AD-19 that the `getInt(4)` read is the sole permitted `command_id` access for BOTH logic (case selection + synthesis) AND TRACE emission; only *emission to logs/metrics* is TRACE-gated.

---

## UF-2 [HIGH] — AD-32 case-3 teardown is a concurrent per-bind operation with no ordering vs the AD-25 flip, the AD-12 ROPC callback, or AD-8 channelInactive; `onConnectionClosed` exactly-once + registry double-remove not guaranteed

**AD-32 case 3 fires on the ingress event loop and says "tear down any in-flight bind on that connection: cancel the ROPC call at the HTTP-client layer (not only the VT scope), zeroize the password, remove the `ConnectionRegistry` entry" — then `writeAndFlush(_resp).addListener(CLOSE)`. It does not order these steps relative to (a) the AD-25 flip trigger (`bind_*_resp` ROK in flight on the egress leg), (b) the AD-12 ROPC `CompletableFuture` verdict callback (which may be completing Allow concurrently), or (c) the AD-8 teardown path ("teardown removes via `channelInactive`", which the addListener(CLOSE) fires later). Two AD-obeying RelayHandlers race differently.**

### The two units

- **E-RELAY-SYNC — "remove-then-close."** In the case-3 handler: (1) remove the `ConnectionRegistry` entry synchronously, (2) zeroize password + cancel ROPC, (3) `writeAndFlush(_resp).addListener(CLOSE)`, (4) call `onConnectionClosed(INGRESS, PRE_COUPLE_NON_BIND_PDU)`. The later `channelInactive` (from CLOSE) finds no entry and does NOT call `onConnectionClosed` again (entry absent ⇒ already-notified).
- **E-RELAY-DEFER — "close-then-channelInactive."** In the case-3 handler: (1) stash `CloseReason=PRE_COUPLE_NON_BIND_PDU` on the channel attribute, (2) `writeAndFlush(_resp).addListener(CLOSE)`, (3) cancel ROPC + zeroize. Defers registry removal AND `onConnectionClosed` to `channelInactive` (honoring AD-8's "teardown removes via `channelInactive`" literally).

### The gap — three concurrent races AD-32 does not order

1. **Registry double-remove / `onConnectionClosed` double- or under-count.** E-RELAY-SYNC removes in the handler and treats `channelInactive` as a no-op; E-RELAY-DEFER does the opposite. AD-8 says teardown removes via `channelInactive`; AD-32 case 3 says "remove the `ConnectionRegistry` entry" inside the violation handler. Both instructions exist. A merged RelayHandler that takes AD-8 + AD-32 each at face value removes the entry twice (once in the handler, once in `channelInactive`) AND fires `onConnectionClosed` twice — `relay_connections_closed_total` double-counts. Conversely, a build that reads AD-27's "called by RelayHandler on teardown" as "channelInactive-only" will MISS the close if the CLOSE listener never fires (e.g. a concurrent RST pre-empts the flush). AD-27 does not state that `onConnectionClosed` is **exactly-once / idempotent**, nor which "teardown" (handler vs channelInactive) owns it.

2. **Race vs the AD-25 flip (the bind_*_resp already in flight on the egress leg).** The case-3 window is pre-flip by definition, but "pre-flip" is a wall-clock window, not a lock. The SMSC's `bind_*_resp` ROK can be in flight on the egress leg — forwarded by `BindInterceptor` toward the ingress event loop — at the instant case 3 fires for a pipelined `submit_sm`. E-RELAY-SYNC removes the registry entry first ⇒ the arriving `bind_*_resp` finds no peer-egress Channel to couple ⇒ BindInterceptor drops it (connection closing anyway — benign). E-RELAY-DEFER has NOT yet removed the entry ⇒ the `bind_*_resp` arrives, the flip fires, the pair couples — **after** the proxy already wrote `submit_sm_resp(RINVBNDSTS) + CLOSE` to the legacy client. The legacy ESME now receives BOTH a `submit_sm_resp` RINVBNDSTS+FIN AND a `bind_*_resp` ROK. AD-25 says flip on receipt of the decoded `bind_*_resp` ROK; AD-32 case 3 says close on the violation. Neither AD says the flip must re-check a "tearing-down" sentinel, so the two units couple-or-not differently for the identical interleaving.

3. **Race vs the AD-12 ROPC verdict callback + the unreachable "HTTP-client layer" cancel.** AD-32 demands "cancel the ROPC call **at the HTTP-client layer** (not only the VT scope)." But AD-12's port contract is `CompletableFuture<Verdict> verify(...)` — the port exposes a CF, not an HTTP-cancel handle. `cf.cancel(true)` may or may not abort the underlying HTTP request depending on the adapter. E-RELAY (relay package) can only call `cf.cancel(true)` — it cannot reach the HTTP client through the port abstraction. E-SECURITY (security package, owns the ROPC adapter per AD-28(4)) can abort the HTTP call but has no port method to invoke. The sharpened register entry (IdP amplification via abandoned in-flight ROPC) is *the* reason AD-32 insists on HTTP-layer cancel — yet the port that would carry it does not exist. Two outcomes: a late-arriving `Allow` verdict completes inside the closing window and, finding (or not finding) the registry entry per race #2, either forwards the bind to an SMSC that is about to receive a FIN (wasted SMSC work + a bind the proxy immediately abandons) or is silently dropped. AD-22's "DENY in-flight" is pool-shutdown at SIGTERM; it does not govern the per-bind case-3 cancel.

### Incompatibility, concretely

Pipelined ESME: `bind_transceiver` → (adjudication Allow, bind forwarded to SMSC) → `submit_sm` before `bind_resp`. SMSC `bind_*_resp` ROK lands within microseconds of the case-3 handler. E-RELAY-SYNC build: legacy gets `submit_sm_resp(RINVBNDSTS)` + FIN, no `bind_resp` (entry already gone). E-RELAY-DEFER build: legacy gets `submit_sm_resp(RINVBNDSTS)` + FIN AND `bind_*_resp(ROK)`, and the pair momentarily couples. Published `relay_connections_closed_total{reason=PRE_COUPLE_NON_BIND_PDU}` differs by 1× vs 2× across builds (race #1). The IdP either is or is not spared the ROPC completion depending on whether the cancel reached the HTTP layer (race #3). Both builds pass AD-8, AD-25, AD-27, AD-32, AD-12.

### Closing AD

**TIGHTEN AD-32 + AD-27 + AD-12.**
1. **AD-32 teardown ordering:** the case-3 handler removes the registry entry **synchronously and marks it tearing-down BEFORE `writeAndFlush`**, so the AD-25 flip re-checks the entry (flip is a no-op if the entry is absent or tearing-down — add this re-check to AD-25). Cancel + zeroize run on the same event loop, before CLOSE.
2. **AD-27 exactly-once:** state that `onConnectionClosed` is **idempotent / exactly-once per channel** (guarded by a CAS on the channel attribute) and is owned by ONE teardown site — recommend `channelInactive`, with the handler only stashing the `CloseReason`. Removes the double/miss-count ambiguity.
3. **AD-12 port:** the `verify` port must carry a cancellation handle that aborts the HTTP client call (e.g. `verify` returns a `VerdictRequest` with `CompletableFuture<Verdict> future()` + `void cancelHttp()`, or `ScopedValue<RequestContext>` carries an abort signal the adapter binds to the HTTP request). Without this, AD-32's "HTTP-client layer" cancel is unimplementable through the seam AD-12 fixes.

---

## UF-3 [MEDIUM] — AD-33's "every denial → one bind_*_resp failure code" enumerates only verifier outcomes; SMSC-side bind failures (AD-32 case-4 generic_nack, non-ROK bind_resp, egress unbind/RST/half-close pre-bind_resp) are not explicitly collapsed, so the enumeration oracle leaks back in

**AD-33 collapses "every denial" to one generic bind-failure code, but its enumeration ("invalid credential, indeterminate/timeout/network-error/`kid`-miss/JWT-fail/cert-fail/introspection-fail") lists ONLY verifier (AD-12) outcomes. AD-32 case 4 routes an SMSC `generic_nack` pre-`bind_resp` to "the AD-33 deny path," but the other SMSC-side bind-failure shapes are not named, and AD-25's "implicitly fails any in-flight bind WITHOUT a `bind_resp`" appears to contradict AD-33's "every denial → `bind_*_resp`."**

### The two units

- **E-SECURITY-BIND — "collapse all bind failures to the one code."** Reads AD-33's intent (no enumeration oracle) and routes EVERY bind failure — verifier Deny, SMSC `generic_nack` (AD-32 case 4), non-ROK `bind_*_resp`, egress connect-fail, egress RST/unbind/half-close pre-`bind_resp` — to the single generic `bind_*_resp` failure code on the ingress.
- **E-RELAY-EGRESS — "propagate only what AD-32 case 4 names."** Reads AD-33's enumeration literally (verifier outcomes only) and AD-32 case 4 ("generic_nack from SMSC → AD-33 deny path"). Concludes the collapse covers verifier denials + SMSC `generic_nack` ONLY. For a non-ROK `bind_*_resp`, an egress RST, an egress unbind, or an egress half-close pre-`bind_resp`, E-RELAY-EGRESS propagates a DIFFERENT code (the SMSC's own non-ROK status, or nothing / a distinct SMSC-side failure code), arguing AD-33's "every denial" is verifier-scoped.

### The gap

AD-33's scope sentence — "scoped to `bind_*_resp` answering a `bind_*` request only" — fixes the *response shape*, not the *set of outcomes collapsed*. The outcome enumeration is verifier-only. AD-32 case 4 explicitly routes ONE SMSC failure (`generic_nack`) into the collapse; the other SMSC-side bind failures (non-ROK `bind_*_resp`, egress unbind/RST/half-close/connect-fail pre-`bind_resp`) are not routed. So two readings both pass AD-33 and AD-32:

- A non-ROK `bind_*_resp` from the SMSC (e.g. `ESME_RINVSYSID`) → E-SECURITY-BIND rewrites it to the generic code on the ingress (collapse holds); E-RELAY-EGRESS forwards the SMSC's distinct non-ROK code (collapse broken — an attacker probing `system_id`s now distinguishes "IdP said no" from "SMSC said no via RINVSYSID" from "SMSC generic_nack").
- An SMSC that tears down with `unbind` (AD-32 case 1) pre-`bind_resp` vs one that tears down with `generic_nack` (case 4) → E-RELAY-EGRESS treats case 1 as "no bind failure propagation" (only case 4 propagates) ⇒ the ingress hangs waiting for a `bind_resp` that never comes; E-SECURITY-BIND propagates both uniformly.

The collision with AD-25 sharpens it: AD-25 says close-on-violation (AD-32 case 3) "implicitly fails any in-flight bind **without** a `bind_resp`" — i.e. case 3 sends NO `bind_resp`. But a bind WAS in flight and IS now failed. AD-33 says "every denial → `bind_*_resp` carrying one generic failure code." A unit that classifies case-3-with-bind-in-flight as a "bind denial" (defensible — the bind was denied) routes it through AD-33 and emits a `bind_*_resp`, contradicting AD-25/AD-32 (which emit the matching non-bind `_resp` + close, no `bind_resp`). The line between "bind denial (AD-33)" and "connection close that implicitly fails a bind (AD-25/AD-32)" is unstated.

### Incompatibility, concretely

Same `system_id`, two SMSC teardown signals pre-`bind_resp`: `generic_nack` (case 4) vs `unbind` (case 1) vs non-ROK `bind_transceiver_resp` (`ESME_RINVSYSID`). E-SECURITY-BIND emits the identical generic failure code for all three (collapse holds — attacker learns nothing). E-RELAY-EGRESS emits the generic code for `generic_nack` only; for `unbind` it hangs the ingress; for non-ROK `bind_resp` it forwards `ESME_RINVSYSID`. An attacker observing ingress `bind_resp` codes now distinguishes three SMSC-side states — the exact `system_id`-enumeration / IdP-availability oracle AD-33 was written to kill. Both builds pass AD-33 (enumeration is verifier-only) and AD-32 (case 4 routed).

### Closing AD

**TIGHTEN AD-33 — make the collapsed-outcome set explicit and exhaustive.** State that the single generic bind-failure code is emitted for the union of: (a) every verifier `Deny*` (already listed); (b) EVERY egress-side bind-establishment failure pre-`bind_resp` — SMSC `generic_nack` (AD-32 case 4), non-ROK `bind_*_resp`, egress connect-fail (CloseReason `EGRESS_CONNECT_FAILED`), egress RST/unbind/half-close pre-`bind_resp`. Add a sentence clarifying that AD-32 case 3 (pre-couple non-bind violation on a connection with a bind in flight) is NOT a "bind denial" under AD-33 — it sends the matching non-bind `_resp` + close and NO `bind_resp` (reconciling AD-25's "without a `bind_resp`" with AD-33's "every denial"). This closes the AD-25↔AD-33 tension too.

---

## UF-4 [MEDIUM] — AD-27's `CloseReason` enum is not exhaustive over the UPDATE's close paths; ~6 real close reasons fall through, so closes are missed or mislabeled

**AD-27 fixes `CloseReason` as a closed enum `{PEER_HALF_CLOSE, PEER_RST, EGRESS_CONNECT_FAILED, OVERSIZED_FRAME, PRE_COUPLE_NON_BIND_PDU, SHUTDOWN_DRAIN, DECODE_ERROR}` and pins cardinality at "2 × |CloseReason|." But the UPDATE adds (or relies on) close paths the enum does not name, and AD-27 does not say `onConnectionClosed` is called for EVERY close — so RelayHandler either misses closes or maps them to the nearest label, differently per build.**

### The gap — close paths with no enum value

| Close path (AD source) | Closest enum value | Problem |
| --- | --- | --- |
| AD-32 case 1 — `unbind`/`unbind_resp` handshake close (proxy emits `unbind_resp` then closes) | PEER_HALF_CLOSE? | Not peer-initiated half-close; clean proxy-initiated post-handshake. No value. |
| AD-32 case 4 — SMSC `generic_nack` pre-`bind_resp` → tear down egress | EGRESS_CONNECT_FAILED? | The connect succeeded; the SMSC sent `generic_nack`. Semantically wrong label. |
| AD-32 case 5 — unknown `command_id` → `generic_nack` + close | DECODE_ERROR? | The frame decoded fine; `command_id` is unknown, not a decode error. Mislabel. |
| AD-30 — declared length < 16 → drop + close (undersized) | OVERSIZED_FRAME? | It is undersized, not oversized. Mislabel. |
| AD-25 — non-ROK `bind_*_resp` → tear down | (none) | No verifier deny, no peer close. No value. |
| AD-11/AD-33 — verifier DENY / routing-miss → bind denied, no couple, close | (none) | BIND_REJECTED missing. |
| AD-4/AD-11 — ingress TLS handshake fail (Mode C REQUIRE) | EGRESS_CONNECT_FAILED? | That value is egress-only; ingress handshake fail has no value. |

AD-27 says `onConnectionClosed` is "called by RelayHandler on teardown with a `CloseReason`" and that the counter cardinality is "2 × |CloseReason|, bounded." It does NOT say `onConnectionClosed` fires for every `channelInactive`, nor does it provide a catch-all. Two readings:

- **E-OBS-COMPLETE — "map every close to the nearest enum value."** Mislabels the 7 paths above (unbind-handshake→PEER_HALF_CLOSE; generic_nack→EGRESS_CONNECT_FAILED; unknown-cmd→DECODE_ERROR; undersized→OVERSIZED_FRAME; non-ROK-bind_resp+DENY→PEER_HALF_CLOSE or DECODE_ERROR). Counter cardinality holds, but the **label distribution is undefined** — two builds distribute identical closes to different labels.
- **E-OBS-STRICT — "fire `onConnectionClosed` only for enum-named reasons."** The 7 paths above do NOT fire the counter → `relay_connections_closed_total` **undercounts** (silently misses clean-handshake closes, denied binds, non-ROK teardowns, ingress handshake fails). The "bounded cardinality" claim holds trivially because whole close classes are invisible.

### Incompatibility, concretely

Same deployment: 100 binds denied by the verifier, 50 unbind-handshake closes, 20 unknown-`command_id` closes. E-OBS-COMPLETE reports these scattered across PEER_HALF_CLOSE / DECODE_ERROR / EGRESS_CONNECT_FAILED (operator cannot diagnose). E-OBS-STRICT reports NONE of them (counter shows only genuine peer half-closes + RSTs). Both obey AD-27 (the enum is closed; the cardinality bound holds). The register's RELAY-010 "increment-on-teardown" assumption (which AD-27 said it replaces) is silently half-satisfied either way.

### Closing AD

**TIGHTEN AD-27 — make `CloseReason` exhaustive OR state the fire-set.** Either (a) extend the enum to cover the close paths above (add at minimum `CLEAN_UNBIND_HANDSHAKE`, `BIND_REJECTED`, `BIND_FAILED_NON_ROK`, `GENERIC_NACK_PRE_BIND`, `UNKNOWN_COMMAND_ID`, `INVALID_LENGTH`, `INGRESS_TLS_HANDSHAKE_FAILED`); or (b) state explicitly which closes fire `onConnectionClosed` and which do not (e.g. "fires for every `channelInactive` except the AD-25 post-flip clean half-close of a fully-coupled session"), and add a catch-all `OTHER` value so no close is silently dropped. Either way, state that the enum is exhaustive over AD-1..AD-34's close paths so two units cannot disagree on the label set.

---

## UF-5 [MEDIUM] — AD-34 intersects "the SSLEngine provider's supported suites" (singular) once at startup, but the architecture runs multiple SSLContexts (ingress server + egress client + optional IdP mTLS, per AD-12/AD-29); per-context intersection + per-context fail-fast is not pinned. TLS 1.3 cipher set also unstated.

**AD-34: "At startup, intersect the configured set with the SSLEngine provider's supported suites; empty intersection → fail-fast." The singular "provider" + "at startup" implies one intersection. But AD-17's matrix has an ingress server context and one-or-more egress client contexts; AD-12 optionally adds an IdP mTLS client context; AD-29 permits per-target `tlsContextId` → a `tls.contexts` map. Each context can have a different provider (SunJSSE default vs an HSM/PKCS#11-backed provider for IdP mTLS).**

### The two units

- **E-BOOTSTRAP-TLS — "one startup intersection."** Computes the configured-vs-supported intersection ONCE against the ingress server context's provider at startup; applies the resulting enabled list to every context. If a non-default egress/IdP provider is narrower, the mismatch is not caught at startup.
- **E-SECURITY-TLS — "per-context intersection."** Intersects per SSLContext at creation (ingress, each egress target, IdP); each must be non-empty or fail-fast. Defends the multi-provider case but reads "the provider" (singular) as over-specified.

### The gap

AD-34 does not say the intersection is evaluated **per SSLContext**, so the two builds diverge on whether a narrow egress/IdP provider is caught at startup (fail-fast) or only at first connection (possibly negotiating a cipher outside the configured set, or failing a single bind). The "empty intersection → fail-fast (AD-17)" guarantee is only as wide as the intersection is evaluated.

Secondary: AD-34 fixes the TLS **1.2** cipher set and protocols `[TLSv1.3, TLSv1.2]` but does NOT state the TLS **1.3** cipher set. JDK SSLEngine auto-negotiates TLS-1.3 ciphers (all AEAD: `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`), so this is largely moot — but a unit could reasonably believe the "no CBC/static-RSA/legacy" policy leaves TLS-1.3 ciphers unconfigured (Reading A) or that TLS-1.3 is implicitly restricted to the GCM/ChaCha set (Reading B). The SEC-089 cipher-enforcement test (Q3's whole point) needs to know which.

### Incompatibility, concretely

An operator fronting an HSM-backed IdP mTLS client context (PKCS#11 provider, supports only `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` + `TLS_CHACHA20_POLY1305_SHA256`) alongside a SunJSSE ingress. E-BOOTSTRAP-TLS computes the ingress intersection (all 4 GCM suites) at startup and passes fail-fast; the IdP context silently negotiates only the 2 the HSM supports — or, if the configured list is narrowed to ECDSA-only by an operator, the IdP context has an empty intersection that E-BOOTSTRAP-TLS never checked and E-SECURITY-TLS catches at startup. SEC-089 (cipher allowlist enforced) passes on one build and fails on the other for the same config.

### Closing AD

**TIGHTEN AD-34.** (1) State the configured-vs-supported intersection is evaluated **for every SSLContext at startup** (ingress server + every egress target context + the IdP mTLS client context), each must be non-empty or fail-fast — "the provider" means each context's provider. (2) Add a one-line TLS-1.3 cipher posture (e.g. "TLS-1.3 ciphers are restricted to the JDK's AEAD set {AES_256_GCM, AES_128_GCM, CHACHA20_POLY1305}; ChaCha20 optional parity with TLS 1.2") so SEC-089 has a deterministic target.

---

## UF-6 [LOW-MEDIUM] — AD-19 "pre-flip counter" / "command_id ONLY in TRACE" phrasing is inconsistent with the UPDATE's own use of command_id and with counters that span pre- and post-flip

**Two phrasing ambiguities in AD-19 (as amended by the UPDATE) let two units diverge.**

### The gap

1. **`relay_connections_closed_total` is described as a "pre-flip counter" but fires post-flip too.** AD-19: "NO `system_id`/`command_id`/`ChannelId` label on ANY counter emitted **before the splice flip** (incl. `relay_connections_closed_total{direction, reason}`…)." AD-27 says `onConnectionClosed` backs that counter and fires on teardown — including teardown of a **coupled** (post-flip) connection. So the counter spans both windows, yet AD-19 frames it as pre-flip. One unit (Reading A) treats the whole counter as unlabeled (matching AD-27) and is correct; another (Reading B) reads AD-19 as "post-flip counters MAY carry `system_id`" and adds a *second*, post-flip close counter labeled with `system_id` (bounded by the routing table, so not unbounded — but a label AD-27 did not authorize). The "incl." parenthetical invites the confusion.

2. **"command_id ONLY in TRACE" vs AD-32's hot-path read.** AD-19: "The offending `command_id` is permitted ONLY in TRACE logs, sourced via … `ByteBuf.getInt(4)`." AD-32 case selection AND response synthesis REQUIRE reading the offender `command_id` at default log level (to classify unbind/enquire_link/generic_nack/case-3 and to synthesize). A unit can read "ONLY in TRACE" literally and refuse to read `command_id` for logic except at TRACE (Reading B) — breaking AD-32 at default log level. The intended meaning is "EMISSION to logs/metrics is TRACE-gated; reading for logic is always allowed." AD-19 does not distinguish emission from reading.

### Incompatibility, concretely

E-OBS-A ships one unlabeled `relay_connections_closed_total` (Reading A). E-OBS-B ships that PLUS `relay_post_flip_closes_total{system_id}` (Reading B) — same close events, two metric series where AD-27 named one. And E-RELAY-B, reading "command_id ONLY in TRACE" literally, classifies case 3 only when TRACE is enabled — at default log level every non-bind PDU falls through case selection. Both pass AD-19 (its wording supports both readings).

### Closing AD

**TIGHTEN AD-19.** (1) Reframe `relay_connections_closed_total` as a counter that spans both windows and is **never** `system_id`/`command_id`/`ChannelId`-labeled (state this directly, not via the "pre-flip" framing). (2) Split the `command_id` rule into "reading `command_id` via `getInt(4)` for AD-32 case selection + response synthesis is always permitted; emitting `command_id` to logs or metrics is TRACE-gated." (This overlaps with UF-1 closing action #3 — they should land together.)

---

## UF-7 [LOW] — AD-32 "bind in flight" is not precisely defined; the verdict-Allow-to-flip window is classified differently

**AD-32 case 3 says "tear down any **in-flight bind** on that connection" and "the response shape is uniform whether or not a bind is in flight." The teardown steps (cancel ROPC, zeroize, remove registry entry) are conditionally meaningful only if a bind is in flight — but "in flight" is not pinned, so two units classify the Allow-verdict-to-flip window differently.**

### The two units

- **E-RELAY-NARROW — "in flight = adjudication outstanding."** Sets `bindInFlight` on bind-received, clears it the moment the verifier returns (Allow or Deny). In the Allow-but-pre-flip window, the bind is NOT "in flight" → case-3 teardown skips the ROPC cancel (already completed) and the zeroize (already done on adjudication completion per AD-12), and only removes the registry entry + closes.
- **E-RELAY-BROAD — "in flight = registry entry exists and not yet flipped (coupled)."** `bindInFlight` is true until the AD-25 flip. In the Allow-but-pre-flip window, the bind IS "in flight" → case-3 teardown attempts to cancel an already-completed ROPC (harmless no-op) and re-zeroize an already-zeroized password (harmless).

### The gap

The two readings usually converge (idempotent cancels/zeroize), but they DIVERGE on whether RelayHandler maintains a SEPARATE `bindInFlight` boolean vs deriving it from `entry != null && !entry.coupled`. If the boolean and the entry's coupled-flag ever disagree (boolean cleared on verdict, entry removed only on `channelInactive`), E-RELAY-NARROW skips teardown steps E-RELAY-BROAD runs, and — under the UF-2 race — the flip re-check uses a different predicate. AD-32 does not equate "bind in flight" to a concrete registry-entry state.

### Incompatibility, concretely

Low observable impact in isolation (the steps are idempotent), but it compounds UF-2 race #2: the "is this connection still coupling-eligible?" predicate is `!bindInFlight` for E-RELAY-NARROW and `!entry.coupled` for E-RELAY-BROAD, and in the Allow-pre-flip window those disagree, so the flip-vs-teardown race resolves differently. Both pass AD-32.

### Closing AD

**TIGHTEN AD-32 — define "bind in flight" concretely.** State that "bind in flight" ≡ a `ConnectionRegistry` entry exists for the connection and has not yet been flipped to coupled (AD-25); the teardown predicate is the entry's state, not a separate boolean. This makes the UF-2 flip re-check and the teardown predicate the same field.

---

## Summary

### UPDATE closure

The UPDATE resolves Q1–Q7 as advertised: AD-32 (Q1) gives a fail-closed, zero-knob pre-couple policy; AD-33 (Q7) collapses the bind-denial wire contract; AD-34 (Q3) pins the cipher default; the AD-24/AD-30 amendments address Q2/Q4/Q5; Q6 is recorded in the CI tier. The amended AD-27 (`onConnectionClosed` + `CloseReason`), AD-3 (unbind/enquire_link corollary), AD-25 (close-on-violation note), and AD-19 (pre-flip counter rule) each land where their owning test-design notes asked. No prior finding (F-1..F-9, NF-1..NF-5) is re-opened.

### New findings introduced by the UPDATE

| # | Severity | Seam (ADs) | First-sprint impact | Closing action |
| --- | --- | --- | --- | --- |
| UF-1 | HIGH | AD-32 case-3 synthesis owner + offender-direction vs AD-7/AD-19/AD-3 | Blocks Epic 2 relay pre-couple story (who owns the lookup; resp/alert offenders unhandled) | TIGHTEN AD-32 (owner = proxy/relay; case-3 request-only + new case for resp/alert; AD-19 read-vs-emit) |
| UF-2 | HIGH | AD-32 case-3 teardown ordering vs AD-25/AD-12/AD-8 + AD-27 exactly-once | Blocks Epic 2 (teardown races flip + verdict; onConnectionClosed double/miss) | TIGHTEN AD-32 (sync remove + tearing-down sentinel + AD-25 re-check) + AD-27 (exactly-once) + AD-12 (cancel handle on the port) |
| UF-3 | MEDIUM | AD-33 outcome set vs AD-32 case-4 / AD-25 (SMSC-side bind failures) | Affects Epic 3 (enumeration oracle re-leaks if SMSC failures not collapsed) | TIGHTEN AD-33 (collapse union includes all egress-side bind failures; case-3 is not a denial) |
| UF-4 | MEDIUM | AD-27 CloseReason exhaustiveness | Affects Epic 4 metrics (~6 close paths missed/mislabeled) | TIGHTEN AD-27 (exhaustive enum OR explicit fire-set + catch-all) |
| UF-5 | MEDIUM | AD-34 provider-intersection scope (multi-context) + TLS-1.3 set | Affects Epic 3 TLS (SEC-089 non-deterministic across providers) | TIGHTEN AD-34 (per-context intersection + TLS-1.3 cipher posture) |
| UF-6 | LOW-MEDIUM | AD-19 pre-flip/command_id-TRACE phrasing | Affects Epic 4 (second labeled counter; logic-break at default log level) | TIGHTEN AD-19 (counter spans both windows; read-vs-emit split) |
| UF-7 | LOW | AD-32 "bind in flight" undefined | Compounds UF-2 | TIGHTEN AD-32 (bind-in-flight ≡ entry exists && !coupled) |

UF-1 and UF-2 should be fixed before the Epic 2 relay pre-couple story splits (they define that story's core contract). UF-3 before Epic 3's bind-denial story. UF-4/UF-5 before Epic 4 metrics and Epic 3 TLS vectors land. UF-6/UF-7 can ride alongside. None blocks the Q1–Q7 test-design exit (the scenarios are unblocked as written); they block clean epic-level implementation.
