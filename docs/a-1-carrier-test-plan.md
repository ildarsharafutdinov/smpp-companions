# A-1 Real-Carrier Test Plan (OBS-035 / OBS-036 / OBS-037)

> **Status:** authored by Story 2.2 T9 (2026-08-16) — the NON-CI half of retiring assumption A-1
> (*"a carrier accepts multiple concurrent binds under one `system_id` and returns each DLR on the
> socket that submitted the MO/MT"*). Executed before any production cutover; owned by operations
> with the carrier's integration/lab contact. Not a CI job.

## 1. Oracle — the real carrier (or a conformance SMSC), never the in-JVM mock

The system-under-oracle for this checkpoint is the **real target carrier's SMSC** (their integration
lab / certification endpoint). If carrier lab access is unavailable, a **conformance SMSC** (a
third-party SMPP 3.4 conformance/certification simulator, e.g. an SMPP conformance test suite's
server) may substitute — it is independent of this codebase and does not assume A-1.

**The in-JVM mock SMSC (`proxy/src/test/.../MockSmsc`) is EXPLICITLY EXCLUDED as an oracle for this
checkpoint — never the in-JVM mock:** it is built on this repo's own production codec (shares the
codec's bugs) and it *emulates* the carrier's affinity by construction (it delivers on whichever
socket the test chose), so it assumes the very property A-1 asserts. The same exclusion applies to
the jSMPP-based mock (OBS-038): both are CI approximations, not falsifications. A-1 is only
genuinely falsifiable against a carrier we do not control.

## 2. Preconditions

- The proxy deployed as `companion.reverse.mode-b` against the carrier's endpoint
  (`companion.reverse.mode-b.smsc` = the carrier lab host:port), plaintext per the carrier's lab
  policy (TLS is Epic 3; the affinity behavior under test is transport-independent).
- Two or more test ESME client connections available (two shells running the legacy test client, or
  two socket handles from `smpp-tools`), each able to submit `submit_sm`.
- Approval from the carrier for concurrent binds under ONE shared test `system_id` (the point of
  A-1 — state this explicitly in the lab request; some carriers reject it by policy, which is
  itself a FAIL result, see §4).
- Packet capture on the proxy host (`tcpdump -i any -w a1.pcap port <carrier-port>`) or the
  carrier's own message traces, plus the proxy's own logs (the SpliceObserver counters land with
  Epic 4; today the relay logs + pcap are the evidence).

## 3. PASS criterion (explicit, measurable)

**PASS** iff ALL of the following hold on the real carrier:

1. **Multi-bind acceptance:** at least **2 concurrent `bind_transceiver` (≥ 2, same window, both
   held open) under the SAME `system_id`** are each answered `bind_transceiver_resp` with
   `command_status = ESME_ROK (0x00000000)` — both binds live simultaneously on the real target
   carrier.
2. **DLR session affinity:** the DLR-affinity assertion of §5 passes in BOTH directions
   (submit on bind A → DLR on bind A's socket; submit on bind B → DLR on bind B's socket), for at
   least 3 DLRs per bind.

Anything less is a FAIL (§4) or an INCONCLUSIVE (§6) — never a partial pass.

## 4. FAIL criterion (explicit)

**FAIL** if ANY of the following occurs on the real carrier:

1. **Multi-bind rejection:** the 2nd (or any) concurrent bind under the same `system_id` is
   rejected — a non-ROK `bind_*_resp` (e.g. `ESME_RALYBND` "already bound", `ESME_RBINDFAIL`), or
   no response within the carrier's bind window.
2. **DLR cross-delivery:** a `deliver_sm` (DLR) is observed on the WRONG bind's socket (a submit
   on bind A's connection yields the DLR on bind B's connection, or vice versa) — the silent
   misdelivery class (REL-1's worst failure).

On FAIL, A-1 is falsified for this carrier: the stateless design's premise (AD-9 — DLRs ride the
coupled socket pair; no `message_id`→session correlation exists to fall back on) does not hold.
Escalate to architecture: record the carrier + evidence in the AD-9/AD-12 accepted-risk register
(`ARCHITECTURE-SPINE.md`) and evaluate the fallback (per-`system_id` connection pinning /
single-bind-per-identity mode) — a design change, out of v1's scope.

## 5. DLR-affinity assertion procedure (the falsifiable core)

For binds A and B (same `system_id`, both ROK, both coupled through the proxy):

1. Note each bind's TCP 4-tuple (client port on the proxy host ↔ carrier socket) from the pcap —
   this is the socket identity the DLR must return on.
2. **Submit on bind A:** send a `submit_sm` with a unique correlation marker in the short message
   (e.g. `A1-PROBE-<timestamp>-<n>`) over connection A. Assert the resulting `deliver_sm` (DLR)
   carrying that marker **arrives on bind A's socket (the same TCP connection that submitted it),
   NOT on bind B's**. Repeat ≥ 3 times with fresh markers.
3. **Mirror on bind B:** submit over connection B; assert the DLR arrives on bind B's socket, not
   A's. Repeat ≥ 3 times.
4. Cross-check neither direction ever observes the other's marker (zero cross-bleed).

The proxy must be IN the path for both binds (both connections are proxy↔carrier legs of two
coupled pairs) — the assertion exercises the full chain: legacy client → proxy splice → carrier
socket affinity → DLR → proxy splice → the originating legacy client.

## 6. Evidence + records

- The pcap (or carrier trace) showing: both `bind_transceiver`/`bind_transceiver_resp` ROK pairs
  with the same `system_id`, and each DLR's TCP stream matching its submit's stream.
- Timestamps, the shared test `system_id`, the carrier lab endpoint, proxy version/commit.
- The PASS/FAIL verdict recorded against this plan (dated) in the run's ops log; on FAIL, the
  §4 escalation.

## 7. INCONCLUSIVE (not FAIL, not PASS)

If the carrier forces one-bind-per-`system_id` **by documented policy** (not observed behavior),
the lab was misconfigured, or DLRs are disabled on the lab account: record the blocker, fix the
lab, re-run. Do not mark PASS without both §3 clauses observed on the real carrier.
