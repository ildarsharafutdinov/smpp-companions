# Test Coverage Scenario Catalog — Companions v1 (SMPP 3.4 Security Proxy)

**Project:** smpp-companions · **Mode:** System-Level · **Architect:** Murat (Master Test Architect)
**Risk threshold:** p1 (5 P0 + 13 P1 = 18 mandatory-coverage risks)
**Toolchain:** JVM — JUnit 5 (Jupiter) + AssertJ (unit/integration) · JQF + jqwik (structural fuzz) · JMH (perf microbenchmarks) · from-scratch open-model load harness (relay percentiles) · in-JVM mock SMSC on codec + jSMPP 3.0.2 (interop-only independent oracle) · Spring Boot test slices + `@ConfigurationProperties` fail-fast matrix · JDK SSLEngine / Netty SslContext TLS vectors · BlockHound (event-loop blocking) · ArchUnit (structure) · OWASP dependency-check / Dependabot + Gradle toolchain / JDK-pin (CI gates).
**Provenance:** 6-area-designer + 1-critic workflow produced 242 atomic scenarios; this catalog applies the Step-4 critic reconciliation (12 additions, 3 dedup removals, 4 reframes/fixes) → **251 scenarios**. Scenarios tagged `[critic-fix]` are added/fixed by that reconciliation; the Deduplication ledger (appendix) records removed IDs.

> Tagging convention for JUnit 5: `@Tag("p0"|"p1"|"p2"|"p3")`, `@Tag("unit"|"fuzz"|"integration"|"conformance"|"perf"|"e2e")`, an area tag (`codec`/`relay`/`sec`/`obs`/`deploy`/`perf`/`e2e`), and `@DisplayName`. (No `@P0`/`@API`/`npx playwright` — this is a JVM backend, not Playwright/k6.)

> **Vocabulary note (2026-08-28, Story 3.4 T4):** the relay vocabulary was UNIFIED — data-plane action `splice` → `relay` ("spliced PDU"/"spliced traffic" → "relayed PDU(s)", `RelayHandler.splice()` → `relayFramedPdu()`); pair-state transition `flip`/`spliced` → `couple`/`coupled` (`flipSpliced()` → `couple()`, `spliced()` → `coupled()`; the AD-25 flip = the couple); and the observability seam type `SpliceObserver` → `RelayObserver` (`NoopSpliceObserver` → `NoopRelayObserver`, `CapturingSpliceObserver` → `CapturingRelayObserver`; the 4 method names unchanged). Live row text below keeps its pre-T4 wording; read it through this mapping (spine AD-1/2/8/25/27/32 carry the dated amendment markers).
>
> **Split note (2026-08-28, Story 3.4 T5):** the couple unit `RelayHandler` was SPLIT into the per-leg `RelayIngressHandler`/`RelayEgressHandler` over the abstract base `CoupledRelayHandler` (D3, owner checkpoint same date; `RelayHandlerTest` split likewise into the two per-leg suites). Rows below naming `RelayHandler` as the couple unit read as `RelayEgressHandler` post-split; the flip/couple trigger is unchanged. Live row text stays.

---

## 1. Summary

### 1.1 Area × priority tally

| Area | Total | P0 | P1 | P2 | P3 |
|------|-------|----|----|----|----|
| CODEC | 41 | 0 | 40 | 1 | 0 |
| RELAY | 25 | 12 | 11 | 2 | 0 |
| SEC | 98 | 52 | 26 | 18 | 2 |
| OBS | 43 | 0 | 14 | 29 | 0 |
| DEPLOY | 14 | 0 | 5 | 9 | 0 |
| PERF | 29 | 0 | 16 | 13 | 0 |
| E2E | 1 | 0 | 1 | 0 | 0 |
| **TOTAL** | **251** | **64** | **113** | **72** | **2** |

- **Coverage core** (risk_threshold = p1): every one of the 18 P0/P1 risks has ≥1 explicit passing scenario. P0 concentration is in SEC (52: the fail-closed / trust-anchoring / credential-free-at-rest crown jewels) and RELAY (12: the five decomposed R5 concurrency seams).
- **Reconciliation delta vs. the 242-scenario designer output:** +12 additions (SEC-093/094/095/096/097/098/099, RELAY-025/026, E2E-001, CODEC-041, OBS-043), −3 dedup removals (RELAY-016, PERF-041, PERF-042), +4 in-place reframes/fixes (SEC-037 rewritten, SEC-048/049 reframed, SEC-089 blocked-on-config, OBS-015 scope-reduced).

### 1.2 Area × level tally (derived directly from each scenario's declared level)

| Area | Unit | Fuzz | Integration | Conformance | Perf | E2E | Total |
|------|------|------|-------------|-------------|------|-----|-------|
| CODEC | 29 | 4 | 4 | 4 | 0 | 0 | 41 |
| RELAY | 3 | 1 | 13 | 6 | 2 | 0 | 25 |
| SEC | 60 | 0 | 38 | 0 | 0 | 0 | 98 |
| OBS | 13 | 0 | 28 | 1 | 0 | 1 | 43 |
| DEPLOY | 0 | 0 | 6 | 0 | 0 | 8 | 14 |
| PERF | 1 | 0 | 0 | 0 | 28 | 0 | 29 |
| E2E | 0 | 0 | 0 | 0 | 0 | 1 | 1 |
| **TOTAL** | **106** | **5** | **89** | **11** | **30** | **10** | **251** |

### 1.3 Critic-fix application map (what changed and why)

**ADDED `[critic-fix: ADDED]` — closes P0/P1 coverage holes + NFR-evidence gaps:**
- `SEC-093` — introspection HTTP-error DENY matrix (network-error / 3xx / 4xx≠default → DenyIndeterminate); closes the asymmetric R1 hole (ROPC path exhaustive, introspection path wasn't). *(Both SEC-013..019 + SEC-093 were later RETIRED with the introspection arm itself — Story 3.4 T1, 2026-08-27; see §4.2.)*
- `SEC-094` — JWT/ROPC no-verdict-cache focused unit (same `BindCredential` twice → token endpoint hit twice); mirrors SEC-019 for the JWT path (AD-12 load-bearing invariant).
- `SEC-095` — extend SEC-042 (type) + SEC-045 (sink-escape) to the OIDC `client_secret` for the non-mTLS confidential-client path.
- `SEC-096` / `SEC-097` — R17 role×mode cells: reverse+A trust-store-missing → refuse; positive forward+A-starts-without-SMSC.
- `RELAY-025` — REL-4 structural arch-scan: no `message_id`→`system_id` map in `relay/` (statelessness invariant).
- `SEC-098` — FR-AUTH-3 no-shared-golden-key config/build scan (per-instance Mode C certs).
- `RELAY-026` — AD-30 shared-constant static assertion (codec-max 65536 and `MaxDirectMemorySize` formula input reference ONE named constant).
- `E2E-001` — two-real-proxy-instance (forward↔reverse) composed-flow end-to-end.
- `SEC-099` / `CODEC-041` / `OBS-043` — CI-gate positive controls (model on RELAY-018's BlockHound control): inject known-bad input and assert each gate *fires*.

**FIXED/REFRAMED `[critic-fix]` — weak or non-implementable scenarios corrected:**
- `SEC-037` `[critic-fix: REWRITTEN]` — drop the infeasible injectable-clock-past-notAfter (SSLEngine uses the system clock; `PKIXBuilderParameters.setDate` banned by AD-13); craft a genuinely already-expired short-lived cert (1970–1971) and assert PKIX rejection against the real clock.
- `SEC-048` `[critic-fix: REFRAMED]` — non-deterministic after GC; reframed as a best-effort fragility guard (NOT zeroization evidence — that is SEC-046).
- `SEC-049` `[critic-fix: REFRAMED]` — JFR OldObjectSample is sampled / heap-dump substring is non-deterministic; reframed as best-effort hygiene guard + JFR/dump hygiene doc (deterministic evidence = SEC-046).
- `SEC-089` `[critic-fix: BLOCKED-ON-CONFIG]` — placeholder until the concrete default cipher allowlist is pinned in config (AD-17/SEC-1); Q3 open blocker.
- `OBS-015` `[critic-fix: SCOPE-REDUCED]` — keep only the e2e packaging/process-exit aspect; drop the re-assertion of splice zero-drop (owned by RELAY-022).

**DEDUP — see §9 Deduplication ledger:** RELAY-016 (folded into RELAY-017), PERF-041 (merged into RELAY-015), PERF-042 (merged into RELAY-017).

---

## 2. CODEC — Codec, framing & SMPP 3.4 conformance

Owns R3 (parser/framing DoS + per-channel containment), R14 (codec diverges from SMPP 3.4), R33 (sole-oracle → golden-vector 3rd oracle), plus codec-level parser support and MAINT-2 purity. The PURE `codec` module (zero upward deps) is the textbook isolation seam.

**CODEC-001** — Framer emits exactly one framed ByteBuf for one complete well-formed PDU delivered in a single read
Level: unit · Priority: P1 · Risks: R3, R14 · NFR: SEC-2, REL-1, FR-TRANSIT-4
- Technique: golden-vector positive decode via EmbeddedChannel single writeInbound; assert one ByteBuf of exact length, reader-aligned.
- Tooling: JUnit5 Jupiter + AssertJ + Netty EmbeddedChannel; hand-authored SMPP 3.4 PDU bytes.
- Notes: Baseline happy path; establishes the one-frame-per-PDU invariant (AD-2) all split/coalesce tests build on.

**CODEC-002** — Framer reassembles one correct PDU when its bytes are split across many reads, including a split inside the 4-octet command_length header
Level: unit · Priority: P1 · Risks: R3, R14 · NFR: SEC-2, REL-1
- Technique: parametrized multi-writeInbound (1-byte, 3-byte, mid-header, mid-body chunks); assert single complete frame, no drop/dup/corrupt.
- Tooling: JUnit5 + AssertJ + EmbeddedChannel (sequential writeInbound calls).
- Notes: Header-split is the trickiest accumulation case; lower-level anchor for CODEC-012 (property) and CODEC-034 (real socket).

**CODEC-003** — Framer emits N distinct frames in order when multiple complete PDUs are coalesced in one read
Level: unit · Priority: P1 · Risks: R3 · NFR: REL-1, SEC-2
- Technique: single writeInbound of 3 concatenated PDUs; assert 3 frames out in arrival order, each length-exact.
- Tooling: JUnit5 + AssertJ + EmbeddedChannel.
- Notes: Validates the framer loops over available complete PDUs per decode call (Netty ByteToMessageDecoder contract).

**CODEC-004** — Framer discards a partial PDU left in the accumulation buffer at channelInactive — no truncated frame emitted
Level: unit · Priority: P1 · Risks: R3 · NFR: REL-1, SEC-2
- Technique: writeInbound a sub-length prefix then close the EmbeddedChannel; assert zero outbound frames and no exception.
- Tooling: JUnit5 + AssertJ + EmbeddedChannel (finish()/close()).
- Notes: Addresses blind-spot (c): partial-PDU-at-channelInactive must not leak a malformed frame into the relay (REL-1 corrupt).

**CODEC-005** — Framer rejects a declared command_length < 16 and closes the channel (fail-closed)
Level: unit · Priority: P1 · Risks: R3 · NFR: SEC-2
- Technique: parametrized negative: command_length ∈ {0,1,15}; assert frame dropped + channel closed, no frame emitted, no allocation.
- Tooling: JUnit5 + AssertJ + EmbeddedChannel.
- Notes: AD-30 lower-bound guard (16 = header-only minimum). 16 itself is tested valid in CODEC-007.

**CODEC-006** — Framer rejects a declared command_length > 65536 (mid-range oversize) and closes the channel
Level: unit · Priority: P1 · Risks: R3 · NFR: SEC-2
- Technique: parametrized negative: command_length ∈ {65537, 70000, 100000}; assert drop+close, no oversized allocation.
- Tooling: JUnit5 + AssertJ + EmbeddedChannel + counting allocator.
- Notes: AD-30 upper reject branch. Off-by-one boundary in CODEC-008; overflow-class in CODEC-010.

**CODEC-007** — Framer accepts command_length == 16 (header-only, zero-body PDU) as a valid frame
Level: unit · Priority: P1 · Risks: R3, R14 · NFR: SEC-2, FR-TRANSIT-4
- Technique: writeInbound a 16-byte header-only PDU (e.g. enquire_link); assert one 16-byte frame emitted, channel open.
- Tooling: JUnit5 + AssertJ + EmbeddedChannel.
- Notes: Lower valid boundary; guards against an off-by-one that rejects legitimate header-only PDUs.

**CODEC-008** — Framer accepts command_length == 65536 (exact max) and rejects 65537 (off-by-one boundary)
Level: unit · Priority: P1 · Risks: R3 · NFR: SEC-2
- Technique: boundary pair: 65536 → one frame, channel open; 65537 → drop+close; assert exact threshold.
- Tooling: JUnit5 + AssertJ + EmbeddedChannel.
- Notes: The classic length-field off-by-one. Distinct from CODEC-006 (mid-range) and CODEC-010 (overflow-class).

**CODEC-009** — Framer waits (no partial frame, no busy-spin) when declared command_length exceeds bytes currently buffered
Level: unit · Priority: P1 · Risks: R3 · NFR: REL-1, SEC-2
- Technique: writeInbound a header declaring N then only N-k body bytes; assert decode returns null / no frame; feed remaining k bytes; assert one frame. Assert bounded call count (no spin).
- Tooling: JUnit5 + AssertJ + EmbeddedChannel.
- Notes: Determinism/REL-1: a custom hand-rolled framer could emit a partial frame or spin; framework ByteToMessageDecoder guards this but the custom decoder must honor it.

**CODEC-010** — Framer rejects overflow-class lengths (near 2^31 / 0xFFFFFFFF) BEFORE any allocation — no OOM, no arithmetic wrap
Level: unit · Priority: P1 · Risks: R3 · NFR: SEC-2
- Technique: inject command_length ∈ {0x7FFFFFFF, 0x80000000, 0xFFFFFFFF}; assert drop+close AND a recording allocator shows zero allocations larger than the max-frame cap (pre-allocation guard verified).
- Tooling: JUnit5 + AssertJ + EmbeddedChannel + instrumented ByteBufAllocator (wraps PooledByteBufAllocator, records alloc sizes) + ByteBufAllocatorMetric.
- Notes: THE critical AD-30 length-field vulnerability: guard arithmetic before allocation, independent of -XX:MaxDirectMemorySize. A naive alloc(command_length) here = OOM or wrap→under-alloc→over-read. Observable via counting allocator.

**CODEC-011** — JQF structural fuzz of SmppFrameDecoder over arbitrary byte streams: no uncaught exception, bounded memory
Level: fuzz · Priority: P1 · Risks: R3 · NFR: SEC-2
- Technique: JQF fuzz with a structure-aware generator (valid 4-byte length prefix + arbitrary tail, plus fully random streams); invariant assertions: no Throwable escapes decode, total allocated bytes ≤ cap×small factor, channel eventually closed on oversize.
- Tooling: JQF (edu.berkeley.cs.jqf) + JUnit5 + AssertJ + EmbeddedChannel + recording allocator; AD-24 mandated fuzz of the framing decoder (the MORE-EXPOSED surface).
- Notes: AD-24 explicit requirement (a). Fuzz finds crash/DoS paths the enumerated reject cases (CODEC-005/006/008/010) cannot foresee.

**CODEC-012** — jqwik property: for any chunking of a valid PDU byte sequence into [1..N] pieces, framer reassembly yields the identical single frame
Level: fuzz · Priority: P1 · Risks: R3 · NFR: REL-1, SEC-2
- Technique: jqwik property: arbitrary PDU + arbitrary partition → feed pieces sequentially → assert one frame equal to original bytes (split-invariance).
- Tooling: jqwik + JUnit5 + AssertJ + EmbeddedChannel.
- Notes: Generalizes CODEC-002 across all split points; defense-in-depth on P1 REL-1 framing integrity. Each level catches distinct defects (unit logic vs arbitrary boundaries vs real TCP in CODEC-034).

**CODEC-013** — A decoder exception on a malformed frame is contained — does not propagate to / kill the event loop
Level: unit · Priority: P1 · Risks: R3 · NFR: SEC-2, REL-1
- Technique: force the worst-case malformed input through EmbeddedChannel; assert exception is delivered to exceptionCaught (channel-specific), not thrown out of decode unchecked; channel closed, event loop intact.
- Tooling: JUnit5 + AssertJ + EmbeddedChannel (capture caughtException).
- Notes: R3 relay-wide-DoS dimension: one bad channel must not crash the shared event loop. Pairs with CODEC-014 (cross-channel proof).

**CODEC-014** — Per-channel isolation: a malformed frame on channel A does not corrupt or block a concurrently-decoding healthy frame on channel B sharing the event loop
Level: integration · Priority: P1 · Risks: R3 · NFR: SEC-2, REL-1
- Technique: two channels on one NioEventLoopGroup; submit malformed PDU to A and golden PDU to B (race/latch); assert B's frame decodes correctly and A is closed without affecting B.
- Tooling: JUnit5 + AssertJ + embedded NioEventLoopGroup (1 thread) + CountDownLatch; or two EmbeddedChannels driven on a shared executor.
- Notes: R3 containment proof across channels (relay-wide-DoS). Distinct from CODEC-013 (single-channel containment).

**CODEC-015** — Framer ByteBuf retain/release correctness on the normal path and the error/reject path — no direct-memory leak
Level: unit · Priority: P1 · Risks: R3 · NFR: REL-1, SEC-2
- Technique: run normal framing + each reject/exception path under Netty ResourceLeakDetector.PARANOID; assert zero leak records; assert ByteBufAllocatorMetric direct-memory returns to baseline after channel close.
- Tooling: JUnit5 + AssertJ + Netty ResourceLeakDetector (PARANOID) + ByteBufAllocatorMetric.
- Notes: R3/R27 error-path ByteBuf-leak dimension; a reject path that allocates-then-throws leaks direct memory per bad PDU (DoS).

**CODEC-016** — Bind parser decodes a golden bind_transceiver PDU to exact system_id, password, system_type, interface_version, and header fields
Level: unit · Priority: P1 · Risks: R14, R33 · NFR: FR-TRANSIT-4, COMP-1
- Technique: golden-vector decode: feed hand-authored (spec-derived) bind_transceiver bytes; assert every C-octet-string field and numeric field equals the spec-authored expected values byte-for-byte.
- Tooling: JUnit5 + AssertJ; golden bytes from the independent corpus (CODEC-030), NOT codec-generated.
- Notes: R14 (spec conformance) + R33 (independent oracle). The golden bytes are authored from the SMPP 3.4 spec, not synthesized by the codec under test.

**CODEC-017** — Bind parser decodes golden bind_transmitter and bind_receiver PDUs correctly (all three bind request types)
Level: unit · Priority: P1 · Risks: R14, R33 · NFR: FR-TRANSIT-4
- Technique: parameterized golden-vector decode over {bind_receiver 0x01, bind_transmitter 0x02, bind_transceiver 0x0F}; assert each decodes to correct command_id + fields.
- Tooling: JUnit5 (parameterized) + AssertJ + golden corpus.
- Notes: command_id differentiation among the three request types; complements CODEC-016 (transceiver) and CODEC-029 (response bit).

**CODEC-018** — Bind parser detects command_status == ESME_ROK on a golden bind_*_resp (the AD-25 splice-flip trigger)
Level: unit · Priority: P1 · Risks: R14, R33 · NFR: FR-TRANSIT-4
- Technique: golden bind_transceiver_resp with command_status 0x00000000; assert parser exposes status==ROK predicate true (the exact signal RelayHandler flips on, AD-25).
- Tooling: JUnit5 + AssertJ + golden corpus.
- Notes: This is the codec-level signal for AD-25; never a peeked command_id, never 'any frame' — the decoded ROK is the trigger.

**CODEC-019** — Bind parser decodes a non-ROK bind_*_resp (e.g. ESME_RINVPASWD 0x0000000E) without raising the ROK trigger
Level: unit · Priority: P1 · Risks: R14 · NFR: FR-TRANSIT-4
- Technique: golden bind_*_resp with non-zero command_status; assert status decoded correctly AND ROK predicate is false (no accidental flip).
- Tooling: JUnit5 + AssertJ + golden corpus.
- Notes: Negative branch of the AD-25 trigger; a false-positive ROK would wrongly splice an unauthenticated session.

**CODEC-020** — Bind parser handles C-octet-string edge cases: empty field (single null), max-length field, and all-fields-empty bind body
Level: unit · Priority: P1 · Risks: R14 · NFR: FR-TRANSIT-4
- Technique: parameterized: system_id/password/system_type at empty (0x00) and spec-max lengths (16/9/13 octets incl. terminator); assert decode without error and exact values.
- Tooling: JUnit5 (parameterized) + AssertJ.
- Notes: Spec boundary conformance; guards against off-by-one on the null terminator and max-length rejection bugs.

**CODEC-021** — Bind parser rejects an unterminated C-octet-string (no null terminator before frame end) without over-reading or looping
Level: unit · Priority: P1 · Risks: R3 · NFR: SEC-2
- Technique: craft a bind body whose system_id runs to the frame end with no 0x00; assert bounded decode (reject), no read past frame limit, no infinite loop (bounded iterations).
- Tooling: JUnit5 + AssertJ + EmbeddedChannel.
- Notes: R3 parser-robustness: the classic unbounded-scan-on-malformed-C-string vulnerability.

**CODEC-022** — Bind parser rejects a truncated bind body (declared fields exceed remaining frame bytes) without ArrayIndexOutOfBounds/negative-size
Level: unit · Priority: P1 · Risks: R3 · NFR: SEC-2
- Technique: frame with valid header but body shorter than mandatory fields; assert graceful reject, no AIOOBE/IndexOutOfBounds, no negative-length arithmetic.
- Tooling: JUnit5 + AssertJ + EmbeddedChannel.
- Notes: R3: all body-length arithmetic must be bounds-checked against the frame before each read.

**CODEC-023** — Bind parser decodes the PDU header (command_id/status/sequence) correctly even when the body is junk
Level: unit · Priority: P1 · Risks: R3 · NFR: SEC-2
- Technique: bind-family command_id + valid header + garbage body; assert header fields parse and body parse fails cleanly (header parse independent of body validity).
- Tooling: JUnit5 + AssertJ.
- Notes: Header robustness; lets the relay route/reject on command_id even when the body is malformed.

**CODEC-024** — Bind parser exposes the password as char[] (or byte[]), never constructing a String — codec seam for zeroization
Level: unit · Priority: P2 · Risks: R8 · NFR: PRIV-1
- Technique: assert BindCredential/parser password accessor return type is char[]/byte[]; bytecode/reflection scan that no java.lang.String is constructed from the password octets in the parser.
- Tooling: JUnit5 + AssertJ + ASM reflection scan over codec classes.
- Notes: Codec-level seam enabling R8 zeroization (full zeroization verification owned by security/). If the parser interns the password into a String, zeroization is impossible — catch it at the codec boundary.

**CODEC-025** — JQF structural fuzz of the bind-family parser over framed buffers: no uncaught exception, no read past the frame limit
Level: fuzz · Priority: P1 · Risks: R3 · NFR: SEC-2
- Technique: JQF generator produces a valid 16-byte header with a bind-family command_id + arbitrary-length arbitrary body; invariants: no Throwable escapes, reader index never exceeds frame length, bounded decode time.
- Tooling: JQF + JUnit5 + AssertJ; AD-24 mandated fuzz of the bind parser.
- Notes: AD-24 explicit requirement (a). Complements the framer fuzz (CODEC-011); the parsed attack surface is exactly these two decoders.

**CODEC-026** — SmppCommandIds.BIND_FAMILY is exactly the 6-id set {0x01,0x02,0x09,0x80000001,0x80000002,0x80000009}
Level: unit · Priority: P1 · Risks: R14 · NFR: FR-TRANSIT-4, COMP-1
- Technique: exhaustive enumeration assertion: BIND_FAMILY contains exactly the three bind requests and their three responses, no more, no less.
- Tooling: JUnit5 + AssertJ.
- Notes: AD-27 single-source-of-truth guard; the authoritative parsed-vs-opaque boundary. Regression-locks the set.

**CODEC-027** — outbind (0x0B) and generic_nack (0x80000000) are NOT in BIND_FAMILY — declared opaque-spliced
Level: unit · Priority: P1 · Risks: R14 · NFR: FR-TRANSIT-4
- Technique: assert neither id is a member of BIND_FAMILY and neither is parsed by the bind parser (opaque path).
- Tooling: JUnit5 + AssertJ.
- Notes: AD-27 explicit declaration; regression guard against accidentally widening the parsed surface (a common mistake since these ids neighbor bind ids).

**CODEC-028** — Non-bind command_ids (submit_sm, deliver_sm, enquire_link, unbind) are not parsed by the bind parser — opaque framed bytes
Level: unit · Priority: P1 · Risks: R14, R3 · NFR: FR-TRANSIT-4, SEC-2
- Technique: parameterized: frame each non-bind command_id; assert the bind parser produces no typed object (pass-through) and the framed ByteBuf is untouched.
- Tooling: JUnit5 (parameterized) + AssertJ + EmbeddedChannel.
- Notes: AD-3/AD-27: only bind family is parsed; everything else (incl. unbind post-couple) is opaque. Confirms the parsed attack surface is exactly two decoders.

**CODEC-029** — command_id response bit (bit 31 / 0x80000000) correctly distinguishes bind request from bind_resp; both recognized as bind-family
Level: unit · Priority: P1 · Risks: R14 · NFR: FR-TRANSIT-4
- Technique: assert bind_transceiver (0x09) and bind_transceiver_resp (0x80000009) both recognized; masking/clearing bit 31 does not conflate request with response.
- Tooling: JUnit5 + AssertJ.
- Notes: R14: a parser that masks bit 31 would mis-handle responses; a parser that ignores it would mis-handle requests.

**CODEC-030** — Spec-derived golden-vector corpus is authored independently and loaded from a resource, not synthesized by the codec under test
Level: unit · Priority: P1 · Risks: R33, R14 · NFR: COMP-1, FR-TRANSIT-3
- Technique: corpus lives as a checked-in resource (e.g. JSON/text of byte arrays + expected decodes) with a provenance header citing SMPP 3.4 spec sections; assert it loads and is non-empty; a test fails if any vector was generated by invoking the codec.
- Tooling: JUnit5 + AssertJ; corpus resource under src/test/resources.
- Notes: THE fix for R33 (sole-oracle blind spot): the in-JVM mock is built ON the codec and shares its bugs; this corpus is the 3rd oracle independent of codec AND jSMPP. Author bytes by hand from the spec.

**CODEC-031** — Independent-oracle agreement: codec decode of golden bytes equals jSMPP decode of the same bytes for the bind family
Level: conformance · Priority: P1 · Risks: R14, R33 · NFR: COMP-1, FR-TRANSIT-3
- Technique: feed each golden bind-family vector to BOTH the codec-under-test and jSMPP 3.0.2; assert field-by-field equality. Disagreement = a real codec or jSMPP defect to triage.
- Tooling: jSMPP 3.0.2 (org.jsmpp:jsmpp:3.0.2, interop-only — NEVER the production codec) + JUnit5 + AssertJ + golden corpus.
- Notes: R33/R14: jSMPP is the 2nd independent oracle; the golden corpus is the 1st. Two independent stacks agreeing on the same bytes is strong spec-conformance evidence.

**CODEC-032** — Encode→bytes round-trip: a typed bind object encoded by the codec produces bytes byte-identical to the golden vector
Level: unit · Priority: P1 · Risks: R14 · NFR: FR-TRANSIT-4
- Technique: construct typed bind from golden expected values; encode; assert output bytes equal the golden byte sequence exactly (no length-field drift, no field reordering, correct null terminators).
- Tooling: JUnit5 + AssertJ + golden corpus.
- Notes: R14 encode-side conformance; catches encoder bugs symmetric to the decoder (CODEC-016). Needed if the codec ever encodes (e.g. bind_resp status mapping); also validates the no-re-serialization property (CODEC-037).

**CODEC-033** — Golden NEGATIVE vectors: spec-derived malformed/truncated/oversized PDUs produce the expected reject outcome deterministically
Level: unit · Priority: P1 · Risks: R3, R33 · NFR: SEC-2
- Technique: curated negative corpus (truncated header, length<16, length>65536, unterminated string, body-shorter-than-fields) each tagged with expected outcome (drop/close); assert exact outcome per vector.
- Tooling: JUnit5 + AssertJ + golden negative corpus.
- Notes: Deterministic oracle for R3 robustness; complements randomized fuzz (CODEC-011/025). Overlap justified — golden = correctness oracle, fuzz = novel-path discovery (P1 defense-in-depth).

**CODEC-034** — Real TCP socket pair: a PDU split at every byte boundary by an adversarial writer reassembles into one correct frame on the reader
Level: conformance · Priority: P1 · Risks: R3, R14 · NFR: REL-1, FR-TRANSIT-3, SEC-2
- Technique: loopback ServerSocket+Socket; for split-point in 0..len: write prefix, flush, write suffix; reader decodes via the real SmppFrameDecoder on a Netty socket pipeline; assert one exact frame per split-point.
- Tooling: JUnit5 + AssertJ + real loopback TCP (java.net Socket/ServerSocket or Netty NioSocketChannel) — NOT ByteBuf slices.
- Notes: Blind-spot (c): must use a REAL socket pair, not ByteBuf slices — only real TCP exercises actual segmentation/coalescing. Anchor for REL-1 framing integrity.

**CODEC-035** — Real TCP socket pair: multiple PDUs and partial fragments interleaved over the wire reassemble in correct order
Level: conformance · Priority: P1 · Risks: R3 · NFR: REL-1, FR-TRANSIT-3
- Technique: send PDU1 fully, then PDU2+half-of-PDU3 in one write, then remainder of PDU3 + PDU4; assert 4 frames out in order, each byte-exact.
- Tooling: JUnit5 + AssertJ + real loopback TCP + Netty socket pipeline.
- Notes: Blind-spot (c) multi-PDU coalesce case; validates ordering and accumulation across TCP write boundaries.

**CODEC-036** — Real TCP socket pair: writer closes mid-PDU — reader emits no truncated frame and sees a clean close
Level: conformance · Priority: P1 · Risks: R3 · NFR: REL-1, SEC-2
- Technique: write a valid PDU then half of a second PDU, then close the socket; assert reader decoded the first frame only, emitted no partial second frame, and channelInactive fired cleanly.
- Tooling: JUnit5 + AssertJ + real loopback TCP.
- Notes: Blind-spot (c) partial-at-close case over a real socket; the production session-end path (AD-25: session ends on TCP half-close).

**CODEC-037** — Byte-exact forwarding: after parsing a bind request, the original framed ByteBuf is byte-identical and un-mutated (ORIGINAL bind preserved for the SMSC)
Level: unit · Priority: P1 · Risks: R14, R3 · NFR: REL-1, FR-TRANSIT-4
- Technique: snapshot framed ByteBuf bytes; run bind parser; assert snapshot == current bytes and reader index is restored (parser reads a slice/copy, never mutates the forward buffer). Property repeated across the bind corpus.
- Tooling: JUnit5 + AssertJ + jqwik property (bind corpus).
- Notes: AD-12: the token is discarded and the ORIGINAL bind is relayed to the SMSC (sole credential authority) — byte-identity of the bind is a SECURITY property. Codec contribution: the parser must not corrupt the forward unit. End-to-end byte-identity across the relay is validated in E2E/relay tests.

**CODEC-038** — Byte-exact forwarding: opaque PDUs (submit_sm/deliver_sm-DLR/enquire_link/unbind) are forwarded byte-identical with no decode/re-serialize path
Level: fuzz · Priority: P1 · Risks: R3, R14 · NFR: REL-1, FR-TRANSIT-4, SEC-2
- Technique: jqwik property over arbitrary non-bind command_ids + arbitrary bodies: assert the codec produces no typed object and the framed ByteBuf forwards untouched (bytes in == bytes out).
- Tooling: jqwik + JUnit5 + AssertJ.
- Notes: AD-2/AD-3: framed-PDU ByteBufs are the forward unit, never round-tripped through a typed object for non-bind. Confirms PRIV-1-friendly opacity and REL-1 byte integrity for the opaque majority of traffic.

**CODEC-039** — Automated inward-only dependency gate: codec compiled classes depend on ZERO smpp.companion.proxy.* packages
Level: integration · Priority: P1 · Risks: R14 · NFR: MAINT-2
- Technique: ArchUnit CI rule: no_classes().that().resideInAPackage('smpp.companion.codec..').should().dependOnClassesThat().resideInAnyPackage('smpp.companion.proxy..'); fails the build on violation.
- Tooling: ArchUnit + JUnit5 + Gradle CI gate.
- Notes: AD-7 load-bearing MAINT-2 invariant enforced mechanically (stronger than any review rule). Direction is strictly proxy→codec.

**CODEC-040** — Codec dependency allowlist: codec depends only on netty-buffer/netty-codec + JDK stdlib — no Spring/Nimbus/proxy-app/observability libs (codec never emits metrics)
Level: integration · Priority: P1 · Risks: R14 · NFR: MAINT-2
- Technique: Gradle dependency-analysis / forbidden-imports scan on codec module: assert the resolved compile classpath contains only {netty-buffer, netty-codec, JDK}; explicitly exclude spring-*, nimbus-*, micrometer-*, slf4j-app. Encode the AD-27 'codec never emits metrics' rule by excluding observability libs.
- Tooling: Gradle dependencyInsight / japicmp-style allowlist task + JUnit5 CI gate.
- Notes: MAINT-2 extractability + AD-27 'codec never emits metrics'. Catches a direct micrometer/Nimbus dep that the ArchUnit package-direction rule (CODEC-039) could miss if the lib isn't under a proxy package.

**CODEC-041** `[critic-fix: ADDED]` — CI-gate positive control: codec dependency-allowlist gate FIRES on an injected forbidden spring-boot-starter-web / nimbus / micrometer dependency
Level: integration · Priority: P1 · Risks: R14, R16 · NFR: MAINT-2, SEC-2
- Technique: positive control modeled on RELAY-018's BlockHound control — inject a forbidden dependency (spring-boot-starter-web, nimbus-jose-jwt, or micrometer-core) into the codec module's resolved compile classpath via a throwaway fixture config and assert CODEC-040's allowlist gate FAILS the build (not merely exists). Proves a misconfigured allowlist / wrong scope cannot silently bypass the gate.
- Tooling: Gradle dependency-analysis / forbidden-imports task + JUnit5 injected-bad-coordinate fixture + AssertJ.
- Notes: [critic-fix] Closes the CI-gate-positive-control gap (cross-level issue). CODEC-040 asserts the gate EXISTS but never injects a known-bad input, so a too-narrow rule would silently disable it while every test passes. Pairs with SEC-099 (CVE gate) and OBS-043 (Actuator/WebFlux gate).

## 3. RELAY — Netty event-loop splice, concurrency & backpressure

Owns R5 (the lone P0 DATA risk), decomposed into all five named seams: pre-couple window (RELAY-002/003), re-bind (RELAY-004), registry teardown race + leak (RELAY-005/006/007), half-close/unbind/RST ordering (RELAY-008/009/010), partial-A-1 affinity (RELAY-011/012). Plus R27 (direct-memory / backpressure / ByteBuf leak) and R28 (event-loop blocking). RELAY-016 was folded into RELAY-017 (see §9).

**RELAY-001** — AD-25 single-flipper guard: splice flag flips ONLY on decoded bind_*_resp with command_status==ESME_ROK (no flip on non-ROK, peeked command_id, arbitrary egress frame, or Verdict.Allow-without-bind_resp)
Level: unit · Priority: P0 · Risks: R5 · NFR: REL-1, FR-TRANSIT-1, AD-25
- Technique: parametrized state-machine matrix over the flip-trigger inputs; pure RelayHandler flip decision in isolation (codec live, no network).
- Tooling: JUnit5/Jupiter parametrized + AssertJ; Netty EmbeddedChannel; hand-fed decoded bind_*_resp objects via the codec branch.
- Notes: Tests the ONE load-bearing runtime mechanism in isolation. Branch matrix: (a) decoded bind_transceiver_resp ROK -> flip + onBindAccept; (b) decoded bind_*_resp non-ROK status -> NO flip + teardown signal; (c) raw frame whose command_id matches bind_resp but NOT decoded -> NO flip (rejects the 'peeked command_id' shortcut AD-25 forbids); (d) arbitrary egress frame (e.g. enquire_link_resp) -> NO flip; (e) Verdict.Allow returned by BindCredentialVerifier but no bind_resp yet -> NO flip. Confirms the control-plane BindAdjudicator never mutates the data-plane flag. Lowest-sufficient level for the flip decision; wire-level confirmation is RELAY-002/008.

**RELAY-002** — Pre-couple eager non-bind PDU on ingress is closed with NO synthetic response; no PDU reaches the egress/SMSC; teardown observed (AD-32, bare-close) `[RESOLVED — Q1 → AD-32]`
Level: conformance · Priority: P0 · Risks: R5, R1(fail-closed) · NFR: REL-1, FR-TRANSIT-1, FR-SEC-5, AD-25, AD-3, AD-32
- Technique: real socket pair with a CountdownLatch-held verdict to widen the pre-couple window; legacy sends a well-formed `submit_sm` (command_id 0x00000004, seq=N) AFTER bind but BEFORE `bind_resp`.
- Tooling: in-JVM mock SMSC on codec; jSMPP 3.0.2 as alternate ESME client (assert its blocking `submit_sm()`/`bind()` handle the bare close gracefully — connection-lost, not a hang); capturing SpliceObserver fake; fake BindCredentialVerifier; byte-capture on both legs.
- Assertions (Given/When/Then): (wire) the proxy emits **NO PDU** toward the legacy ESME — the connection is closed (bare-close, above-spec fail-closed; no synthetic `_resp`); (no-splice) `onFramedPdu(EGRESS)` for the `submit_sm` NEVER fires + zero `submit_sm` bytes reach the SMSC; (no-couple) `onBindAccept` NEVER fires; the in-flight bind is torn down (ConnectionRegistry entry removed + marked tearing-down BEFORE close; ROPC cancelled via the AD-12 handle, password zeroized); (observable) `onConnectionClosed(INGRESS, PRE_COUPLE_NON_BIND_PDU)` fires + `relay_connections_closed_total{direction=ingress,reason=pre_couple_non_bind_pdu}` increments with NO `system_id`/`command_id` label; (privacy) no `submit_sm` body in logs/metrics at default level.

**RELAY-002a** / **RELAY-002b** — *(removed 2026-07-23)*. The pre-couple `unbind`-handshake and `enquire_link`-keepalive carve-outs were dropped for implementation simplicity; AD-32 now closes uniformly on everything except the bind family (an `unbind` or `enquire_link` pre-couple → close, no response, per the RELAY-002 bare-close path). The interop constraint (carrier `enquire_link` keepalive interval must exceed PERF-3 bind latency) is in the Accepted-Risk Register + the A-1 carrier check.

**RELAY-002c** — Egress `generic_nack` (or non-ROK `bind_*_resp`) from the SMSC pre-`bind_resp` is **forwarded verbatim** to the legacy ESME as the bind result (SMSC = sole credential authority); no splice flip; both legs torn down (AD-32 case 4) `[Q1 → AD-32]`
Level: integration · Priority: P1 · Risks: R32, R5 · NFR: REL-1, AD-32
- Technique/Notes: mock SMSC sends `generic_nack` (and separately a non-ROK `bind_resp`) pre-`bind_resp`; byte-capture asserts the SMSC's actual response bytes reach the legacy unchanged, `onBindAccept` never fires (no couple), and both legs close. Distinct from proxy-own denials (IdP/routing → AD-33 collapse) and SMSC transport-death (no PDU → AD-33 synthesized).

**RELAY-003** — Pre-couple non-bind PDU arriving on the egress leg (deliver_sm from SMSC before couple) is NOT leaked to the legacy client
Level: conformance · Priority: P0 · Risks: R5 · NFR: REL-1, FR-TRANSIT-1, AD-3, AD-25
- Technique: real socket pair; mock SMSC pushes a deliver_sm in the window between egress-connect and the decoded bind_resp ROK; assert zero egress-to-ingress splice pre-flip.
- Tooling: in-JVM mock SMSC on codec (programmed to emit deliver_sm pre-bind_resp); capturing SpliceObserver; fake BindCredentialVerifier.
- Notes: The egress Channel may exist (connected) but the pair is not yet coupled (flag pre-flip). Under AD-32 case 4, a pre-couple egress non-bind PDU (e.g. `deliver_sm`) → egress closed + bind-failure propagated to the ingress leg within PERF-3 (R32). Assert `SpliceObserver.onFramedPdu(INGRESS)` count == 0 (nothing leaked to legacy before the session is auth-established) AND `onConnectionClosed(EGRESS, …)` fires. (`generic_nack` specifically = RELAY-002c.) Mirror of RELAY-002 on the egress leg; both needed because the two legs have asymmetric pipelines (egress has no BindInterceptor).

**RELAY-004** — Client retry-bind (second bind_transceiver) arriving while the first adjudication is in-flight is deterministically rejected/teardown — no second pair created, no ConnectionRegistry corruption
Level: integration · Priority: P0 · Risks: R5 · NFR: REL-1, AD-8, AD-25
- Technique: fake BindCredentialVerifier that blocks its returned CompletableFuture until latched; inject a second bind on the same ingress Channel mid-wait; assert registry holds exactly one entry and the second bind is rejected (error/close) not enqueued-then-coupled.
- Tooling: Netty EmbeddedChannel or in-JVM pair; fake BindCredentialVerifier with CountdownLatch-held verdict; AssertJ on ConnectionRegistry.size() and a capturing SpliceObserver.
- Notes: R5a sub-branch. The retry-bind is a bind-family PDU pre-couple, so AD-3 routes it to BindInterceptor (not opaque). The ambiguous case: two binds racing on one ingress Channel. Assertion must pin the deterministic outcome (reject-second-or-teardown-both) so neither 'silent second couple overwriting the first registry entry' nor 'duplicate egress pair' can occur. Cross-referenced with the pre-couple-policy open question (Q1).

**RELAY-005** — Near-simultaneous channelInvalid on both legs tears down idempotently: registry entry removed exactly once, password double-zeroize is safe, stale Channel attribute cleared, both legs closed
Level: integration · Priority: P0 · Risks: R5, R8 · NFR: REL-1, REL-4, AD-8, AD-12
- Technique: race two channelInvalid events (ingress+egress) with a CountDownLatch/CyclicBarrier release; assert no ConcurrentModificationException, remove is idempotent (second remove is a no-op), Channel attribute is nulled, and the zeroize path is re-entrant (double-zeroize of an already-zeroed char[] does not throw).
- Tooling: Netty EmbeddedChannel pair; ConnectionRegistry bean; a CountDownLatch to align the two invalidation threads; AssertJ; reflectively assert char[] contents are zero after the double call.
- Notes: R5b teardown-race seam. AD-8 teardown removes via channelInvalid; the race is when both legs invalidate ~simultaneously. The zeroize re-entrancy assertion covers the relay slice of R8. Stale Channel attribute clearing is folded here (a stale attr referencing a dead entry is a leak vector). jcstress-level statistical coverage is RELAY-007.

**RELAY-006** — Egress-connect failure AFTER the ConnectionRegistry entry was created removes the entry and tears down the ingress leg — no orphaned entry, no half-created pair lingering
Level: integration · Priority: P0 · Risks: R5, R32 · NFR: REL-1, REL-4, AD-8
- Technique: fake BindCredentialVerifier returns Allow; registry entry created optimistically; mock egress Bootstrap.connect() fails; assert registry empties, ingress Channel closes, capturing SpliceObserver records no onBindAccept.
- Tooling: in-JVM pair; a failing egress connect (bind to a refused port or an injected failing ChannelFuture); ConnectionRegistry size assertions; capturing SpliceObserver.
- Notes: The registry-aspect of egress-establishment failure (R5b orphan). Distinct from RELAY-020 (R32 legacy-notification/no-hang behavior). The entry-must-not-leak assertion is load-bearing (a leaked entry = a phantom pair counting against PERF-2 and corrupting teardown enumeration in AD-22).

**RELAY-007** — ConnectionRegistry concurrent lifecycle (put/get/remove/double-remove across ingress ChannelIds) preserves no-lost-entry / no-orphan / no-double-add invariant under all thread interleavings `[BLOCKED-ON-Q2]`
Level: unit · Priority: P0 · Risks: R5 · NFR: REL-1, REL-4, AD-8
- Technique: jcstress-style concurrency stress of the registry as a single isolated unit; millions of interleavings across concurrent putters/getters/removers; assert size and presence invariants hold at every observed state.
- Tooling: jcstress harness (or a JUnit-based deterministic stress with a CountDownLatch flood); AssertJ; ConcurrentHashMap-backed registry under test.
- Notes: Addresses blind-spot #2 (statistical concurrency defects). A single-shot race (RELAY-005) cannot prove the invariant; this exhausts thread permutations. Lower-than-integration level because the registry is one bean with a narrow contract. **Open question Q2:** if the team does NOT adopt jcstress as a build target, downgrade to a JUnit-based stress harness (much weaker coverage) and add a high-iteration soak with randomized delay injection to approximate interleaving coverage.

**RELAY-008** — Post-couple TCP half-close (channelInvalid) on either leg propagates teardown to BOTH legs and the registry; in-flight framed PDUs are deterministically drained or dropped (no dup, no corrupt partial frame)
Level: conformance · Priority: P0 · Risks: R5 · NFR: REL-1, FR-TRANSIT-1, AD-2, AD-3, AD-8
- Technique: real socket pair coupled and splicing; close one leg's socket (half-close) mid-stream; assert the peer leg closes, registry entry removed, and a sequence-number-ordered stream of PDUs shows no gap/dup/corrupt at the boundary.
- Tooling: in-JVM mock SMSC on codec; jSMPP 3.0.2 client driving a numbered submit_sm stream; capturing SpliceObserver; sequence-number integrity assertion.
- Notes: R5c core. AD-3: 'session ends on TCP half/close (channelInvalid) on either leg, which tears the per-bind pair.' The REL-1 headline guarantee. The sequence-number assertion distinguishes drop/dup/corrupt. Oracle-independence: sequence integrity is cross-checked by the jSMPP-driven stream (independent client).

**RELAY-009** — In-flight unbind_resp / submit_sm_resp racing the peer's channelInvalid completes-or-cancels cleanly — no partial frame written to the wire, no duplicate on re-arm
Level: conformance · Priority: P0 · Risks: R5 · NFR: REL-1, AD-2, AD-25
- Technique: real socket pair; schedule a write of unbind_resp (opaque, post-couple) simultaneously with a peer-side close; capture the egress byte stream and assert no truncated PDU length-prefix reaches the peer.
- Tooling: in-JVM pair with a recording ByteBuf sink on the legacy side; CountDownLatch to align write+close; assert the captured bytes parse as zero or exactly one complete framed PDU.
- Notes: R5c ordering sub-branch. Risk = a half-flushed PDU (4-byte length header claiming N but only M<N written before close) which a peer codec may mis-parse. Asserts Netty's write-cancellation yields a clean (empty or whole) byte stream. Distinct from RELAY-008 (teardown propagation); this tests the write/close micro-race.

**RELAY-010** — Peer TCP RST mid-splice tears down both legs + registry and the teardown is OBSERVED (SpliceObserver / metric) — not a silent drop of in-flight PDUs
Level: conformance · Priority: P0 · Risks: R5 · NFR: REL-1, FR-TRANSIT-1, AD-8, AD-27
- Technique: real socket pair; inject a TCP RST (SO_LINGER 0 close) on one leg while PDUs are in flight; assert both legs close, registry empties, and a teardown/metric event fires (so the drop is diagnosable, not silent).
- Tooling: in-JVM pair; a capturing SpliceObserver plus an increment-on-teardown metric; assert the observer/metric recorded the invalidation.
- Notes: R5c RST sub-branch. 'Silent drop' is the worst REL-1 failure (PDUs vanish with no signal). The relay cannot recover a RST'd in-flight PDU, but it MUST surface the teardown (AD-19/AD-27 observability). Assertion is two-part: (1) correct teardown, (2) non-silent (observable).

**RELAY-011** — Concurrent coupled pairs under the same system_id show zero DLR cross-bleed: a deliver_sm on each egress leg lands on its originating ingress leg ONLY
Level: conformance · Priority: P0 · Risks: R5 · NFR: REL-1, REL-4, FR-TRANSIT-2, AD-9
- Technique: open N coupled pairs (same system_id, distinct ingress Channels); inject a uniquely-tagged deliver_sm on each egress; assert each tag arrives on exactly its originating ingress via the capturing SpliceObserver per-Channel.
- Tooling: in-JVM mock SMSC on codec emulating A-1 multi-bind affinity; capturing SpliceObserver wired per ingress Channel; AssertJ on tag-to-channel mapping.
- Notes: R5d — the CI-testable core of A-1. The coupled pair IS the session affinity (AD-9); if affinity leaks, a DLR routes to the wrong legacy bind = silent misdelivery (worst class). Oracle-independence caveat: the mock EMULATES A-1 (assumes the property); this validates the relay's pair-isolation, NOT the carrier's affinity behavior. Mock cannot surface a real SMSC-LB-failover misroute — see RELAY-012 and the non-CI A-1 ops plan (OBS-035..038).

**RELAY-012** — Egress reconnect/flap does NOT re-route stale DLRs to a new or different pair: old registry entry torn down, stale egress channel discarded
Level: integration · Priority: P1 · Risks: R5 · NFR: REL-1, REL-4, FR-TRANSIT-2, AD-9
- Technique: flap the egress leg (close + reconnect) mid-session; assert the old registry entry is removed, a stale deliver_sm on the old egress Channel is dropped (not forwarded to the new or any other pair), and the new pair binds cleanly.
- Tooling: in-JVM pair with a controllable egress Channel; capturing SpliceObserver; AssertJ that no onFramedPdu fires for the stale deliver_sm.
- Notes: R5d partial-A-1-affinity under flap. FLAG: the real SMSC-LB-failover silent-misdelivery risk is NON-CI (R38) — the mock cannot reproduce a carrier-side LB failover where the SMSC itself misroutes. This scenario covers the CI-testable relay slice (no stale-channel reuse). The residual P0 risk (carrier LB affinity) docks under the non-CI A-1 ops plan (AD-24/AD-31).

**RELAY-013** — Direct-memory ceiling holds under combined PERF-1 (10K submit_sm/s) + PERF-2 (10K idle pairs) load: ByteBufAllocatorMetric activeDirectMemory stays at/below the AD-30 formula bound, no OOM/allocation-failure
Level: perf · Priority: P1 · Risks: R27 · NFR: REL-2, SEC-2, PERF-1, PERF-2, AD-21, AD-30
- Technique: open-model soak at the combined PERF-1+PERF-2 envelope; sample ByteBufAllocatorMetric.pinnedDirectMemory/activeDirectMemory and PooledByteBufAllocatorMetric along the run; assert peak <= max_frame x max_inbound_depth x concurrent_pairs x safety_factor and zero allocation failures.
- Tooling: open-model load harness (load-gen on separate cores); in-JVM mock SMSC as sink; ByteBufAllocatorMetric + PooledByteBufAllocatorMetric assertions; one named AD-30 formula constant shared with the codec max so they cannot drift (now statically asserted by RELAY-026).
- Notes: R27 budget-at-cliff. Asserts the named AD-30 formula holds at the design envelope. Methodology (open-model, separate-core load-gen, p50/90/99/99.9 disclosure) is owned by the Epic-6 perf area; this scenario asserts the memory invariant only. Compile-time shared-constant guard = RELAY-026.

**RELAY-014** — AUTO_READ backpressure state machine: high-water write-completion disarms read, low-water re-arms it (parametrized over threshold crossings)
Level: unit · Priority: P1 · Risks: R27 · NFR: REL-2, AD-2, AD-30
- Technique: pure state-machine test of the backpressure handler with a fake Channel whose autoRead state and outbound buffer depth are controllable; parametrized over high-water-trip / low-water-re-arm / idle / double-trip.
- Tooling: JUnit5 parametrized + AssertJ; Netty EmbeddedChannel with a controllable ChannelConfig; reflectively drive the high/low-water marks.
- Notes: Lowest-sufficient level for the backpressure state machine (AD-2/AD-30). The end-to-end correlated-burst behavior is RELAY-015 (perf). Keep both: cheap deterministic pinning of the trip/re-arm logic + load-level proof.

**RELAY-015** — Correlated slow-consumer burst: egress leg stalls while ingress floods — AUTO_READ backpressure trips, direct memory stays bounded, no OOM (absorbs PERF-041's budget-not-exceeded slice)
Level: perf · Priority: P1 · Risks: R27 · NFR: REL-2, SEC-2, PERF-1, AD-2, AD-30
- Technique: open-model burst: drive ingress at PERF-1 rate while the egress mock stalls (artificial per-write delay / zero read on the SMSC side) for a burst window; assert ingress autoRead disarms at high-water, direct memory plateaus (does not grow unbounded) AND ByteBufAllocatorMetric.usedDirectMemory() stays within the AD-30 budget, and re-arms when the stall releases.
- Tooling: in-JVM mock SMSC with an injectable stall (injectable Clock/scheduler seam); ByteBufAllocatorMetric sampling; assert peak direct memory, the low-water re-arm fires, and the budget is not exceeded.
- Notes: R27 correlated-slow-consumer-burst seam. The 'correlated' part is key: many ingress channels stalling into one slow egress simultaneously (a realistic SMSC slowdown). `[critic-fix: absorbed PERF-041]` — PERF-041 (same-level slow-egress burst) was merged here; its only distinct slice (explicit ByteBufAllocatorMetric budget-not-exceeded assertion) is now part of this scenario. Distinct from the steady-state ceiling (RELAY-013) — this is the transient cliff. REL-2 (backpressure not OOM) is the headline assertion.

**RELAY-017** — Error-path ByteBuf release integrity: zero leaks across the error+churn matrix (decode exception, oversized frame, write failure, channelInvalid mid-write) under Netty PARANOID ResourceLeakDetector (absorbs RELAY-016 + PERF-042)
Level: integration · Priority: P1 · Risks: R27 · NFR: REL-2, SEC-2, AD-2, AD-30
- Technique: parametrized error+churn matrix; run each fault path through the relay with -Dio.netty.leakDetection.level=PARANOID; assert zero 'LEAK' records at teardown across the matrix AND ByteBufAllocatorMetric returns to baseline after each fault path.
- Tooling: Netty ResourceLeakDetector PARANOID; JUnit5 parametrized over the fault inputs (decode exception, oversized frame, write failure / peer RST, channelInvalid mid-write); in-JVM pair; assert the leak-detection log/report is empty after full registry drain and metric returns to pre-failure baseline.
- Notes: R27 error-path-leak seam. Every acquired framed ByteBuf must be released exactly once on every path, including the paths that throw. PARANOID is the mechanical guarantee code-review cannot give. `[critic-fix: absorbed RELAY-016 + PERF-042]` — RELAY-016's autoRead-disarmed-on-write-failure assertion and PERF-042's metric-returns-to-baseline assertion were folded into this matrix (the write-failure cell was triplicated). Invariant = ref-count integrity across the WHOLE error matrix, not read-arming; the surviving-leg autoRead-stays-disarmed assertion from the former RELAY-016 is retained as one matrix cell.

**RELAY-018** — BlockHound positive control: a deliberately injected blocking call on an event-loop thread IS detected (allow-list is not over-broad)
Level: integration · Priority: P1 · Risks: R28 · NFR: PERF-1, AD-4
- Technique: register BlockHound on the NioEventLoopGroup threads; inject a Thread.sleep / blocking Future.get into the RelayHandler path; assert BlockHound throws its blocking-call error.
- Tooling: BlockHound with a test-specific allow-list; JUnit5; an instrumented RelayHandler that conditionally blocks.
- Notes: Addresses blind-spot #3 (AD-4 is convention-enforced; JFR only catches VT pinning, not event-loop blocking). The 'test the detector' positive control: it MUST fire on an injected blocking call, proving the allow-list (needed for legitimate JDK internals like SslHandler delegated tasks) has not swallowed real violations. Paired with RELAY-019. This is the MODEL for the CI-gate positive controls (SEC-099/CODEC-041/OBS-043).

**RELAY-019** — BlockHound clean on the relay hot path: driving bind -> couple -> splice -> unbind -> half-close churn yields ZERO blocking-call detections on event-loop threads
Level: integration · Priority: P1 · Risks: R28 · NFR: PERF-1, PERF-4, AD-4, AD-1
- Technique: with BlockHound engaged on event-loop threads, run the full relay lifecycle churn (bind adjudication via fast fake verifier, couple, bidirectional splice, unbind, half-close) for N iterations; assert no BlockingOperationError.
- Tooling: BlockHound; in-JVM pair; fake BindCredentialVerifier returning an already-completed Allow (so the VT pool is exercised off the event loop); AssertJ that no BlockHound error fires.
- Notes: The real assertion of AD-4: production relay paths do not block event-loop threads. Distinct from RELAY-018 (proves the detector works). Catches a stray blocking DNS/file/Future.get call that convention/review missed — the mechanical backstop. Fake verifier ensures the control plane stays on VTs (so a control-plane block would NOT fire here, correctly).

**RELAY-020** — Egress TCP connect refused AFTER Verdict.Allow: legacy client receives bind_resp error (or clean close) within the PERF-3 timeout, registry cleaned, no hang/leak
Level: integration · Priority: P2 · Risks: R32 · NFR: REL-3, PERF-3, AD-12
- Technique: fake BindCredentialVerifier returns Allow; egress Bootstrap.connect() to a refused port; with an injectable Clock advance past the egress-connect timeout; assert legacy receives a synthesized bind_resp error or clean close within the PERF-3 bound and the registry empties.
- Tooling: in-JVM pair; injectable Clock/scheduler; fake verifier; a refused egress endpoint; AssertJ on the legacy-received PDU and registry size; no Thread.sleep.
- Notes: R32 — the underspecified error path: ALLOW won, but the relay cannot reach the SMSC. Risk = a hanging legacy socket. Injectable Clock makes the timeout deterministic. Registry-cleanup aspect is RELAY-006; this isolates the legacy-facing no-hang behavior. Exact ESME_* status code deferred to a single story (Q7) — assert 'bind_resp with non-ROK status OR clean close, within timeout'.

**RELAY-021** — Egress TLS handshake failure post-ALLOW (TCP up, handshake fails) tears down the half-created pair: legacy notified, no lingering pair
Level: integration · Priority: P2 · Risks: R32 · NFR: REL-3, PERF-3, SEC-1
- Technique: fake verifier Allow; egress TCP connects but the egress SslHandler handshake fails (present an untrusted/wrong cert); assert teardown propagates to ingress, legacy notified within timeout, registry empties, no half-coupled pair.
- Tooling: in-JVM pair with a controllable egress SslContext (presents a cert not in the trust store); injectable Clock; capturing SpliceObserver (assert no onBindAccept).
- Notes: R32 sub-branch: failure occurs LATER than RELAY-020 (after TCP, during handshake). Distinct because the registry entry may exist and the egress Channel is further along, so the teardown path differs. Asserts the handshake-fail callback propagates fully to the ingress leg (a subtle gap: the failure fires on the egress event loop but must close the ingress leg via the registry).

**RELAY-022** — Graceful shutdown (AD-22) drains in-flight splices within the configured timeout: no silent drop of completed PDUs, no corrupt partial frame written, ConnectionRegistry empties to zero
Level: integration · Priority: P1 · Risks: R11 · NFR: REL-1, REL-3, AD-8, AD-22
- Technique: with N coupled pairs mid-splice, fire SIGTERM (Spring SmartLifecycle graceful-shutdown callback); enumerate the registry drain; assert in-flight PDUs either complete within the timeout or are cleanly closed (no partial frame), and registry size reaches 0.
- Tooling: Spring Boot test slice exercising SmartLifecycle; in-JVM mock SMSC; capturing SpliceObserver; sequence-number integrity on the drained streams; injectable Clock to bound the drain window deterministically.
- Notes: R11 relay/concurrency slice. AD-22 step 3 (drain in-flight splices by enumerating the registry). Defect class: shutdown closes channels mid-write, truncating a PDU (corrupt) or dropping a completed PDU silently (REL-1). The full AD-22 step ordering is owned by the OBS/bootstrap area (OBS-016 — 5 steps since the two JWKS drain steps died with local JWT verification, Story 3.4 T2, 2026-08-27); this scenario owns the relay drain step. (OBS-015's re-assertion of this zero-drop invariant was dropped as duplicated; OBS-015 keeps only the e2e packaging/process-exit aspect.)

**RELAY-023** — ALLOW verdict racing SIGTERM does NOT couple: adjudication is cancelled (shutdownNow on the VT pool) fail-closed, flag never flips, legacy gets bind_resp error
Level: integration · Priority: P1 · Risks: R11 · NFR: REL-3, FR-SEC-5, AD-11, AD-22, AD-28
- Technique: fake verifier holds the Allow verdict until latched; fire SIGTERM so AD-22 step 2 (DENY in-flight = shutdownNow + await on the VT pool) races the verdict completion; assert the pair does NOT couple (no onBindAccept), legacy is closed with bind_resp error.
- Tooling: in-JVM pair; fake BindCredentialVerifier with a CountDownLatch-held Allow; Spring SmartLifecycle shutdown trigger; capturing SpliceObserver; AssertJ on flip state and legacy-received PDU.
- Notes: R11 partial-verdict race — the specific 'verdict completing at the same instant as shutdown must not cause a couple' defect. AD-28: the VT pool is shutdownNow()+awaited on shutdown. Fail-closed (AD-11) governs: indeterminate shutdown-time verdict -> no couple. Load-bearing relay-side assertion of the shutdown race; control-plane STS-cancellation correctness is owned by the security area (OBS-019).

**RELAY-024** — Dedicated race-soak: bind -> couple -> splice -> teardown under delay-injection + event-loop-jitter + randomized-channelInvalid, asserting REL-1 invariants over millions of iterations `[BLOCKED-ON-Q2]`
Level: fuzz · Priority: P0 · Risks: R5 · NFR: REL-1, REL-2, REL-4, AD-2, AD-8, AD-25, AD-30
- Technique: long-running randomized soak (distinct from the Epic-6 throughput soak): a testing EventExecutor injecting random delays, randomized channelInvalid timing on either leg, randomized egress-connect-failure and peer-RST injection; assert over millions of cycles: registry size returns to 0, zero ByteBuf leaks (PARANOID), no drop/dup/corrupt in a numbered-PDU stream, no orphaned pairs.
- Tooling: custom Netty testing EventExecutor with delay injection; randomized fault injector; PARANOID ResourceLeakDetector; numbered-sequence submit_sm integrity check; capturing SpliceObserver; assert final registry size == 0 and leak log empty.
- Notes: Addresses blind-spot #2 directly: the statistical concurrency defects (pre-couple window, teardown race, half-close/RST ordering, write-failure leak) are NOT surfaced by single-shot conformance or by the throughput soak. This is the race-detector. Distinct from RELAY-007 (jcstress on the registry alone) — this exercises the full relay lifecycle under jitter. Seed all randomness (deterministic, reproducible failures). **Open question Q2:** jcstress adoption is unresolved; if not adopted, strengthen the soak iteration count + delay injection.

**RELAY-025** `[critic-fix: ADDED]` — REL-4 structural arch-scan: no message_id→system_id correlation map exists in relay/ (statelessness invariant)
Level: integration · Priority: P1 · Risks: (structural REL-4; backs R5d / R38) · NFR: REL-4, AD-8
- Technique: ArchUnit CI rule scanning smpp.companion.relay..: assert no field/type whose key type is a message_id (String/long/sequence-number) mapping to a system_id / Channel / pair reference exists (no message_id-keyed map / cache). Behavioral coverage exists (RELAY-011 DLRs route via the coupled channel); this is the structural guard so a future 'performance cache' adding a message_id→system_id map cannot break REL-4 without failing this scan.
- Tooling: ArchUnit + source/field-type scan + JUnit5 + Gradle CI gate.
- Notes: [critic-fix] Closes the REL-4 NFR-evidence gap. REL-4/AD-8 make 'message_id→system_id correlation never exists; socket-pairing state only' the load-bearing statelessness invariant (the thing that makes future HA possible). CODEC-039/SEC-090 have arch scans; REL-4 had none. RELAY-011 would still pass if a redundant message_id map were added (the coupled channel still works), so a structural scan is required.

**RELAY-026** `[critic-fix: ADDED]` — AD-30 shared-constant static assertion: codec-max (65536) and MaxDirectMemorySize formula input reference ONE named constant
Level: integration · Priority: P1 · Risks: R27 · NFR: REL-2, SEC-2, AD-30
- Technique: ArchUnit/Gradle static assertion: the codec max frame size (65536) and the MaxDirectMemorySize formula input (max_frame × max_inbound_depth × concurrent_pairs × safety_factor) both reference the SAME named constant (compile-time AST / reference scan). Compile-time drift prevention — a runtime soak (RELAY-013/PERF-040) cannot catch a conservative drift where both happen to be large enough that the soak passes while the constants silently differ.
- Tooling: ArchUnit + Gradle build task (AST/reference scan) + JUnit5 CI gate.
- Notes: [critic-fix] Closes the cross-level gap (open question Q5). AD-30's headline invariant is 'one named formula so the codec max and the allocator budget cannot drift.' The specific R27 defect is the codec max and MaxDirectMemorySize silently diverging. RELAY-013/PERF-040/DEPLOY-004 assert the budget holds at runtime; none makes the compile-time shared-constant assertion.

## 4. SEC — Security: fail-closed adjudication, trust anchoring, credential-free-at-rest, fail-fast, TLS

The crown jewels. Owns the P0 set R1 (fail-closed enumeration, decomposed per-branch), R2 (ROPC/IdP interop outage), R7 (trust anchoring), R8 (credential-free / zeroization). The `BindCredentialVerifier` port (`CompletableFuture<Verdict>`) + sealed `Verdict` + `BindCredential` record make adjudication unit-testable with a fake verifier, decoupled from Nimbus/ROPC/IdP. The ~15 DENY branches are an exhaustive parameterized matrix — a single missed branch = accept-on-indeterminate = credential bypass.

### 4.1 ROPC token-endpoint DENY matrix (AD-11, R1) — exhaustive per-branch

**SEC-001** — Deny bind (DenyInvalid) when the ROPC token endpoint returns HTTP 401
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3, FR-AUTH-1
- Technique: parametrized negative via the BindCredentialVerifier port; injected fake IdP HTTP returns 401; assert Verdict=DenyInvalid (definitive invalid credential).
- Tooling: JUnit5 @ParameterizedTest + AssertJ; in-JVM fake OIDC HTTP (WireMock-equivalent) + injectable Clock. *(The fake JWKS source clause died with local verification, Story 3.4 T2, 2026-08-27.)*
- Notes: Branch-1 of the exhaustive AD-11 matrix. DenyInvalid (not Indeterminate) because 401 is a definitive credential rejection; pin the subtype. (The matrix's non-401 deny cause re-worded 2026-08-27, Story 3.4 T1+T2: not "fails local verification" but "is not a 200 + three-segment token".)

**SEC-002** — Deny bind (DenyIndeterminate) when ROPC returns 200 with a non-JWT JSON body
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: parametrized negative via port; fake IdP returns 200 application/json without a JWT; assert DenyIndeterminate.
- Tooling: JUnit5 + fake IdP HTTP + AssertJ.
- Notes: Non-401 that does not yield a locally-verifiable JWT -> DENY per AD-11.

**SEC-003** — Deny bind (DenyIndeterminate) when ROPC returns 200 with an HTML body
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: parametrized negative; fake IdP returns 200 text/html (e.g. a login page from a misconfigured proxy); assert DenyIndeterminate.
- Tooling: JUnit5 + fake IdP HTTP + AssertJ.

**SEC-004** — Deny bind (DenyIndeterminate) when ROPC returns 200 with an empty body
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: parametrized negative; fake IdP returns 200 with zero-length body; assert DenyIndeterminate.
- Tooling: JUnit5 + fake IdP HTTP + AssertJ.

**SEC-005** — Deny bind (DenyIndeterminate) when ROPC returns 200 with a malformed/unparseable JWT
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: parametrized negative; fake IdP returns 200 with a structurally invalid JWT string (truncated/garbage); assert DenyIndeterminate, no exception escapes.
- Tooling: JUnit5 + fake IdP HTTP + AssertJ; Nimbus parse failure absorbed by the adapter.
- **Status (Story 3.4 T2, 2026-08-27): EXPECTATION INVERTED — re-pointed.** The adapter no longer parses token content: a three-segment-but-garbage token now yields `Allow` (pinned by `threeSegmentTokenIsNeverLocallyParsed`), and the deny this row wanted survives only for tokens that are NOT three-segment (the D6 arm, pinned by `opaqueTokenDeniesFailClosedWithoutAWireRound2`). Nimbus is no longer on the token path at all.

**SEC-006** — Deny bind (DenyIndeterminate) when ROPC returns a 3xx redirect
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: parametrized negative; fake IdP returns 302; assert DenyIndeterminate (no redirect follow to an untrusted endpoint).
- Tooling: JUnit5 + fake IdP HTTP + AssertJ.

**SEC-007** — Deny bind (DenyIndeterminate) when ROPC returns 4xx other than 401
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: parametrized negative across {400,403,429}; fake IdP returns each; assert DenyIndeterminate (only 401 maps to DenyInvalid).
- Tooling: JUnit5 @ParameterizedTest + fake IdP HTTP + AssertJ.

**SEC-008** — Deny bind (DenyIndeterminate) when ROPC returns 5xx
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: parametrized negative across {500,502,503}; assert DenyIndeterminate.
- Tooling: JUnit5 @ParameterizedTest + fake IdP HTTP + AssertJ.

**SEC-009** — Deny bind (DenyIndeterminate) when the ROPC call exceeds the configured deadline
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, PERF-3, SEC-3
- Technique: injectable-clock negative; fake IdP stalls, Clock advances past the PERF-3 deadline; assert DenyIndeterminate with no late-allow when the response finally arrives.
- Tooling: JUnit5 + injectable Clock/scheduler seam + fake IdP HTTP + AssertJ.
- Notes: Injectable clock (blind-spot 5); deterministic, no Thread.sleep. Covers JWT/ROPC timeouts — NOT TLS cert-path validation (see SEC-037 boundary note).

**SEC-010** — Deny bind (DenyIndeterminate) on ROPC network error (refused/reset/EOF)
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: parametrized negative; fake IdP client throws ConnectException/ConnectionResetException/EOF; assert DenyIndeterminate, exception absorbed (no Nimbus/IO type crosses the port).
- Tooling: JUnit5 @ParameterizedTest + fake IdP HTTP + AssertJ.

**SEC-011** — Deny bind (DenyIndeterminate) on JWT kid absent from cached JWKS, with background refresh but no foreground refresh-and-retry
Level: unit · Priority: P0 · Risks: R1, R20 · NFR: FR-SEC-5, SEC-3
- Technique: fake JWKS missing the token kid; assert immediate DenyIndeterminate, exactly one background refresh scheduled, the bind path performs zero synchronous refreshes (AD-11).
- Tooling: JUnit5 + fake JWKS source (refresh-counting) + injectable Clock + AssertJ.
- **Status (Story 3.4 T2, 2026-08-27): RETIRED — local JWT signature/claim verification was removed from the production adapter (user-directed, TLS-as-sole-trust-anchor, spine AD-12/D7; the proxy is the issued token's only consumer). No production code path examines token content past the three-segment count, so this row is structurally unimplementable; the successor pins are `RopcBindCredentialVerifierTest.jwtVerdictDerivesFromTheEndpointAlone` + `threeSegmentTokenIsNeverLocallyParsed`.**

**SEC-012** — Deny bind (DenyInvalid) on verdict/local-JWT disagreement (200 valid-looking JWT, local JWKS verification fails)
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: fake IdP returns 200 + a JWT whose signature does not verify against cached JWKS; assert DenyInvalid (DENY always wins on defense-in-depth disagreement).
- Tooling: JUnit5 + fake IdP HTTP + fake JWKS + AssertJ.
- **Status (Story 3.4 T2, 2026-08-27): RETIRED — local JWT signature/claim verification was removed from the production adapter (user-directed, TLS-as-sole-trust-anchor, spine AD-12/D7; the proxy is the issued token's only consumer). No production code path examines token content past the three-segment count, so this row is structurally unimplementable; the successor pins are `RopcBindCredentialVerifierTest.jwtVerdictDerivesFromTheEndpointAlone` + `threeSegmentTokenIsNeverLocallyParsed`.** (This row's premise — a local verify that can disagree with the endpoint — is exactly what died.)

### 4.2 RFC 7662 introspection DENY matrix (AD-11, R1) — exhaustive per-branch

*(Section RETIRED 2026-08-27, Story 3.4 T1 — the opaque-token introspection arm was removed from the production adapter (user-directed; spine AD-12 amendment). Every row below is structurally unimplementable in production: no second wire arm exists, and a non-JWT token response denies at the D6 arm. The AC8 ratification record and the test-tier `RopcSlice*` slice (own container) keep the historical path green.)*

**SEC-013** — Deny opaque-token bind (DenyInvalid) when introspection returns active:false
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: parametrized negative via port; fake introspection endpoint returns 200 {"active":false}; assert DenyInvalid.
- Tooling: JUnit5 + fake introspection HTTP + AssertJ.
- Notes: Opaque-token RFC7662 path enumeration.
- **Status (Story 3.4 T1, 2026-08-27): RETIRED — the RFC 7662 introspection arm was removed from the production adapter (user-directed, JWT-only adjudication; spine AD-12 amendment). No production code path can exercise this row; the successor pin is `RopcBindCredentialVerifierTest.opaqueTokenDeniesFailClosedWithoutAWireRound2` (a non-JWT token response denies fail-closed with zero wire round-2). The test-tier `RopcSlice*` slice keeps the historical ratification green in its own container.**

**SEC-014** — Deny opaque-token bind (DenyIndeterminate) when introspection returns non-JSON
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: fake introspection returns 200 text/plain; assert DenyIndeterminate.
- **Status (Story 3.4 T1, 2026-08-27): RETIRED — the RFC 7662 introspection arm was removed from the production adapter (user-directed, JWT-only adjudication; spine AD-12 amendment). No production code path can exercise this row; the successor pin is `RopcBindCredentialVerifierTest.opaqueTokenDeniesFailClosedWithoutAWireRound2` (a non-JWT token response denies fail-closed with zero wire round-2). The test-tier `RopcSlice*` slice keeps the historical ratification green in its own container.**
- Tooling: JUnit5 + fake introspection HTTP + AssertJ.

**SEC-015** — Deny opaque-token bind (DenyIndeterminate) when introspection 200 JSON omits the active field
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: fake introspection returns 200 {} (no active); assert DenyIndeterminate.
- **Status (Story 3.4 T1, 2026-08-27): RETIRED — the RFC 7662 introspection arm was removed from the production adapter (user-directed, JWT-only adjudication; spine AD-12 amendment). No production code path can exercise this row; the successor pin is `RopcBindCredentialVerifierTest.opaqueTokenDeniesFailClosedWithoutAWireRound2` (a non-JWT token response denies fail-closed with zero wire round-2). The test-tier `RopcSlice*` slice keeps the historical ratification green in its own container.**
- Tooling: JUnit5 + fake introspection HTTP + AssertJ.

**SEC-016** — Deny opaque-token bind (DenyIndeterminate) when introspection active is the wrong JSON type
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: parametrized across {"active":"true"}, {"active":1}, {"active":"yes"}; assert DenyIndeterminate (only boolean true accepts).
- **Status (Story 3.4 T1, 2026-08-27): RETIRED — the RFC 7662 introspection arm was removed from the production adapter (user-directed, JWT-only adjudication; spine AD-12 amendment). No production code path can exercise this row; the successor pin is `RopcBindCredentialVerifierTest.opaqueTokenDeniesFailClosedWithoutAWireRound2` (a non-JWT token response denies fail-closed with zero wire round-2). The test-tier `RopcSlice*` slice keeps the historical ratification green in its own container.**
- Tooling: JUnit5 @ParameterizedTest + fake introspection HTTP + AssertJ.

**SEC-017** — Deny opaque-token bind (DenyIndeterminate) when introspection returns 5xx
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: fake introspection returns 503; assert DenyIndeterminate.
- **Status (Story 3.4 T1, 2026-08-27): RETIRED — the RFC 7662 introspection arm was removed from the production adapter (user-directed, JWT-only adjudication; spine AD-12 amendment). No production code path can exercise this row; the successor pin is `RopcBindCredentialVerifierTest.opaqueTokenDeniesFailClosedWithoutAWireRound2` (a non-JWT token response denies fail-closed with zero wire round-2). The test-tier `RopcSlice*` slice keeps the historical ratification green in its own container.**
- Tooling: JUnit5 + fake introspection HTTP + AssertJ.

**SEC-018** — Deny opaque-token bind (DenyIndeterminate) on introspection timeout
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, PERF-3, SEC-3
- Technique: injectable clock; introspection stalls past deadline; assert DenyIndeterminate.
- **Status (Story 3.4 T1, 2026-08-27): RETIRED — the RFC 7662 introspection arm was removed from the production adapter (user-directed, JWT-only adjudication; spine AD-12 amendment). No production code path can exercise this row; the successor pin is `RopcBindCredentialVerifierTest.opaqueTokenDeniesFailClosedWithoutAWireRound2` (a non-JWT token response denies fail-closed with zero wire round-2). The test-tier `RopcSlice*` slice keeps the historical ratification green in its own container.**
- Tooling: JUnit5 + injectable Clock + fake introspection HTTP + AssertJ.

**SEC-019** — Introspection verdict is never cached — a second identical opaque-token bind re-queries the IdP
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: issue the same opaque token twice via verify(); assert the introspection HTTP endpoint is hit twice (no verdict cache; mirrors the no-verdict-cache JWT rule).
- **Status (Story 3.4 T1, 2026-08-27): RETIRED — the RFC 7662 introspection arm was removed from the production adapter (user-directed, JWT-only adjudication; spine AD-12 amendment). No production code path can exercise this row; the successor pin is `RopcBindCredentialVerifierTest.opaqueTokenDeniesFailClosedWithoutAWireRound2` (a non-JWT token response denies fail-closed with zero wire round-2). The test-tier `RopcSlice*` slice keeps the historical ratification green in its own container.**
- Tooling: JUnit5 + counting fake introspection HTTP + AssertJ.

**SEC-093** `[critic-fix: ADDED]` — Introspection HTTP-failure DENY matrix (network-error / 3xx / 4xx≠default → DenyIndeterminate)
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: parametrized negative via the BindCredentialVerifier port mirroring SEC-007/008/010 for the introspection path: (a) introspection network error (ConnectException / ConnectionResetException / EOF) → DenyIndeterminate; (b) 3xx redirect (302/307) → DenyIndeterminate (no redirect follow to an untrusted endpoint); (c) 4xx other than the active:false semantic (400/403/429) → DenyIndeterminate. Exception absorbed; no Nimbus/IO type crosses the port.
- Tooling: JUnit5 @ParameterizedTest + AssertJ + fake introspection HTTP (WireMock-equivalent).
- Notes: [critic-fix] Closes the asymmetric R1 P0 hole: the ROPC path (SEC-001..010) was exhaustively enumerated but the introspection path was missing network-error, 3xx, and 4xx branches that AD-11 explicitly names ('anything other than HTTP 200 + JSON + boolean active:true → DENY'). One missed branch = accept-on-indeterminate = the worst defect class.
- **Status (Story 3.4 T1, 2026-08-27): RETIRED — the RFC 7662 introspection arm was removed from the production adapter (user-directed, JWT-only adjudication; spine AD-12 amendment). No production code path can exercise this row; the successor pin is `RopcBindCredentialVerifierTest.opaqueTokenDeniesFailClosedWithoutAWireRound2` (a non-JWT token response denies fail-closed with zero wire round-2). The test-tier `RopcSlice*` slice keeps the historical ratification green in its own container.**

**SEC-094** `[critic-fix: ADDED]` — JWT/ROPC no-verdict-cache: the same BindCredential re-hits the token endpoint (mirrors SEC-019 for the JWT path)
Level: unit · Priority: P0 · Risks: R1, R8 · NFR: FR-SEC-5, SEC-3
- Technique: issue the same BindCredential (same system_id + password) twice via verify(); assert the ROPC token endpoint is hit exactly twice (counting fake IdP) — proving no verdict cache on the JWT path. Mirrors SEC-019 (introspection). *("JWKS may be cached" clause died with the cache, Story 3.4 T2, 2026-08-27 — nothing is cached now.)*
- Tooling: JUnit5 + counting fake IdP HTTP + AssertJ.
- Notes: [critic-fix] AD-12 load-bearing invariant ('re-validate every bind'; the 'cache JWKS only' qualifier died with the cache, Story 3.4 T2, 2026-08-27). The no-verdict-cache rule for the JWT path was asserted only by reference (SEC-019 covers introspection; PERF-015 only implies it by counting adjudications). A verdict cache on the JWT path = credential-bypass-equivalent hole.

### 4.3 JWT defense-in-depth (alg/kid/exp/nbf/iss/aud/sig) — R1

*(Section RETIRED 2026-08-27, Story 3.4 T2 — local JWT signature/claim verification was removed from the production adapter (user-directed, TLS-as-sole-trust-anchor, spine AD-12/D7). Every row below guards a verification that no longer exists; the only surviving token check is the structural three-segment gate (library-free), pinned by the two D7 successor rows noted per-entry.)*

**SEC-020** — Reject JWT with alg=none (DenyInvalid)
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3, SEC-4
- Technique: spec-derived JWT vector with header {"alg":"none"} and no signature; assert DenyInvalid.
- Tooling: JUnit5 + hand-crafted JWT vectors (independent of Nimbus generation) + AssertJ.
- Notes: Oracle-independence (blind-spot 1): vectors are spec-derived, not generated by Nimbus.
- **Status (Story 3.4 T2, 2026-08-27): RETIRED — local JWT signature/claim verification was removed from the production adapter (user-directed, TLS-as-sole-trust-anchor, spine AD-12/D7; the proxy is the issued token's only consumer). No production code path examines token content past the three-segment count, so this row is structurally unimplementable; the successor pins are `RopcBindCredentialVerifierTest.jwtVerdictDerivesFromTheEndpointAlone` + `threeSegmentTokenIsNeverLocallyParsed`.**

**SEC-021** — Reject JWT alg-confusion (RS256 token where HS256 is expected, and vice versa)
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3, SEC-4
- Technique: parametrized alg-confusion vectors (RS<->HS key confusion); assert DenyInvalid, the public key is never reinterpreted as an HMAC secret.
- **Status (Story 3.4 T2, 2026-08-27): RETIRED — local JWT signature/claim verification was removed from the production adapter (user-directed, TLS-as-sole-trust-anchor, spine AD-12/D7; the proxy is the issued token's only consumer). No production code path examines token content past the three-segment count, so this row is structurally unimplementable; the successor pins are `RopcBindCredentialVerifierTest.jwtVerdictDerivesFromTheEndpointAlone` + `threeSegmentTokenIsNeverLocallyParsed`.**
- Tooling: JUnit5 + hand-crafted JWT vectors + Nimbus verify + AssertJ.

**SEC-022** — Reject JWT kid path/key-injection (kid with traversal or referencing an attacker key)
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3, SEC-4
- Technique: vectors with kid containing '../', absolute paths, or a value not in JWKS; assert DenyIndeterminate and that no file/path lookup occurs on the kid.
- **Status (Story 3.4 T2, 2026-08-27): RETIRED — local JWT signature/claim verification was removed from the production adapter (user-directed, TLS-as-sole-trust-anchor, spine AD-12/D7; the proxy is the issued token's only consumer). No production code path examines token content past the three-segment count, so this row is structurally unimplementable; the successor pins are `RopcBindCredentialVerifierTest.jwtVerdictDerivesFromTheEndpointAlone` + `threeSegmentTokenIsNeverLocallyParsed`.**
- Tooling: JUnit5 + crafted JWT vectors + fake JWKS + AssertJ.

**SEC-023** — Reject JWT past exp with no false-accept across the configured skew window (injectable clock)
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: injectable clock parametrized across exp boundary (just-before/just-after exp, at skew edge); assert DenyInvalid once exp passes, no late allow inside skew beyond the bound.
- Tooling: JUnit5 @ParameterizedTest + injectable Clock + AssertJ.
- Notes: Injectable clock (blind-spot 5) for time-based JWT adjudication. (Not TLS cert-path — see SEC-037.)
- **Status (Story 3.4 T2, 2026-08-27): RETIRED — local JWT signature/claim verification was removed from the production adapter (user-directed, TLS-as-sole-trust-anchor, spine AD-12/D7; the proxy is the issued token's only consumer). No production code path examines token content past the three-segment count, so this row is structurally unimplementable; the successor pins are `RopcBindCredentialVerifierTest.jwtVerdictDerivesFromTheEndpointAlone` + `threeSegmentTokenIsNeverLocallyParsed`.**

**SEC-024** — Reject JWT with nbf in the future with no false-accept (injectable clock)
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: injectable clock parametrized across nbf boundary; assert DenyInvalid before nbf.
- **Status (Story 3.4 T2, 2026-08-27): RETIRED — local JWT signature/claim verification was removed from the production adapter (user-directed, TLS-as-sole-trust-anchor, spine AD-12/D7; the proxy is the issued token's only consumer). No production code path examines token content past the three-segment count, so this row is structurally unimplementable; the successor pins are `RopcBindCredentialVerifierTest.jwtVerdictDerivesFromTheEndpointAlone` + `threeSegmentTokenIsNeverLocallyParsed`.**
- Tooling: JUnit5 @ParameterizedTest + injectable Clock + AssertJ.

**SEC-025** — Reject JWT with iss mismatch (DenyInvalid)
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: valid-signature JWT with wrong issuer claim; assert DenyInvalid.
- **Status (Story 3.4 T2, 2026-08-27): RETIRED — local JWT signature/claim verification was removed from the production adapter (user-directed, TLS-as-sole-trust-anchor, spine AD-12/D7; the proxy is the issued token's only consumer). No production code path examines token content past the three-segment count, so this row is structurally unimplementable; the successor pins are `RopcBindCredentialVerifierTest.jwtVerdictDerivesFromTheEndpointAlone` + `threeSegmentTokenIsNeverLocallyParsed`.**
- Tooling: JUnit5 + crafted JWT vectors + AssertJ.

**SEC-026** — Reject JWT with aud mismatch (DenyInvalid)
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3
- Technique: valid-signature JWT with wrong audience claim; assert DenyInvalid.
- **Status (Story 3.4 T2, 2026-08-27): RETIRED — local JWT signature/claim verification was removed from the production adapter (user-directed, TLS-as-sole-trust-anchor, spine AD-12/D7; the proxy is the issued token's only consumer). No production code path examines token content past the three-segment count, so this row is structurally unimplementable; the successor pins are `RopcBindCredentialVerifierTest.jwtVerdictDerivesFromTheEndpointAlone` + `threeSegmentTokenIsNeverLocallyParsed`.**
- Tooling: JUnit5 + crafted JWT vectors + AssertJ.

**SEC-027** — Reject JWT with a tampered signature (DenyInvalid)
Level: unit · Priority: P0 · Risks: R1 · NFR: FR-SEC-5, SEC-3, SEC-4
- Technique: take a valid JWT, flip a payload byte, re-encode; assert DenyInvalid (signature verification failure).
- **Status (Story 3.4 T2, 2026-08-27): RETIRED — local JWT signature/claim verification was removed from the production adapter (user-directed, TLS-as-sole-trust-anchor, spine AD-12/D7; the proxy is the issued token's only consumer). No production code path examines token content past the three-segment count, so this row is structurally unimplementable; the successor pins are `RopcBindCredentialVerifierTest.jwtVerdictDerivesFromTheEndpointAlone` + `threeSegmentTokenIsNeverLocallyParsed`.**
- Tooling: JUnit5 + crafted JWT vectors + AssertJ.

### 4.4 ROPC/IdP happy-path interop against real Keycloak 26.x (R2 — the gate-blocker)

**SEC-028** — ROPC JWT happy path against a real Keycloak 26.x yields Allow, discards the token, and relays the ORIGINAL bind
Level: integration · Priority: P0 · Risks: R2 · NFR: SEC-3, FR-AUTH-1, FR-SEC-1, PRIV-1
- Technique: end-to-end AD-12 path 1: ROPC -> 200 + three-segment JWT -> Allow (re-pointed 2026-08-27, Story 3.4 T2: the local-JWKS-verify step died; the structural gate is the only token check); assert the token is not relayed and the original bind PDU reaches the SMSC unchanged.
- Tooling: Testcontainers Keycloak 26.x (or equivalent real IdP) + in-JVM mock SMSC capturing the forwarded bind + AssertJ.
- Notes: Confirms the ROPC happy path on the most fragile dependency; aligns with Story 3.1 viability gate. Nightly tier.

**SEC-029** — Opaque-token RFC 7662 introspection happy path against a real Keycloak yields Allow
Level: integration · Priority: P0 · Risks: R2 · NFR: SEC-3, FR-AUTH-1
- Technique: AD-12 path 2: configure realm to issue opaque tokens; assert introspection active:true -> Allow.
- Tooling: Testcontainers Keycloak 26.x + AssertJ.
- **Status (Story 3.4 T1, 2026-08-27): RETIRED — the RFC 7662 introspection arm was removed from the production adapter (user-directed, JWT-only adjudication; spine AD-12 amendment). No production code path can exercise this row; the successor pin is `RopcBindCredentialVerifierTest.opaqueTokenDeniesFailClosedWithoutAWireRound2` (a non-JWT token response denies fail-closed with zero wire round-2). The test-tier `RopcSlice*` slice keeps the historical ratification green in its own container.**

**SEC-030** — Provider authentication via mTLS RFC 8705 (not client_secret) reaches the token endpoint
Level: integration · Priority: P0 · Risks: R2 · NFR: SEC-3, FR-AUTH-1, FR-AUTH-4
- Technique: AD-12 path 3: client authenticates to Keycloak token endpoint with an mTLS client cert (RFC 8705); assert 200 + JWT.
- Tooling: Testcontainers Keycloak 26.x with mTLS client-auth realm + AssertJ.

**SEC-031** — At least one DENY branch end-to-end against a real Keycloak (wrong password -> 401 -> DENY; stopped IdP -> timeout -> DENY)
Level: integration · Priority: P0 · Risks: R2, R1 · NFR: FR-SEC-5, SEC-3, PERF-3
- Technique: AD-12 path 4: drive wrong-credential (401->DenyInvalid) and IdP-down (timeout->DenyIndeterminate) against the real IdP; assert the ESME sees a denied bind_resp.
- Tooling: Testcontainers Keycloak 26.x + jSMPP/in-JVM ESME client + AssertJ.

**SEC-032** — ROPC viability probe and fallback decision-tree artifact (Story 3.1)
Level: integration · Priority: P0 · Risks: R2 · NFR: SEC-3, FR-AUTH-1
- Technique: assert Keycloak 26.x advertises/accepts grant_type=password (Direct Access Grants present); assert a written fallback decision tree (non-OIDC password-check service behind the port / Mode-C-only / Mode B plaintext-only / cancel scope) exists under the AD-12 accepted-risk register if a removal notice is detected.
- Tooling: Testcontainers Keycloak 26.x + docs/CI artifact presence check.
- Notes: Gate-blocker: lands before any other Epic 3 story; can run parallel with Epic 1.

### 4.5 Trust anchoring — cacerts-default-is-insecure, REQUIRE-vs-WANT, cert edge-cases (R7, P0)

**SEC-033** — Ingress Mode C never falls back to JDK cacerts — a client cert chaining only to a public/cacerts root is rejected
Level: integration · Priority: P0 · Risks: R7 · NFR: SEC-1, SEC-3, FR-AUTH-4, FR-SEC-4
- Technique: build the ingress SslContext with the operator trust store and assert the cacerts-override is present (default-state-is-insecure); present a client cert chaining to a cacerts root -> handshake fails.
- Tooling: JUnit5 + crafted X.509 vectors (keytool/BouncyCastle) + JDK SSLEngine loopback pair / Netty EmbeddedChannel.

**SEC-034** — Egress AD-26 never falls back to JDK cacerts — an SMSC/peer server cert chaining to a public root is rejected
Level: integration · Priority: P0 · Risks: R7 · NFR: SEC-1, SEC-3, FR-SEC-4
- Technique: build the egress client SslContext with the operator trust store; assert the override is present; a peer cert chaining to cacerts -> handshake fails (default-is-insecure -> explicit override required).
- Tooling: JUnit5 + crafted X.509 vectors + JDK SSLEngine client/server pair.

**SEC-035** — Mode C uses clientAuth(REQUIRE) — a TLS connection with no client certificate fails the handshake
Level: integration · Priority: P0 · Risks: R7 · NFR: SEC-1, FR-AUTH-4
- Technique: REQUIRE-vs-WANT regression: connect with no client cert; assert handshake failure (not a WANT-style soft accept).
- Tooling: JUnit5 + JDK SSLEngine pair + AssertJ.

**SEC-036** — Reject a Mode C client certificate with the wrong EKU (serverAuth-only presented as a client cert)
Level: integration · Priority: P0 · Risks: R7 · NFR: SEC-1, FR-AUTH-4
- Technique: crafted cert with extendedKeyUsage=serverAuth only; assert PKIX rejection when presented as a client cert.
- Tooling: JUnit5 + BouncyCastle/keytool X.509 vectors + JDK SSLEngine pair.

**SEC-037** `[critic-fix: REWRITTEN]` — Reject a genuinely already-expired peer certificate (real system clock; no injectable clock)
Level: integration · Priority: P0 · Risks: R7 · NFR: SEC-1, FR-AUTH-4
- Technique: craft a genuinely already-expired short-lived X.509 (validity window entirely in the past, e.g. 1970-01-01..1971-01-01) via BouncyCastle/keytool and assert PKIX rejection against the REAL system clock on both ingress Mode C and egress legs.
- Tooling: JUnit5 + crafted already-expired X.509 (BouncyCastle/keytool) + JDK SSLEngine pair.
- Notes: [critic-fix] The original technique ('injectable clock set past notAfter') is INFEASIBLE: the JDK SSLEngine / X509TrustManager cert-path validator reads the system clock for notAfter, and the only date-injection API (PKIXBuilderParameters.setDate) is BANNED by AD-13 ('no custom PKIXBuilderParameters'). Fixed by crafting a cert that is genuinely already expired and asserting against the real clock. Testability boundary: the injectable-Clock seam covers JWT exp/nbf (SEC-023/024) and ROPC/introspection timeouts (SEC-009/018), but NOT TLS cert-path validation.

**SEC-038** — Reject a self-signed certificate not reaching a configured anchor
Level: integration · Priority: P0 · Risks: R7 · NFR: SEC-1, FR-AUTH-4
- Technique: present a self-signed cert absent from the operator trust store; assert rejection (no implicit trust).
- Tooling: JUnit5 + crafted self-signed X.509 + JDK SSLEngine pair.

**SEC-039** — Reject a certificate carrying an unknown critical extension (PKIX default)
Level: integration · Priority: P0 · Risks: R7 · NFR: SEC-1, FR-AUTH-4, SEC-4
- Technique: crafted cert with an unrecognized critical extension; assert PKIX rejection (no custom chain code, rely on PKIX defaults per AD-13).
- Tooling: JUnit5 + BouncyCastle X.509 vectors + JDK SSLEngine pair.

**SEC-040** — Egress raw-IP SMSC target: endpointIdentificationAlgorithm=null allows an IP-SAN cert (AD-20)
Level: integration · Priority: P0 · Risks: R7 · NFR: SEC-1
- Technique: configure an IP-addressed SMSC; assert endpointIdentificationAlgorithm is explicitly null (Netty 4.2 HTTPS default overridden) and an IP-SAN cert verifies; an HTTPS-algorithm check is NOT applied to the raw IP.
- Tooling: JUnit5 + IP-SAN X.509 vector + JDK SSLEngine client.

**SEC-041** — Egress cacerts/public-PKI SMSC trust is opt-in (any mode) with a loud warning + ack, never the default
Level: integration · Priority: P0 · Risks: R7, R18 · NFR: SEC-1, FR-SEC-4
- Technique: default config uses the operator trust store as sole gate; explicit opt-in flag + ack enables cacerts/public-PKI in any mode with a loud startup warning; absence -> never cacerts.
- Tooling: JUnit5 + Spring Boot config slice + startup-output capture + AssertJ.

### 4.6 Credential-free-at-rest / zeroization (R8, P0)

**SEC-042** — Credential primitives are char[]/byte[] and never String (password char[], token byte[])
Level: unit · Priority: P0 · Risks: R8 · NFR: PRIV-1, FR-SEC-1, FR-SEC-4
- Technique: parametrized arch/type assertion: BindCredential.password is char[]; the adapter's access token field is byte[]; no String field/variable holds either (ArchUnit + reflection scan over security/).
- Tooling: ArchUnit + reflection/field-type scan + AssertJ.

**SEC-043** — The Verdict sealed interface carries no credential or token field
Level: unit · Priority: P0 · Risks: R8 · NFR: PRIV-1, FR-SEC-1
- Technique: arch assertion: Allow/DenyInvalid/DenyIndeterminate permit no credential/token/string-reason members; a credential cannot escape via the Verdict.
- Tooling: ArchUnit / reflection over the sealed Verdict + AssertJ.

**SEC-044** — The BindCredentialVerifier port signature carries no token — token never crosses the port boundary
Level: unit · Priority: P0 · Risks: R8, R31 · NFR: PRIV-1, FR-SEC-1
- Technique: arch assertion: verify(BindCredential, ScopedValue<RequestContext>) accepts only BindCredential (SystemId + char[] password); the ROPC access token is internal to the adapter and never appears in the port contract.
- Tooling: ArchUnit / reflection over the port + AssertJ.

**SEC-045** — Credential never escapes via log, metric, Verdict, or CompletableFuture (parametrized over sinks)
Level: unit · Priority: P0 · Risks: R8 · NFR: PRIV-1, FR-SEC-1, FR-OBS-2
- Technique: drive an adjudication with a known password/token through {log appender incl TRACE, capturing SpliceObserver + MeterRegistry, returned CompletableFuture, RequestContext}; assert neither secret substring appears in any sink.
- Tooling: JUnit5 @ParameterizedTest + capturing log appender + capturing SpliceObserver + AssertJ.

**SEC-046** — Password char[] is zeroized on adjudication completion, connection teardown, and exception (parametrized over paths) — THE deterministic zeroization evidence
Level: unit · Priority: P0 · Risks: R8 · NFR: PRIV-1, FR-SEC-1
- Technique: parametrized over {Allow-completion, channelInvalid teardown, adjudication-throws}; assert the password char[] contents are all '\0' after each path (test retains a reference to the SAME array, checked immediately after the zeroize call).
- Tooling: JUnit5 @ParameterizedTest + AssertJ; deterministic via fake verifier + injectable Clock.
- Notes: This is the deterministic zeroization evidence. SEC-048/049 are best-effort fragility guards that DEPEND on this for the actual guarantee.

**SEC-047** — Token byte[] is discarded and zeroized; the ORIGINAL bind (not the token) is forwarded to the SMSC *(title re-worded 2026-08-27, Story 3.4 T2 — "after local verify" died with local verification; the discard/zeroize/relay-original behavior is unchanged)*
Level: integration · Priority: P0 · Risks: R8, R2 · NFR: PRIV-1, FR-SEC-1
- Technique: after an Allow, assert the token byte[] is zeroed and the bytes forwarded to the SMSC are the original bind_transceiver PDU (system_id/password preserved end-to-end, no token on the wire).
- Tooling: in-JVM mock SMSC (captures forwarded PDU) + fake IdP + AssertJ.

**SEC-048** `[critic-fix: REFRAMED]` — Best-effort heap-inspection fragility guard (NOT zeroization evidence — that is SEC-046)
Level: integration · Priority: P0 · Risks: R8 · NFR: PRIV-1, FR-SEC-1
- Technique: test-only instrumentation registers live char[]/byte[] buffers; after adjudication + a forced GC, assert no live buffer retains non-zero credential bytes (best-effort, Java zeroization fragility guard).
- Tooling: JUnit5 + test-only heap-inspection hook + forced GC + AssertJ.
- Notes: [critic-fix] REFRAMED as a best-effort fragility guard only. A passing test does NOT prove zeroization: the GC may have collected the buffer (proving collection, not zeroing), escape analysis may optimize the array away, and a live-buffer scan finds nothing if the buffer was already reclaimed. The DETERMINISTIC zeroization evidence is SEC-046 (same-reference char[] all-'\0' immediately after the zeroize call). Instrumentation seam must be accepted as test-only.

**SEC-049** `[critic-fix: REFRAMED]` — Best-effort JFR/heap-dump hygiene guard + JFR/dump hygiene doc (NOT deterministic evidence)
Level: integration · Priority: P0 · Risks: R8 · NFR: PRIV-1, FR-SEC-1
- Technique: run adjudication under a JFR recording with OldObjectSample enabled and capture a heap dump; assert no password/token substring appears in retained samples (best-effort). Document JFR/dump hygiene guidance alongside (configure OldObjectSample interval / disable heap dumps on credential paths in prod).
- Tooling: JUnit5 + JFR recording parse + heap-dump parse (hprof/PathProfiler-equivalent) + AssertJ + a JFR/dump hygiene doc under docs/.
- Notes: [critic-fix] REFRAMED as a best-effort hygiene check, NOT validation. JFR OldObjectSample is a sampled profiler (interval-based); a short-lived per-bind credential may never be sampled, so 'no sample found' does not prove the credential cannot leak — only that it was not sampled this run. Heap-dump substring matching also assumes the secret is a recognizable contiguous string (a char[] may be fragmented). The deterministic zeroization evidence is SEC-046.

### 4.7 Startup fail-fast `@ConfigurationProperties` matrix (R17, P1)

**SEC-050** — Startup refuses on an invalid trust store (absent/empty/wrong-format/wrong-password/zero-entries)
Level: unit · Priority: P1 · Risks: R17, R7 · NFR: FR-DEPLOY-3, SEC-1
- Technique: config-scan @ConfigurationProperties fail-fast matrix: 5 parametrized invalid trust-store states each -> non-zero exit with a clear message.
- Tooling: JUnit5 + Spring Boot @ConfigurationProperties test slice + AssertJ (exit-code/message).

**SEC-051** — Startup refuses a forward-role instance configured in Mode B (forbidden cell)
Level: unit · Priority: P1 · Risks: R17 · NFR: FR-DEPLOY-3, FR-DEPLOY-2
- Technique: config matrix: role=forward + mode=B -> refuse (Mode B is reverse-only).
- Tooling: JUnit5 + Spring Boot config test slice + AssertJ.
- **Status (Story 1.3, 2026-08-04): STRUCTURALLY ENFORCED — retired from the runtime matrix.** The
  config tree was restructured so the role×mode cell is the property path (`companion.<role>.<mode>.*`);
  `Forward` exposes only `mode-a`/`mode-c`, so there is no `companion.forward.mode-b` node to configure.
  The forbidden cell is impossible-by-construction; a stray `forward.mode-b` key is rejected by
  `@ConfigurationProperties(ignoreUnknownFields=false)` at bind time. No cross-field validator rule and
  no runtime refusal test remain for SEC-051.

**SEC-052** — Mode B reverse starts only with opt-in ack; without ack it refuses, with ack it warns and starts
Level: unit · Priority: P1 · Risks: R17 · NFR: FR-DEPLOY-3, FR-SEC-2
- Technique: config matrix: reverse+B without ack -> refuse; reverse+B with ack -> startup emits loud plaintext warning then starts (AD-17 Mode B posture).
- Tooling: JUnit5 + Spring Boot config test slice + startup-output capture + AssertJ.

**SEC-053** — Startup refuses a non-https OIDC provider URL
Level: unit · Priority: P1 · Risks: R17 · NFR: FR-DEPLOY-3, SEC-3
- Technique: config: provider URL scheme=http -> refuse (AD-12 SEC-3 link must be https).
- Tooling: JUnit5 + Spring Boot config test slice + AssertJ.

**SEC-054** — Startup refuses a missing/unset OIDC provider URL
Level: unit · Priority: P1 · Risks: R17 · NFR: FR-DEPLOY-3, SEC-3
- Technique: config: provider URL absent -> refuse.
- Tooling: JUnit5 + Spring Boot config test slice + AssertJ.

**SEC-055** — Startup refuses bad/missing SMPP bind or SMSC ports
Level: unit · Priority: P1 · Risks: R17 · NFR: FR-DEPLOY-3
- Technique: config: out-of-range/negative/unset ports -> refuse.
- Tooling: JUnit5 + Spring Boot config test slice + AssertJ.

**SEC-056** — Startup refuses a forward instance (Mode A/C) missing the server cert+key
Level: unit · Priority: P1 · Risks: R17 · NFR: FR-DEPLOY-3
- Technique: required-config matrix cell: forward+A/C without server cert+key paths -> refuse.
- Tooling: JUnit5 + Spring Boot config test slice + AssertJ.

**SEC-057** — Startup refuses a reverse Mode C instance missing the client cert+key
Level: unit · Priority: P1 · Risks: R17 · NFR: FR-DEPLOY-3
- Technique: required-config matrix cell: reverse+C without client cert+key -> refuse.
- Tooling: JUnit5 + Spring Boot config test slice + AssertJ.

**SEC-058** — Startup refuses a forward instance with an empty/missing routing table
Level: unit · Priority: P1 · Risks: R17 · NFR: FR-DEPLOY-3
- Technique: config: forward with no system_id allow-list entries -> refuse (AD-29 1:1, no default route per AD-11).
- Tooling: JUnit5 + Spring Boot config test slice + AssertJ.

**SEC-059** — Startup refuses a reverse instance missing the SMSC endpoint
Level: unit · Priority: P1 · Risks: R17 · NFR: FR-DEPLOY-3
- Technique: config: reverse without SMSC host/port -> refuse.
- Tooling: JUnit5 + Spring Boot config test slice + AssertJ.

**SEC-060** — Startup refuses a missing or unreadable secret file (cert/key/trust-store/cred)
Level: unit · Priority: P1 · Risks: R17, R22 · NFR: FR-DEPLOY-3, DEP-1
- Technique: parametrized over secret types: each path absent or unreadable (permissions/IO error) -> refuse (AD-18).
- Tooling: JUnit5 + Spring Boot config test slice + tmpfs file fixtures + AssertJ.

**SEC-061** — Startup refuses a TLS floor configuration below TLS 1.2
Level: unit · Priority: P1 · Risks: R17 · NFR: FR-DEPLOY-3, SEC-1
- Technique: config: protocols include SSLv3/TLS1.0/TLS1.1 -> refuse; floor is TLS 1.2 min.
- Tooling: JUnit5 + Spring Boot config test slice + AssertJ.

**SEC-096** `[critic-fix: ADDED]` — R17 role×mode cell: reverse+A missing the client trust store → refuse (forward/SMSC server-cert anchor)
Level: unit · Priority: P1 · Risks: R17, R7 · NFR: FR-DEPLOY-3, FR-DEPLOY-2, SEC-1
- Technique: config-scan @ConfigurationProperties fail-fast cell: role=reverse + mode=A with the client trust store absent/empty/wrong-format → refuse (non-zero exit + clear message); pins the role×mode-specific cell the way SEC-051 pins forward+B.
- Tooling: JUnit5 + Spring Boot @ConfigurationProperties test slice + AssertJ.
- Notes: [critic-fix] AD-17 required-config matrix cell not explicitly asserted. SEC-050 tests generic invalid-trust-store; no scenario pinned reverse+A-missing-trust-store → refuse. A regression that wrongly skipped the trust store on reverse+A (MitM SMSC harvests plaintext passwords) would not fail any current test.

**SEC-097** `[critic-fix: ADDED]` — R17 role×mode cell: forward+A STARTS without an SMSC endpoint (SMSC endpoint not required for forward)
Level: unit · Priority: P1 · Risks: R17 · NFR: FR-DEPLOY-3
- Technique: config-scan positive: role=forward + mode=A with no SMSC host/port configured → startup proceeds (does not refuse). The complement of SEC-059 (reverse missing SMSC → refuse).
- Tooling: JUnit5 + Spring Boot config test slice + AssertJ.
- Notes: [critic-fix] AD-17 cell: forward+A forwards to reverse, so the SMSC endpoint is NOT required. No positive scenario asserted a forward+A instance starts without an SMSC endpoint. A regression that wrongly required SMSC on forward+A would not fail any current test.

### 4.8 Mode A two-proxy ACL-isolation (R18, deployer-dependent control) — warning + ack + doc + scan

**SEC-063** — Mode A forward deployment emits a loud ACL-isolation startup warning
Level: integration · Priority: P1 · Risks: R18 · NFR: FR-SEC-2, FR-DEPLOY-3
- Technique: config/startup scan: role=forward + mode=A -> startup log contains the ACL-isolation warning (forward cannot authenticate reverse in one-way TLS).
- Tooling: JUnit5 + Spring Boot startup capture + AssertJ.
- Notes: Deployer-dependent control (blind-spot 4); CI-testable portion = warning + ack + doc + scan.

**SEC-064** — Mode A forward ack gate — warn-and-start occurs only with explicit opt-in acknowledgment
Level: integration · Priority: P1 · Risks: R18 · NFR: FR-SEC-2, FR-DEPLOY-3
- Technique: without the ack flag the startup posture is refuse-or-loud-warn; with the ack flag it proceeds after the warning (pin the exact posture).
- Tooling: JUnit5 + Spring Boot config slice + startup capture + AssertJ.

**SEC-065** — Runbook documenting Mode A two-proxy ACL isolation exists under docs/
Level: integration · Priority: P1 · Risks: R18 · NFR: FR-SEC-2, OPS-1
- Technique: doc-presence + content scan: docs/ contains a runbook describing the Mode A ACL-isolation requirement and operator reverse-proxy host ACL (AD-31/AD-12).
- Tooling: CI docs-presence check + grep/markdown scan.

**SEC-066** — CI config/startup scan detects forward+Mode-A and asserts the warning + ack are present
Level: integration · Priority: P1 · Risks: R18 · NFR: FR-SEC-2, FR-DEPLOY-3
- Technique: config-scan gate in CI: any forward+Mode-A config sample must carry the ack flag and emit the warning; absence fails the gate.
- Tooling: CI config-scan step (Gradle task) over bundled config samples.

### 4.9 JWKS kid-miss / refresh (R20) — P2

**SEC-067** — Concurrent kid-miss binds coalesce to exactly one background JWKS refresh (single-flight)
Level: integration · Priority: P2 · Risks: R20 · NFR: SEC-3
- Technique: race/concurrency: N concurrent binds with the same missing kid; assert the refresh task runs exactly once (single-flight dedup), all N binds still DENY immediately.
- Tooling: JUnit5 + counting fake JWKS refresher + CountDownLatch + AssertJ.

**SEC-068** — JWKS refresh rate is bounded — repeated kid-misses in a window trigger at most one refresh (no thundering herd)
Level: integration · Priority: P2 · Risks: R20 · NFR: SEC-3
- Technique: sustained kid-miss storm within the refresh window; assert refresh count <= the configured bound (no IdP amplification / self-DoS).
- Tooling: JUnit5 + fake JWKS refresher + injectable Clock + AssertJ.

**SEC-069** — kid-miss bind path DENYs immediately and performs zero synchronous foreground refresh-and-retry
Level: unit · Priority: P2 · Risks: R20, R1 · NFR: FR-SEC-5, SEC-3
- Technique: assert the verify() call returns DenyIndeterminate without awaiting any refresh (AD-11); the background refresh is fire-and-forget.
- Tooling: JUnit5 + fake JWKS refresher (refresh blocks never) + injectable Clock + AssertJ.

**SEC-070** — After a successful background refresh, a subsequent bind with the previously-missing kid is Allowed (cache swapped whole)
Level: unit · Priority: P2 · Risks: R20 · NFR: SEC-3
- Technique: trigger kid-miss -> bg refresh populates the kid via an AtomicReference whole-swap; re-issue the bind -> Allow.
- Tooling: JUnit5 + fake JWKS source + injectable Clock + AssertJ.

### 4.10 VT / delegated-task pool saturation (R21) — P2

**SEC-071** — VT adjudication pool saturation fails-closed: new binds DENY rather than queue unbounded or OOM
Level: integration · Priority: P2 · Risks: R21 · NFR: SEC-3, PERF-3, FR-SEC-5
- Technique: saturate the bounded VT adjudication pool with in-flight binds (fake IdP stalls); assert new binds return DenyIndeterminate (fail-closed, AD-11/AD-28), not block/queue/OOM.
- Tooling: JUnit5 + bounded VT pool + stalling fake IdP + injectable Clock + AssertJ.

**SEC-072** — SslHandler delegated-task pool saturation aborts the TLS handshake (never CallerRunsPolicy, never unbounded)
Level: integration · Priority: P2 · Risks: R21 · NFR: SEC-1, FR-SEC-5
- Technique: saturate the fixed platform-thread delegated-task executor; assert the handshake fails (deny the connection) and crypto never runs on the event loop (AD-4/AD-28).
- Tooling: JUnit5 + bounded platform-thread pool + Netty EmbeddedChannel + BlockHound on event-loop threads + AssertJ.

**SEC-073** — Pool recovery: after saturation clears, new binds and handshakes succeed again (no deadlock or leak)
Level: integration · Priority: P2 · Risks: R21 · NFR: SEC-3, SEC-1
- Technique: saturate then release; assert subsequent binds -> Allow and handshakes succeed; assert pool threads/queues return to idle (no leaked tasks).
- Tooling: JUnit5 + bounded pools + stalling fake IdP + AssertJ.

**SEC-074** — No virtual thread is spawned per bind outside the bounded adjudication pool (AD-28 convention)
Level: unit · Priority: P2 · Risks: R21, R9 · NFR: SEC-3
- Technique: arch/scan assertion: the only VT source for adjudication is the single bounded ExecutorService in security/; no Thread.ofVirtual()/Executors.newVirtualThreadPerTaskExecutor ad-hoc in the bind path.
- Tooling: ArchUnit + source/dependency scan + AssertJ.

### 4.11 Secret file-path / no-env-var-value (R22, AD-18) — P2

**SEC-075** — Configuration rejects a secret supplied as an env-var VALUE rather than a file path
Level: unit · Priority: P2 · Risks: R22 · NFR: FR-DEPLOY-3, DEP-1
- Technique: config binding refuses a value that resolves to secret material in an env var (AD-18: secrets are file paths only); -> refuse with a clear message.
- Tooling: JUnit5 + Spring Boot config test slice + env-var fixtures + AssertJ.

**SEC-076** — Every companion.* secret key resolves to a file path (no inline secret value anywhere)
Level: unit · Priority: P2 · Risks: R22 · NFR: DEP-1, FR-DEPLOY-3
- Technique: config-scan: enumerate all companion.* secret-bearing keys and assert each is a Path (cert, key, trust-store, OIDC cred); no inline PEM/secret string.
- Tooling: JUnit5 + config metadata scan + AssertJ.

**SEC-077** — No secret material is present in the process environment at runtime (/proc/self/environ, docker inspect env)
Level: integration · Priority: P2 · Risks: R22, R35 · NFR: DEP-1, PRIV-1
- Technique: launch the proxy with mounted secret files; scan /proc/self/environ (and docker inspect Env in the Docker shape) and assert no cert/key/password/secret value is present — only file paths.
- Tooling: JUnit5 + /proc/self/environ parse + Docker inspect (Docker shape) + AssertJ.

### 4.12 bind_resp status → OIDC-outcome mapping (R23, no enumeration oracle) — P2

**SEC-078** — bind_resp status collapses DenyInvalid vs DenyIndeterminate — no system_id enumeration oracle on the wire `[BLOCKED-ON-Q7]`
Level: unit · Priority: P2 · Risks: R23 · NFR: PRIV-1, SEC-3
- Technique: parametrized: drive DenyInvalid and DenyIndeterminate; assert the wire bind_resp status code does not reveal the OIDC outcome category to the ESME (mapping owned by a single story — Q7).
- Tooling: JUnit5 + bind_resp status-mapping oracle + AssertJ.

**SEC-079** — bind_resp does not distinguish IdP-down (timeout) from bad-credential (401) on the wire `[BLOCKED-ON-Q7]`
Level: unit · Priority: P2 · Risks: R23 · NFR: PRIV-1, SEC-3
- Technique: assert the ESME-observable status for a timeout DENY equals the status for a 401 DENY (no IdP-availability enumeration).
- Tooling: JUnit5 + bind_resp status-mapping oracle + AssertJ.

**SEC-080** — bind_resp never carries a stack trace or internal reason string `[BLOCKED-ON-Q7]`
Level: unit · Priority: P2 · Risks: R23 · NFR: PRIV-1, FR-OBS-2
- Technique: drive every DENY path incl. exception; assert the on-the-wire bind_resp contains only a status code, never a Throwable/stacktrace/internal message (AD-19 errors convention).
- Tooling: JUnit5 + bind_resp encoder assertion + AssertJ.

### 4.13 TLS 1.3 0-RTT/early-data (R24) — P3

**SEC-081** — Ingress TLS 1.3 0-RTT/early-data is rejected (replay not possible)
Level: integration · Priority: P3 · Risks: R24 · NFR: SEC-1
- Technique: a TLS 1.3 client attempts 0-RTT early data; assert the server does not accept/process early data (SSLEngine configured to reject).
- Tooling: JUnit5 + JDK SSLEngine TLS 1.3 pair + early-data vector + AssertJ.

**SEC-082** — Egress TLS 1.3 client does not request or send 0-RTT to the SMSC/forward peer
Level: integration · Priority: P3 · Risks: R24 · NFR: SEC-1
- Technique: assert the egress SSLEngine/client does not enable 0-RTT (no early data sent on resumption).
- Tooling: JUnit5 + JDK SSLEngine TLS 1.3 client + AssertJ.

### 4.14 CompletableFuture × ScopedValue context propagation / STS confinement (R31, R9) — P2

**SEC-083** — Event-loop consumer completing verify() reads RequestContext from a Channel attribute, not ScopedValue
Level: integration · Priority: P2 · Risks: R31 · NFR: COMP-2, FR-AUTH-1
- Technique: the verify() CompletableFuture completes after the STS scope has closed; assert the event-loop consumer resolves RequestContext via a Channel attribute and performs no ScopedValue lookup (which would be unbound/empty post-scope).
- Tooling: JUnit5 + Netty EmbeddedChannel + capturing fake verifier + AssertJ.
- Notes: CF × ScopedValue propagation gap (blind-spot via R31).

**SEC-084** — STS fork does not retain BindCredential beyond the scope lifetime (no leak after join)
Level: integration · Priority: P2 · Risks: R31, R8, R9 · NFR: PRIV-1, COMP-2
- Technique: after the adjudication scope closes, assert no surviving thread/CompletableFuture holds a BindCredential reference (scope-bounded; no orphan retaining the credential).
- Tooling: JUnit5 + StructuredTaskScope + reference-tracking + AssertJ.

**SEC-085** — CI Gradle toolchain / JDK-pin gate refuses an unpinned JDK 25 build
Level: integration · Priority: P2 · Risks: R9, R16 · NFR: COMP-2, SEC-5
- Technique: toolchain assertion: the build fails if the JDK vendor/version does not match the pinned 25.0.x build (STS preview-API shape stability).
- Tooling: Gradle toolchain + JavaToolchain spec + CI pin assertion.

**SEC-086** — StructuredTaskScope usage is confined to the control plane (security/ + bootstrap/); event-loop code does not reference it
Level: unit · Priority: P2 · Risks: R9 · NFR: COMP-2
- Technique: arch/package scan: StructuredTaskScope references exist only in security/ and bootstrap/; relay/ event-loop handlers contain none (data-plane stays pure-stable API).
- Tooling: ArchUnit / source scan + AssertJ.

### 4.15 TLS floor / cipher / no-rolled-crypto / CVE (R17/R7/R16) — runtime vectors + CI gates

**SEC-087** — TLS 1.2 minimum enforced at runtime — a TLS 1.1 ClientHello fails the handshake
Level: integration · Priority: P1 · Risks: R17 · NFR: SEC-1
- Technique: runtime TLS-floor vector: a client offering only TLS 1.1 -> handshake fails (SEC-1).
- Tooling: JUnit5 + JDK SSLEngine pair + protocol-restricted client + AssertJ.

**SEC-088** — TLS 1.3 is preferred and succeeds at runtime
Level: integration · Priority: P1 · Risks: R17 · NFR: SEC-1
- Technique: runtime TLS-floor vector: a TLS 1.3 handshake completes successfully on both legs.
- Tooling: JUnit5 + JDK SSLEngine pair + AssertJ.

**SEC-089** `[critic-fix: BLOCKED-ON-CONFIG]` — Cipher allowlist enforced — a non-allowlisted cipher fails the handshake; a secure default ships and is operator-tunable
Level: integration · Priority: P1 · Risks: R17 · NFR: SEC-1
- Technique: runtime vector: client offers only a non-allowlisted cipher -> handshake fails; the default allowlist is present in shipped config and overridable.
- Tooling: JUnit5 + JDK SSLEngine pair + cipher-restricted client + AssertJ.
- Notes: [critic-fix] PLACEHOLDER — not implementable until the concrete default cipher allowlist is pinned in config (AD-17/SEC-1; open question Q3). Until then it cannot assert a specific non-allowlisted cipher is rejected because the allowlist is undefined.

**SEC-090** — No hand-rolled crypto/TLS/JWT — TLS uses JDK SSLEngine and JWT uses Nimbus; no custom signature-verify or TLS-record code
Level: unit · Priority: P1 · Risks: R7 · NFR: SEC-4
- Technique: dependency/arch scan: no custom PKIXBuilderParameters, no custom chain-validation code, no hand-rolled JWT signature math; crypto sourced only from JDK SSLEngine + Nimbus (AD-13/SEC-4).
- Tooling: ArchUnit + Gradle dependency scan + source scan + AssertJ.

**SEC-091** — CI CVE/dependency-check gate fails on a known CVE in Netty/JDK/Nimbus and asserts Nimbus >= 10.0.2 (CVE-2025-53864)
Level: integration · Priority: P1 · Risks: R16 · NFR: SEC-5
- Technique: CI dependency-scan gate: OWASP dependency-check / Dependabot fail the build on a known vulnerable Netty/JDK/Nimbus; assert the Nimbus floor version.
- Tooling: OWASP dependency-check + Dependabot + Gradle version-pin assertion (CI).

**SEC-092** — PERF-3 DENY timeout boundary — adjudication crossing the 2-5s deadline fails-closed DENY, not late-allow
Level: unit · Priority: P1 · Risks: R1, R2 · NFR: PERF-3, FR-SEC-5
- Technique: injectable-clock boundary: advance the clock across the configured 2-5s DENY deadline; assert Verdict=DenyIndeterminate and that a response arriving after the deadline cannot flip to Allow.
- Tooling: JUnit5 + injectable Clock/scheduler seam + fake IdP + AssertJ.

### 4.16 client_secret hygiene + FR-AUTH-3 no-shared-golden-key + CVE positive control (critic additions)

**SEC-095** `[critic-fix: ADDED]` — OIDC client_secret hygiene: char[]/byte[] (not String) and never escapes via log/metric when the non-mTLS confidential-client path is configured
Level: unit · Priority: P0 · Risks: R8 · NFR: PRIV-1, FR-SEC-1, FR-SEC-4
- Technique: extend SEC-042 (type assertion) and SEC-045 (sink-escape) to the OIDC client_secret when the non-mTLS confidential-client path is configured: (a) assert the loaded client_secret is held as char[]/byte[] with no String field/variable holding it (ArchUnit + reflection scan over security/); (b) drive a bind with a planted client_secret sentinel through the capturing sinks (log appender incl TRACE, SpliceObserver, MeterRegistry, returned CompletableFuture, RequestContext) and assert the sentinel never appears in any sink.
- Tooling: ArchUnit + reflection/field-type scan + JUnit5 @ParameterizedTest + capturing log appender + capturing SpliceObserver + AssertJ.
- Notes: [critic-fix] AD-12 allows confidential-client auth via client_secret (not just mTLS RFC 8705). The client_secret is a LONG-LIVED in-memory runtime secret loaded from a file. SEC-042/045 name only the per-bind password and the ROPC access token — NOT the client_secret. Only enabled when the non-mTLS confidential-client path is configured (SEC-030 covers the mTLS path).

**SEC-098** `[critic-fix: ADDED]` — FR-AUTH-3 no-shared-golden-key config/build scan (per-instance Mode C certs; no baked client cert/key in image or repo)
Level: integration · Priority: P1 · Risks: R7 · NFR: FR-AUTH-3, FR-AUTH-4, SEC-1
- Technique: config/build scan: assert no baked/embedded client cert/key material lives in the image or repo (no PEM/PKCS12 under src/ or in any image layer); Mode C client certs are sourced exclusively from mounted secret files (per-instance). A deployment baking one shared client cert/key into the image — the exact thing FR-AUTH-3 forbids — fails the scan.
- Tooling: JUnit5 + Gradle / image-filesystem scan (grep for PEM/PKCS12 markers in src/ and image layers) + AssertJ.
- Notes: [critic-fix] Closes the FR-AUTH-3 NFR-evidence gap. SEC-036..039 test PKIX rejection; SEC-040 tests IP-SAN; none asserts the per-instance / no-shared-golden-image property. Partly non-CI (two-instance), but a config/build scan is feasible. The full two-instance property is also exercised by E2E-001.

**SEC-099** `[critic-fix: ADDED]` — CI-gate positive control: CVE/dependency-check FIRES on an injected known-vulnerable Netty/JDK/Nimbus coordinate (Nimbus < 10.0.2 / CVE-2025-53864)
Level: integration · Priority: P1 · Risks: R16 · NFR: SEC-5
- Technique: positive control modeled on RELAY-018's BlockHound control — inject a known-vulnerable coordinate (e.g. a Netty below the patched version, or Nimbus < 10.0.2 / CVE-2025-53864) into a throwaway resolved configuration and assert the OWASP dependency-check / Dependabot gate FAILS the build (not merely exists). Proves a misconfigured suppression file / wrong scope cannot silently disable the gate.
- Tooling: OWASP dependency-check + Dependabot + Gradle version-pin + JUnit5 injected-bad-coordinate fixture + AssertJ.
- Notes: [critic-fix] Closes the CI-gate-positive-control gap (cross-level issue). SEC-091 (and SEC-085/DEPLOY-014) assert the gate EXISTS but never inject a known-bad input, so a misconfigured OWASP suppression file or wrong dependency scope would silently disable the gate while every test passes. Pairs with CODEC-041 and OBS-043.

**SEC-100** `[story-3.3-review: ADDED 2026-08-27]` — TLS policy/material startup refusal (SMPP-leg TLS factory): every refusal arm carries the SEC-100 id, and EVERY `companion.forward.tls-contexts` entry is eagerly validated at startup — including entries no routing entry references
Level: unit · Priority: P0 · Risks: R7 · NFR: FR-SEC-1 (AD-13/AD-18/AD-34)
- Technique: boot each refusal arm and assert the exception message names SEC-100 — unparseable/absent cert/key/trust-store files, the 5-state trust-store matrix, empty AD-34 cipher/protocol intersection per context (incl. the suite/protocol applicability case: TLS-1.3-only suites selected with `protocols=[TLSv1.2]`), and the orphan arm: an UNREFERENCED `tls-contexts` entry with nonexistent/unparseable material refuses startup (before the 2026-08-27 patch such dead config escaped both the validator — keySet-derived — and the factory, which loaded only routing-referenced ids).
- Tooling: JUnit5 + AssertJ + committed PKI fixtures (`keycloak/certs/`, incl. the §10 foreign-CA pair) + `Runnable::run` delegated-task executor.
- Notes: Created at the Story 3.3 adversarial review (decision D2, 2026-08-27): the AD-34 intersection and constructor-wrap refusals previously carried no SEC id, and the orphan-eager-load closed an AD-18 hole on the re-keyed surface. Biters: `CompanionConfigMatrixTest` SEC-098 rows + `SmppLegTlsFactoryTest` 5-state/intersection/orphan matrix.

## 5. OBS — Observability & operability

Owns R10 (/metrics surface: cardinality DoS + PRIV-1 body leak + handler hardening + loopback-only), R11 end-to-end (graceful shutdown AD-22 7-step), R37 (docs drift from `companion.*`), R38 (A-1 non-CI ops plan must be genuinely falsifiable). NFRs OBS-1/2/3, OPS-1/2, PRIV-1, REL-3, FR-OBS-1/2. The `SpliceObserver` interface (pinned triggers; no content/PDU-type method by design — AD-27) is the metrics/observability seam.

### 5.1 /metrics contract + handler hardening (R10)

**OBS-001** — GET /metrics on the dedicated loopback returns HTTP 200 with valid Prometheus text exposition and the expected metric contract
Level: integration · Priority: P2 · Risks: R10 · NFR: OBS-1, FR-OBS-1
- Technique: golden-contract scrape: bind the real dedicated Netty metrics loop on 127.0.0.1, GET /metrics, assert 200, Content-Type text/plain;version=0.0.4, and parse body with a Prometheus text parser; assert required names present (submit/throughput counters, bind accept/reject counters, resource gauges, custom active-VT gauge, ByteBufAllocatorMetric-derived direct-memory gauge).
- Tooling: JUnit5/Jupiter + AssertJ; in-JVM Netty handler on a bound loopback socket; Prometheus text-format parser (io.prometheus:prometheus-metrics-exposition-formats or simpleclient HTTPServer decoder) as an independent micro-oracle.
- Notes: Contract test for the whole OBS-1 surface; subsequent OBS-002..OBS-015 assert individual branches. No Actuator/Tomcat/WebFlux on this path (see OBS-013).

**OBS-002** — Non-GET method to /metrics is rejected with 405 and performs no state change
Level: integration · Priority: P2 · Risks: R10 · NFR: OBS-1, OBS-3
- Technique: parametrized negative over POST/PUT/DELETE/PATCH/HEAD/CONNECT/OPTIONS to /metrics; assert 405 (or 404) for each; assert no counter/gauge mutated by the attempt (read is the only permitted effect).
- Tooling: JUnit5 parameterized + Netty EmbeddedChannel driving the real HttpServerCodec+HttpObjectAggregator+handler pipeline; capturing SimpleMeterRegistry.
- Notes: Method gating is one of two handler-hardening axes (AD-19); paired with path gating OBS-003.

**OBS-003** — Any path other than exactly /metrics is rejected with 404
Level: integration · Priority: P2 · Risks: R10 · NFR: OBS-1, OBS-3
- Technique: parametrized negative over /, /metrics/, /Metrics, /metrics?x=1, /admin/metrics, /metrics/../etc, //metrics, /v1/metrics; assert 404 for each and that no scrape body is produced.
- Tooling: JUnit5 parameterized + Netty EmbeddedChannel; AssertJ on FullHttpResponse status.
- Notes: Exact-path-only (no prefix/wildcard), case-sensitive, no trailing slash — the path matcher is a common bypass surface.

**OBS-004** — Metrics server binds loopback IPv4 only (127.0.0.1); localhost/::1 is not used and a non-loopback bind is not opened
Level: integration · Priority: P1 · Risks: R10, R17 · NFR: OBS-1, SEC-2
- Technique: after SmartLifecycle start, assert the metrics ServerSocketChannel.localAddress() is bound to 127.0.0.1 (not 0.0.0.0, not ::1, not link-local); assert the bind target string in config-resolution is the literal 127.0.0.1 (localhost is rejected/resolved away to avoid ::1); optionally assert a connect to the published port via a non-loopback interface is unreachable.
- Tooling: JUnit5 + AssertJ; Spring Boot test slice booting the metrics SmartLifecycle bean; java.net.NetworkInterface enumeration to confirm no 0.0.0.0/wildcard listen.
- Notes: Blind spot: full 'rejects a remote connect' is environment-dependent (no remote NIC in CI); assert the bind literal + localAddress as the CI-portable proxy. This binding is the SOLE authentication of the endpoint (AD-19) → P1.

**OBS-005** — Oversized HTTP header and oversized body are rejected before parsing completes (bounded limits)
Level: integration · Priority: P2 · Risks: R10 · NFR: OBS-1, SEC-2
- Technique: parametrized negative: (a) a request line + headers exceeding maxHeaderLength → 400/414 and no scrape; (b) a GET with a Content-Length/maxContentLength body exceeding the bound → 413 and the aggregator raises TooLongFrameException handled as a hard reject; assert the channel is closed and no relay-loop work is scheduled.
- Tooling: JUnit5 parameterized + Netty HttpObjectAggregator with the configured caps; AssertJ on response status + channel close future.
- Notes: Bounded sizes are the DoS bound on the handler (AD-19). Header vs body are two distinct Netty limits — cover both.

**OBS-006** — HTTP request-smuggling vectors are neutralized by HttpServerCodec+HttpObjectAggregator (no hand-rolled parsing)
Level: integration · Priority: P1 · Risks: R10 · NFR: OBS-1, SEC-2
- Technique: golden-vector negative: feed CL.TE, TE.CL, TE.TE, duplicated Content-Length, Content-Length over Transfer-Encoding, chunked-extension obfuscation, malformed chunk-size byte vectors to the real pipeline; assert each yields exactly one FullHttpRequest that is then 404/405 (or a 400 close) and that no second 'smuggled' request is dispatched on the same channel.
- Tooling: JUnit5 parameterized over a curated smuggling byte-vector corpus; Netty EmbeddedChannel with the production HttpServerCodec+HttpObjectAggregator+handler; AssertJ that only one inbound message is observed.
- Notes: Defense for the explicit R10 smuggling concern; proves the team did not hand-roll HTTP parsing. Connection-per-request (close after scrape) further shrinks the surface.

**OBS-007** — A bind accept for a routing-table system_id emits a labeled counter whose label value is within the routing-table set
Level: integration · Priority: P2 · Risks: R10 · NFR: OBS-1, FR-OBS-1
- Technique: capturing-observer positive: install a capturing SpliceObserver + SimpleMeterRegistry behind the seam; drive a bind_transceiver with a system_id present in a fixed fake routing table through to the AD-25 flip; assert binds.accepted{system_id=<table-value>} increments by 1 and the label value equals exactly that table entry.
- Tooling: JUnit5 + Micrometer SimpleMeterRegistry; capturing SpliceObserver impl (AD-27 seam); fake BindCredentialVerifier returning Allow; AssertJ on meter map.
- Notes: Establishes the happy-path label contract; the negative/attack cases are OBS-008/OBS-009.

**OBS-008** — A high-cardinality burst of distinct unknown system_ids does not expand the metric series count beyond the routing-table bound
Level: integration · Priority: P2 · Risks: R10 · NFR: OBS-1, SEC-2
- Technique: cardinality-DoS soak (short): drive N (e.g. 10000) binds each with a unique unknown system_id; snapshot SimpleMeterRegistry.getMeters().size() before and after; assert the delta is 0 (or only the fixed unlabeled counters), i.e. series count stays bounded to the routing-table size regardless of input distinctness.
- Tooling: JUnit5 + SimpleMeterRegistry; capturing SpliceObserver; AssertJ delta assertion; @RepeatedTest / parameterized for stability.
- Notes: Defense-in-depth on OBS-009 — proves the bound holds under cardinality attack, not just for one input.

**OBS-009** — A bind whose system_id is NOT in the routing table increments an unlabeled counter and never creates a free-form system_id label
Level: integration · Priority: P1 · Risks: R10, R23 · NFR: OBS-1, PRIV-1, SEC-2
- Technique: cardinality-bound negative: drive a bind with an arbitrary attacker-chosen system_id absent from the routing table; assert binds.rejected.unknown_system_id (unlabeled) increments; assert NO meter carries the raw system_id as a label value; assert SpliceObserver.onBindReject is NOT invoked with that raw system_id (routing-miss goes straight to the unlabeled counter per AD-27).
- Tooling: JUnit5 + SimpleMeterRegistry; capturing SpliceObserver; fake routing table; AssertJ that the meter map contains no key whose tag value equals the attacker string.
- Notes: The single most important cardinality/enumeration property (AD-19). Prevents label-injection + system_id enumeration via the metrics surface → P1.

**OBS-010** — Message/PDU body never appears in the /metrics scrape text (PRIV-1)
Level: integration · Priority: P1 · Risks: R10, R8 · NFR: OBS-1, PRIV-1
- Technique: negative-by-absence: splice a submit_sm carrying a unique sentinel short_message body through a coupled pair; scrape /metrics; assert the sentinel string is absent from the scrape text; assert the SpliceObserver recorded only onFramedPdu(Direction) events (PDU count, no byte volume, no content) and that no body-derived label/counter appears — the interface carries neither PDU type nor body by construction (AD-27).
- Tooling: JUnit5 + in-JVM coupled channel pair on codec; capturing SpliceObserver; AssertJ that scrape text does not contain the sentinel substring.
- Notes: SpliceObserver interface has NO content/PDU-type method by design (AD-27) — assert both the contract (interface shape) and the runtime absence of the sentinel.

**OBS-011** — The custom active-virtual-thread gauge exists and reports the actual active VT count (jvm_threads_* excludes VTs)
Level: unit · Priority: P2 · Risks: R10 · NFR: OBS-1, PERF-2
- Technique: controlled-thread probe: with the adjudication VT pool idle, read the custom gauge; spawn K bound VTs (or instrumented fake pool of size K) and re-read; assert gauge == K and that Micrometer jvm_threads_live / daemon do NOT move by K (they undercount VTs); tear down VTs and assert gauge returns to baseline.
- Tooling: JUnit5 + Micrometer gauge; a test-instrumented VT pool (or the real bounded pool with a count latch); AssertJ.
- Notes: AD-19 mandates the custom gauge precisely because built-in JVM thread metrics miss VTs. Keep as a UNIT seam test (gauge wiring) — PERF-2 owns the resource-at-scale claim.

**OBS-012** — The metrics scrape runs on a dedicated EventLoopGroup that is not the SMPP relay EventLoopGroup (scraping cannot stall the relay)
Level: integration · Priority: P2 · Risks: R10, R28 · NFR: OBS-1, PERF-1
- Technique: wiring assertion: resolve both the metrics SmartLifecycle bean's EventLoopGroup and the relay ServerBootstrap's child EventLoopGroup from the Spring context; assert they are distinct instances (identity !=); assert no handler in the metrics pipeline is attached to the relay group; (secondary) block the metrics loop briefly and assert relay throughput is unaffected.
- Tooling: JUnit5 + Spring Boot test context; AssertJ identity check on the two EventLoopGroup beans; optional capturing RelayHandler throughput probe.
- Notes: AD-19 isolation invariant. Formal throughput-while-scraped proof lives in Epic 6 (PERF-1) — this asserts the structural isolation. Blind spot: isolation is partly convention — assert the wiring mechanically.

**OBS-013** — No Actuator/Tomcat/WebFlux/Reactor runtime dependency is on the classpath serving /metrics
Level: unit · Priority: P2 · Risks: R10, R16 · NFR: OBS-1, SEC-2
- Technique: build/CI scan: resolve the runtime classpath of the proxy module and assert none of spring-boot-starter-web, spring-boot-starter-tomcat, spring-boot-starter-webflux, spring-boot-actuator-(web), reactor-core, reactor-netty are present (or are present only at test scope); fail the build on a violation.
- Tooling: Gradle test using the resolved configurations (or owasp/dependency-check + a custom Gradle dependency-rule task); AssertJ on resolved-component coordinates.
- Notes: AD-16/AD-19 forbid a web stack on the proxy. A drift here silently re-introduces an Actuator management surface — catch at build time, not runtime. Positive control = OBS-043.

**OBS-014** — SpliceObserver.onBindReject is fired only for Verdict DenyInvalid/DenyIndeterminate from BindCredentialVerifier (pinned-trigger contract)
Level: integration · Priority: P2 · Risks: R10, R23 · NFR: OBS-1, OBS-2
- Technique: contract negative: trigger each deny source — (a) fake verifier returning DenyIndeterminate → assert onBindReject invoked once with that Verdict; (b) routing-miss (system_id not in table) → assert onBindReject NOT invoked, only the unlabeled counter increments; (c) kid-miss → same as (b); (d) config deny → same as (b). Pinned-trigger source-of-truth assertion.
- Tooling: JUnit5 parameterized over deny-source; capturing SpliceObserver; fake BindCredentialVerifier; fake routing table + JWKS cache; AssertJ on observer call list.
- Notes: AD-27 pinned triggers. Complements OBS-009 (cardinality) by asserting the routing of deny events. The AD-25 flip-timing (onBindAccept fires at flip not at verdict) is owned by RELAY (R5).

### 5.2 Graceful shutdown AD-22 end-to-end (R11)

**OBS-015** `[critic-fix: SCOPE-REDUCED]` — End-to-end SIGTERM during steady splice: process exits within the Spring shutdown timeout (packaging/process-exit aspect)
Level: e2e · Priority: P1 · Risks: R11, R5 · NFR: REL-3, REL-1
- Technique: in-JVM full journey: bind→splice steady-state; deliver SIGTERM-equivalent (SpringContextClosed/SmartLifecycle.stop); assert process exit within the configured graceful timeout and that the drain sequence is initiated. Capture drop/dup via a sequence-number ledger on the mock SMSC.
- Tooling: JUnit5 + in-JVM real socket pair + in-JVM mock SMSC on codec; capturing SpliceObserver; Spring Boot test lifecycle; injectable Clock to bound the timeout deterministically; AssertJ on the sequence ledger.
- Notes: [critic-fix] SCOPE-REDUCED — keeps ONLY the e2e packaging / process-exit-within-timeout aspect for Epic-5 acceptance. The re-assertion of splice zero-drop was DROPPED as duplicated (owned by RELAY-022's isolated relay-drain invariant: no-partial-frame, registry→0). The packaged-shape SIGTERM→PID-1 propagation is R34 (DEPLOY-006); this is the in-JVM end-to-end.

**OBS-016** — AD-22 shutdown macro-ordering holds (acceptor stop before in-flight DENY before splice drain before exit) *(re-worded 2026-08-27, Story 3.4 T2: 7 steps → 5 — the jwks-refresh-stopped and jwks-cache-closed events died with local JWT verification; spine AD-22 amendment)*
Level: integration · Priority: P1 · Risks: R11 · NFR: REL-3
- Technique: phase-ordering probe: install a capturing lifecycle listener that records an ordered event list (acceptor-stopped, adjudications-denied, drain-started, drain-completed, vt-drained, exit — the jwks-refresh-stopped/jwks-cache-closed events died with local JWT verification, Story 3.4 T2, 2026-08-27); trigger SIGTERM; assert the recorded sequence matches the AD-22 order pairwise (each step's first timestamp ≤ next step's first timestamp).
- Tooling: JUnit5 + Spring Boot SmartLifecycle test; capturing shutdown orchestrator listener; fake verifier/routing; AssertJ on ordered event list.
- Notes: Macro ordering. Pairwise-timestamp assertion avoids over-constraining concurrent steps. *(The JWKS refresh-then-close sub-ordering note died with the cache, Story 3.4 T2, 2026-08-27 — OBS-018 retired; see below.)*

**OBS-017** — A new bind attempted after the acceptor stops is rejected/DENYed (no new session accepted during shutdown)
Level: integration · Priority: P1 · Risks: R11, R1 · NFR: REL-3, FR-SEC-5
- Technique: negative ordering: begin shutdown; once acceptor-stopped is observed, attempt a fresh SMPP TCP connect+bind; assert either the connect is refused OR, if accepted pre-drain-close, the adjudication returns DENY and the bind_resp is a non-ROK status; assert no new entry is added to the ConnectionRegistry.
- Tooling: JUnit5 + in-JVM socket pair; capturing ConnectionRegistry (AD-8 seam); fake verifier; AssertJ on registry size + bind_resp status.
- Notes: Fail-closed during shutdown (AD-11/AD-22 step 2). Prevents a late bind racing into the drain window.

**OBS-018** — JWKS refresh ScheduledExecutorService is shut down (and awaited) BEFORE the JWKS cache is closed (no refresh-after-close orphan)
Level: integration · Priority: P1 · Risks: R11, R20 · NFR: REL-3
- Technique: micro-ordering seam: inject a fake JWKS cache whose close() records a nano-time stamp + a flag, and a fake refresh ScheduledExecutorService whose shutdown()+awaitTermination() records a stamp; trigger SIGTERM; assert refresh-shutdown timestamp < cache-close timestamp and that no refresh task runs after close(); assert cache.close() is invoked exactly once.
- Tooling: JUnit5 + fake AtomicReference<JwkSet> cache wrapper + fake ScheduledExecutorService; injectable Clock for deterministic timestamps; AssertJ ordering.
- Notes: AD-22 steps 4→5 — the subtle ordering the register calls out. The AD-8 cache exposes close() precisely for this; exploit that seam.
- **Status (Story 3.4 T2, 2026-08-27): RETIRED — the JWKS cache, its refresh executor, and the AD-22 steps 4→5 ordering all died with local JWT verification (spine AD-22/AD-28(2) amendments). `AdjudicationLifecycleTest`'s stop-body pins now cover deny-in-flight → client/secret release only.**

**OBS-019** — An in-flight adjudication at SIGTERM is DENYed fail-closed and its token discarded (no partial-verdict Allow race)
Level: integration · Priority: P1 · Risks: R11, R1, R8 · NFR: REL-3, FR-SEC-5, PRIV-1
- Technique: partial-verdict race negative: install a fake BindCredentialVerifier whose verify() blocks on a CountDownLatch (simulating an in-flight ROPC call) and captures the password char[]; submit a bind so adjudication is pending; trigger SIGTERM; assert the bind_resp sent to the legacy client is a non-ROK/DENY status (never Allow), the latch is released with shutdownNow(), and the captured char[] is zeroed (all zeros) on the discard path.
- Tooling: JUnit5 + blocking fake BindCredentialVerifier (AD-12 seam) + CountDownLatch; capturing bind_resp; AssertJ on status + Arrays.equals(char[], zeros).
- Notes: R11 partial-verdict race + R1 fail-closed + R8 token-discard on the shutdown path, atomically. Proves DENY never loses to an in-flight Allow during drain. Relay-side counterpart = RELAY-023.

**OBS-020** — A splice whose peer never half-closes is force-closed at the Spring graceful-shutdown timeout (process exits within bound, not hung)
Level: integration · Priority: P1 · Risks: R11, R3 · NFR: REL-3, REL-2
- Technique: timeout-bounding negative: establish a coupled pair whose egress peer never sends FIN/RST (keep open); trigger SIGTERM; with an injectable Clock/scheduler advancing to the configured drain timeout, assert the channel is force-closed and the JVM exits within timeout+epsilon; assert no in-flight PDU is corrupted (half-flushed) on the force-close.
- Tooling: JUnit5 + in-JVM socket pair with a peer that holds the connection; injectable Clock to advance the drain deadline deterministically (no hard wait); AssertJ on exit-within + channel close future.
- Notes: AD-22 'Spring graceful-shutdown timeout bounds the drain window.' Injectable Clock is mandatory here (blind spot 5) — a real wall-clock wait is non-deterministic.

**OBS-021** — The bounded VT adjudication pool is drained (shutdownNow+await) before exit; no orphaned adjudication VT survives
Level: integration · Priority: P2 · Risks: R11, R9 · NFR: REL-3
- Technique: drain-completeness probe: register the adjudication ExecutorService with the shutdown orchestrator; spawn several adjudication VTs (some blocking); trigger SIGTERM; assert shutdownNow() is invoked, awaitTermination returns within the sub-budget, and a post-exit thread dump (or ThreadMXBean snapshot) shows zero surviving companion adjudication VTs.
- Tooling: JUnit5 + the real bounded VT pool (AD-28) or a test double; ThreadMXBean/java.lang.Thread enumeration for VT residuals; AssertJ.
- Notes: AD-22 step 6 + AD-28. Overlaps R9 (STS orphan) — scoped here to the shutdown exit-completeness slice; R9/R31 own the STS-fork/ScopedValue-propagation concerns.

### 5.3 Logging contract + PRIV-1 (R10/R8)

**OBS-022** — Startup emits a structured JSON-line log with a UTC ISO-8601 timestamp and a config-resolved summary containing no secret values
Level: integration · Priority: P2 · Risks: R10, R8 · NFR: OBS-2, PRIV-1
- Technique: contract positive: boot a minimal Spring context to the 'started' event; capture the startup JSON-line via a test LogAppender; assert each line parses as JSON, has ts in UTC ISO-8601 (Z suffix), and the config-resolved summary includes role, mode, ports, OIDC provider host (not full URL creds); assert no field value contains a known secret sentinel planted in the cert/key/client-cred file paths.
- Tooling: JUnit5 + capturing LogCaptor/ListAppender; a JSON parser; injectable Clock to assert deterministic ts; AssertJ.
- Notes: FR-OBS-2 startup/config-resolved line. Injectable Clock used for the timestamp determinism.

**OBS-023** — Bind-accept log line is JSON with UTC ISO-8601 ts and the routing-table system_id; the password is absent even at TRACE
Level: integration · Priority: P1 · Risks: R10, R8 · NFR: OBS-2, PRIV-1
- Technique: PRIV-1 negative-by-absence: drive a bind with a known sentinel password through to accept; capture logs at both INFO and TRACE; assert the accept line is JSON with ts + system_id; assert the sentinel password string appears in NO captured line at ANY level.
- Tooling: JUnit5 + capturing LogCaptor at TRACE; fake verifier returning Allow; AssertJ that no line contains the sentinel.
- Notes: R8 credential-escape via logs. The system_id may be logged (PRIV-1 permits it); the password never — assert the distinction explicitly.

**OBS-024** — Bind-reject log line carries system_id + Verdict type with no password and no stack trace at default level
Level: integration · Priority: P2 · Risks: R10, R8 · NFR: OBS-2, PRIV-1
- Technique: contract negative: trigger each Verdict (DenyInvalid, DenyIndeterminate) via the fake verifier; capture INFO logs; assert the reject line is JSON with ts, system_id, verdict; assert no password sentinel and no throwable/stack-trace field; assert the wire bind_resp carries only the mapped status code.
- Tooling: JUnit5 + capturing LogCaptor at INFO; fake BindCredentialVerifier; AssertJ.
- Notes: Consistency-convention 'never a stack trace on the wire.' The status-code→verdict mapping correctness itself is R23 (Q7); this asserts the log/wire carries no stacktrace + no password.

**OBS-025** — PDU/message body is absent from logs at default (INFO) level and present only when the level is raised to TRACE
Level: integration · Priority: P1 · Risks: R10, R8 · NFR: OBS-2, PRIV-1
- Technique: level-gated content negative: splice a submit_sm with a unique sentinel body; capture logs at default level → assert sentinel absent; raise the companion body-logging level to TRACE → assert sentinel present (proves TRACE plumbing exists and is the only body path); restore default → assert sentinel absent again.
- Tooling: JUnit5 + capturing LogCaptor with dynamic level toggle; in-JVM coupled pair; AssertJ substring checks; self-cleaning fixture (restore level in @AfterEach).
- Notes: PRIV-1 + OBS-2: TRACE-only, off by default. The load-bearing content-suppression assertion; pair with OBS-010 (metrics) for full PRIV-1 surface coverage.

**OBS-026** — Log level is configurable via application.yml and defaults to a non-TRACE level (TRACE body logging off by default)
Level: integration · Priority: P2 · Risks: R10 · NFR: OBS-2
- Technique: config-binding positive: boot two contexts — (a) default application.yml → assert effective body-log level is not TRACE and a sentinel body is NOT logged; (b) application.yml with the companion body-logging level set to TRACE → assert the sentinel IS logged; assert relaxed binding resolves the documented key.
- Tooling: JUnit5 + Spring Boot @SpringBootTest with two profiles; capturing LogCaptor; AssertJ.
- Notes: OBS-2 'level configurable' + 'TRACE off by default.' Ties to OBS-030 (the key must be documented and bound).

**OBS-027** — Every JSON log line carries a UTC ISO-8601 timestamp (Z suffix) parseable to an Instant, set from the injectable Clock
Level: unit · Priority: P2 · Risks: R10 · NFR: OBS-2
- Technique: format-contract unit: feed a fixed Clock instant; emit startup/bind-accept/bind-reject/error lines through the JSON-line formatter; assert each line's ts field parses via DateTimeFormatter.ISO_OFFSET_DATE_TIME, ends with 'Z', and equals the fixed instant exactly (no epoch millis, no local-zone offset).
- Tooling: JUnit5 + the JSON-line formatter under test + a fixed Clock; AssertJ on parsed Instant.
- Notes: Convention 'UTC ISO-8601.' Injectable Clock (blind spot 5) makes the timestamp deterministic — no sleeping.

**OBS-028** — No Java stack trace is emitted on the SMPP wire or in default-level logs on an internal error during bind handling
Level: integration · Priority: P2 · Risks: R10, R3 · NFR: OBS-2, SEC-2
- Technique: error-containment negative: inject a runtime exception inside BindInterceptor/RelayHandler on the bind path; capture the wire bind_resp bytes and the INFO logs; assert the bind_resp payload contains no Java class-name/stack-frame string and the log line carries a message + verdict/status but no full stack-trace multiline at default level.
- Tooling: JUnit5 + in-JVM channel with a handler that throws; bind_resp byte capture; LogCaptor at INFO; AssertJ that no stack-frame regex matches the wire payload.
- Notes: Consistency-convention error row. Overlaps R3 per-channel exception containment (owned E1/E2) — scoped here to the no-stacktrace-on-wire/log observable.

### 5.4 Docs drift / config-docs consistency (R37)

**OBS-029** — Config reference docs and @ConfigurationProperties are bidirectionally consistent (every documented companion.* key binds; every bindable key is documented)
Level: unit · Priority: P2 · Risks: R37 · NFR: OPS-1, FR-DEPLOY-3
- Technique: consistency-scan CI test: extract the set of companion.* keys from docs/config-reference (parse the markdown table) and the set of properties from the @ConfigurationProperties class via reflection (field/prefix traversal); assert set equality both directions; fail the build on any drift.
- Tooling: JUnit5 + reflection over @ConfigurationProperties + a markdown-table parser over docs/; AssertJ set equality; runs in CI (no runtime needed).
- Notes: R37 core. Catches docs drift at build time. The role×mode fail-fast matrix itself is covered by R17 (Epic 1); this is the docs↔binding surface only.

**OBS-030** — Docs per-mode (A/B/C × forward/reverse) matrix matches the AD-17 required/optional/forbidden matrix
Level: unit · Priority: P2 · Risks: R37, R17 · NFR: OPS-1, FR-DEPLOY-2
- Technique: docs-vs-spec matrix check: parse the per-mode deployment matrix from docs; assert each of the 6 cells (forward×A/B/C, reverse×A/B/C) matches AD-17's required/optional/forbidden classification (incl. forward×B forbidden, reverse×B opt-in).
- Tooling: JUnit5 + markdown parser + an embedded copy of the AD-17 expected matrix as the oracle; AssertJ cell-by-cell.
- Notes: Guards the most safety-relevant doc (wrong matrix cell → silent insecure startup). Runtime enforcement is R17 (Epic 1); this is the doc-accuracy mirror.

**OBS-031** — Docs contain the Mode B plaintext warning text, the explicit opt-in acknowledgment, and the reverse-only constraint
Level: unit · Priority: P2 · Risks: R37, R18 · NFR: OPS-1
- Technique: docs-completeness scan: assert docs deployment guide contains (a) the Mode B 'plaintext password over public internet' warning, (b) the opt-in ack mechanism/string, (c) the 'Mode B is reverse-only' statement; fail build if any absent.
- Tooling: JUnit5 + docs text scan over docs/; AssertJ presence of canonical substrings.
- Notes: AD-17 Mode B posture. The runtime warning+ack is R17; this asserts the operator-facing doc mirrors it.

**OBS-032** — Docs publish the TLS cipher-allowlist policy (1.2 min / 1.3 pref + allowlist + operator-tunable note) `[BLOCKED-ON-Q3]`
Level: unit · Priority: P2 · Risks: R37, R16 · NFR: OPS-1, SEC-1
- Technique: docs-completeness scan: assert docs contain TLS 1.2 minimum, 1.3 preferred, the concrete default cipher allowlist, and the operator-tunable statement; cross-check the documented allowlist matches the config-default allowlist value.
- Tooling: JUnit5 + docs scan + config-default value comparison; AssertJ.
- Notes: SEC-1 published policy (AD-31). Drift between doc allowlist and config default is the specific R37 failure mode. Depends on Q3 (concrete cipher allowlist pin).

**OBS-033** — Docs state the ROPC (Direct Access Grants) deprecation trajectory and the Keycloak build-pinning guidance
Level: unit · Priority: P2 · Risks: R37, R2 · NFR: OPS-1
- Technique: docs-completeness scan: assert the deployment guide discloses (a) v1 authenticates via ROPC / Direct Access Grants, (b) the RFC 9700 / OAuth 2.1 removal-track status, (c) the operator must pin their Keycloak build.
- Tooling: JUnit5 + docs scan; AssertJ presence of canonical substrings.
- Notes: Epic 6 carry-forward. OPS-1 honesty obligation for the most fragile dependency (R2).

**OBS-034** — Docs contain the deployer-dependent controls runbook: Mode A ACL-isolation warning and egress cacerts-prevention/opt-in
Level: unit · Priority: P1 · Risks: R37, R18, R7 · NFR: OPS-1, SEC-1
- Technique: docs-completeness scan: assert docs/runbooks contain (a) the Mode A two-proxy ACL-isolation requirement + the 'ingress cannot authenticate egress in one-way TLS' warning, (b) the egress trust-store never-cacerts default + the explicit opt-in for public-PKI SMSC trust; cross-link to the startup-warning text asserted in R18.
- Tooling: JUnit5 + docs scan over docs/runbooks; AssertJ presence of canonical substrings.
- Notes: Blind spot 4: deployer-dependent controls are CI-tested only via warning+ack+runbook+config-scan. The runtime warning/ack/config-scan side is R18/R7 (E3/E5); this is the docs surface (R37) that docks under AD-31. P1 because it backs two P0/P1 risks.

### 5.5 A-1 non-CI ops plan — genuinely falsifiable (R38)

**OBS-035** — A-1 ops plan exists under docs/ and defines an explicit, measurable PASS criterion (≥2 concurrent binds, same system_id, both ROK on the real target carrier)
Level: unit · Priority: P2 · Risks: R38 · NFR: OPS-1, REL-4
- Technique: docs-falsifiability scan: assert docs/a-1-carrier-test-plan (or equivalent) exists and contains a pass criterion with a numeric concurrency bound (≥2) + same-system_id + ROK-on-real-carrier; fail the build if absent or non-numeric.
- Tooling: JUnit5 + docs scan with regex for the pass-criterion shape; AssertJ.
- Notes: R38 core: make the A-1 checkpoint actually falsifiable. The plan MUST target the real carrier, not the in-JVM mock (which assumes A-1).

**OBS-036** — A-1 ops plan defines an explicit FAIL criterion and the DLR-affinity assertion (submit on bind A -> deliver_sm observed on bind A, not bind B)
Level: unit · Priority: P2 · Risks: R38, R5 · NFR: OPS-1, REL-1, REL-4
- Technique: docs-falsifiability scan: assert the plan contains (a) a fail criterion (2nd bind rejected by carrier, OR DLR observed on the wrong bind), and (b) a concrete DLR-affinity assertion procedure (submit_sm on bind A -> assert deliver_sm returns on bind A's socket, not bind B's); fail the build if either is absent or ambiguous.
- Tooling: JUnit5 + docs scan; AssertJ presence of affinity-assertion language.
- Notes: The DLR-affinity assertion is what makes A-1 falsifiable for the stateless design's headline guarantee (REL-1/REL-4). Without it the checkpoint is theatre.

**OBS-037** — A-1 ops plan specifies execution against the real target carrier (or an independent SMSC oracle), never the in-JVM codec-based mock
Level: unit · Priority: P2 · Risks: R38, R33 · NFR: OPS-1
- Technique: docs-falsifiability scan: assert the plan names the real target carrier / conformance SMSC as the system-under-oracle and explicitly excludes the in-JVM mock (which emulates/assumes A-1) as a valid oracle for this checkpoint.
- Tooling: JUnit5 + docs scan; AssertJ.
- Notes: Oracle independence (blind spot 1). The in-JVM mock cannot falsify A-1 because it assumes it; the plan must say so.

**OBS-038** — Conformance: against the jSMPP independent server-side mock, ≥2 concurrent binds under one system_id both ROK and a DLR returns on the originating bind's coupled channel
Level: conformance · Priority: P1 · Risks: R38, R33, R5 · NFR: REL-1, REL-4, COMP-1
- Technique: independent-oracle conformance: stand up a jSMPP server-side mock (NOT the codec-based in-JVM mock); open 2 concurrent binds with the same system_id -> assert both bind_*_resp are ROK; submit_sm on bind A -> assert the resulting deliver_sm (DLR) arrives on bind A's coupled channel and NOT on bind B; assert the proxy's ConnectionRegistry routes by coupled pair (AD-9 affinity).
- Tooling: JUnit5 + jSMPP 3.0.2 server-side mock (independent oracle, alternate codec) as the SMSC; in-JVM proxy; capturing SpliceObserver; AssertJ on ROK + DLR-channel identity.
- Notes: Oracle-independence defense-in-depth (blind spot 1): jSMPP shares neither the production codec's bugs nor its A-1 assumption (the jSMPP server allows multi-bind by configuration). Validates the proxy's affinity BEHAVIOR; the true A-1 falsification remains the non-CI real-carrier step (OBS-035..037). P1 for the oracle-independence gap (R33).

### 5.6 No-management-API + immutability + direct-memory gauge (R10)

**OBS-039** — No management paths exist: candidate operator-control paths all return 404/405 and perform no state-changing action
Level: integration · Priority: P2 · Risks: R10 · NFR: OBS-3
- Technique: negative probe over a dictionary (/drain, /drain/, /reload, /rotate, /shutdown, /stop, /health, /healthz, /ready, /live, /admin, /manage, /api, /config, /actuator, /actuator/env, /, /index.html); for each assert 404 or 405; assert the routing table, TLS context, and ConnectionRegistry are byte-identical before/after the probe sweep (no side effect).
- Tooling: JUnit5 parameterized over the dictionary; in-JVM metrics loop; capturing registry/routing snapshot; AssertJ.
- Notes: OBS-3 'no management API.' /metrics is the ONLY responding path and it is read-only (OBS-040).

**OBS-040** — GET /metrics is idempotent and mutates no runtime state; the scrape body contains only counters/gauges (no writable/command fields)
Level: integration · Priority: P2 · Risks: R10 · NFR: OBS-1, OBS-3
- Technique: read-only invariant: snapshot all meter values + registry size + ConnectionRegistry contents; GET /metrics three times in succession; assert each response body is exposition-only (no POST-like command fields, no 'set'/'reset' tokens) and that the post-scrape state equals the pre-scrape state (modulo monotonic counter ticks from the scrape mechanics itself).
- Tooling: JUnit5 + SimpleMeterRegistry snapshot; in-JVM metrics loop; AssertJ state-equality + body-shape.
- Notes: Proves /metrics is explicitly NOT a management API (OBS-3). Complements OBS-002 (method gate) by asserting the GET itself is side-effect-free.

**OBS-041** — Editing application.yml or touching a cert file at runtime does NOT reload/rotate (config + TLS material are immutable post-startup; rotation requires re-deploy)
Level: integration · Priority: P2 · Risks: R10, R37 · NFR: OBS-3, OPS-2
- Technique: immutability negative: after startup, (a) append a new system_id to the routing config file on disk and assert the routing table in memory is unchanged (a bind with the new system_id is still DENYed as unknown), (b) touch/replace the cert file and assert the live SslContext is unchanged (a new handshake still uses the old cert); assert no file-watch/reload mechanism is wired.
- Tooling: JUnit5 + Spring Boot test context; in-JVM bind attempt post-edit; capturing SslContext; AssertJ on routing table + cert identity.
- Notes: OPS-2 (rotation = re-deploy) + OBS-3 (no runtime reload). Confirms the headless product has no live control surface — changes require restart/re-deploy.

**OBS-042** — ByteBufAllocatorMetric-derived direct-memory gauge is exposed and tracks allocator direct bytes (resource-observability seam)
Level: integration · Priority: P2 · Risks: R10, R27 · NFR: OBS-1, PERF-2, REL-2
- Technique: gauge-contract positive: allocate and release a known quantity of direct buffers via the shared PooledByteBufAllocator; scrape /metrics; assert a direct-memory gauge tracks the allocation delta (within pooling chunking) and returns toward baseline on release; assert the gauge value source is ByteBufAllocatorMetric (AD-21 seam), not a static guess.
- Tooling: JUnit5 + shared PooledByteBufAllocator + ByteBufAllocatorMetric; Micrometer gauge; AssertJ delta before/after alloc and after release.
- Notes: AD-21 exposes ByteBufAllocatorMetric precisely so this is observable; exploit the seam. The direct-memory-budget-at-cliff saturation is R27 (E2/E6 perf); this asserts the gauge plumbing only.

**OBS-043** `[critic-fix: ADDED]` — CI-gate positive control: forbidden-runtime-dependency gate FIRES on an injected spring-boot-actuator-web / WebFlux / Tomcat / Reactor dependency
Level: unit · Priority: P2 · Risks: R10, R16 · NFR: OBS-1, SEC-2
- Technique: positive control modeled on RELAY-018's BlockHound control — inject a forbidden runtime dependency (spring-boot-actuator-(web), spring-boot-starter-tomcat, spring-boot-starter-webflux, reactor-core, reactor-netty) into the proxy module's runtime classpath via a throwaway fixture config and assert OBS-013's gate FAILS the build (not merely exists). Proves a drift that re-introduces an Actuator/management surface cannot pass silently.
- Tooling: Gradle resolved-configurations task + JUnit5 injected-bad-dep fixture + AssertJ.
- Notes: [critic-fix] Closes the CI-gate-positive-control gap (cross-level issue). OBS-013 asserts the gate EXISTS but never injects a known-bad dep. Pairs with SEC-099 (CVE gate) and CODEC-041 (codec allowlist gate).

## 6. DEPLOY — Packaging, two-shape parity, Docker secrets, arch/IPv4 matrix

Owns R12 (two-shape parity drift), R34 (Docker SIGTERM/PID-1 propagation), R35 (DEP-1 Docker-secrets / distroless non-root), R36 (COMP-3/4 build+runtime gates: Epoll-vs-NIO, IPv4-only, x86/ARM matrix). Most are E2E (packaged-shape) and lift into Epic 5 acceptance (blind spot 6).

**DEPLOY-001** — jlink runtime image bundles the crypto + management JDK modules (jdk.crypto.ec, jdk.crypto.cryptoki, java.management)
Level: integration · Priority: P1 · Risks: R12 · NFR: FR-DEPLOY-1, MAINT-5, COMP-2
- Technique: image-module-scan / jdeps-driven module-resolution CI gate (static, deterministic).
- Tooling: jlink --list-modules (or jdeps --print-module-deps against the proxy fat JAR) + JUnit5 assertion in a CI step; module-list diff vs the required set.
- Notes: Static cheapest gate for jlink completeness. The runtime proof that jdk.crypto.ec (TLS handshakes) and jdk.crypto.cryptoki (PKCS12 trust-store load) actually function in the Docker shape folds into DEPLOY-005. Resolve the module set via jdeps from the fat JAR, not a hand-maintained --add-modules list, so it cannot drift.

**DEPLOY-002** — Epoll native transport library is present in the distroless image for the target arch and its linked libc matches the image base (glibc for distroless, musl if alpine)
Level: integration · Priority: P1 · Risks: R12, R36 · NFR: FR-DEPLOY-1, COMP-3
- Technique: image-filesystem scan + libc-match check (ldd/ldconfig) CI gate; assert both x86_64 and aarch_64 netty-transport-native-epoll classifiers are on the build classpath.
- Tooling: Docker image filesystem scan for libnetty_transport_native_epoll_linux_{x86_64,aarch_64}.so at the Netty extraction path + ldd libc-dependency match against the base; Gradle dependency assertion for both Epoll classifiers.
- Notes: jlink builds only JDK modules; the Epoll .so is an application resource extracted by Netty at runtime. Drift vector: only the x86_64 classifier pulled in (ARM image lacks the .so → silent NIO fallback). DEPLOY-013 is the runtime backstop; this is the static arch/libc gate.

**DEPLOY-003** — --enable-preview is present and functional at runtime in BOTH the Docker entrypoint AND the JAR launcher
Level: e2e · Priority: P1 · Risks: R12, R9 · NFR: FR-DEPLOY-1, COMP-2
- Technique: runtime JVM-arg introspection + preview-API instantiate across both packaged shapes (parity).
- Tooling: Launch java -jar (JAR shape) AND docker run (Docker shape); assert RuntimeMXBean.getInputArguments() contains '--enable-preview' in BOTH and that a StructuredTaskScope (JEP 505 preview) instantiates without PreviewFeatureException in the Docker shape.
- Notes: STS requires --enable-preview process-wide (AD-5). Drift: the Docker entrypoint omits the flag → the Docker shape throws PreviewFeatureException where the JAR shape works. JDK 25 build-pin (R9) is DEPLOY-014; this asserts the flag is threaded identically into both launchers.

**DEPLOY-004** — -XX:+UseZGC and -XX:MaxDirectMemorySize are set at runtime in BOTH shapes
Level: e2e · Priority: P1 · Risks: R12 · NFR: FR-DEPLOY-1, COMP-2, PERF-2, SEC-2
- Technique: runtime JVM-arg + GC introspection across both packaged shapes (parity).
- Tooling: Launch both shapes; assert RuntimeMXBean.getInputArguments() contains -XX:+UseZGC and -XX:MaxDirectMemorySize=<AD-30 formula value> in BOTH, and GarbageCollectorMXBean name contains 'ZGC' in BOTH.
- Notes: Distinct consequences per flag: omitting -XX:+UseZGC → GC behavior diverges between shapes; omitting -XX:MaxDirectMemorySize → Netty defaults to an unbounded-ish direct budget → OOM at scale where the JAR shape survives. MaxDirectMemorySize value must equal the AD-30 named formula (compile-time shared-constant guard now = RELAY-026).

**DEPLOY-005** — Two-shape behavioral parity: identical config surface, modes A/B/C, and auth paths (ROPC-JWT allow, introspection, DENY) yield identical observable outcomes in the runnable-JAR and distroless-Docker shapes
Level: e2e · Priority: P1 · Risks: R12 · NFR: FR-DEPLOY-1, FR-DEPLOY-2, COMP-1
- Technique: golden-outcome parity-smoke / diff across packaged shapes (deterministic via the BindCredentialVerifier port seam).
- Tooling: JUnit5 + in-JVM mock SMSC + a fake BindCredentialVerifier (AD-12 port) programmed to return Allow / DenyInvalid / DenyIndeterminate + Testcontainers distroless image; run the SAME bind->splice->DLR + Mode A/B/C journeys via java -jar and docker run; golden diff of structured-log lines + /metrics counters.
- Notes: HEADLINE R12 parity test. Angle is SHAPE PARITY (delta between JAR and Docker = zero), NOT auth correctness (R1/R2) or protocol correctness (R14/R33) — overlap is defense-in-depth. Fake verifier makes verdicts deterministic and decouples parity from Keycloak; real Mode A/B/C TLS in both shapes exercises jdk.crypto.ec + PKCS12 load (closes the DEPLOY-001 loop).

**DEPLOY-006** — docker stop (SIGTERM to the container PID 1) reaches the JVM and the AD-22 graceful-drain log sequence appears in order before exit
Level: e2e · Priority: P2 · Risks: R34 · NFR: REL-3, OPS-2
- Technique: signal-delivery + drain-sequence assertion on the packaged Docker shape (exec-form entrypoint or tini).
- Tooling: Testcontainers distroless image; docker stop (SIGTERM) the container; capture stdout; assert with awaitility the ordered AD-22 step log lines appear before exit; assert entrypoint is exec-form (JSON array) or tini-init.
- Notes: Deploy-scoped to SIGNAL PROPAGATION (R34): the failure is a shell-form ENTRYPOINT that makes /bin/sh PID 1 — /bin/sh never forwards SIGTERM to the JVM, so AD-22 never runs. DRAIN CORRECTNESS is owned by R11 (REL/OBS); this asserts only that the signal reaches the JVM and the drain sequence is initiated in order. LIFT into Epic 5 acceptance (blind spot 6).

**DEPLOY-007** — Distroless image runs as a non-root UID/GID and can read Docker secrets mounted under /run/secrets (correct ownership/perms)
Level: e2e · Priority: P2 · Risks: R35 · NFR: DEP-1, FR-DEPLOY-4
- Technique: packaged-shape startup-success assertion under non-root UID with mounted secrets.
- Tooling: Testcontainers distroless image with USER <nonroot-uid>:<gid>; mount TLS cert/key, trust store, OIDC client cred as Docker secrets under /run/secrets with 0440 owned by the non-root UID; assert the container reaches 'ready' and docker inspect confirms non-zero UID.
- Notes: Failure: distroless defaults to root (or the secret files are root-owned 0600) → non-root JVM cannot read /run/secrets → startup fail-fast (or the image is forced to run root, defeating DEP-1). DEP-1 contract = secrets via mounted files, never env values.

**DEPLOY-008** — A secret supplied as an environment-variable VALUE (Docker environment injection) is rejected at startup in the Docker shape (AD-18)
Level: e2e · Priority: P2 · Risks: R35, R22 · NFR: DEP-1, FR-DEPLOY-3
- Technique: packaged-shape fail-fast assertion on the Docker env-injection vector.
- Tooling: Testcontainers distroless image with the OIDC client credential (or a TLS key) injected as an env var via docker environment/compose; assert the container exits non-zero with the AD-18 error and no secret value appears in stdout.
- Notes: Deploy/Docker-vector of AD-18 (env values leak via /proc/<pid>/environ and docker inspect). The config-level rejection matrix is R22 (SEC-075/076); this is the Docker-shape E2E on the env-injection channel — distinct injection vector, defense-in-depth on the DEP-1 contract.

**DEPLOY-009** — Startup fails fast (non-zero exit) in the Docker shape when a secret file path is missing or unreadable
Level: e2e · Priority: P2 · Risks: R35 · NFR: DEP-1, FR-DEPLOY-3
- Technique: packaged-shape fail-fast assertion on bad secret-file state.
- Tooling: Testcontainers distroless image; (a) mount a config secret path pointing at a non-existent file; (b) mount a file unreadable by the non-root UID (wrong ownership/perms); assert both exit non-zero at startup validation with a clear message, before any listener binds.
- Notes: Two atomic bad-states (missing vs unreadable-perms) under one fail-fast behavior. Fail-fast must occur BEFORE the SMPP/metrics listeners bind (no partial-start with secrets unresolved).

**DEPLOY-010** — On Linux the relay starts on Epoll native transport (not an NIO fallback), and Epoll-only assertions are gated on the transport actually being Epoll
Level: integration · Priority: P2 · Risks: R36 · NFR: COMP-3
- Technique: runtime transport-class probe + assertion-gating on OS==Linux (do not pass on NIO what only matters on Epoll).
- Tooling: JUnit5: assert Epoll.isAvailable()==true on Linux CI runners; assert the SMPP acceptor channel class name contains 'Epoll' (EpollServerSocketChannel) and the event-loop group is EpollEventLoopGroup; guard any Epoll-specific assertion behind a transport==Epoll predicate so a dev NIO run cannot false-pass.
- Notes: R36 subtlety: a test that silently runs on NIO in dev but asserts Epoll-only behavior is a false pass, and prod silently falling back to NIO (missing .so) is a perf/behavior regression. DEPLOY-002 is the static lib-presence gate; this is the runtime 'Epoll actually active + assertions correctly gated' proof.

**DEPLOY-011** — /metrics listener binds to the IPv4 loopback literal 127.0.0.1 (Inet4Address), not 'localhost'/::1/0.0.0.0
Level: integration · Priority: P2 · Risks: R36 · NFR: COMP-4, OBS-1
- Technique: bound-local-address class assertion on the dedicated metrics Netty loop.
- Tooling: JUnit5 + launched metrics event-loop group; assert the bound localAddress's InetAddress is an Inet4Address equal to 127.0.0.1; negative: configuring 'localhost' (which resolves to ::1 on dual-stack hosts) or 0.0.0.0 is rejected/refused at config validation.
- Notes: COMP-4 = IPv4 only. 'localhost' resolves to ::1 (IPv6 loopback) on dual-stack Linux → either a bind failure or an IPv6 bind that violates COMP-4/AD-19. Loopback-only is also the sole /metrics authentication (AD-19). Overlaps OBS-004 (the binding assertion) — DEPLOY-011 owns the Inet4Address class angle.

**DEPLOY-012** — Outbound egress to the SMSC and IdP connects over IPv4 (Inet4Address) even when the hostname has AAAA records
Level: integration · Priority: P2 · Risks: R36 · NFR: COMP-4
- Technique: dual-stack mock resolver + outbound remote-address class assertion (preferIPv4Stack).
- Tooling: JUnit5 + mock SMSC and mock IdP hostnames resolving to BOTH A and AAAA records; assert -Djava.net.preferIPv4Stack=true is present (both shapes) and the connected Channel.remoteAddress() InetAddress is an Inet4Address for both egress targets.
- Notes: COMP-4 egress side. A dual-stack hostname whose AAAA is tried first yields an IPv6 connect (violates IPv4-only). Enforce via preferIPv4Stack (parity across shapes — folds into the JVM-args introspection family of DEPLOY-003/004) plus a behavioral remote-address assertion.

**DEPLOY-013** — Build and packaged smoke pass on BOTH x86 (amd64) and ARM (arm64) CI runners
Level: e2e · Priority: P2 · Risks: R36 · NFR: COMP-3, COMP-1
- Technique: CI architecture matrix (build + packaged smoke per arch).
- Tooling: CI matrix on amd64 and arm64 native runners (or QEMU cross-build with native smoke where feasible): Gradle build + jlink/Docker image build + a packaged bind->splice smoke on each arch; assert the arch-correct Epoll classifier loads on each (links to DEPLOY-002).
- Notes: COMP-3 = Linux x86/ARM only. Catches the ARM Epoll-classifier omission and any arch-specific JNI/native assumption. Runtime backstop for DEPLOY-002's static arch scan. Prefer native arm64 runners (QEMU can mask native perf behavior). Weekly/manual tier.

**DEPLOY-014** — Gradle toolchain pins the exact JDK 25 build and the build refuses/warns off-pin (R9 build-pin)
Level: integration · Priority: P2 · Risks: R36, R9 · NFR: COMP-2
- Technique: Gradle javaToolchains + JavaVersion pin assertion CI gate.
- Tooling: Gradle buildsrc/failure build assertion: toolchain resolves to JDK 25 (vendor+version pin, e.g. exact 25.0.x), and a build-time task fails (or a loud CI gate trips) if LanguageVersion or vendor diverges from the pin; fence --enable-preview/STS preview shape to the pinned build.
- Notes: The build-pin that backs R9 (STS preview-API drift across JDK 25 builds) and the COMP-2 JDK-25 floor. Without it, a CI runner with a different JDK 25 build can silently change STS preview semantics process-wide. Positive control = SEC-099 (applies to the CVE gate family). Pin the exact build, not just the major version.

---

## 7. PERF — Performance, resource & methodology

Owns R6 (targets unmet/overclaimed — methodology IS the bar), R25 (load-gen coordinated omission / open-vs-closed model), R26 (JMH harness pitfalls), R27 (direct-memory budget — shared with RELAY), R28 (event-loop blocking — shared with RELAY), R29 (bind-rate ceiling hidden by mock IdP), R30 (GC/backpressure cliffs). The from-scratch open-model harness is itself a deliverable (Epic 6) with explicit methodology gates. PERF-041 and PERF-042 were merged into RELAY-015 / RELAY-017 (see §9).

### 7.1 Codec JMH microbenchmarks (R26, PERF-4)

**PERF-001** — JMH submit_sm encode hits 3e5-1.5e6 ops/s/core band with result Blackholed
Level: perf · Priority: P1 · Risks: R26 · NFR: PERF-4
- Technique: JMH @Benchmark (AverageTime ns/op + Throughput ops/s/core) on codec submit_sm encode; spec-derived golden-vector input (oracle-independent, not mock-derived); Blackhole the encoded ByteBuf to defeat DCE; Fork>=2, warmup to convergence; @State thread-local input so no allocation enters the measured path. Assert band 3e5-1.5e6.
- Tooling: JMH (JDK 25 --enable-preview); codec module isolated (zero proxy deps, AD-7); -prof gc; golden-vector corpus.
- Notes: Lower PERF-4 band. Conflating this codec-only single-core number with relay msg/s is the #1 overclaim trap; label strictly codec-capability no-I/O. Golden-vector inputs (blind-spot 1).

**PERF-002** — JMH submit_sm decode hits 5e5-1.8e6 ops/s/core band with decoded object Blackholed
Level: perf · Priority: P1 · Risks: R26 · NFR: PERF-4
- Technique: JMH @Benchmark on codec submit_sm decode from a golden-vector framed ByteBuf; Blackhole decoded PDU + every field read to defeat DCE; Fork>=2, warmup-to-convergence, thread-local @State. Assert higher band 5e5-1.8e6 ops/s/core. Report ns/op + ops/s/core.
- Tooling: JMH; codec isolation; -prof gc; golden-vector corpus.
- Notes: Post-couple object codec is dormant (AD-2) so this is the capability bench, not relay hot path (that is PERF-003 framing).

**PERF-003** — JMH SmppFrameDecoder throughput characterized as the every-PDU hot path
Level: perf · Priority: P2 · Risks: R26 · NFR: PERF-4
- Technique: JMH @Benchmark on SmppFrameDecoder.decode over a stream of framed submit_sm bytes; Blackhole emitted ByteBuf; report frames/s/core. This framer stays live post-couple (AD-2) on every PDU on both legs.
- Tooling: JMH; codec module; golden-vector byte streams.
- Notes: Framing is the more-exposed surface (runs per-PDU for connection lifetime); perf characterization complements the R3 fuzz coverage.

**PERF-004** — JMH -prof gc confirms per-op allocation is controlled (no GC interference invalidates the codec bench)
Level: perf · Priority: P1 · Risks: R26 · NFR: PERF-4
- Technique: Run PERF-001/002 with -prof gc; assert per-op allocation is the single expected framed ByteBuf (no scratch heap objects per encode/decode); GC pauses in the measurement window negligible. Per-iteration @State setup isolates input construction from the measured path.
- Tooling: JMH -prof gc; allocation tracking.
- Notes: Catches the R26 pitfall where per-op allocation inflates or misrepresents the codec number; underpins PERF-001/002 credibility.

**PERF-005** — JMH fork-to-fork variance within tolerance proves the codec number is not harness noise
Level: perf · Priority: P2 · Risks: R26 · NFR: PERF-4
- Technique: Multiple JMH forks; assert coefficient of variation across forks below threshold (e.g. <5%) and warmup iterations converged. Validates the harness methodology, not just the headline number.
- Tooling: JMH.
- Notes: Guards the bench-credibility slice of R26 (warmup/fork adequacy).

**PERF-006** — UNIT: codec encode/decode produces exactly one framed ByteBuf per PDU (no hot-path heap scratch)
Level: unit · Priority: P2 · Risks: R26 · NFR: PERF-4
- Technique: Fast UNIT test (no JMH) wrapping the allocator with a counting delegate; assert encode yields exactly one framed ByteBuf (the AD-2 splice unit) and zero scratch heap buffers; decode does not retain extra buffers. Regression guard that PERF-004 allocation assumptions hold.
- Tooling: JUnit5 + AssertJ; test-only counting ByteBufAllocator delegating to pooled allocator.
- Notes: Satisfies prefer-PERF-but-some-UNIT-for-codec; codec purity seam (AD-7) makes this instant and isolated.

### 7.2 PERF-1 relay throughput (R6/R25, open-model harness)

**PERF-010** — Open-model load harness on separate pinned cores passes the coordinated-omission check
Level: perf · Priority: P1 · Risks: R25, R6 · NFR: PERF-1
- Technique: Load-gen drives submit_sm at a fixed offered rate via an independent scheduler (open model, not closed-loop req/resp gating); load-gen pinned via taskset/cpuset to cores disjoint from the proxy event-loop cores. Coordinated-omission check: inject a known 50ms mock-SMSC pause mid-run and assert it shows in p99.9 (a closed-loop harness would hide it); contrast run closed-model to expose the delta.
- Tooling: Custom open-model load harness (Epic-6 deliverable); in-JVM mock SMSC with injectable delay; taskset/cpuset.
- Notes: Core R25 scenario. The from-scratch harness has no reference, so the injected-pause check IS the no-coordinated-omission proof.

**PERF-011** — Sustained ≥10K submit_sm/s at mTLS both legs publishes p50/p90/p99/p99.9 table
Level: perf · Priority: P1 · Risks: R6, R25 · NFR: PERF-1
- Technique: Open-model harness (PERF-010); pre-bind N pairs with JWKS warm and verdicts adjudicated BEFORE the measurement window (no verdict cache, AD-12); sustain ≥10K submit_sm/s over a defined window; collect per-PDU end-to-end latency; publish p50/p90/p99/p99.9. TLS 1.3 mTLS both legs; single instance.
- Tooling: Open-model harness; in-JVM mock SMSC; TLS 1.3 both legs; JFR.
- Notes: The headline PERF-1 number. The percentile table (not a peak) is the deliverable.

**PERF-012** — Stretch ~25K submit_sm/s attempted; saturation knee reported if not reached
Level: perf · Priority: P2 · Risks: R6 · NFR: PERF-1
- Technique: Same harness; sweep offered rate toward 25K; report achieved sustained rate + the knee (offered rate where latency goes nonlinear). No 25K claim without the percentile table + knee.
- Tooling: Open-model harness.
- Notes: Stretch target; honest-ceiling band per anchors is 10K-25K end-to-end. >25K without a published harness reads as overreach.

**PERF-013** — No-crypto baseline (TLS off both legs) with same harness/payloads attributes relay-vs-crypto cost
Level: perf · Priority: P1 · Risks: R6 · NFR: PERF-1
- Technique: Re-run PERF-011 harness with SslHandler removed on both legs (or NULL cipher), identical payloads and offered rate; throughput/latency delta = crypto cost. Publish baseline alongside the mTLS number; same load-gen cores, same mock SMSC.
- Tooling: Open-model harness in no-TLS config; in-JVM mock SMSC.
- Notes: Methodology bar (R6): the only way to attribute relay cost vs crypto cost since no published mTLS-vs-plaintext JVM-SMPP delta exists.

**PERF-014** — Payload-corner sweep: 180B GSM-7, UCS-2 single, 3-segment UDH burst p99 each
Level: perf · Priority: P2 · Risks: R6 · NFR: PERF-1
- Technique: Parametrized over the three PDU-size corners from the perf anchors; run PERF-011 harness per corner; report p99 for each. 3-segment UDH = 3 submit_sm per message burst.
- Tooling: Open-model harness; parametrized payload fixtures (golden-vector-derived).
- Notes: No published payload-size-sensitivity data for any JVM SMPP stack; self-measured. Three corners, one parametrized scenario.

**PERF-015** — PERF-1 OIDC-cached resolved: JWKS warm + verdict NOT cached (AD-12); bind-rate reported separately
Level: perf · Priority: P1 · Risks: R6, R29 · NFR: PERF-1, PERF-3
- Technique: Assert harness warms JWKS pre-measurement, establishes binds BEFORE the submit_sm window (no adjudication during the run), and does NOT cache verdicts (each bind re-adjudicates per AD-12 — proven directly by SEC-094). Bind-rate (adjudications/s) measured and reported as a SEPARATE metric, never conflated with submit_sm throughput.
- Tooling: Open-model harness; instrumented fake BindCredentialVerifier counting adjudications; warm-JWKS fixture.
- Notes: Resolves the PERF-1 OIDC-cached ambiguity: cached = JWKS, NOT verdict. Mis-reading this would silently inflate PERF-1. The no-verdict-cache assertion is now also a focused unit (SEC-094).

**PERF-016** — Saturation knee found and failure modes reported (drop/OOM/backpressure/TLS-exec saturation)
Level: perf · Priority: P1 · Risks: R6, R30 · NFR: PERF-1, REL-2
- Technique: Sweep offered rate 5K to beyond knee; identify latency-inflection knee; at/beyond knee report WHICH failure mode manifests first (PDU drop via SpliceObserver, OOM, AUTO_READ backpressure re-arm, SslHandler delegated-task exec saturation AD-28, GC thrash). Failure modes reported, not hidden.
- Tooling: Open-model harness; SpliceObserver capturing observer; ByteBufAllocatorMetric; JFR.
- Notes: Methodology gate (R6): no peak number is credible without its knee + failure mode.

**PERF-017** — Per-PDU added relay latency p99 <1ms vs zero-latency mock SMSC
Level: perf · Priority: P1 · Risks: R6 · NFR: PERF-4
- Technique: Zero-processing-latency mock SMSC (echoes submit_sm_resp immediately); measure relay added per-PDU latency (ingress-arrival to egress-departure via injected timestamp/SpliceObserver seam); p99 < 1ms. Isolates relay cost from SMSC round-trip which dominates real latency.
- Tooling: Single-connection micro-harness or open-model; zero-latency in-JVM mock SMSC; injectable timestamp seam.
- Notes: PERF-4 relay component. Do NOT promise sub-ms bind latency (bind = TLS+OIDC, RTT-bound); only steady-state per-PDU is sub-ms.

### 7.3 PERF-2 idle-pair resource demo (R6)

**PERF-020** — 10K idle socket pairs held in <1GB heap / <1 vCPU idle with full environment disclosure
Level: perf · Priority: P1 · Risks: R6 · NFR: PERF-2
- Technique: Establish 10K bound ESME-proxy-SMSC pairs (~20K sockets) on loopback; let GC settle; measure JVM heap (MemoryMXBean), RSS (/proc/pid/status VmRSS), idle CPU% over a sustained idle window. Disclose HW model/cores/RAM, JDK distro+exact build, host rebooted before run, sysctl (fs.nr_open, net.core.somaxconn, SO_RCVBUF/SO_SNDBUF). Highest overclaim risk.
- Tooling: Idle-pair harness (mock SMSC + N loopback ESMEs via codec/jSMPP); /proc reader; MemoryMXBean; JFR.
- Notes: Highest overclaim risk; no number without disclosure. 20K sockets is under the 65K ephemeral-port ceiling so a single loopback IP suffices.

**PERF-021** — Idle-pair measurement methodology + 1K/2K/5K/10K linearity ramp
Level: perf · Priority: P2 · Risks: R6 · NFR: PERF-2
- Technique: Define protocol: explicit GC-settle wait, RSS sampled at multiple post-settle points, idle-CPU integrated over a window (not instantaneous). Ramp 1K/2K/5K/10K pairs; plot heap/RSS vs pair count; assert near-linear (nonlinear jump = per-pair fixed overhead like a leaked thread or per-channel allocator = defect signal).
- Tooling: Idle-pair harness; MemoryMXBean; /proc VmRSS sampler.
- Notes: Linearity is a defect detector, not just a number; a nonlinear jump reveals a leak the headline 10K figure could hide.

### 7.4 PERF-3 bind latency (R6/R29, injectable clock)

**PERF-030** — Warm bind p99 ~250ms with co-located mock IdP and warm JWKS via injectable clock
Level: perf · Priority: P1 · Risks: R29, R6 · NFR: PERF-3
- Technique: Bind-latency harness with a fake BindCredentialVerifier returning Allow after a configurable mock-IdP delay (0-RTT co-located); JWKS warm; injectable Clock for deterministic timestamps. Measure bind-arrival-to-bind_resp-ROK p99; assert ≤250ms. Injectable clock removes wall-clock variance.
- Tooling: Bind-latency harness; fake BindCredentialVerifier; injected Clock; warm-JWKS fixture.
- Notes: Injectable Clock seam mandatory (testability concern 2); no Thread.sleep in the measurement.

**PERF-031** — Cold-path bind p99 ≤2s on first bind after cold JWKS fetch (injectable clock)
Level: perf · Priority: P1 · Risks: R6 · NFR: PERF-3
- Technique: Clear JWKS cache; issue a bind; cold JWKS fetch delay injected via Clock/scheduler (deterministic); assert bind completes (ROK after adjudication) within ≤2s p99. Validates the cold-path allowance.
- Tooling: Bind-latency harness; injected Clock; cold-JWKS fixture.
- Notes: Cold path = first bind after rotation or cross-region IdP; deterministic via injected clock.

**PERF-032** — Fail-closed DENY returns DenyIndeterminate within 2-5s via injectable clock past deadline
Level: perf · Priority: P1 · Risks: R6 · NFR: PERF-3
- Technique: Fake BindCredentialVerifier that never resolves (simulates IdP timeout/network error); injectable Clock advances past the configured ROPC deadline; assert Verdict.DenyIndeterminate returned within [2s,5s] and the bind denied (no accept-on-indeterminate). Deterministic; no Thread.sleep.
- Tooling: Bind-latency harness; injected Clock; fake never-resolving BindCredentialVerifier.
- Notes: PERF-3 timing of the DENY path; the ~15-branch fail-closed enumeration (R1) is owned by SEC, this validates only the 2-5s latency.

**PERF-033** — Real-Keycloak bind-rate published as the one external-IdP number (~15 logins/s/vCPU reference)
Level: perf · Priority: P2 · Risks: R29 · NFR: PERF-3
- Technique: Bind-rate harness against a real Keycloak 26.x (Testcontainers-equivalent); measure sustained binds/s (each bind = one ROPC token call + local JWT verify, verdict NOT cached); JWKS warm; report against the ~15 logins/s/vCPU Keycloak anchor. The one published external-IdP number, clearly labeled real-Keycloak.
- Tooling: Real Keycloak 26.x (Testcontainers-equivalent); bind-rate harness; Nimbus JWT verify.
- Notes: R29: mock IdP hides the bind-rate ceiling; only a real Keycloak run yields a credible published number. Nightly tier.

**PERF-034** — Mock-IdP bind-rate explicitly labeled regression-only, never the published ceiling
Level: perf · Priority: P2 · Risks: R29 · NFR: PERF-3
- Technique: The mock-IdP bind-rate (PERF-030 harness, fake verifier) reported in a SEPARATE column labeled mock-IdP regression-only; assert the published report never presents the mock number as the real bind-rate ceiling. Guards R29 (mock hides the ceiling).
- Tooling: Bind-rate harness; report-schema assertion.
- Notes: Report-hygiene gate for R29; ensures the regression-fast mock number cannot masquerade as the external-IdP ceiling.

### 7.5 Direct-memory / backpressure / GC / shutdown perf slices (R27/R30/R28/R11)

**PERF-040** — ByteBufAllocatorMetric usedDirectMemory() stays ≤ MaxDirectMemorySize at the PERF-1 cliff (AD-30 formula)
Level: perf · Priority: P1 · Risks: R27 · NFR: REL-2, PERF-1
- Technique: At the saturation knee (PERF-016), sample ByteBufAllocatorMetric.usedDirectMemory(); assert it stays within the AD-30-derived MaxDirectMemorySize budget (max_frame x max_inbound_depth x concurrent_pairs x safety_factor). The cliff is the stress point where the named formula is validated.
- Tooling: Open-model harness at knee; ByteBufAllocatorMetric; PooledByteBufAllocator (AD-21).
- Notes: Validates the one named formula (AD-30) so codec max and allocator budget cannot drift. Compile-time shared-constant guard = RELAY-026. R27 perf-measurement slice. (PERF-041/042 merged into RELAY-015/017.)

**PERF-050** — ZGC worst-case pause at PERF-1 offered rate characterized via JFR
Level: perf · Priority: P2 · Risks: R30 · NFR: PERF-1
- Technique: Run PERF-011 with JFR recording (generational ZGC flags); extract max GC pause from JFR/ZGC log; report worst-case pause at the offered rate. Characterization (no locked pause NFR) feeding the disclosure.
- Tooling: JFR (jdk.GCPhasePause events); generational ZGC (-XX:+UseZGC); JMC/JFR parser.
- Notes: No published ZGC-under-SMPP-relay pause figure; self-measured and labeled as such.

**PERF-051** — ZGC cycle frequency and allocation-rate ceiling characterized across offered rates
Level: perf · Priority: P2 · Risks: R30 · NFR: PERF-1
- Technique: Sweep offered rate 5K to knee; record GC cycle frequency and allocation rate (ByteBufAllocatorMetric + JFR); identify the allocation rate where ZGC can no longer keep up (pause-frequency cliff). Characterizes the GC backstop to the relay ceiling.
- Tooling: JFR; ByteBufAllocatorMetric; open-model harness.
- Notes: Feeds the saturation-knee story (PERF-016); separates GC-cliff from backpressure-knee.

**PERF-052** — Oscillating load across the backpressure knee: no OOM/drop/dup/corrupt + delay-injection/race
Level: perf · Priority: P2 · Risks: R30, R27 · NFR: REL-1, REL-2
- Technique: Oscillate offered rate across the knee (below/above/below) with injected egress jitter/delay and randomized channelInvalid events (race-fuzz flavor); assert transit integrity (no drop/dup/corrupt via sequence-numbered payloads + SpliceObserver), no OOM; report failure modes at each crossing. Delay-injection addresses blind-spot 2.
- Tooling: Open-model harness with jitter + delay-injection + randomized-channelInvalid; sequence-numbered payloads; SpliceObserver capturing observer.
- Notes: Soak is throughput-oriented by default; this adds the race/jitter axis blind-spot 2 calls out. R5 concurrency defects are the RELAY owner's; this is the perf-thrash slice.

**PERF-060** — BlockHound on Netty event-loop threads asserts zero blocking during PERF-1; tail uncorrelated
Level: perf · Priority: P2 · Risks: R28 · NFR: PERF-1
- Technique: Install BlockHound with allowed-blocking configured for the event-loop thread-name pattern; run PERF-011; assert no disallowed blocking call fires on event-loop threads; cross-check that any p99.9 spike is NOT explained by a blocking event. JFR catches VT pinning only; BlockHound catches platform-thread event-loop stalls (blind-spot 3).
- Tooling: BlockHound; JFR; open-model harness.
- Notes: R28 perf-measurement slice (correlating blocking with tail). The primary no-blocking-on-event-loop assertion is RELAY-019 (convention-enforced); this is the under-load measurement backstop.

**PERF-061** — Graceful shutdown under PERF-1 offered rate drains within Spring timeout with no in-flight drop
Level: perf · Priority: P2 · Risks: R11 · NFR: REL-3, PERF-1
- Technique: At sustained PERF-1 rate, send SIGTERM; assert the AD-22 7-step drain completes within Spring graceful-shutdown timeout; assert no in-flight submit_sm dropped post-SIGTERM (sequence-numbered payloads + SpliceObserver). Perf-measurement slice of R11.
- Tooling: Open-model harness; SIGTERM injection; SpliceObserver; Spring graceful-shutdown.
- Notes: Duplicate-coverage guard: OBS/RELAY owns AD-22 step-ordering; this measures only drain-time + zero-drop under PERF-1 load.

### 7.6 Methodology / disclosure gates (R6) — the bar

**PERF-070** — Disclosure gate: every perf number tagged with payload + cipher + single-instance + HW/JDK/reboot/sysctl
Level: perf · Priority: P1 · Risks: R6 · NFR: PERF-1, PERF-2, PERF-3, PERF-4
- Technique: Report-schema assertion (parsed perf-report / CI gate) that every throughput, latency, and resource number carries: payload bytes, mTLS cipher (or no-crypto), single-instance qualifier, HW model + core count + RAM, JDK distro + exact build, reboot-confirmed-before-run, sysctl tuning (fs.nr_open, somaxconn, SO_RCVBUF/SO_SNDBUF). Missing tag = gate fail.
- Tooling: Report-schema validator (CI gate); parsed perf-report artifact.
- Notes: The methodology bar (R6). Every self-measured number is labeled self-measured with its conditions; nothing borrowed.

**PERF-071** — Reporting gate: no peak number published without its saturation knee and failure modes
Level: perf · Priority: P1 · Risks: R6, R30 · NFR: PERF-1
- Technique: Report-schema assertion that every sustained-peak throughput number is accompanied by (a) the saturation knee (offered rate at latency inflection) and (b) the failure mode at/beyond the knee. A peak without knee+failure = gate fail (overclaim guard).
- Tooling: Report-schema validator.
- Notes: Complements PERF-016 (which produces the data); this enforces it is published for every number.

---

## 8. E2E — Composed multi-instance end-to-end (critic addition)

**E2E-001** `[critic-fix: ADDED]` — Two-real-proxy-instance (forward↔reverse) composed-flow end-to-end
Level: e2e · Priority: P1 · Risks: R12 · NFR: FR-DEPLOY-1, FR-AUTH-3, COMP-1, FR-TRANSIT-1
- Technique: stand up TWO real proxy instances — a forward instance and a reverse instance — composed as the AD-12 deployment topology (legacy ESME → forward → OIDC adjudication → forward↔reverse Mode C mTLS leg → reverse → SMSC). Drive a full bind→splice→submit_sm→DLR journey end-to-end. Assert: forward adjudicates the bind (fake/real IdP), the forward↔reverse Mode C mTLS leg handshakes, the reverse reaches the SMSC, submit_sm splices through both legs byte-intact, and the DLR returns on the originating pair. Catches integration bugs specific to the two-proxy seam no per-leg test can (e.g. reverse mishandling a bind the forward already adjudicated, or the forward↔reverse Mode C leg).
- Tooling: JUnit5 + two in-JVM proxy instances (forward + reverse) + in-JVM mock SMSC on codec + jSMPP 3.0.2 ESME + fake BindCredentialVerifier + JDK SSLEngine Mode C pair + capturing SpliceObserver + AssertJ.
- Notes: [critic-fix] Closes the two-proxy-seam gap (cross-level issue). AD-12 defines the deployment topology as a two-proxy chain; AD-17 fixes one-instance=one-role. Every relay/SEC scenario uses ONE proxy instance + mock SMSC; DEPLOY-005 runs single-instance. The composed forward↔reverse Mode C leg and the reverse-handling-of-forward-adjudicated-bind path are only exercised here. Also exercises the FR-AUTH-3 per-instance-cert property across two instances (complements SEC-098's static scan). Weekly/manual tier (open question Q4).

---

## 9. Appendices

### 9.1 Deduplication ledger (4 critic decisions; 3 removals, 1 scope-reduction)

| Removed / changed | Merged into / action | Reason | Critic verdict |
|---|---|---|---|
| **RELAY-016** (write-failure → peer teardown + autoRead disarmed) | folded into **RELAY-017**'s error+churn matrix; the autoRead-disarmed-on-write-failure assertion is retained as one matrix cell | The write-failure teardown cell was triplicated (RELAY-010 wire/RST/observability, RELAY-016 lifecycle/read-arming, RELAY-017 PARANOID ref-count). RELAY-010 (conformance, wire) and RELAY-017 (full error-matrix ref-count integrity under PARANOID) are the lowest-sufficient levels. | Keep RELAY-010 + RELAY-017; fold RELAY-016. |
| **PERF-041** (slow egress + correlated ingress burst, perf) | merged into **RELAY-015** (same-level slow-egress burst); PERF-041's only distinct slice (explicit ByteBufAllocatorMetric budget-not-exceeded assertion) is now part of RELAY-015 | Both LEVEL=perf on the identical fault (stall egress, flood ingress at PERF-1, assert AUTO_READ trips + memory bounded). Same-level redundancy, not lower-vs-higher defense-in-depth. | Keep RELAY-015 (named R27 correlated-burst seam); drop PERF-041. |
| **PERF-042** (egress write failure → metric baseline + PARANOID, perf) | merged into **RELAY-017** (integration, LOWER level) error+churn matrix; PERF-042's 'metric returns to baseline' assertion folded into RELAY-017 | PERF-042's write-failure cell is a subset of RELAY-017's matrix at a higher level. | Keep RELAY-017 (lower level, broader error matrix); drop PERF-042. |
| **OBS-015** (e2e SIGTERM drain, scope-REDUCED not removed) | kept ONLY for the e2e packaging / process-exit-within-timeout aspect; its re-assertion of splice zero-drop was DROPPED (owned by RELAY-022) | Both asserted in-flight submit_sm drain with zero drop/dup within timeout. OBS-015 is needed for Epic-5 packaged-shape acceptance, but its drain-correctness assertion duplicated RELAY-022's isolated relay-drain invariant. | Keep RELAY-022 for the invariant; keep OBS-015 only for packaging/process-exit. |

### 9.2 Open questions / pre-implementation blockers (architecture must resolve before the owning epic's exit)

- **Q1 — Pre-couple non-bind PDU policy** ✅ RESOLVED → **AD-32** (close + matching `_resp` `ESME_RINVBNDSTS` 0x4; carve-outs for `unbind`/`enquire_link`/egress-`generic_nack`; zero knobs). RELAY-002 rewritten + RELAY-002a/b/c siblings added.
- **Q2 — jcstress adoption** ✅ RESOLVED → **AD-24 note** (jcstress on cross-thread state, nightly + delay-injection soak). P0 R5 holds.
- **Q3 — Cipher allowlist pin** ✅ RESOLVED → **AD-34** (ECDHE-AES-GCM default, `companion.tls.*`, fail-fast). SEC-089 + OBS-032 unblocked.
- **Q4 — Two-proxy E2E** ✅ RESOLVED → **AD-24 note** (E2E-001 weekly tier; also validates DEP-1).
- **Q5 — AD-30 shared-constant assertion** ✅ RESOLVED → **AD-30 amendment** (ArchUnit one-constant + startup `ByteBufAllocatorMetric` self-check).
- **Q6 — CI-gate positive controls** ✅ RESOLVED (per-gate known-bad fixture + assert-it-fires, CI tier).
- **Q7 — bind_resp status→OIDC-outcome mapping** ✅ RESOLVED → **AD-33** (binary wire collapse; exact code per owning story). SEC-078..080 unblocked.

### 9.3 Coverage core — the 18 P0/P1 risks and their primary owning scenarios

Every one of the 18 mandatory-coverage risks (risk_threshold = p1) has ≥1 explicit scenario. P0 risks in bold.

| Risk | Priority | Primary scenario evidence |
|------|----------|---------------------------|
| **R1** (fail-closed branch miss) | P0 | SEC-001..027 (ROPC + JWT), SEC-013..019 + **SEC-093** (introspection), SEC-092 (timeout), SEC-094 (no-verdict-cache) |
| **R2** (ROPC/IdP outage) | P0 | SEC-028..032 (real Keycloak, viability probe + fallback tree) |
| **R5** (concurrency → REL-1) | P0 | RELAY-001..011,024 (5 decomposed seams) + race-soak |
| **R7** (trust anchoring) | P0 | SEC-033..041 (cacerts-default-is-insecure, REQUIRE-vs-WANT, cert edges), SEC-098 (FR-AUTH-3 no-shared-golden-key) |
| **R8** (credential-free / zeroization) | P0 | SEC-042..049, SEC-095 (client_secret) |
| R3 (parser/framing DoS) | P1 | CODEC-005..011/025/033, CODEC-013..015 |
| R6 (PERF overclaim) | P1 | PERF-010..017/070/071 (methodology gates) |
| R11 (graceful shutdown) | P1 | OBS-015..021, RELAY-022/023 |
| R12 (two-shape parity) | P1 | DEPLOY-001..005, E2E-001 |
| R14 (codec diverges) | P1 | CODEC-016..033, CODEC-039..041 |
| R16 (CVE/dep drift) | P1 | SEC-091/SEC-099 (CVE gate + positive control) |
| R17 (startup fail-fast) | P1 | SEC-050..061, SEC-096/097 (role×mode cells) |
| R18 (Mode A ACL isolation) | P1 | SEC-063..066, OBS-034 |
| R25 (coordinated omission) | P1 | PERF-010 (open-model + injected-pause check) |
| R26 (JMH pitfalls) | P1 | PERF-001..006 |
| R27 (direct-memory budget) | P1 | RELAY-013/015/017/026, PERF-040 |
| R28 (event-loop blocking) | P1 | RELAY-018/019 (BlockHound + control), PERF-060 |
| R33 (sole-oracle → golden vector) | P1 | CODEC-030/031/033 (3rd oracle + jSMPP agreement) |

### 9.4 Testability boundaries (inherited from Step 3; recorded for implementers)

- **Injectable Clock does NOT cover TLS cert-path validation.** The seam covers JWT exp/nbf (SEC-023/024), ROPC/introspection timeouts (SEC-009/018, PERF-030..032), and shutdown drain windows (OBS-020). It does NOT cover TLS notAfter — SSLEngine uses the system clock and `PKIXBuilderParameters.setDate` is banned by AD-13. SEC-037 uses a genuinely already-expired cert instead.
- **A-1 is unfalsifiable in CI.** The in-JVM mock SMSC EMULATES A-1 (assumes it); the only genuine A-1 gate is the non-CI real-carrier ops plan (OBS-035..038). OBS-038 (jSMPP server-side mock) is the strongest CI approximation.
- **Zeroization is deterministically evidenced only by SEC-046** (same-reference char[] all-'\0' immediately after the zeroize call). SEC-048/049 are best-effort fragility guards with inherent false-negative risk.
- **Performance targets are first-of-kind and self-measured** — the methodology (PERF-070/071) and the open-model harness (PERF-010) are themselves the deliverables; no peak number is credible without its saturation knee + failure modes.

---

*End of catalog. 251 scenarios across 7 areas (CODEC 41 · RELAY 25 · SEC 98 · OBS 43 · DEPLOY 14 · PERF 29 · E2E 1). Generated by the BMad TEA testarch-test-design workflow (system-level), Step-5 output.*
