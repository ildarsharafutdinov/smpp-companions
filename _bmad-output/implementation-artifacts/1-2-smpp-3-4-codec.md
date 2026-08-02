---
baseline_commit: 0515c48529a19a3de92ba7db18ab18ef3654df2c
---

# Story 1.2: SMPP 3.4 Codec

Status: done

> Story 1.2 fills the `codec/` module (seeded empty by Story 1.1) with the PURE SMPP 3.4 protocol
> layer: length-framing, bind-family parsing, the `command_id` source-of-truth, a spec-derived
> golden-vector corpus, fuzzing of both decoders, and the JMH microbench anchors. This is TEA
> handoff **E1/S1** — the bottom of the epic DAG; every later epic mounts on it. ADs owned:
> **AD-3, AD-7, AD-24, AD-27, AD-30** (with AD-2, AD-25, AD-32, AD-33, AD-23, AD-35 as constraints).

---

## ⚠️ Read first — spec reconciliation & decisions

Three items below are NOT copy-paste from the planning docs. The dev agent must act on these, not
on the source artifacts where they conflict. **Status: #1 is a spec-error directive (act, don't
ask); #2 (fuzz lib) proceeds on the Jazzer default — confirm at completion; #3 (JMH location) is
RESOLVED pre-dev → `proxy/src/jmh`.**

### 1. SPEC ERROR in CODEC-026 / CODEC-029 — `bind_transceiver` command_id

`_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md:221,241` asserts
`SmppCommandIds.BIND_FAMILY = {0x01,0x02,0x0F,0x80000001,0x80000002,0x8000000F}` — i.e.
`bind_transceiver = 0x0F`. **This is wrong.** Per the authoritative SMPP 3.4 spec (§5.1.2.1) and
jSMPP 3.0.2 (`org.jsmpp.bean.CommandId`, this story's independent oracle for CODEC-031):

| Command | Correct command_id | The doc's wrong value |
|---|---|---|
| `bind_receiver` | `0x00000001` | ✓ matches |
| `bind_transmitter` | `0x00000002` | ✓ matches |
| **`bind_transceiver`** | **`0x00000009`** | ✗ `0x0F` (unassigned in SMPP 3.4; `0x0F` is the `ESME_RINVSYSID` *status* code — likely the typo origin) |
| `bind_receiver_resp` | `0x80000001` | ✓ matches |
| `bind_transmitter_resp` | `0x80000002` | ✓ matches |
| **`bind_transceiver_resp`** | **`0x80000009`** | ✗ `0x8000000F` |

**VERIFIED against the primary source** (`docs/SMPP_v3_4_Issue1_2.pdf`, SMPP 3.4 Issue 1.2, 169pp,
§5.1.2 command_id table, 2026-07-26): the spec lists `bind_transceiver = 0x00000009` /
`bind_transceiver_resp = 0x80000009` — confirms the correction below alongside the jSMPP oracle.

**Implement the correct values** — `BIND_FAMILY = {0x00000001, 0x00000002, 0x00000009, 0x80000001,
0x80000002, 0x80000009}`. The CODEC-031 jSMPP cross-oracle test will **fail** against `0x0F` (jSMPP
decodes transceiver as `0x09`), and real-carrier interop (Epic 2 A-1) would break. The CODEC-026
assertion must use the correct 6-id set. Cross-check: `org.jsmpp.bean.CommandId.BIND_TRANSCEIVER`
in CODEC-031. **Log a one-line correction against `test-coverage-scenarios.md:221,241` in the Dev
Agent Record** so the planning artifact can be fixed upstream.

### 2. DECISION-NEEDED — fuzz library for CODEC-011 / CODEC-025 (JQF vs Jazzer)

The docs disagree: `test-coverage-scenarios.md` names **JQF** (`edu.berkeley.cs.jqf`); the QA example
at `test-design-qa.md:743` uses **Jazzer** (`com.code_intelligence.jaz.api.FuzzTest`). jqwik
(CODEC-012/037/038) is separate and fixed. **This story's recommendation: Jazzer** (more actively
maintained, the JUnit-5 `@FuzzTest` API the QA doc actually uses, works on Gradle 9.6.1 / JUnit 6 /
JDK 25; current API specifics in "Latest tech information" below). Alternative: JQF (better
generator ergonomics for CODEC-025's "valid header + arbitrary body"). Both can fuzz the two
decoders. **Confirm with the user** (decision surfaced at story completion); until then, proceed
with Jazzer. Whichever is chosen: versions are impl-selected, **green build (AC10) is the compat
proof** (same pattern as Story 1.4).

### 3. RESOLVED (pre-dev) — JMH source location → `proxy/src/jmh`

**Decision: JMH lives in a `jmh` sourceSet inside `proxy` (`proxy/src/jmh/java/...`), applied via
`me.champeau.jmh` `0.7.3` in `proxy/build.gradle.kts`. NOT a separate standalone `bench` module.**

Rationale (from a Context7 + adversarial-architect review, 2026-07-26):
- **The "JMH recommends a separate project" premise is backwards for this tooling.** The
  `me.champeau.jmh` plugin's *official* model is a dedicated `jmh` sourceSet *inside the same
  project* — explicitly to AVOID a separate project. Runtime JIT/devirtualization isolation comes
  from JMH's forked JVM + the self-contained `jmhJar` fat JAR, NOT from module separation. The
  "separate project" lore is from the old JMH Maven-archetype workflow.
- **A separate `bench` module would break compilation of every codec benchmark.** codec exposes
  Netty types in its public API (`SmppFrameDecoder extends io.netty…ByteToMessageDecoder`) but
  declares netty as `implementation`, not `api`. Under `java-library`, a separate consumer of
  `project(":codec")` cannot see netty on its compile classpath → every `@Benchmark` touching
  `ByteBuf` (all of PERF-001..006) fails to compile, forcing netty re-declaration + a drift surface.
  `proxy/src/jmh` pays none of this (proxy's main already carries netty onto the jmh classpath).
- **It's a spine deviation with a recurrent tail.** AD-7 fixes the module count at exactly **two**
  in four places (line 63, AD-7, Structural Seed :373, Consistency table :292); line 405 names the
  perf home as "the proxy test module"; AD-35 is worded "applied to BOTH modules." `proxy/src/jmh`
  needs NO spine amendment — line 405's "proxy test module" already covers the JMH sourceSet.
- **It self-destructs when relay benchmarks arrive** (PERF-1..4 span relay + codec, Capability map
  :385); `proxy/src/jmh` scales there with zero restructuring.

The fail-closed consistency argument for a separate module (structural "bench can't import proxy"
boundary, matching CODEC-040's gate-over-ArchUnit philosophy) is real but defeated here: codec has
no implementation-scope library surface for benchmarks to reach, so the isolation dividend is
symbolic. It is purchased instead via the **three hardening adds** below.

**Three hardening adds (load-bearing — implement all three):**
1. **ArchUnit guard** — one-line rule: classes in `..jmh..` may NOT depend on
   `..smpp.companion.proxy..` (relay/security/config). The structural substitute for the module
   boundary. ArchUnit is already a project testImplementation.
2. **Widen the null-safety predicate** (`buildSrc/.../smpp.null-safety.gradle.kts:37`) to
   `name == "compileJava" || name == "compileJmhJava"` — the fail-closed option the file's own
   comment prescribes. Zero collateral (no `compileJmhJava` task exists in codec); benchmark
   classes must be JSpecify-clean under `smpp.companion.*`.
3. **Smoke-test `./gradlew jmh`** on Gradle 9.6.1 / JDK 25 before commit — the plugin's compat
   table certifies only through Gradle 8.0 and JMH 1.37's ASM is unverified on JDK 25 class files
   (bump `jmh { jmhVersion = ... }` if bytecode generation fails). Keep JMH nightly-tier so a
   breakage cannot fail the PR build.

`me.champeau.jmh`'s `compileJmhJava` task lands in the null-safety gate's `else` branch and
**bypasses NullAway** unless add #2 widens the predicate — see "Null-safety gate + the JMH
sourceSet" below.

---

## Story

**As a** proxy platform engineer,
**I want** a PURE, extractable, conformance-proven and fuzz-hardened SMPP 3.4 codec (length-framing,
bind-family parser, `command_id` source-of-truth, golden-vector oracle, fuzz, JMH anchors),
**so that** every later epic (relay, TLS/OIDC, ops) mounts on a correct, fast, dependency-pure
protocol layer whose conformance is falsifiable by an independent oracle rather than by the codec's
own author.

---

## Acceptance Criteria

ACs are grouped; each maps to the TEA scenario IDs (`CODEC-0xx`, `PERF-0xx`) in
`_bmad-output/test-artifacts/test-design/test-coverage-scenarios.md`, which carry the full
technique/tooling/notes for each. Implement every mapped scenario.

### AC1 — `SmppFrameDecoder`: length-framing (AD-7, AD-2, AD-30)
A custom Netty decoder produces **one framed `ByteBuf` per PDU** on both legs, generic to every PDU,
reassembling across arbitrary TCP segmentation/coalescing. Enforces AD-30 bounds.
- Reject `command_length < 16` (drop + close). Maps: CODEC-005.
- Drop + close on `command_length > 65536`; `== 65536` accepted, `65537` rejected (off-by-one). Maps: CODEC-006, CODEC-008.
- `== 16` (header-only PDU) accepted. Maps: CODEC-007.
- **Pre-allocation overflow guard**: `0x7FFFFFFF`, `0x80000000`, `0xFFFFFFFF` must NOT cause an
  allocation, OOM, or arithmetic wrap — reject before any `ByteBuf` allocation. Maps: **CODEC-010** (load-bearing).
- Single-read one-PDU; header-split reassembly; coalesced N-PDU decode; partial-at-close emits no
  truncated frame; wait-on-partial. Maps: CODEC-001..004, CODEC-009.
- Exception containment (no Throwable escapes decode → channel closed, not crashed) + per-channel
  isolation + retain/release correctness. Maps: CODEC-013..015.
- **Over a real loopback TCP socket pair** (NOT `ByteBuf` slices): split at every byte boundary
  reassembles one correct frame (CODEC-034); interleaved multi-PDU + partials reassemble in order
  (CODEC-035); writer closes mid-PDU → no truncated frame, clean close (CODEC-036).

### AC2 — `SmppCodec`: bind-family parser (AD-7, AD-25, AD-12)
Parses **only** the bind family from a framed `ByteBuf` into typed objects; every non-bind PDU is
opaque (untouched `ByteBuf`). Exposes header `command_id`/`command_status`/`sequence_number` +
`system_id`, `password`, `system_type`, `interface_version`.
- Decode golden `bind_transceiver` (all fields), `bind_transmitter`, `bind_receiver`. Maps: CODEC-016, CODEC-017.
- `command_status == ESME_ROK` predicate on `bind_*_resp` (the AD-25 flip trigger); non-ROK
  `bind_*_resp` (e.g. `ESME_RINVPASWD 0x0000000E`) decodes cleanly without raising — **assuming a `system_id`-bearing response (SMPP §4.1.4.2 lists `system_id` mandatory)**; a header-only denial (no body — a shape some SMSCs send) is rejected + closed as fail-closed (T3 review 2026-07-29: strict reject chosen over graceful empty-body decode). Maps: CODEC-018, CODEC-019.
- C-octet-string edge cases (empty / max-length / all-empty); unterminated C-octet-string → no
  over-read / no spin; truncated body → no AIOOBE / no negative-size; header decodes even with junk body. Maps: CODEC-020..023.
- **Password exposed as `AsciiString`** (revises the original `char[]`/`byte[]` clause — user-directed
  2026-07-28 override for C-octet type-uniformity; zeroization via `AsciiString.array()` is fragile due to
  the `toString()` cache, so the deeper "no `String` from password" guarantee is deferred to CODEC-024 P2;
  CODEC-024, PRIV-1).
- **Byte-exact forwarding**: after parsing a bind request the original framed `ByteBuf` is
  byte-identical and un-mutated (reader index restored; parser reads a slice/copy). This is a
  **security** property — the ORIGINAL bind is relayed to the SMSC (AD-12). Maps: CODEC-037.

### AC3 — `SmppCommandIds.BIND_FAMILY`: single source-of-truth (AD-27, AD-3)
- `BIND_FAMILY` is **exactly the 6 correct ids** `{0x00000001, 0x00000002, 0x00000009, 0x80000001,
  0x80000002, 0x80000009}` (see spec reconciliation #1). Maps: CODEC-026.
- `outbind (0x0000000B)` and `generic_nack (0x80000000)` are NOT members → opaque-spliced. Maps: CODEC-027.
- Non-bind command_ids (`submit_sm`, `deliver_sm`, `enquire_link`, `unbind`) not parsed → opaque. Maps: CODEC-028.
- Response bit (bit 31 / `0x80000000`) distinguishes request from `_resp`; both bind-family. Maps: CODEC-029.
- Opaque PDUs forward byte-identical with no decode/re-serialize path (jqwik property). Maps: CODEC-038.

### AC4 — AD-30 max constant + framing reject
- One named codec constant `MAX_COMMAND_LENGTH = 65536` (covers `message_payload` TLV max). The
  framer's drop+close policy (AC1) references it.
- Ship a **RELAY-026 stub test** documenting the three-way contract (codec constant ≡ future formula
  input ≡ future config default all reference ONE constant). The full assertion lands in Story 1.3
  when the config key exists; log the remainder to `deferred-work.md`. Do **not** compute
  `MaxDirectMemorySize` and do **not** add config keys (Story 1.3 owns them).

### AC5 — Spec-derived golden-vector corpus (the 3rd oracle) (CODEC-030, CODEC-033)
- Populate `codec/src/test/resources/golden-vectors/` with **hand-authored-from-the-spec** bind-family
  vectors (`.bin`/`.smpp`), each carrying the first-line provenance header
  `# provenance: <SMPP 3.4 §section> ; raw-hex: <lowercase hex>`. Must be authored independently of
  the codec (a test fails if any vector was generated by invoking the codec).
- Add **negative vectors** (truncated header, length<16, length>65536, unterminated string,
  body-shorter-than-fields) each tagged with its expected reject outcome.
- **Promote** `GoldenVectorCorpusTest.corpusScaffoldIsInPlace_nonEmptyAssertionDeferredToStory1_2`
  to a real `assertThat(count).isGreaterThan(0)` + per-vector provenance assertion. **Fold in the
  deferred `StringCaseLocaleUsage` fix** at the golden-vector loader (`GoldenVectors.java` — the
  `.toLowerCase()` → `.toLowerCase(Locale.ROOT)` extension filter; was `GoldenVectorCorpusTest.java:67`
  pre-refactor) and clear that entry in `deferred-work.md`.

### AC6 — Independent-oracle conformance (CODEC-031, CODEC-032)
- Declare `org.jsmpp:jsmpp:3.0.2` as **`testImplementation` on `codec`** (NOT 2.3.11; interop-only,
  never production). For each golden bind-family vector: codec decode == jSMPP decode field-by-field.
- Encode→bytes round-trip: a typed bind object encoded by the codec produces bytes byte-identical to
  the golden vector (needs a bind-family **encoder**). (Requires the encoder; this story ships it.)

### AC7 — Fuzzing both decoders (AD-24) (CODEC-011, CODEC-012, CODEC-025, CODEC-037, CODEC-038)
- Fuzz `SmppFrameDecoder` over arbitrary byte streams: no Throwable escapes decode, total allocated
  bytes ≤ cap × small factor, channel closed on oversize. Maps: CODEC-011.
- Fuzz the bind parser over framed buffers (valid 16-byte header with a bind-family command_id +
  arbitrary body): no Throwable, reader index never exceeds frame length, bounded decode time. Maps: CODEC-025.
- jqwik properties: any chunking reassembles identically (CODEC-012); byte-exact bind forwarding
  (CODEC-037); opaque forward byte-identity (CODEC-038). (Library: per decision-needed #2, default Jazzer for the fuzz scenarios + jqwik for the properties.)
- PR tier runs bounded/time-boxed fuzz; full-corpus expansion is a nightly concern (wire the tag,
  don't block the build).

### AC8 — JMH codec microbench (PERF anchors) (PERF-001..006)
- `submit_sm` **encode** in `3×10⁵–1.5×10⁶ ops/s/core` (result Blackholed); **decode** in
  `5×10⁵–1.8×10⁶ ops/s/core` (decoded object + every field Blackholed). Input = golden-vector bytes;
  thread-local `@State`; `Fork ≥ 2`; warmup to convergence. Maps: PERF-001, PERF-002.
- `SmppFrameDecoder.decode` throughput characterized as the every-PDU hot path (frames/s/core). Maps: PERF-003.
- `-prof gc` confirms per-op allocation is controlled (no GC interference). Maps: PERF-004.
- Fork-to-fork variance CoV < 5%, warmup converged. Maps: PERF-005.
- **Unit guard**: encode yields exactly one framed `ByteBuf` + zero scratch heap buffers; decode
  retains no extras (counting-allocator delegate). Maps: PERF-006.
- Location **`proxy/src/jmh`** (decision #3 RESOLVED); run via `./gradlew jmh`; nightly tier.
- **Smoke-test `./gradlew jmh`** on Gradle 9.6.1 / JDK 25 before commit (me.champeau.jmh `0.7.3`'s
  compat table certifies only through Gradle 8.0; JMH 1.37's ASM is unverified on JDK 25 class files).
  Bump `jmh { jmhVersion = ... }` if bytecode generation fails; keep JMH nightly-tier so a breakage
  cannot fail the PR build.
- **ArchUnit guard**: benchmark classes (`..jmh..`) may NOT depend on `..smpp.companion.proxy..`
  (decision #3 hardening add #1).

### AC9 — Purity + null-safety gates stay green (CODEC-039, CODEC-040, CODEC-041, AD-35)
- CODEC-039 ArchUnit inward-only rule stays green (now load-bearing — real codec classes exist).
- CODEC-040 allowlist `{io.netty, org.jspecify, org.projectlombok}` stays green on both compile AND
  runtime classpath; jspecify + lombok are `compileOnly` (lombok also `annotationProcessor`) so codec
  RUNTIME stays {io.netty}+JDK. CODEC-041 positive control extended with a symmetric lombok-accepted
  test. _(2026-07-27 amendment, user-directed: `org.projectlombok` admitted to follow the resolved
  `// FIXME: replace with lombok`; compile-time-only → AD-7/AD-27 runtime purity unchanged. See Dev Agent Record.)_
- **Every new codec sub-package gets its own `@NullMarked package-info.java`** (JSpec does not
  propagate to sub-packages — Story 1.4 caught a miss of this kind).
- All codec `compileJava` is NullAway-clean at ERROR severity. Annotate genuinely-nullable types with
  `@org.jspecify.annotations.Nullable`; for Netty call sites of unknown nullness, annotate the call
  site (preferred) or `@SuppressWarnings("NullAway")` + `// reason: …` (last resort).
- No `// FIXME` markers left in source.

### AC10 — Green build proof
`./gradlew clean build :buildSrc:test` is GREEN on JDK 25 + `--enable-preview`. No test removed or
`@Disabled` to make a gate pass. The dev records the command + outcome in the Dev Agent Record.

---

## Tasks / Subtasks

- [x] **T1 — Command-id source-of-truth** (AC3, AC4)
  - [x] `smpp.companion.codec.command.SmppCommandIds` with `BIND_FAMILY` = the correct 6-id set
        (spec reconciliation #1) + `MAX_COMMAND_LENGTH = 65536` (AD-30) + response-bit helpers.
  - [x] `package-info.java` (`@NullMarked`) for the new sub-package.
  - [x] Unit tests: CODEC-026/027/028/029.
  - [x] RELAY-026 stub test (AC4); log remainder to `deferred-work.md`.
- [x] **T2 — `SmppFrameDecoder`** (AC1)
  - [x] `smpp.companion.codec.framer.SmppFrameDecoder extends ByteToMessageDecoder` (NOT
        `LengthFieldBasedFrameDecoder`). Read `command_length` via `in.getInt(in.readerIndex())`;
        honor the ByteToMessageDecoder contract (check `readableBytes()`, return without moving
        reader index when incomplete).
  - [x] AD-30 reject policy: `<16` drop+close; `>65536` drop+close; overflow-class
        (`0x7FFFFFFF`/`0x80000000`/`0xFFFFFFFF`) reject **before** any allocation.
  - [x] `package-info.java` (`@NullMarked`).
  - [x] Unit tests CODEC-001..015 (use Netty `EmbeddedChannel`); real-TCP tests CODEC-034..036.
- [x] **T3 — `SmppCodec` bind parser + PDU model + encoder** (AC2, AC6)
  - [x] `smpp.companion.codec.bind` package: typed bind PDU model (header + `system_id`, `password`
        as `char[]`, `system_type`, `interface_version`), `SmppCodec` (bind branch:
        `MessageToMessageDecoder<ByteBuf>` over a framed `ByteBuf`), `ESME_ROK` predicate,
        non-mutating slice read, and a bind-family **encoder** (for CODEC-032).
  - [x] `package-info.java` (`@NullMarked`).
  - [x] Unit tests CODEC-016..023, CODEC-028, CODEC-037 (+ encoder round-trip).
- [x] **T4 — Golden-vector corpus** (AC5)
  - [x] Author `.bin`/`.smpp` bind-family + negative vectors with provenance headers in
        `codec/src/test/resources/golden-vectors/`.
  - [x] Promote the deferred non-empty assertion; fold in the `Locale.ROOT` fix; clear `deferred-work.md`.
- [x] **T5 — jSMPP cross-oracle conformance** (AC6)
  - [x] `testImplementation("org.jsmpp:jsmpp:3.0.2")` on `codec`; CODEC-031 + CODEC-032 tests.
- [x] **T6 — Fuzz + properties** (AC7)
  - [x] Add fuzz lib (default Jazzer `com.code-intelligence:jazzer-junit`) + jqwik as
        `testImplementation` on `codec`; CODEC-011, CODEC-025, CODEC-012/037/038.
- [x] **T7 — JMH microbench** (AC8)
  - [x] Apply `me.champeau.jmh` (`0.7.3`) in `proxy/build.gradle.kts`; sources at
        `proxy/src/jmh/java/...`; PERF-001..006.
  - [x] Widen the null-safety predicate to `name == "compileJava" || name == "compileJmhJava"`
        (`buildSrc/.../smpp.null-safety.gradle.kts:37`) — decision #3 hardening add #2; keep
        benchmark classes JSpecify-clean under `smpp.companion.*`.
  - [x] Add a one-line ArchUnit rule: classes in `..jmh..` may NOT depend on
        `..smpp.companion.proxy..` — decision #3 hardening add #1.
  - [x] Smoke-test `./gradlew jmh` on Gradle 9.6.1 / JDK 25 (JMH .37 ASM risk); nightly-tier.
- [x] **T8 — Gates green + finalize** (AC9, AC10)
  - [x] Confirm CODEC-039/040/041 + AD-35 green; add `@NullMarked package-info.java` to every new
        sub-package; full `./gradlew clean build :buildSrc:test` green.
  - [x] Record the spec-error correction (reconciliation #1) in the Dev Agent Record.

### Review Findings

_T1 code review (2026-07-27) — 3 parallel adversarial layers (Blind Hunter, Edge Case Hunter, Acceptance Auditor). Verdict: clean — no High/Med defects; spec reconciliation #1 (`bind_transceiver = 0x09`) verified correct against `docs/SMPP_v3_4_Issue1_2.pdf` §5.1.2 (`0x0F` is the `ESME_RINVSYSID` status code, confirming the catalog typo); AC3/AC4 + AD-3/AD-7/AD-27/AD-30/AD-35 all met; CODEC-039/040 gates green. 3 low-severity patches below; 4 items dismissed (redundant hex assertion, harmless class-level `@NullMarked`, `p1` tag verified-correct vs catalog, CODEC-027/028 scope-split already documented)._

- [x] [Review][Patch] Warn the T2 framer in the `MAX_COMMAND_LENGTH` javadoc about the signed-int comparison pitfall — `ByteBuf.getInt` returns a *signed* int, so an overflow-class `command_length` (e.g. `0xFFFFFFFF` = -1) passes a naive `> MAX` check; the AD-30 `< 16` floor is the real guard. [`codec/src/main/java/smpp/companion/codec/command/SmppCommandIds.java:31`]
- [x] [Review][Patch] Add a caveat to `requestIdOf` — it returns `0x00000000` (unassigned) for `generic_nack` (`0x80000000`), which has no underlying request; the current javadoc overpromises. [`codec/src/main/java/smpp/companion/codec/command/SmppCommandIds.java:74`]
- [x] [Review][Patch] Pin the bit-31 predicate at its boundaries — assert `isResponse`/`requestIdOf` at `0x80000000`, `0x00000000`, `0xFFFFFFFF`, and `requestIdOf(0x80000000) == 0`; the boundaries most likely to drift in a future regression. [`codec/src/test/java/smpp/companion/codec/command/SmppCommandIdsTest.java:69`]

_T2 code review (2026-07-28) — 3 parallel adversarial layers (Blind Hunter, Edge Case Hunter, Acceptance Auditor) + per-finding verification (7 agents), run on the uncommitted LFBD-subclass framer + the `MIN_COMMAND_LENGTH` move. Verdict: the framer PRODUCT CODE is correct — no product defect, no AC1/AD violation (CODEC-010 reject-before-allocation, CODEC-008 off-by-one, CODEC-013 exception containment, CODEC-014 per-channel isolation all genuinely hold; verified against the Netty 4.2.16 bytecode). 3 CONFIRMED findings, all low / test-quality — the framer's TESTS prove less than they claim:_

- [x] [Review][Patch] CODEC-015 reject-path "no leaked buffer escapes channel close" assertion is vacuous — `ResourceLeakDetector` PARANOID only `logger.error`s at GC (never throws) and `EmbeddedChannel.finishAndReleaseAll()` doesn't throw on an orphaned retained slice, so the leak dimension isn't actually enforced; the adjacent `maxRequested<=MAX` carries the real evidence (see next finding). [`codec/src/test/java/smpp/companion/codec/framer/SmppFrameDecoderTest.java:442`]
- [x] [Review][Patch] CODEC-010 load-bearing reject-before-allocation proof is weak — the single `writeInbound` builds its input via `Unpooled.buffer` (the DEFAULT allocator) and `MERGE_CUMULATOR` returns that input directly (cumulation empty + contiguous), so the per-channel `RecordingAllocator`/`ctx.alloc()` is never called → `maxRequested` stays 0 → `assertThat(maxRequested).isLessThanOrEqualTo(MAX)` evaluates to `0 <= 65536` (true for any decoder). It still catches a `ctx.alloc().buffer(malformed)` regression but not a `Unpooled.buffer(malformed)` bypass, and doesn't measure cumulation growth as the `RecordingAllocator` javadoc claims. [`codec/src/test/java/smpp/companion/codec/framer/SmppFrameDecoderTest.java:360`]
- [x] [Review][Patch] CODEC-013 inline comment `// reads as -1 (signed getInt)` is stale — the LFBD subclass reads UNSIGNED (`getUnsignedInt`) so `0xFFFFFFFF`→4294967295 and is rejected by the `maxFrameLength` ceiling (`TooLongFrameException`), not the `<16` floor; the `isInstanceOf(DecoderException.class)` assertion still holds (`TooLongFrameException extends DecoderException`) but the comment misrepresents the active AD-30 overflow path. [`codec/src/test/java/smpp/companion/codec/framer/SmppFrameDecoderTest.java:373`]

_T3 code review (2026-07-29) — 3 parallel adversarial layers (Blind Hunter, Edge Case Hunter, Acceptance Auditor) on the staged bind-family parser + encoder + helpers (`SmppCodec`, `SmppBindEncoder`, `SmppBytes`, `SmppHeaderEncoder`, `SmppBindRequest/Response/Pdu`, `SmppFrame`) + the FIXME-refactor fallout (`SmppCommandIds`, `SmppFrameDecoder`). Verdict: the product code is sound. Edge Case Hunter found **0** defects, verifying the load-bearing Netty 4.2.16 contracts from source (`bytesBefore` bounds `[readerIndex, writerIndex)`; `ByteBufUtil.copy(AsciiString, ByteBuf)` advances writerIndex via `writeBytes`; `MessageToMessageDecoder` releases the input in its `finally` — exactly offset by the codec's `retain()`/`retainedSlice()`); refcount on all paths incl. throw-mid-parse (no reject-path leak), CODEC-037 non-mutation, bounded NUL scan (CODEC-021), truncated-body reject (CODEC-022), and R3 fail-closed containment all hold. `./gradlew clean build` GREEN; `:codec:test` = 46 / 0 fail / 0 skip; CODEC-039/040/041 + AD-35 green; AC9 (no `FIXME`) clean. 2 decision-needed + 2 low patch findings; 2 dismissed (password type = documented 2026-07-28 user override; `SmppFrame` extraction = architecturally sound — frame-length bounds ≠ `command_id`s, and `public` is required for AD-30 cross-module consumption)._

- [x] [Review][Decision→Patch] **Header-only `bind_*_resp` denial raises instead of decoding cleanly (AC2 / CODEC-019 / AD-25).** A non-ROK `bind_*_resp` from a real SMSC frequently arrives header-only (no `system_id` body — e.g. a bare `ESME_RINVPASWD`); `SmppCodec.decodeResponse` calls `readAscii(body, "system_id")` first, which throws `DecoderException` (empty body → `bytesBefore` returns −1) → `exceptionCaught` → `ctx.close()`, so the relay never observes the typed denial / `isOk()==false`. The security property holds (no splice — fail-closed close) but the explicit AC2/AD-25 "non-ROK `bind_resp` decodes cleanly (no throw)" is violated for a common interop shape and the denial code is lost to diagnostics. CODEC-019's test only ships a `system_id`-bearing response, so the gap is unexercised. [`codec/src/main/java/smpp/companion/codec/bind/SmppCodec.java:80`]
- [x] [Review][Decision→Defer] **`password` is `AsciiString` (the 2026-07-28 override) BUT the record's auto-`toString()` concretely leaks it via the documented "fragile seam" (CODEC-024 / PRIV-1).** The type choice is a documented user override (not a defect); the sharper issue: `SmppBindRequest` is a `record`, so its auto-generated `toString()` renders every component — calling `AsciiString.toString()` on the password, which caches a surviving `String`. So "callers must avoid `toString()` on the password" is insufficient: logging the PDU object (a plausible relay debug/error path) leaks it, and this would FAIL the deferred CODEC-024 P2 "no `String` from password octets" bytecode scan. [`codec/src/main/java/smpp/companion/codec/bind/SmppBindRequest.java:49`] — **deferred to T6 (CODEC-024 P2):** the bytecode scan will enforce "no `String` from password octets"; the `AsciiString` type + the record `toString()` leak are accepted until then under the 2026-07-28 override. See `deferred-work.md`.
- [x] [Review][Patch] `address_range` spec-max (≤41 incl. terminator) is not exercised — `maxLengthFieldsDecode` hits `system_id`/`password`/`system_type` at max but passes `address_range=""`; the AC2 "C-octet max-length" clause isn't covered for that field (same `readAscii` path → code correct, test gap). One assertion closes it. [`codec/src/test/java/smpp/companion/codec/bind/SmppCodecTest.java:259`]
- [x] [Review][Patch] Dev Agent Record / AC2 text drift after the refactor — AC2 :153 still says "`char[]`/`byte[]`"; Dev Record :704 says the password accessor is "`char[]`"; Dev Record :728 references "`SmppCommandIds.MIN_COMMAND_LENGTH`" (moved to `SmppFrame` this session). Reconcile the stale passages. [`_bmad-output/implementation-artifacts/1-2-smpp-3-4-codec.md`]

_T4 code review (2026-07-29) — 3 parallel adversarial layers (Blind Hunter, Edge Case Hunter, Acceptance Auditor) + per-finding verification (14 verifiers), run on the uncommitted golden-vector corpus + promoted loader test (`GoldenVectorCorpusTest`, 11 `.smpp` vectors, `README.md`). Verdict: AC5 is MET — corpus populated (6 positive bind-family + 5 negative, all 5 negative categories present + tagged), scaffold promoted to a real non-empty + per-vector provenance assertion, `Locale.ROOT` folded, `deferred-work.md` entry cleared; the vectors are spec-correct today (every `command_length` == octet count, every `command_id` ∈ `BIND_FAMILY`, `bind_transceiver = 0x09`). 8 findings dismissed (5 by-design/T5-deferred non-defects — `command_status`/NUL/field-semantics validation is explicitly T5's jSMPP decode oracle; the unsigned-overflow `0xFFFFFFFF` class is already covered in `SmppFrameDecoderTest` CODEC-010; the C-octet max-length happy path is already in `SmppCodecTest` CODEC-020; `isNotEmpty`≡`isGreaterThan(0)`). 1 decision-needed (resolved 2026-07-29 → defer to T5), 2 patch, 3 defer below._

- [x] [Review][Defer] **Negative vectors are not a biting oracle — the `CODEC-…` reject tag is never tied to the bytes (AC5/CODEC-030, R14).** `if (!negative)` skips `assertWellFormedBindPdu`, so a negative vector's bytes are parsed and discarded; the reject tag is checked for shape only (non-empty, `CODEC-` prefix), never against the actual malformation. 2 of 5 negatives (`negative_unterminated_string`, `negative_body_shorter_than_fields`) are length-self-consistent with a bind-family `command_id`, so they would PASS as valid positives if their ` ; reject: ` tag were dropped. The framer-stage negatives (CODEC-005/008/009) have no bite-verification in the golden oracle at all. AC5's literal text is met (tags present) and the vectors are correct today, so this is latent — but a corpus whose stated purpose is independent falsification does not falsify its negatives. [`codec/src/test/java/smpp/companion/codec/golden/GoldenVectorCorpusTest.java:70-93`] — **deferred to T5 (user decision 2026-07-29):** a T5 codec-conformance test will feed each golden negative vector through the real decoder + jSMPP and verify each rejects as tagged (strictly stronger than T4 structural assertions; requires a deliberate negative-reject test alongside CODEC-031, which is positive-only field-equality today). **✅ RESOLVED in T5 (2026-07-30):** `BindConformanceTest.negativeVectorRejectsAsTagged` (CODEC-033) now feeds every golden negative through the real framer→parser pipeline and asserts each rejects/awaits exactly as tagged (CODEC-005/008 framer-reject; CODEC-009 await; CODEC-021/022 parser-reject).
- [x] [Review][Patch] **Provenance parser uses unscoped `indexOf` — a marker substring inside `<ref>` can misclassify / throw `StringIndexOutOfBoundsException`.** _Resolved in T5: the parser was extracted into the shared `GoldenVectors` loader, where the reject-marker search is SCOPED to after the raw-hex marker (`header.indexOf(REJECT_MARKER, hexStart)`), so a ` ; reject: ` substring in a `<§ref>` note can no longer set `hexEnd < hexStart` or throw. [`codec/src/test/java/smpp/companion/codec/golden/GoldenVectors.java`]_
- [x] [Review][Patch] **Stale `StringCaseLocaleUsage` line cite after T4 folded the fix.** _Resolved in T5: AC5 :186 now cites the `Locale.ROOT` filter's current home (`GoldenVectors.java`); the call moved out of `GoldenVectorCorpusTest` entirely when T5 extracted the shared loader. The `1-4` story doc's cleared-`deferred-work` pointer is out of this story's scope (it referenced 1.2's then-deferred entry, now folded). The AC5 spec stays imperative._
- [x] [Review][Defer] **No independent per-vector `command_id` pin — membership-only via `isBindFamily`.** [`codec/src/test/java/smpp/companion/codec/golden/GoldenVectorCorpusTest.java:124`] — deferred: deliberate T4 trade-off (catches the 0x09↔0x0F constant drift; only a wrong-but-bind-family id would slip); T5's jSMPP decode oracle pins the `command_id` per vector. **✅ RESOLVED in T5 (2026-07-30):** CODEC-031 decodes each golden vector via jSMPP and asserts the `command_id` (and every field) per vector.
- [x] [Review][Defer] **`bind_transmitter_resp` (0x80000002) has no positive vector — 5 of 6 `BIND_FAMILY` ids covered.** [`codec/src/test/resources/golden-vectors/`] — deferred: the three response ids parse identically (no untested path); AC5 does not mandate one vector per id; a 12th vector would be a near-no-op against an already-covered decode path.

_T5 code review (2026-07-30) — 3 parallel adversarial layers (Blind Hunter, Edge Case Hunter, Acceptance Auditor) + per-finding adversarial verification (5 verifiers, each re-derived from source), run on the uncommitted T5 jSMPP cross-oracle work (`build.gradle.kts` +jSMPP `testImplementation`, `GoldenVectors` shared loader, refactored `GoldenVectorCorpusTest`, new `BindConformanceTest` — CODEC-031/032/033). Verdict: **AC6 is MET** — the Acceptance Auditor found no clause unmet and no AD violated (CODEC-031 pins `command_id` + every body field per vector for BOTH requests and responses against jSMPP 3.0.2, closing the deferred "no per-vector command_id pin"; CODEC-032 decode→encode byte-identity across all 3 request types; CODEC-033 covers all 5 negative categories at the correct stage through the real `SmppFrameDecoder→SmppCodec` pipeline; jSMPP is `testImplementation`-only and verified OFF the main classpath so CODEC-040/AD-7/AD-27 hold; R14/R33 corpus independence honored — no vector produced by invoking the codec; CODEC-024 no-`toString()`-on-password honored in the assertion body). T5 adds NO production code; the 3 confirmed findings are all low / test-quality (assertion strength + a latent refcount seam), none a correctness defect. 2 dismissed below. `./gradlew clean build :buildSrc:test` GREEN._

- [x] [Review][Decision→Patch] **The CODEC-022 `body-shorter-than-fields` vector actually triggers the CODEC-021 (unterminated) path; the merged `case "CODEC-021","CODEC-022"` arm checks only the common `DecoderException` supertype, so the biting oracle does NOT validate the 022 tag against its named malformation.** The vector body is `"id\0"` (3 bytes): after `readAscii(system_id)` the slice is empty, so `readAscii(password)` → `bytesBefore` on 0 readable bytes → −1 → throws the *unterminated* (CODEC-021) exception; `readByte`/CODEC-022 (the truncated-mandatory-field guard) is never reached and has **zero** byte-level coverage suite-wide (the T3 `truncatedBodyRejectsCleanly` test uses the same `"id\0"` body and also hits 021). Confirmed empirically by running the real pipeline against the bytes. A regression that drops the CODEC-022 `readByte` AIOOBE-guard (→ AIOOBE instead of `DecoderException`) passes silently. [`codec/src/test/java/smpp/companion/codec/golden/BindConformanceTest.java:210`] — **decision needed:** **(A)** add a genuine CODEC-022 vector whose body completes every C-octet field (each NUL-terminated) and truncates at a mandatory FIXED field so `readByte(interface_version)` is the throw site (e.g. header + `system_id\0 + password\0 + system_type\0` then STOP → "truncated body — mandatory field interface_version absent"), which makes CODEC-033 actually bite on 022; OR **(B)** the simpler fail-closed option — narrow the CODEC-033 class javadoc / AC6-closure note to "parser-stage negatives reject (framer-vs-parser-vs-await verified; 021-vs-022 not separately distinguished)". **Recommended: (A)** — making the oracle actually bite is CODEC-033's stated purpose (the T4→T5 deferral existed precisely to tie the tag to the bytes). **✅ RESOLVED (user, 2026-07-30): option (B) — narrow the claim.** Edit the CODEC-033 class javadoc + the AC6-closure note to "parser-stage negatives reject (framer-vs-parser-vs-await verified; 021-vs-022 not separately distinguished)"; no new vector.
- [x] [Review][Patch] **CODEC-033 asserts the 'drop' but never the fail-closed channel 'close' half of the named outcome.** `negativeVectorRejectsAsTagged` checks `capture.cause` (not-null + `DecoderException` for 005/008/021/022; null for 009) but never `channel.isOpen()`. Production `SmppCodec.exceptionCaught` does `ctx.fireExceptionCaught(cause); ctx.close()` (`SmppCodec.java:95-98`), but `SmppCodecTest` has **zero** `close`/`isActive` assertions — so a regression deleting the parser's `ctx.close()` (channel stays OPEN after a malformed-PDU reject — the R3/SEC-2 fail-closed property) passes the whole suite green. The framer's close is already well-covered (`SmppFrameDecoderTest` has 12 `isActive` hits); the gap is the parser-reject branches CODEC-021/022. Fix: add `assertThat(channel.isOpen()).as("%s: a reject must fail-closed the channel (R3)", v.name()).isFalse()` to the 005/008/021/022 branches and the symmetric `.isTrue()` to the 009 (await) branch. [`codec/src/test/java/smpp/companion/codec/golden/BindConformanceTest.java:199-219`]
- [x] [Review][Patch] **CODEC-032's `isInstanceOf(SmppBindRequest)` assertion + `encode` sit OUTSIDE the try/finally that releases `originalFrame`, so an assertion/encode failure leaks the retained frame (refCnt 1).** Lines 169-173 run before the `try` (174); the `finally` (179-180) releases `req.originalFrame()` — unreachable on that failure path. CODEC-031 does it correctly (dispatch inside the try; releases via the always-in-scope `pdu` reference). `@AfterEach` does not reclaim it (the PDU was already `readInbound`-out of the channel; `toRelease` holds only the wrapped inbound + `encoded`, not `originalFrame`). Unreachable today (`positiveRequestVectors` always yields a request; `encode` doesn't throw on a valid parsed request) but a latent leak + structural inconsistency. Fix: mirror CODEC-031 — wrap the cast+assertion+encode+equality in one try/finally that releases `pdu.originalFrame()` via the `pdu` reference. [`codec/src/test/java/smpp/companion/codec/golden/BindConformanceTest.java:169-181`]

_Dismissed (2): (1) the parametrized display name `[{0}]` dumps the whole `Vector` record (incl. the password) into the JUnit test name — mechanism true, but the security imputation is false: the golden-vector passwords (`secret`/`pw`) are public spec-example fixtures already committed in cleartext `.smpp` files, and CODEC-024/PRIV-1 governs the production parser not interning the password, not test display names; the legitimate kernel (a verbose name, inconsistent with `GoldenVectorCorpusTest`'s clean `v.name()`) is cosmetic. (2) the CODEC-005/CODEC-008 floor/ceiling merge asserting only `DecoderException` — the CODEC-008 off-by-one ceiling IS already pinned by `SmppFrameDecoderTest`'s 65536-accepted/65537-rejected boundary, the merge matches the established `isInstanceOf(DecoderException.class)` convention used throughout the framer's own tests, and CODEC-033's contract is the outcome class (framer-reject vs await vs parser-reject), not the internal exception subclass — already-covered / by-design._

_SmppBytes.readAscii regression review (2026-07-30) — focused review of the uncommitted working-tree edit to `codec/src/main/java/smpp/companion/codec/bind/SmppBytes.java` (`@SmppBytes.java`). The 3-line edit to `readAscii` (intending to return the `EMPTY_STRING` constant for an empty field) re-called `readNullTerminated(slice, …)` in the non-empty branch instead of reusing the already-read `byte[] string` — so every non-empty C-octet field consumed the NEXT field's bytes (full body desync) or threw "unterminated". Empirically confirmed: **16/32 codec tests failed** (every CODEC-031 positive, CODEC-016/018/023, CODEC-032). HIGH correctness blocker (AD-12 byte-exact bind relay + AC2 violated; real-carrier interop dies on the first non-empty `system_id`/`password`). Fixed (1 token — `new AsciiString(string)`); the run also surfaced a latent NPE in the T5 CODEC-032 `finally` (a rejecting positive left `pdu==null`), now null-guarded. `:codec:build` GREEN; 61 tests 0 fail / 0 skip; CODEC-040 unchanged. (Solo verdict — the regression was already empirically proven by the diff + HEAD comparison + 16 failing tests, so the 3-layer adversarial fan-out was not warranted.)_

- [x] [Review][Patch] **`readAscii` double-read regression — a non-empty C-octet field consumed the next field.** The edit re-called `readNullTerminated` instead of reusing `string`; it mis-parsed every non-empty field (16/32 tests red). Fix: `new AsciiString(string)`. [`codec/src/main/java/smpp/companion/codec/bind/SmppBytes.java:62`]
- [x] [Review][Patch] **CODEC-032 `finally` NPE masked the real failure when a positive rejected (`pdu==null`).** Surfaced by the readAscii run (NPE at `BindConformanceTest.java:180`). Fix: null-guard `pdu` before `originalFrame().release()`. [`codec/src/test/java/smpp/companion/codec/golden/BindConformanceTest.java:179`]

_T6 code review (2026-07-31) — 3 parallel adversarial layers (Blind Hunter, Edge Case Hunter, Acceptance Auditor) + per-finding refutation verification (17 verifiers, each re-derived from source — several ran `:codec:test` + inspected the JUnit XML; 1 verifier died on a 429 rate-limit and was re-verified by the orchestrator), run on the staged T6 fuzz+property tests (`codec/build.gradle.kts` +Jazzer `0.24.0`/+jqwik `1.10.1`, 5 new test files — CODEC-011/012/025/037/038). 18 raw → 12 confirmed-real → 8 distinct after dedup. **Verdict: the codec PRODUCT CODE is correct — zero production defects, zero AD violations** (CODEC-040/AD-7/AD-27 purity holds: Jazzer+jqwik are `testImplementation`-only, verified off the MAIN classpath; **the jqwik `@Property` half of AC7 is SOLID** — 1000 real tries each, reassembly/forwarding/opaque invariants genuinely enforced, every `@Property` method annotation-free so none silently skipped). **The defects are confined to the JAZZER FUZZ half + comments:** the `@FuzzTest`s run only the empty input (no seed corpus) and the CODEC-011 bounded-memory assertion is structurally vacuous — i.e. the fuzz tests prove less than they claim (same shape as the T2 framer-test finding at :301). 2 decision-needed + 5 low/med patch + 7 dismissed. The green build (AC10) is exactly what masks the no-op fuzz._

- [x] [Review][Decision] **Jazzer `@FuzzTest` runs only the empty input on the PR tier — no seed corpus exists, so each fuzz test exercises exactly ONE trivial input (CODEC-011/CODEC-025, AC7).** No Jazzer corpus is checked in (`codec/src/test/resources` holds only `golden-vectors/`; no `SmppFrameDecoderFuzzTest/`/`SmppCodecFuzzTest/` corpus dirs, no `@SeedCorpus`, no `.cifuzz-corpus`, no `JAZZER_FUZZ=1` wiring — verified). Per Jazzer 0.24 regression mode, with no corpus each `@FuzzTest` replays ONLY the default empty input — confirmed empirically (both fuzz XMLs report `tests="1"`, testcase `<empty input>`): `fuzzFramer(byte[0])` decodes nothing/allocates nothing/closes nothing (all 3 CODEC-011 assertions pass trivially), and `fuzzBindParser` runs one header-only bind the parser rejects as truncated. The comments + Dev Record claim a "regression-mode seed corpus on the PR tier" that does not exist, and the "66 tests, 0 skip" evidence counts these no-op runs as passing. The codec is correct and the named reject paths are covered deterministically (CODEC-006/008/010/021/022) + by the 1000-try jqwik properties — so **no runtime/relay risk** — but AC7's "PR tier runs bounded fuzz" is, in substance, unmet and the fuzz half of AC7 is currently theatrical. **Decision needed:** **(A)** ship a hand-authored PR seed corpus now (well-formed + oversize + truncated + malformed bodies under `src/test/resources/<FuzzTest>/`, or a `@SeedCorpus` method) so PR-tier fuzz actually bites; or **(B)** the simpler option — accept PR fuzz as infrastructure-only (Jazzer wired, runs every build) and correct the comments + Dev Record to say so, deferring real corpus expansion to nightly `JAZZER_FUZZ=1` (which has no scheduled entry point today either). **Recommended: (A)** — a small static corpus also closes the AC9/AC10 "no no-op tests" concern. [CODEC-011 `SmppFrameDecoderFuzzTest.java:36-37,107`; CODEC-025 `SmppCodecFuzzTest.java:39,65`; absent corpus dirs under `codec/src/test/resources/`] — **✅ RESOLVED (user, 2026-07-31): option (A) — ship a PR seed corpus (becomes the first patch below).**
- [x] [Review][Decision] **The "jqwik `@Tag`/`@DisplayName` on `@Property` → silent skip" gotcha is overclaimed vs jqwik's own docs — correct the wording?** The load-bearing comment (`build.gradle.kts:46-51` + the headers of all 3 property tests) asserts as "verified" that a Jupiter `@DisplayName` OR `@Tag` on a jqwik `@Property` makes jqwik silently skip it. jqwik 1.10.1's docs show the OPPOSITE for `@Tag` (`@Property @Tag("fast")` is a documented supported pattern) and name `@Disabled` as the actual Jupiter incompatibility (it recommends jqwik's own `@Label` for display names). The properties DO run today (every `@Property` method is annotation-free; `skipped=0` verified) and you empirically observed the skip+fix this session — but the causal predicate as written is broader than the docs support (it may be a jqwik-version/Platform-6 bug rather than a general `@Tag`/`@DisplayName` rule). **Decision needed:** **(A)** keep the empirical guidance ("annotation-free `@Property` methods run reliably on this toolchain") but soften the causal claim to what's actually certain; or **(B)** leave it as-is (your observation may reflect a real version-specific bug the docs don't capture). [build.gradle.kts:46-51; `SmppCodecForwardingPropertyTest.java:30-32`; `SmppCodecOpaquePropertyTest.java:29-31`; `SmppFrameDecoderPropertyTest.java:76-77`] — **✅ RESOLVED (user, 2026-07-31): leave the claim as-is; only the stale "downgraded to 5.14.4" text (patch below) is corrected.**
- [x] [Review][Patch] **CODEC-011 "bounded memory" assertion is vacuous — `RecordingAllocator.maxRequested()` is always 0.** A single `writeInbound` ⇒ no cumulation merge ⇒ `ctx.alloc()` is never called for cumulation growth; the framer's emit is a zero-copy `retainedSlice`; both rejects throw before allocating. So `maxRequested(0) <= MAX*2` is tautologically true for ANY input — the P1/R3/SEC-2 DoS-bound invariant is never actually asserted. (Same structural anti-pattern the T2 review already flagged+fixed in `SmppFrameDecoderTest` CODEC-010 — re-appeared here.) Fix: feed the input in multiple `writeInbound` chunks so `MERGE_CUMULATOR` grows the cumulation (observed: chunking yields `maxRequested=64`), ideally with an overflow-class declared length to prove the LFBD `failFast` ceiling rejects before any large allocation. [`codec/src/test/java/smpp/companion/codec/framer/SmppFrameDecoderFuzzTest.java:70-105,123-125`]
- [x] [Review][Patch] **`SmppFrameDecoderPropertyTest` class javadoc states a Platform downgrade that was reverted + re-asserts the disproven "skips on Platform 6".** Lines 29-31 say "codec's JUnit Platform is downgraded 6.0.3 -> 5.14.4 so jqwik ... silently skips `@Property` on Platform 6" — false: `build.gradle.kts:29` pins `junit-bom:6.0.3` (no downgrade), and the file's OWN method-level NOTE (76-77) + the Dev Record give the corrected root cause. The sibling property tests already carry the correct gotcha note; this class header was never reconciled. Fix: replace the stale passage with the corrected narrative (annotation-free `@Property` on native Platform 6.0.3). [`codec/src/test/java/smpp/companion/codec/framer/SmppFrameDecoderPropertyTest.java:28-32`]
- [x] [Review][Patch] **The jqwik tests' `ExceptionCapture` tail swallows EVERY throwable ⇒ a real pipeline regression surfaces as an ambiguous null/size assertion instead of the actual cause.** All 3 property tests' tail `exceptionCaught` is a pure no-op (no `cause` field), unlike the sibling fuzz tests (same diff) which RECORD + assert the cause. When `SmppCodec`/`SmppFrameDecoder` throws mid-decode, production `exceptionCaught` fires-then-closes; the no-op tail discards the cause, `readInbound()` returns null, and the property fails with "expected not null" / "size 1 but was 0" rather than the real exception. Fix: record the cause and fail-loud with it when no output is produced (mirror the fuzz-test capture). [`SmppCodecForwardingPropertyTest.java:42-47`; `SmppCodecOpaquePropertyTest.java:43-48`; `SmppFrameDecoderPropertyTest.java:45-50`]
- [x] [Review][Patch] **CODEC-011 clause (c) "channel closed on oversize" is not positively asserted — only the converse is checked (`if (!isActive()) cause is DecoderException`).** It never feeds a guaranteed-oversize declared length and asserts `isActive()==false`, so a regression that silently DROPS an oversize PDU without closing would skip the assertion and pass green. The oversize→close behavior IS exhaustively covered by `SmppFrameDecoderTest` CODEC-006/008/010, so this is a within-CODEC-011 completeness gap, not a suite-wide hole. Fix (pairs with the corpus decision above): include an oversize/overflow-class seed and add a positive `assertThat(channel.isActive()).isFalse()` for it. [`codec/src/test/java/smpp/companion/codec/framer/SmppFrameDecoderFuzzTest.java:129-134`]
- [x] [Review][Patch] **CODEC-037 pre-try leak window — `encode`/`getBytes`/`EmbeddedChannel` ctor run BEFORE the try-finally, so a throw there leaks the `encoded` + throwaway `dummy` buffers.** Lines 81-83 precede the `try` (84); the `finally` (98-99) releases them only if the try was entered. Unreachable for the valid provider inputs (only an OOM-level `Error` reaches it) but a latent leak + structural inconsistency (mirrors the T5-fixed CODEC-032 seam). Fix: hoist the three statements into the try (release via the in-scope refs). [`codec/src/test/java/smpp/companion/codec/bind/SmppCodecForwardingPropertyTest.java:81-83,98-99`]

_Dismissed (7): (1) "PR/nightly fuzz split is fictitious / JAZZER_FUZZ unwired" — Jazzer's regression-vs-continuous dual mode is native; regression runs on every build (not cosmetic), and the nightly mechanism is the standard `JAZZER_FUZZ=1` env-var (a CI-finalize concern, out of scope for a test-only task). (2) "CODEC-025 over-read assertion only conditional" — the non-null `DecoderException` lower bound for malformed/truncated bodies IS asserted in `SmppCodecTest` CODEC-021/022; the fuzz test's job is the over-read direction. (3) "RecordingAllocator bounds initialCapacity not footprint" — refuted by Netty 4.2.16 source: `initialCapacity` IS the actual `new byte[]`/direct-allocation size (`maxCapacity` is a never-pre-reserved growth ceiling). (4) "CODEC-011 controlled-close only checked when `!isActive`" — unreachable: `SmppFrameDecoder.exceptionCaught` always fires-then-closes, so the active branch necessarily has no cause; plus covered by CODEC-005/006/008/010/013/014. (5) "CODEC-037 throwaway `Unpooled.buffer(1)` dummy is a smell" — self-admitted nitpick; no leak (refcnt 1 → released once), `encode` genuinely ignores `originalFrame`. (6) "'wire the tag' has no in-repo Gradle wiring" — over-reads AC7; the tag IS attached (selectable by CI), and continuous fuzz being an env-var opt-in is what keeps the build unblocked. (7) "tier tags inconsistent (CODEC-012/038 `fuzz` vs CODEC-037 `unit`)" — real but cosmetic (no tag filter is wired, so zero effect today) and the "correct" tier for a bounded jqwik property is itself ambiguous; the finding's premise (CODEC-012 is "deterministic") is wrong — all three use jqwik random generation._

_✅ Patches applied + verified (2026-07-31): all 6 resolved — corpus shipped (CODEC-011/025 `@MethodSource` seeds), CODEC-011 chunked feeding (bounded-memory assertion now non-vacuous — `maxRequested` reflects real cumulation growth) + positive oversize→close, stale "downgraded to 5.14.4" javadoc reconciled, jqwik `ExceptionCapture` made fail-loud, CODEC-037 pre-try block hoisted. `./gradlew clean build :buildSrc:test` GREEN; codec **79 tests / 0 fail / 0 skip / 0 errors** (was 66; +13 regression seeds — `SmppFrameDecoderFuzzTest` 1→8, `SmppCodecFuzzTest` 1→7, both now exercising well-formed / oversize / overflow-class / floor / truncated / unterminated / coalesced shapes on PR); CODEC-040 unchanged `{io.netty, org.jspecify, org.projectlombok}`; zero ErrorProne warnings. Story stays `in-progress` (T7 JMH + T8 finalize pending)._

_T7 code review (2026-08-02) — 3 parallel adversarial layers (Blind Hunter, Edge Case Hunter, Acceptance Auditor) + a gradle build-smoke agent + per-finding source-re-derivation verification (12 agents total), run on the uncommitted JMH microbench + guards (`proxy/build.gradle.kts` +`me.champeau.jmh` 0.7.3 + the `test→compileJmhJava` edge, `buildSrc` null-safety predicate widened to `compileJmhJava`, `CodecMicrobenchmarks` PERF-001/002/003, `JmhIsolationArchitectureTest`, `CodecAllocationGuardTest` PERF-006). Verdict: the T7 product + guard code is **FUNCTIONALLY CORRECT — zero production defects, zero AC8 intent actually unmet, zero AD violations.** Empirically verified: `./gradlew :proxy:compileJmhJava` GREEN with NullAway **PROVEN live on `compileJmhJava`** (a throwaway `@Nullable`→`@NonNull` probe FAILED the compile, then recompiled clean after removal — the widened predicate is genuinely fail-closed); `./gradlew :codec:test --tests *CodecAllocationGuardTest` = 2/0/0 (encode==1, decode==0, `refCnt==1`); `JmhIsolationArchitectureTest` **NON-VACUOUS** (a probe asserted `ClassFileImporter().importPackages("smpp.companion")` loads `smpp.companion.jmh.*` — the rule evaluates real classes, not an empty selection); full `:proxy:test` = 9/0/0; and the AC8 / decision-#3-hardening-#3 smoke test **`./gradlew :proxy:jmh` → BUILD SUCCESSFUL in 34s on Gradle 9.6.1 / JDK 25**, clearing the JMH 1.37 bytecode-gen ASM-on-JDK-25 risk (the story's #1 cited risk) — encode 8.5 ops/µs, decode 6.4 ops/µs, frame 10.2 ops/µs (faster than the conservative AC8 bands, as expected for characterization; the Dev Record's smoke-test claim is TRUE). The codec API surface the benchmarks call (`SmppBindEncoder.encode(req, alloc)`, the 11-component `SmppBindRequest` ctor order/types, `SmppCommandIds.BIND_TRANSCEIVER=0x09`/`INTERFACE_VERSION_3_4=0x34`, `SmppCodec` zero-alloc slice decode, `SmppFrameDecoder` LFBD `retainedSlice`) was independently verified against the committed T1-T6 source. **All 6 confirmed findings are LOW-severity and confined to documentation/wording overclaims in nightly-tier benchmark + guard code** (prose that overstates what the structural mechanisms actually intercept); 1 dismissed. 3 patch + 1 defer below._

- [x] [Review][Patch] **PERF-006 decode guard overclaims "zero scratch allocations" — `decode` never routes through the `CountingAllocator`, so `allocations()==0` is a tautology, not an interception.** `CountingAllocator` overrides only `newHeapBuffer`/`newDirectBuffer`, so it counts only ByteBufs from `alloc.buffer(...)`. `SmppCodec.decode` NEVER consults `ctx.alloc()` — it reads via `buf.slice()` + `frame.retainedSlice(...)` (both allocator-bypassing derived views) and `SmppBytes.readAscii` allocates `new byte[]` + `new AsciiString` per non-empty C-octet field (≈4 `byte[]` + 3 `AsciiString` of genuine per-op GC garbage for the golden bind, none allocator-routed). So `alloc.allocations()==0` holds because decode bypasses the allocator entirely, not because the delegate intercepted zero allocations — the same `RecordingAllocator`-bypass anti-pattern flagged+fixed in the T2 CODEC-010 and T6 CODEC-011 reviews. The load-bearing decode checks that DO bite are `originalFrame().refCnt()==1` (the literal spec property "decode retains no extras") + the `commandId` sanity; the encode half IS genuinely guarded (`SmppBindEncoder.encode` calls `alloc.buffer(commandLength)`, count==1 holds regardless of `preferDirect`). Fix: tighten the `@DisplayName` / assertion message / class javadoc to "zero scratch **ByteBuf** allocations via the channel allocator" (the decode path is genuinely zero-ByteBuf-alloc by design, so the count cannot be made to bite — the durable invariant is the `refCnt==1` check, which already bites). [`codec/src/test/java/smpp/companion/codec/perf/CodecAllocationGuardTest.java:103,108,116-118`]
- [x] [Review][Patch] **`CodecMicrobenchmarks` class javadoc claims "no allocation enters the measured path," but PERF-002/PERF-003 allocate a `retainedDuplicate()` wrapper inside each `@Benchmark`.** The class javadoc (lines 44-45) holds only for PERF-001 `encodeBindRequest`; PERF-002 `decodeBindRequest` and PERF-003 `frameSubmitSm` call `goldenFrame.retainedDuplicate()` / `submitFrame.retainedDuplicate()` per invocation to feed the `EmbeddedChannel` without consuming the shared `@State` buffer (necessary — `MessageToMessageDecoder`/`ByteToMessageDecoder` release the input after decode). `ByteBuf.retainedDuplicate()` allocates a fresh wrapper per call — a real per-op heap allocation in the measured path, so PERF-004's `-prof gc` per-op count for PERF-002/003 includes this harness wrapper (an engineer relying on the javadoc would mis-attribute it to the codec). The `retainedDuplicate` is unavoidable harness setup (not deletable); the durable PERF-006 counting-allocator guard is correctly unaffected (slice/duplicate views don't route through it). Fix: reword the javadoc to acknowledge the necessary `retainedDuplicate` wrapper on the decode/frame paths. [`proxy/src/jmh/java/smpp/companion/jmh/CodecMicrobenchmarks.java:44-45`, contradicted by :82 (PERF-002) and :102 (PERF-003)]
- [x] [Review][Patch] **PERF-005 overclaimed as a "durable in-CI guard"; warmup (2×1s) cannot demonstrate convergence and no CoV<5% gate exists.** The class javadoc (lines 32-33) labels "PERF-005 fork-variance + PERF-006's unit allocation guard" as the durable in-CI guards (plural). PERF-006 genuinely is one (a unit test in `:codec:test`); PERF-005 is neither — the `:proxy:jmh` task is nightly-tier (NOT wired into `build`/`check`, by AC8 design), there is **no CoV<5% assertion anywhere in the repo**, and the CoV figure is a one-time manual characterization in the Dev Record (not a guard). `@Warmup(iterations=2, time=1)` gives only 2 warmup points — too few to observe convergence (JMH best practice is 5+). The Dev Record is internally inconsistent with the javadoc (it says "PERF-006 is the durable guard", singular). Fix: one-line javadoc reword (PERF-005 is a manual characterization; PERF-006 is the sole durable in-CI guard); optionally bump `@Warmup(iterations=5)` so a future run can actually show convergence. [`proxy/src/jmh/java/smpp/companion/jmh/CodecMicrobenchmarks.java:32-33,50-52`]
- [x] [Review][Defer] **PERF-004 (`-prof gc`) is not reproducibly wired — a one-shot manual measurement reverted from the committed build; `./gradlew :proxy:jmh` yields throughput only.** The committed `jmh {}` block sets only `jmhVersion`/`includeTests` — no `profilers = [gc]` line — and `CodecMicrobenchmarks` carries no `@Profiler` override (JMH gc profiling is CLI/plugin-config-driven, not annotation-driven). The Dev Record confirms `-prof gc` was added temporarily to record encode 172.3 B/op, decode 448 B/op, frame 104 B/op, then REVERTED "so default throughput runs stay clean"; a fresh `:proxy:jmh` does not reproduce the PERF-004 allocation evidence. Mild because PERF-006's counting-allocator unit guard is the durable PR-tier substitute and the Dev Record is transparent about the revert + substitute; re-deriving the PERF-004 evidence is a trivial one-line change. [`proxy/build.gradle.kts:47-53`] — **deferred:** the no-profilers config is a deliberate, documented tradeoff (clean nightly throughput runs); permanently re-wiring `-prof gc` is a design choice, not an unambiguous patch. See `deferred-work.md`.

_Dismissed (1): PERF-002 decodes 10 of 11 `SmppBindRequest` fields into the Blackhole (`originalFrame()` is `.release()`d, not `bh.consume()`d — a literal "every field Blackholed" wording deviation). Confirmed but dismissed: `SmppCodec` constructs `originalFrame` via `frame.retainedSlice(...)` (a refcount side effect on `frame`), and `pdu.originalFrame().release()` mutates that refcount via a volatile write, so the JIT cannot elide the field load — the read is preserved exactly as `bh.consume()` would preserve it, and the retainedSlice allocation cannot be DCE'd. PERF-002 decode throughput is measured correctly; the deviation is purely literal-text non-compliance with zero functional consequence._

_Story-level code review (2026-08-02) — 5 adversarial lenses (Blind Hunter, Edge Case Hunter, Acceptance Auditor, Security/Fail-Closed, Test-Efficacy) + per-finding source re-derivation (7 agents, ~727k tokens), run on the full committed Story 1.2 diff (`0515c48..HEAD`/`7f870c0`; 52 files, +4405/−136). Verdict: **the codec product code is clean** — Blind Hunter, Edge Case Hunter, and Acceptance Auditor each returned **zero findings**; every load-bearing invariant was re-verified at HEAD (CODEC-010 reject-before-allocation via LFBD `failFast` + unsigned read; R3/SEC-2 channel-close on every reject path incl. the `SmppCodec` parser branches; AD-12/CODEC-037 byte-exact un-mutation via `slice()` + retain-after-parse; AD-27 no Micrometer; AD-33 `generic_nack`/non-ROK `bind_resp` non-mutation; CODEC-040 runtime purity). 1 decision-needed (test-efficacy, LOW); 1 dismissed — the `SmppBindRequest.toString()` password leak was re-raised by the Security lens but is **already tracked** as deferred-work CODEC-024 P2 (no production call at HEAD → not a today-defect), so re-raising adds nothing._

- [x] [Review][Decision→Patch] **The `CODEC-022` unit test + golden vector trip the `CODEC-021` path, not the `readByte` truncated-fixed-field guard they claim (CODEC-022/CODEC-021, test-efficacy, LOW).** `SmppCodecTest.truncatedBodyRejectsCleanly` (`SmppCodecTest.java:302-310`, `@DisplayName "CODEC-022 … no AIOOBE"`) feeds body `{'i','d',0}` = `"id\0"` (3 octets). Parse order: `readAscii(system_id)` consumes all 3 bytes → `readAscii(password)` calls `bytesBefore` on an EMPTY slice → −1 → throws `DecoderException` at `SmppBytes.java:45` (the **CODEC-021** unterminated path); the `readByte` guard at `SmppBytes.java:68` (the **CODEC-022** mechanism for `interface_version`/`addr_ton`/`addr_npi`) is **never reached**. The test asserts only `instanceof DecoderException`, which passes because CODEC-021 also throws it — so the test is vacuous for the readByte/CODEC-022 path it claims (a regression deleting the `readByte` bounds check → AIOOBE instead of `DecoderException` stays GREEN here). The golden vector `negative_body_shorter_than_fields.smpp` (raw-hex `…696400` = `"id\0"`, tagged `reject: CODEC-022`) has the identical body and the same mismatch. The genuine CODEC-022 path **is** exercised PR-tier by `SmppCodecFuzzTest.truncatedBody()` (`"sys\0pw\0st\0"` → reaches `readByte(interface_version)` on an empty slice), so the property is guarded — just not by the test/vector that claims CODEC-022. [`codec/src/test/java/smpp/companion/codec/bind/SmppCodecTest.java:305`] — **decision needed:** **(A)** make the labeled CODEC-022 tests genuinely bite — change the unit-test body (and the golden vector) to terminate all three C-octet strings then omit the fixed fields (e.g. `{'i','d',0,'p','w',0,'s','t',0}`), so `readByte(interface_version)` is the throw site (consistent with how T2/T6/T7 resolved the same vacuous-assertion anti-pattern by strengthening the existing test, no new infra); OR **(B)** the simpler option — relabel the unit test + vector as CODEC-021 / "021-vs-022 not separately distinguished" (consistent with the 2026-07-30 T5 decision for CODEC-033; the genuine 022 path is already fuzz-covered). **Recommended: (A)** — a one-line body change makes the CODEC-022 label truthful and the oracle actually bite, this story's own established resolution for vacuous assertions. **✅ RESOLVED (user, 2026-08-02): option (A) — make it bite.** Changed the unit-test body to `{'i','d',0,'p','w',0,'s','t',0}` (`"id\0pw\0st\0"`, 9 octets → 0 bytes left for `interface_version`, so `readByte(interface_version)` on an empty slice is the genuine CODEC-022 throw site) and updated the golden vector `negative_body_shorter_than_fields.smpp` to the matching 9-octet body (raw-hex `00000019000000090000000000000004696400707700737400`); corrected the now-stale `BindConformanceTest:218` comment. `./gradlew :codec:test` GREEN — **81 tests / 0 fail / 0 skip** (count unchanged); path re-derived (0 bytes remain for the fixed fields after the three C-octets).

---

## Dev Notes

### What already exists (from Stories 1.1 + 1.4) — EXTEND, don't replace

- `codec/build.gradle.kts` — applies `smpp.java-conventions` + `smpp.null-safety` +
  `smpp.codec-purity`; deps: `netty-bom:4.2.16.Final` (platform), `netty-buffer` + `netty-codec`
  (`implementation`), `org.jspecify:jspecify:1.0.0` (`compileOnly`); test: JUnit BOM 6.0.3,
  `junit-jupiter`, AssertJ 3.27.7, ArchUnit 1.4.2. **Do not** remove/reorder the plugins; keep
  jspecify `compileOnly`.
- `codec/src/main/java/smpp/companion/codec/package-info.java` — already `@NullMarked` (root codec
  package). **New sub-packages each need their own `@NullMarked package-info.java`.**
- `codec/src/test/java/smpp/companion/codec/CodecIsolationArchitectureTest.java` — CODEC-039
  (`codec..` → no deps on `proxy..`). Trivially green today; **1.2 makes it load-bearing — do not weaken.**
- `codec/src/test/java/smpp/companion/codec/golden/GoldenVectorCorpusTest.java` — tagged
  `@Tag("unit") @Tag("codec") @Tag("p2")`; enforces the provenance header; has the explicitly-named
  deferred assertion to promote (AC5) and the `StringCaseLocaleUsage` site at line 67.
- `codec/src/test/resources/golden-vectors/README.md` — the provenance-header format spec
  (`# provenance: <ref> ; raw-hex: <lowercase hex>`); corpus is intentionally empty today.

### SMPP 3.4 wire-format reference (author golden vectors + parser from this)

**Authoritative spec on disk**: `docs/SMPP_v3_4_Issue1_2.pdf` (SMPP 3.4 Issue 1.2, 169pp). Read the
relevant sections directly from this local file — do **not** fetch the spec from the web. Key
sections: §5.1.2 (command_id table — source of truth for AC3 / decision #1); §4.1–§4.4 (PDU header
+ `command_length`); the bind-family PDU definitions (§4.1.1–§4.1.4) for golden-vector authoring
(AC5); and the `command_status` code table (`ESME_ROK = 0x00000000`, the bind-denial codes). The
summary below is a convenience extract; where it and the PDF disagree, **the PDF wins**.

- **Header — 16 octets, all unsigned big-endian:**
  `command_length[4] | command_id[4] | command_status[4] | sequence_number[4]`.
  `command_length` is the **total** PDU length (includes these 4 octets + the whole header + body).
  Min `16` (header-only PDU: `unbind`, `enquire_link`, `generic_nack`). Cap `65536` (AD-30; covers
  `message_payload` TLV max).
- **`command_id` (relevant subset):** `bind_receiver 0x00000001`, `bind_transmitter 0x00000002`,
  `bind_transceiver 0x00000009`, `*_resp = request | 0x80000000`, `unbind 0x00000006`,
  `enquire_link 0x00000015`, `submit_sm 0x00000004`, `deliver_sm 0x00000005`, `outbind 0x0000000B`,
  `generic_nack 0x80000000`. (Response bit = bit 31.)
- **`command_status`:** `ESME_ROK = 0x00000000`. Bind denials: `ESME_RINVPASWD 0x0000000E`,
  `ESME_RINVSYSID 0x0000000F`, `ESME_RINVSYSTYP 0x00000011`. (Zero in requests.)
- **Bind request body (after the 16-byte header):** `system_id` (C-octet, ≤16), `password`
  (C-octet, ≤9), `system_type` (C-octet, ≤13), `interface_version` (1 octet; `0x34` = SMPP 3.4),
  `addr_ton` (1), `addr_npi` (1), `address_range` (C-octet, ≤41).
- **`bind_*_resp` body:** `system_id` (C-octet, ≤16) + optional TLVs (e.g. `sc_interface_version`).
- **C-octet string:** NUL-terminated ASCII; the terminating `0x00` counts toward the max; empty
  string = a single `0x00`. (CODEC-020/021 exercise the edges + the unterminated case.)
- The codec parses **only** the bind family. All other PDUs are opaque framed `ByteBuf`s — no TLV
  parser, no non-bind body parser (AD-3/AD-32).

### Architecture compliance (the binding ADs)

- **AD-7** — codec is PURE (zero dep on relay/TLS/OIDC/config/metrics/app); direction `proxy → codec`
  strictly inward. Owns exactly three deliverables: `SmppFrameDecoder`, `SmppCodec` (bind branch),
  `SmppCommandIds.BIND_FAMILY`. [ARCHITECTURE-SPINE.md:97-113]
- **AD-2** — the framer emits the framed-`ByteBuf` splice unit (each PDU forwarded exactly once,
  boundaries preserved); `SmppCodec` stays safe to leave dormant in the pipeline post-couple (must
  not re-emit/mutate framed ByteBufs). [ARCHITECTURE-SPINE.md:72-76]
- **AD-24** — author a from-scratch conformance suite (no OSS suite exists); **structurally fuzz
  BOTH decoders**; jSMPP 3.0.2 is the interop-only independent oracle; the in-JVM mock SMSC is built
  ON the codec (Epic 2) — which is exactly why the golden corpus must be independent. [ARCHITECTURE-SPINE.md:205-208]
- **AD-25** — the relay flips on the **decoded** `bind_*_resp` `command_status == ESME_ROK`. The codec
  MUST expose this as a typed predicate; the relay never byte-peeks. Non-ROK `bind_resp` still
  decodes cleanly (no throw). [ARCHITECTURE-SPINE.md:210-213]
- **AD-27** — `SmppCommandIds.BIND_FAMILY` is the single source of truth, consumed (not redefined) by
  `relay/`; `outbind`/`generic_nack` are opaque; **the codec NEVER emits metrics** (no Micrometer
  anywhere in `smpp.companion.codec.*`). [ARCHITECTURE-SPINE.md:220-223]
- **AD-30** — `MAX_COMMAND_LENGTH = 65536` named constant; `<16`/`>65536`/overflow-class reject
  before allocation. The `MaxDirectMemorySize = max_frame × max_inbound_depth ×
  concurrent_pairs × safety_factor` formula + its config inputs are **Story 1.3**; 1.2 ships only
  the constant + the framing reject + the RELAY-026 stub. [ARCHITECTURE-SPINE.md:235-238]
- **AD-32** — codec contribution is narrow: bind family → typed; everything else → opaque; invalid
  `command_length` → AD-30 drop+close. The codec does **not** synthesize any `_resp` (bare-close is a
  relay concern). Header octets 4-7 (`command_id`) / 12-15 (`sequence_number`) may be read by the
  relay for case selection; body parsing of non-bind PDUs stays forbidden. [ARCHITECTURE-SPINE.md:245-252, :80]
- **AD-33** — the codec is not the wire-collapse author; it only exposes the ROK predicate and must
  NOT mutate SMSC-originated `generic_nack`/non-ROK `bind_resp` in transit. [ARCHITECTURE-SPINE.md:254-257]
- **AD-23** — no reflection-heavy patterns (`Class.forName`, `MethodHandle.invoke`, dynamic proxies,
  runtime-annotation dispatch). Pure data classes + explicit Netty handler wiring. [ARCHITECTURE-SPINE.md:200-203]
- **AD-35** — null-safety gate inherited from Story 1.4 (see below).

### Library / framework requirements (exact versions)

| Component | Version | Role |
|---|---|---|
| JDK | 25 (vendor not pinned; `--enable-preview` process-wide) | runtime/compile. Codec uses **no** preview APIs. |
| Gradle | 9.6.1 (wrapper) | build |
| Netty | 4.2.16.Final (`netty-bom`; `netty-buffer` + `netty-codec`) | `ByteBuf`, `ByteToMessageDecoder`, `ChannelHandler` |
| JSpecify | 1.0.0 (`compileOnly`) | `@NullMarked` / `@Nullable` |
| NullAway / Error Prone | 0.13.8 / 2.50.0 (`net.ltgt.errorprone` 5.1.0) | already wired by Story 1.4 |
| JUnit Jupiter | via BOM 6.0.3; AssertJ 3.27.7; ArchUnit 1.4.2 | unit/arch tests |
| jSMPP | `org.jsmpp:jsmpp:3.0.2` (`testImplementation`, **not** 2.3.11) | CODEC-031 oracle |
| Fuzz (default) | Jazzer `com.code-intelligence:jazzer-junit` (impl-selected) | CODEC-011/025 (decision #2) |
| jqwik | (impl-selected) `testImplementation` | CODEC-012/037/038 properties |
| JMH | `me.champeau.jmh` `0.7.3` plugin (in `proxy`; default JMH 1.37) | PERF-001..006 (decision #3 RESOLVED: `proxy/src/jmh`) |

Versions not pinned in the architecture are impl-selected; **the green build (AC10) is the
mutual-compat proof** — same discipline as Story 1.4. Record chosen versions in the Dev Agent Record.

### Null-safety gate + the JMH sourceSet (load-bearing gotcha — RESOLVED → option (a))

`smpp.null-safety` enforces NullAway at ERROR **only on `compileJava`**; every other JavaCompile
task (`compileTestJava`, and **`compileJmhJava`** for the new `proxy/src/jmh` sourceSet) lands in
the `else` branch and **silently bypasses NullAway** (`buildSrc/src/main/kotlin/smpp.null-safety.gradle.kts:32-37`).
**Resolution (decision #3, hardening add #2): option (a)** — extend the `mainCompile` predicate at
line 37 to `name == "compileJava" || name == "compileJmhJava"`. This widens ERROR-level NullAway to
the jmh sources only (no `compileJmhJava` task exists in codec, so zero collateral there) and
requires benchmark classes to be JSpecify-clean under `smpp.companion.*` (or excluded via
`NullAway:ExcludedPackages`).

### File structure requirements

- MAIN: `codec/src/main/java/smpp/companion/codec/<sub>/…` — suggested sub-packages `command`,
  `framer`, `bind` (+ a `pdu` model package if desired). Each carries its own
  `@NullMarked package-info.java`.
- TEST: `codec/src/test/java/smpp/companion/codec/<sub>/…` — unit + conformance + fuzz.
- RESOURCES: `codec/src/test/resources/golden-vectors/*.bin|*.smpp` (only these extensions are
  enumerated by the loader).
- JMH: `proxy/src/jmh/java/…` (decision #3 RESOLVED). `me.champeau.jmh` (`0.7.3`) is declared in
  `proxy/build.gradle.kts` (inline version, like proxy's other external plugins).
- Build edits: `codec/build.gradle.kts` (add test deps); `proxy/build.gradle.kts` (add
  `me.champeau.jmh` `0.7.3` + `proxy/src/jmh`); `buildSrc/.../smpp.null-safety.gradle.kts` (widen
  predicate to `compileJmhJava` — decision #3 hardening add #2). New gate logic (if any) goes
  in `buildSrc/.../smpp.<name>.gradle.kts` with a GradleTestKit positive control under
  `buildSrc/src/test/kotlin/smpp/companions/buildsrc/gates/`.

### Testing requirements / patterns to reuse

- **Netty `EmbeddedChannel`** for framer/parser unit tests (CODEC-001..023). For CODEC-034..036 use a
  **real loopback TCP socket pair** (java.net `Socket`/`ServerSocket` or `NioSocketChannel`) — NOT
  `ByteBuf` slices; only real TCP exercises segmentation/coalescing.
- **GradleTestKit + `withPluginClasspath()`** positive controls (the established pattern at
  `buildSrc/src/test/kotlin/smpp/companions/buildsrc/gates/`) — follow if any new gate is added; for
  every load-bearing config line, add a "remove this line → build now succeeds" mutation control.
- **Tagging** (match the existing tests): `@Tag("unit"|"fuzz"|"integration"|"conformance"|"perf")` +
  `@Tag("p0".."p3")` + `@Tag("codec")` + `@DisplayName`. Fuzz/perf are nightly-tier; PR tier is
  bounded/time-boxed.
- **No `Thread.sleep`**; deterministic only. No no-op tests inflating the green count.

### Previous-story intelligence

- **Story 1.1** established the substrate + the empty codec skeleton + the fail-closed gate pattern
  + the golden-vector directory/provenance convention. It explicitly deferred to 1.2: codec impl
  (framer/bind parser/`BIND_FAMILY`/fuzz/golden content/JMH), the `max_command_length` constant, and
  jSMPP wiring. [1-1-…md:134-137,144,174-179,244]
- **Story 1.4** wired the null-safety gate; the precompiled-script-plugin accessor gotcha (already
  handled — if adding a new buildSrc plugin that creates configs/extensions at apply time, expect the
  same `add(...)` + `ExtensionAware` lookup pattern); and the false-positive protocol for unannotated
  third-party code (Netty 4.2 is not `@NullMarked` — annotate call sites). [1-4-…md:103-114,172,202-203]
- Commit-message convention: `feat(codec): Story 1.2 SMPP 3.4 codec (framer + bind parser +
  command_id SoT) (AD-3/AD-7/AD-24/AD-27/AD-30)`, body lists per-AC evidence + any deviation,
  footer `Co-Authored-By: Claude <noreply@anthropic.com>`. Linear history on `master`; **branch off
  `master` before committing** if asked to commit.

### Latest tech information (Context7, 2026-07)

- **Netty 4.2 framing** — _SUPERSEDED 2026-07-28 (user-directed; see the FIXME-resolution entry in the
  Dev Agent Record): the framer is now a `LengthFieldBasedFrameDecoder` subclass, NOT a custom
  `ByteToMessageDecoder`._ `LengthFieldBasedFrameDecoder` does treat the length field as *bytes-following*
  by default, but `lengthAdjustment = -4` reconciles that with SMPP's total-length `command_length`
  (verified against the 4.2.16 source). The AD-30 reject-before-alloc policy is enforced via `maxFrameLength`
  (ceiling, strict `>` + `failFast`) + a `getUnadjustedFrameLength` override (the `< 16` floor); the
  reader-index discipline below is now LFBD's responsibility rather than hand-rolled. _(Original pre-switch
  note, kept for T3+ `EmbeddedChannel` context: when a custom `ByteToMessageDecoder` IS warranted — e.g. the
  bind parser — check `readableBytes()` before reading; return **without modifying the reader index** if a
  frame is incomplete; read the length via `in.getInt(in.readerIndex())` — never `getInt(0)`.)_
- **Jazzer (default fuzz lib)** — `@FuzzTest` + `FuzzedDataProvider`
  (`com.code_intelligence.jazzer.junit.FuzzTest` / `com.code_intelligence.jazzer.api.FuzzedDataProvider`);
  dep `com.code-intelligence:jazzer-junit`; fuzzing mode via `JAZZER_FUZZ=1 ./gradlew test`, plain
  `./gradlew test` runs seed/regression executions.
- **jqwik** — `@Property` + `@Forall` + `Arbitraries.*` for the CODEC-012/037/038 properties.
- **JMH (`me.champeau.jmh` `0.7.3`, applied in `proxy`)** — dedicated `proxy/src/jmh/java` sourceSet
  (the plugin's official model — isolation comes from the `jmhJar` fat JAR + JMH's forked JVM, not
  from module separation; decision #3 RESOLVED); `./gradlew jmh`; `benchmarkMode = ['thrpt']` for the
  ops/s bands; `@Benchmark`/`@State(Scope.Thread)`/`@Fork`/`@Warmup`/`@Measurement`; Blackhole the
  result/decoded object; `-prof gc` for allocation control. **Smoke-test on Gradle 9.6.1 / JDK 25**
  — the plugin's compat table certifies only through Gradle 8.0 and JMH 1.37's ASM is unverified on
  JDK 25 class files (bump `jmh { jmhVersion = ... }` if bytecode generation fails).

### Project Structure Notes

- Aligns with the two-module inward-only seam (AD-7). New sub-packages under
  `smpp.companion.codec.*` follow the spine's structural seed; no conflict with existing layout.
- **Out of scope** (do NOT do in 1.2): relay/splice/coupling (`proxy/relay/`, Epic 2); TLS/OIDC/
  JWKS/ROPC (`proxy/security/`, Epic 3); config matrix + AD-30 formula inputs + any `application.yml`
  keys (Story 1.3); `SpliceObserver` (Epic 2 seed / Epic 4 impl); full AD-22 shutdown body (Epic 4);
  PERF-1 throughput / end-to-end percentile table / idle-CPU-at-10K (Epic 6); native-image build
  (AD-23); AD-32 `_resp` synthesis + AD-33 deny-code pinning (relay/Epic 3).

### References

- Epic 1 goal + Story 1.2 scope: `epics.md:347-355`; sprint note `sprint-status.yaml:53-54`.
- Codec ADs: `ARCHITECTURE-SPINE.md` AD-7(:97-113), AD-2(:72-76), AD-24(:205-208), AD-25(:210-213),
  AD-27(:220-223), AD-30(:235-238), AD-32(:245-252), AD-33(:254-257), AD-23(:200-203), AD-35(:264-267).
- AC scenario catalog: `test-coverage-scenarios.md` CODEC-001..041 (:67-315), PERF-001..006 (:1393-1429).
- TEA handoff E1/S1: `smpp-companions-handoff.md:58` (risk map R3/R14/R26/R33 :92-104).
- Prior stories: `1-1-gradle-two-module-substrate-and-ci-scaffold.md`; `1-4-compile-time-null-safety-enforcement.md`.
- Deferred: `deferred-work.md` (AD-30 config inputs → 1.3; `StringCaseLocaleUsage` → fold in here).
- Existing skeleton: `codec/build.gradle.kts`; `codec/src/main/java/smpp/companion/codec/package-info.java`;
  `codec/src/test/.../CodecIsolationArchitectureTest.java`; `codec/src/test/.../golden/GoldenVectorCorpusTest.java`;
  `codec/src/test/resources/golden-vectors/README.md`.
- Gates: `buildSrc/src/main/kotlin/smpp.{java-conventions,codec-purity,null-safety}.gradle.kts`.

---

## Dev Agent Record

### Agent Model Used

glm-5.2[1m] (via Claude Code harness); effort=ultracode (xhigh + dynamic workflow orchestration).

### Debug Log References

- **RED→GREEN cycle (T1):** wrote `SmppCommandIdsTest` + `MaxCommandLengthContractTest` + the `command`
  `package-info.java` first; `./gradlew :codec:compileTestJava` → **25 errors** (`cannot find symbol
  SmppCommandIds`) = RED confirmed (tests genuinely depend on the impl). Implemented `SmppCommandIds`;
  `./gradlew :codec:build` → **BUILD SUCCESSFUL** = GREEN.
- **Gates re-verified with the new code:** `:codec:enforceDependencyAllowlist` → "CODEC-040 OK — codec
  classpath is {io.netty, org.jspecify} + JDK stdlib only"; ArchUnit CODEC-039 green against the new
  `smpp.companion.codec.command..` sub-package (no proxy deps); `compileJava` NullAway-clean (AD-35).
- **Test execution (verified, 0 skipped):** `SmppCommandIdsTest`=5, `MaxCommandLengthContractTest`=1,
  `CodecIsolationArchitectureTest`=1 — all green, no regressions in `codec`.

- **RED→GREEN cycle (T2):** wrote `framer/package-info.java` + `SmppFrameDecoderTest` (13 tests) first;
  `:codec:compileTestJava` → **cannot find symbol `SmppFrameDecoder`** = RED confirmed. Implemented
  `SmppFrameDecoder` (custom `ByteToMessageDecoder`: peek `getInt(readerIndex())`, AD-30 reject before
  alloc, `readRetainedSlice` zero-copy frame); first GREEN run → 12/13, 1 test-logic bug (CODEC-002's split
  loop asserted no-frame-after-first at `split==len`, where the first fragment IS the complete PDU) — fixed to
  uniformly assert exactly-one-byte-identical-frame across both writes at every split. Then GREEN (13/13).
- **Netty 4.2 API gotchas (caught red, not green-by-luck):** (a) `io.netty.channel.EmbeddedChannel` moved to
  `io.netty.channel.embedded` in 4.2 (was `io.netty.channel` in 4.1) — import fixed. (b) `NioEventLoopGroup`
  (io.netty.channel.nio) is `@Deprecated` in 4.2; the real-TCP harness switched to
  `MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory())`. Found via direct `javac -Xlint:deprecation`
  on the file (Gradle's lint config surfaced only the bare "Note: deprecated API" summary).
  `NioServerSocketChannel`/`NioSocketChannel` are NOT deprecated (still in `netty-transport`).
- **CODEC-010 (the load-bearing AD-30 case):** proved reject-before-allocation with a `RecordingAllocator`
  (wraps `UnpooledByteBufAllocator`, records the max requested capacity) — `0x7FFFFFFF`/`0x80000000`/
  `0xFFFFFFFF` all reject with `maxRequested ≤ MAX` (the cumulation only grew to the input size, never to the
  malformed length). The `< 16` floor catches the two negative overflow values (signed `getInt`); `0x7FFFFFFF`
  hits `> MAX` — the single guard the T1 review patch #1 prescribed.
- **CODEC-036 (real-TCP close-mid-PDU):** first attempt timed out — the latch awaits were OUTSIDE the
  try-with-resources, so the server was torn down (and the connection RST'd on close) before the read loop
  drained P1. Fixed by awaiting WHILE the server is alive (mirrors CODEC-034/035). `shutdownOutput()` → the
  server reads EOF → `channelInactive` (latched) → no truncated second frame (`decodeLast` default discards
  the partial cumulation).
- **Gates re-verified (T2):** CODEC-040 prints `{io.netty, org.jspecify, org.projectlombok}` (no new dep —
  the NIO classes live in `netty-transport`, already transitive of netty-codec; nothing added to
  `codec/build.gradle.kts`); CODEC-039 ArchUnit green against the new `..codec.framer..` package (now
  load-bearing); CODEC-041 + AD-35 green via the full `:buildSrc:test`. `compileJava` NullAway-clean + zero
  ErrorProne warnings (the one `FutureReturnValueIgnored` on `ctx.close()` is `@SuppressWarnings`'d with a
  reason — Netty's `ChannelFuture`, best-effort fail-closed close, AC9 third-party allowance).
- **Test execution (verified, 0 skipped, T2):** `SmppFrameDecoderTest`=13, `SmppFrameDecoderTcpTest`=3 — all
  green; full codec suite 26 tests (1+1+6+3+13+2) 0 fail / 0 skip, no regressions. `./gradlew clean build
  :buildSrc:test` GREEN (AC10).

### Completion Notes List

- **T1 complete — Command-id source-of-truth (AC3, AC4).** Delivered `SmppCommandIds` (`BIND_FAMILY` =
  the spec-correct 6-id set, `MAX_COMMAND_LENGTH = 65536` (AD-30), response-bit helpers `isResponse` /
  `requestIdOf` / `isBindFamily`) + `@NullMarked` `command/package-info.java`.
- **Spec reconciliation #1 APPLIED (not copy-paste):** `bind_transceiver = 0x00000009` /
  `bind_transceiver_resp = 0x80000009`, NOT the `0x0F` / `0x8000000F` asserted at
  `test-coverage-scenarios.md:221,241`. CODEC-026 asserts the corrected set; the jSMPP cross-oracle
  (CODEC-031, T5) will independently confirm `0x09` (`org.jsmpp.bean.CommandId.BIND_TRANSCEIVER`).
  **Correction logged here, not edited into the planning artifact** — the catalog is a planning doc;
  its CODEC-026/029 literals still read `0x0F`/`0x8000000F` upstream and are flagged for the next
  planning-docs pass (see `deferred-work.md`).
- **CODEC-027/028 scope split (transparent):** the *membership* clauses (outbind `0x0B` /
  generic_nack `0x80000000` / submit_sm·deliver_sm·enquire_link·unbind are NOT bind-family) are
  asserted at the SoT level here. The *parser-runtime* halves ("the bind parser emits no typed object
  for those ids") land with the bind parser in T3 — the parser consumes only `BIND_FAMILY`, so opacity
  is structural. Mirrored in the `SmppCommandIdsTest` javadoc.
- **RELAY-026 stub shipped (AC4):** `MaxCommandLengthContractTest` pins `MAX_COMMAND_LENGTH == 65536`
  and documents the AD-30 three-way contract (codec-constant ≡ formula-input ≡ config-default). The
  full assertion lands in Story 1.3 (config key + `MaxDirectMemorySize` formula); remainder logged to
  `deferred-work.md`.
- **No `// FIXME` markers introduced.** No new dependencies (`java.util.Set` + `org.jspecify` only —
  inside the CODEC-040 allowlist). The AC10 full `./gradlew clean build :buildSrc:test` is deferred to
  T8 (story completion); `:codec:build` is green for T1.
- **T1 code review (2026-07-27) — clean; 3 low patches applied, build green.** 3 parallel adversarial
  layers found no High/Med defects; the `0x09` spec reconciliation was verified correct against
  `docs/SMPP_v3_4_Issue1_2.pdf` §5.1.2 (`0x0F` = `ESME_RINVSYSID` status code). Applied: (1)
  `MAX_COMMAND_LENGTH` javadoc warns T2's framer about the signed-int `ByteBuf.getInt` pitfall (the
  `<16` floor is the guard); (2) `requestIdOf` javadoc caveats the generic_nack→`0` undefined case;
  (3) `SmppCommandIdsTest` +1 boundary test pinning the bit-31 predicate at `0x80000000`/`0x00000000`/
  `0xFFFFFFFF` (now 6 tests, 0 skipped, green). CODEC-039/040 + AD-35 still green; see `### Review Findings`.
- **FIXME resolved (2026-07-27) — `// FIXME: replace with lombok` → ADOPTED (user-directed).**
  Widened CODEC-040's `allowedGroups` to admit `org.projectlombok` (compile-time-only, mirroring
  `org.jspecify`); applied the `io.freefair.lombok` plugin (`9.5.0`; forward-compat to Gradle 9.6.1 —
  green build is the proof) in `codec/build.gradle.kts`, pinning Lombok `1.18.46` (JDK 25 support) via
  its `lombok { }` extension — the plugin wires `compileOnly` + `annotationProcessor` for every source
  set; applied `@lombok.experimental.UtilityClass` to `SmppCommandIds` (Lombok now makes it final +
  generates the private ctor). AD-7/AD-27 RUNTIME purity unchanged — lombok stays off runtimeClasspath
  (compileOnly); only the COMPILE allowlist grew. AD-23's runtime-annotation-dispatch ban is not
  triggered (Lombok is compile-time codegen). Verified: `./gradlew clean build :buildSrc:test` GREEN;
  CODEC-040 prints `{io.netty, org.jspecify, org.projectlombok}`; CODEC-041 +1 symmetric
  lombok-accepted control (6 tests); ErrorProne+NullAway coexist with Lombok on JDK 25. AC9 allowlist
  text + gate comment/messages updated to match.

- **T2 complete — `SmppFrameDecoder` length-framing (AC1; AD-2/AD-7/AD-30).** Delivered a custom
  `ByteToMessageDecoder` (NOT `LengthFieldBasedFrameDecoder` — SMPP's `command_length` is the TOTAL PDU
  length, not bytes-following): peeks `in.getInt(in.readerIndex())` without advancing the reader index,
  waits for the full body, emits one zero-copy `readRetainedSlice` frame per PDU (the AD-2 forward unit),
  and loops naturally for coalesced PDUs. AD-30 reject-before-alloc (`< 16 || > MAX`, the floor catching
  every overflow-class negative signed-int) throws a `DecoderException`; `exceptionCaught` fires it
  downstream (CODEC-013 observability) then `ctx.close()` (drop + close, AC1). + `@NullMarked`
  `framer/package-info.java`.
- **CODEC-011/012 scope split (transparent):** CODEC-011 (Jazzer framer fuzz) and CODEC-012 (jqwik
  chunking property) are Level `fuzz`, mapped to AC7, and land in **T6** with the fuzz/property libraries
  (no Jazzer/jqwik dep yet). T2 owns the deterministic framer proof: CODEC-001..010, 013, 014, 015
  (`EmbeddedChannel`) + CODEC-034..036 (real loopback TCP). The CODEC-011/012 invariants (no Throwable
  escapes decode; chunk-invariance) are structurally pre-supported by the defensive decode (bounds-checked,
  framework-contained throws).
- **No new dependencies.** The real-TCP harness needs `NioServerSocketChannel`/`NioSocketChannel`/
  `MultiThreadIoEventLoopGroup` — all in `netty-transport` (already transitive of netty-codec). Nothing
  added to `codec/build.gradle.kts`; CODEC-040 allowlist unchanged.
- **Netty 4.2 reconciliation (act, don't carry over):** `NioEventLoopGroup` is `@Deprecated` (→
  `MultiThreadIoEventLoopGroup` + `NioIoHandler`); `EmbeddedChannel` is in `io.netty.channel.embedded`.
  Recorded here so T3+ (bind parser on `EmbeddedChannel`) reuse the corrected imports.
- **AC1 fully met** (every CODEC-001..010/013/014/015 + 034..036 clause asserted, 0 skipped); story stays
  `in-progress` (T3–T8 pending). AC10 `./gradlew clean build :buildSrc:test` GREEN.
- **FIXME resolved (2026-07-28) — `// FIXME: use LengthFieldBasedFrameDecoder` → SWITCHED to an LFBD
  subclass (user-directed; supersedes T2's "NOT `LengthFieldBasedFrameDecoder`" directive and the
  "Latest tech information" Netty-framing bullet below).** The note's `{offset=0,len=4,adjust=-4,strip=0}`
  recipe was verified against the actual Netty 4.2.16 `LengthFieldBasedFrameDecoder` source (Context7 +
  decompiled class): `lengthAdjustment = -4` reconciles LFBD's default "bytes following the field" with
  SMPP's total-length `command_length`, so LFBD frames SMPP correctly. The AD-30 policy maps onto two LFBD
  hooks, BOTH firing before the only happy-path slice (`extractFrame`): the **ceiling** is LFBD's native
  `maxFrameLength` (strict `>` → `==65536` accepted / `65537` rejected — CODEC-008; `failFast` throws
  `TooLongFrameException` before the body is read/allocated, so overflow-class `0x7FFFFFFF/0x80000000/
  0xFFFFFFFF` reject with no oversized alloc — CODEC-006/010/015; LFBD reads UNSIGNED so overflow is caught
  by the ceiling, not the floor — contrast the prior custom decoder's signed-`getInt` floor trick, same
  outcome); the **floor** is a `getUnadjustedFrameLength` override that throws a `DecoderException` on
  `command_length < 16` (the earliest length read, after the 4-byte-present guard — CODEC-005).
  `exceptionCaught` (fire + `ctx.close()`) is unchanged. Verified: `:codec:build` GREEN;
  `SmppFrameDecoderTest`=13, `SmppFrameDecoderTcpTest`=3 — **0 fail / 0 skip**; CODEC-040 still
  `{io.netty, org.jspecify, org.projectlombok}` (LFBD ∈ netty-codec — no new dep); zero `// FIXME` in
  source (AC9). Files: `SmppFrameDecoder.java` (rewritten), `framer/package-info.java` (doc updated).
- **FIXME resolved (2026-07-28) — `// FIXME: move to SmppCommandIds near MAX_COMMAND_LENGTH` → DONE.**
  Moved `MIN_COMMAND_LENGTH = 16` from `SmppFrameDecoder` (package-private) to `SmppCommandIds`
  (`public static final int`, immediately before `MAX_COMMAND_LENGTH`) so the AD-30 `{min, max}` bounds
  share one source of truth (AD-27/AD-30). The decoder now references `SmppCommandIds.MIN_COMMAND_LENGTH`
  in both the `getUnadjustedFrameLength` floor check and its javadoc. **Also corrected a stale note** left
  by the LFBD switch: the `MAX_COMMAND_LENGTH` "Framer handoff note" still described the *prior* custom
  decoder's signed-`getInt` floor catching overflow — under the LFBD subclass the framer reads unsigned
  (`getUnsignedInt`), so overflow is caught by the `maxFrameLength` *ceiling*, not the floor; rewritten to
  state the accurate mechanism (signed-int pitfall preserved as contrast). No test changes (tests use their
  own `HEADER=16` PDU-builder constant, untouched); `:codec:build` GREEN, 26 tests 0 fail/skip; CODEC-040
  unchanged; zero `// FIXME` in source (AC9).
- **T2 code review (2026-07-28) — applied all 3 CONFIRMED patches (low / test-quality); the framer product code
  was already correct (verified against Netty 4.2.16 bytecode; no AC1/AD violation).** (1) **CODEC-013** —
  replaced the stale `// reads as -1 (signed getInt)` comment with the LFBD reality (unsigned `getUnsignedInt` →
  4294967295, rejected by the `maxFrameLength` ceiling, not the `<16` floor). (2) **CODEC-010** — made the
  load-bearing reject-before-allocation proof MEANINGFUL: a single `writeInbound` of an `Unpooled.buffer` bypasses
  `ctx.alloc()` (MERGE_CUMULATOR returns the input directly when the cumulation is empty + contiguous), leaving
  `maxRequested==0` so the old `maxRequested<=MAX` held for any decoder. Added an allocator-aware `declaringLength`
  overload and routed the CODEC-006/008/010/015 reject-path inputs through `ctx.alloc()`; the bound is now
  `<= actual input size` (HEADER + filler), proving no allocation was driven by the malformed length. (3) **CODEC-015**
  — replaced the vacuous PARANOID + `finishAndReleaseAll` leak assertion (PARANOID only `logger.error`s at GC;
  `finishAndReleaseAll` can't throw on an orphaned slice) with a real guard: `RecordingAllocator.allocationCount()==1`
  on the reject path (the framer allocated nothing beyond the test input → nothing to leak). Tight bounds verified
  empirically — `maxRequested == input size` (MERGE_CUMULATOR short-circuits, no cumulation alloc),
  `allocationCount == 1`. `:codec:build` GREEN; framer 16 tests (13+3) 0 fail/skip; CODEC-040 unchanged. Story
  stays in-progress (T3–T8 pending; this was a task-level review, not the story-completion CR).

- **T3 complete — `SmppCodec` bind parser + typed bind PDU model + encoder (AC2, AC6; AD-3/AD-7/AD-12/
  AD-25/AD-27/AD-32).** _Type/suppression note: the field types, helper class name, and suppression mentions
  in this entry reflect the INITIAL T3 state (password `char[]`, C-octet fields `byte[]`, helper `CoctetStrings`,
  `ArrayRecordComponent` suppressions). They are SUPERSEDED by the "FIXME resolved (2026-07-28)" entry below —
  password + ALL C-octet fields are `AsciiString`, the helper is `SmppBytes`, and both records are array-free
  (no suppressions). Read this entry as the pre-refactor snapshot._
  Delivered `smpp.companion.codec.bind`: a sealed `SmppBindPdu` (permits
  `SmppBindRequest` / `SmppBindResponse`) carrying the header (`commandId`/`commandStatus`/`sequenceNumber`)
  + a retained, byte-exact `originalFrame()` (the AD-2 forward unit); `SmppBindResponse.isOk()` is the AD-25
  ROK predicate, placed on the response ONLY (a request carries status 0 == ROK, so a shared predicate would
  be a splice footgun). `SmppCodec extends MessageToMessageDecoder<ByteBuf>` sits one hop after the framer;
  it parses `BIND_FAMILY` only (opacity is structural — every other `command_id` is forwarded as the untouched
  framed `ByteBuf` via `buf.retain()`, AD-3/AD-32). The parse is non-mutating (CODEC-037): header via absolute
  `getInt`, body via an UNRETAINED `slice`, so the input's content + reader index are never touched; the
  original is `retainedSlice`'d ONLY after the whole body parses → a malformed-body throw retains nothing
  (no reject-path leak). A package-private `CoctetStrings` does the bounded C-octet scan (finite
  `[readerIndex, writerIndex)` range → CODEC-021 no over-read / no spin; bounds-checked fixed-field reads →
  CODEC-022 no AIOOBE), and the symmetric encode. _(Password / C-octet field types: see the superseding FIXME-resolution note below.)_ `SmppBindEncoder`
  is a static utility (offline — AD-32 forbids hot-path reserialise) for the CODEC-032 round-trip. + `@NullMarked`
  `bind/package-info.java`.
- **Two design forks locked with the user (AskUserQuestion, 2026-07-28):** (1) **password = `char[]`**
  _(initial decision — SUPERSEDED 2026-07-28 by the user's `DO use AsciiString password`; see the FIXME-resolution
  entry below: the password is now an `AsciiString`, zeroization via `array()` is fragile due to the `toString()`
  cache)_ — the Java credential convention + the CODEC-024/PRIV-1 zeroization seam (`Arrays.fill(pw,'\0')`);
  decoded from the
  ASCII C-octet bytes via US_ASCII (high-bit/non-ASCII password octets map to `'?'` — an accepted lossy tradeoff,
  documented at `CoctetStrings.chars`). (2) **sealed `SmppBindPdu` hierarchy** — `SmppBindRequest` (all body
  fields) / `SmppBindResponse` (`systemId` only; TLV tail stays in `originalFrame`, AD-3) — no `@Nullable` body
  fields under `@NullMarked`. Other C-octet fields (`systemId`/`systemType`/`addressRange`) — kept as lossless
  `byte[]` initially, later unified to `AsciiString` (SUPERSEDED — see the FIXME-resolved note below; non-ASCII
  octets preserved, not lossy `String`).
- **Tests (verified, 0 skipped):** `SmppCodecTest`=18 (CODEC-016 transceiver-decode-all-fields; 017 ×3 the three
  request types; 018 ROK-true; 019 non-ROK-false; 020 all-empty + spec-max-length; 021 unterminated→reject
  bounded; 022 truncated→reject; 023 header-parses-with-junk-body; 028 ×6 non-bind opaque pass-through incl.
  outbind/generic_nack; 037 byte-exact + reader-index-restored) + `SmppBindEncoderTest`=2 (encode→exact-wire-bytes
  + decode(encode(·)) symmetry). Every bind PDU is hand-authored from the spec (raw `ByteBuffer`) — never
  codec-synthesised (R14/R33). Full codec suite 46 tests, 0 fail / 0 skip, no regressions.
- **Gates (T3):** CODEC-039 ArchUnit green against the new `..codec.bind..` package (no proxy deps — now
  load-bearing); CODEC-040 unchanged `{io.netty, org.jspecify, org.projectlombok}` (no new dep — `MessageToMessageDecoder`
  ∈ netty-codec); `compileJava` NullAway-clean (AD-35); zero `// FIXME` (AC9). ErrorProne `ArrayRecordComponent`
  — initially ×5 on the `byte[]`/`char[]` record components, but **fully resolved** once every C-octet field
  (incl. the password) became an `AsciiString` (both records array-free → all such suppressions removed; see
  the FIXME-resolution note below). Only the pre-existing deferred `StringCaseLocaleUsage` warning remains
  (AC5/T4 owns it).
- **CODEC-024 scope note (transparent):** the password accessor is `AsciiString` (revised 2026-07-28 — see the FIXME-resolved note below; the return-type half of CODEC-024 is
  proven — CODEC-016 compiles + asserts on `req.password()` as an `AsciiString`); the deeper ASM "no `java.lang.String`
  constructed from the password octets" bytecode-scan half is P2 and needs an `org.ow2.asm` testImplementation —
  it is NOT in T3's listed test set and is deferred (the design supports it; surface for T6/confirmation). The
  full CODEC-032 golden-corpus round-trip lands in T5 (jSMPP) + T4 (corpus); T3 ships the encoder + a hand-built
  round-trip. CODEC-025 (bind fuzz) / CODEC-038 (opaque jqwik) are fuzz-tier → T6. **AC2 is substantially met by
  T3** (every parser clause asserted); story stays `in-progress` (T4–T8 pending).

- **FIXME resolved (2026-07-28) — three themes the dev marked across the T3 source, addressed:**
  - **`use AsciiString` (ADOPTED for ALL C-octet fields — user-directed, 2026-07-28):** every C-octet field,
    INCLUDING the password, is now Netty `io.netty.util.AsciiString` (∈ netty-common, already transitive on the
    codec classpath → CODEC-040 unchanged) — a lossless `CharSequence` over the raw bytes (high-bit octets
    preserved), zero-conversion to `ByteBuf`, and NOT an array (kills every `ArrayRecordComponent` warning — both
    records are array-free → all such suppressions removed; the `@SuppressWarnings` on `SmppBindRequest` is gone).
    **The password was initially kept `char[]` (the CODEC-024 zeroization seam); the user then directed
    `DO use AsciiString password`, overriding that for full type-uniformity.** This revises CODEC-024/AC2: the
    accessor is an `AsciiString`, not `char[]`/`byte[]`. Zeroization is still *possible* — `AsciiString.array()`
    exposes the backing `byte[]` for `Arrays.fill(pw.array(), pw.arrayOffset(), pw.arrayOffset()+pw.length(),
    (byte)0)` — but FRAGILE: `AsciiString` lazily caches `toString()`, so a `password.toString()` call leaves a
    `String` copy that survives a backing-array wipe (callers must avoid `toString()` on the password). The deferred
    CODEC-024 P2 bytecode scan will assert the AsciiString form + this caveat rather than a `char[]` return type.
    `CoctetStrings` is simplified to `readAscii` (→ `AsciiString`, every field) + a lossless zero-alloc
    `write(ByteBuf, AsciiString)` via `array()`/`arrayOffset()`/`length()`; the `char[]` password read/write paths
    were removed.
  - **`use MIN_COMMAND_LENGTH` (ADOPTED):** `SmppCodec` + `SmppBindEncoder` now reference
    `SmppFrame.MIN_COMMAND_LENGTH` (moved out of `SmppCommandIds` → `SmppFrame` — frame-length bounds ≠ `command_id`s;
    T3 review-refactor 2026-07-29; the 16-octet command header IS the minimum legal PDU — a header-only PDU)
    instead of local `HEADER = 16` literals; the bind package no longer redefines the `16`.
  - **`create const for comparison` (ADOPTED):** added `SmppCommandIds.INTERFACE_VERSION_3_4 = 0x34` (SMPP 3.4
    §4.1.1); referenced in the `SmppBindRequest.interfaceVersion` javadoc, the encoder, and the tests (replacing
    the `0x34` literals).
  - **Test-side note:** `assertThat(asciiString)` is ambiguous in AssertJ (`AsciiString` is both `CharSequence` and
    `Comparable`, matching both `assertThat(CharSequence)` and `<T>assertThat(T extends Comparable)`); the AsciiString
    assertions cast to `(CharSequence)` to pick the content-`.equals` overload. `:codec:build` GREEN; 46 tests
    0 fail / 0 skip; zero `// FIXME`; CODEC-040 unchanged; `ArrayRecordComponent` fully resolved (no array
    components remain — no suppression anywhere).

- **T4 complete — Spec-derived golden-vector corpus (AC5; CODEC-030).** Populated `codec/src/test/resources/golden-vectors/`
  with **6 positive** bind-family vectors (all three request types — `bind_transceiver` all-fields,
  `bind_transmitter` all-empty, `bind_receiver` all-fields — plus `bind_receiver_resp` ROK,
  `bind_transceiver_resp` ROK + `sc_interface_version` TLV, and a non-ROK `bind_receiver_resp`
  `ESME_RINVPASWD` that decodes clean with `isOk()=false` per AD-25/CODEC-019) and **5 negative** vectors
  (length<16 / length>65536 / truncated-header / unterminated-C-octet / body-shorter-than-fields), each
  tagged with its expected reject outcome. Each vector is a one-line text file: first line is the provenance
  header `# provenance: <§ref> ; raw-hex: <lowercase hex>` (+ optional ` ; reject: CODEC-…` for negatives);
  the `raw-hex` IS the wire bytes, decoded by the loader via `java.util.HexFormat` (one source, diff-stable,
  no header/body drift). Authored independently of the codec — no vector is produced by invoking
  `SmppCodec`/`SmppBindEncoder` (R14/R33). Promoted `GoldenVectorCorpusTest`: the deferred scaffold
  assertion → a real `assertThat(corpus).isNotEmpty()` + a per-vector provenance assertion (parseable
  lowercase hex; positive vectors are length-self-consistent — `command_length == byte count`, AD-30 bounds,
  bind-family `command_id` via `SmppCommandIds.isBindFamily`; negative vectors carry a `CODEC-…` reject tag).
  Folded the deferred `StringCaseLocaleUsage` fix (`.toLowerCase()` → `.toLowerCase(Locale.ROOT)` at the
  `listVectors` filename filter) — entry cleared from `deferred-work.md`. RED→GREEN observed (corpus-empty →
  `corpusIsNonEmpty` FAILED → vectors authored → GREEN). **Tests (verified, 0 skipped):** `GoldenVectorCorpusTest`=3
  (was 2; +1); full codec suite **47** tests, 0 fail / 0 skip. **Gates (T4):** CODEC-039/040 + AD-35 green;
  CODEC-040 unchanged `{io.netty, org.jspecify, org.projectlombok}` (no new dep — corpus is test resources +
  a test class using only `HexFormat`/`SmppCommandIds`/`SmppFrame`, all already on the classpath); zero
  `// FIXME` (AC9); zero ErrorProne warnings (the last one, `StringCaseLocaleUsage`, is resolved). `:codec:build`
  GREEN (AC10 full `clean build :buildSrc:test` stays deferred to T8). **AC5 fully met by T4**; the
  field-by-field jSMPP cross-oracle (CODEC-031/033) lands in T5. Story stays `in-progress` (T5–T8 pending).
- **T5 complete — jSMPP cross-oracle conformance (AC6; CODEC-031, CODEC-032, CODEC-033).** Declared
  `org.jsmpp:jsmpp:3.0.2` as `testImplementation` on `codec` (interop-only, NEVER production). Its sole
  transitive (`org.slf4j:slf4j-api`) is test-scoped too, so the CODEC-040 main classpath gate stays
  `{io.netty, org.jspecify, org.projectlombok}` + JDK (the gate scans `compileClasspath`/`runtimeClasspath`,
  NOT test) — AD-7/AD-27 runtime purity unchanged. Verified by decompiling jSMPP 3.0.2 that
  `DefaultDecomposer.bind(byte[])`/`bindResp(byte[])` take the FULL PDU (16-octet header + body) and read
  system_id/password/system_type/interface_version/addr_ton/addr_npi/address_range (the exact set to compare).
- **CODEC-031 — codec decode == jSMPP decode, field-by-field (6 positives).** `BindConformanceTest.codecDecodeAgreesWithJsmpp`
  decodes each golden positive through the real `SmppFrameDecoder → SmppCodec` pipeline AND via jSMPP, asserting
  command_id/command_status/sequence_number + every body field (system_id/password/system_type/interface_version/
  addr_ton/addr_npi/address_range on requests; +system_id on responses; TLV tail intentionally opaque — AD-3).
  **Cross-oracle surfaced a real representation difference:** jSMPP's `readCString` returns `null` for an EMPTY
  C-octet string (single NUL, SMPP §3.1), whereas the codec decodes it as an empty `AsciiString`; both are
  spec-faithful — normalized via `expectedAscii(jsmppValue == null ? "" : …)` (no `toString()` on the password,
  CODEC-024). This is exactly the independent-agreement falsification CODEC-031 exists for. Closes the deferred
  "no per-vector command_id pin" (jSMPP keys on command_id and pins every field per vector).
- **CODEC-032 — codec encode reproduces the golden wire bytes byte-for-byte (3 requests).** decode →
  `SmppBindEncoder.encode` → `assertThat(bytes).isEqualTo(golden)` (no command_length drift, no field reorder,
  correct NUL terminators). Corpus-scale decode/encode round-trip, stronger than T3's single-vector test.
- **CODEC-033 — every golden negative rejects/awaits as tagged through the REAL pipeline (5 negatives).**
  `BindConformanceTest.negativeVectorRejectsAsTagged` feeds each negative through `SmppFrameDecoder → SmppCodec`
  and asserts per-vector: CODEC-005/008 → framer reject (DecoderException, no frame); CODEC-009 (12-octet
  header declaring 26) → framer WAITS (no cause, no partial frame — clean); CODEC-021/022 → framer emits the
  length-self-consistent frame, the PARSER rejects. No negative ever surfaces a typed `SmppBindPdu` (the T4
  "tag never tied to the bytes" concern — now falsified). jSMPP is the POSITIVE oracle only; it assumes
  well-formed input, so its negative behavior isn't a spec oracle (documented in the test).
- **Shared `GoldenVectors` loader extracted** (T4 review patch #1): the corpus parser moved out of
  `GoldenVectorCorpusTest` into a package-private `GoldenVectors` utility with the reject-marker search SCOPED
  to after the raw-hex marker (`indexOf(REJECT_MARKER, hexStart)`), closing the unscoped-`indexOf`/`StringIndexOutOfBounds`
  finding. `GoldenVectorCorpusTest` now consumes the loader (CODEC-030 substance preserved). The `Vector` record
  stores hex (not `byte[]`) to stay array-free (ErrorProne `ArrayRecordComponent` runs on test compiles too).
  T4 review patch #2 (stale `:67` cite) resolved — AC5 :186 now cites `GoldenVectors.java`.
- **RED→GREEN (T5):** CODEC-031 first run NPE'd on 3 request vectors — jSMPP's null-for-empty (above), fixed by
  `expectedAscii`. CODEC-032/033 were green first run. AsciiString/AssertJ ambiguity resolved with
  `(CharSequence)` casts (the T3-known gotcha).
- **Tests (verified, 0 skipped):** `BindConformanceTest`=14 (6× CODEC-031 [3 req + 3 resp] + 3× CODEC-032 +
  5× CODEC-033), `GoldenVectorCorpusTest`=3 (refactored); full codec suite **61** tests, 0 fail / 0 skip.
  `./gradlew clean build :buildSrc:test` GREEN (AC10). **Gates (T5):** CODEC-040 unchanged
  `{io.netty, org.jspecify, org.projectlombok}` (jSMPP test-scoped → off the main classpath); CODEC-039/041 +
  AD-35 green; zero `// FIXME` (AC9); zero ErrorProne warnings on test compile. **AC6 fully met by T5**; story
  stays `in-progress` (T6–T8 pending).

- **T6 complete — Fuzz + jqwik properties (AC7; AD-24).** Delivered CODEC-011/025 (Jazzer `@FuzzTest`) +
  CODEC-012/037/038 (jqwik `@Property`) on `codec`. Deps `com.code-intelligence:jazzer-junit:0.24.0` +
  `net.jqwik:jqwik:1.10.1`, both `testImplementation` ONLY → off the MAIN classpath → CODEC-040 stays
  `{io.netty, org.jspecify, org.projectlombok}` (AD-7/AD-27 runtime purity unchanged; the gate scans MAIN,
  not test). Both engines execute on the project's NATIVE JUnit Platform 6.0.3 — **NO downgrade needed**.
- **CODEC-011 (Jazzer framer fuzz):** `SmppFrameDecoderFuzzTest.fuzzFramer(byte[])` — arbitrary byte stream;
  invariants: no Throwable escapes `writeInbound` (R3), bounded memory (a `RecordingAllocator` capturing
  ONLY the framer's own allocations proves none exceed `MAX × 2` — the small factor covers Netty cumulation
  growth), and any framer-driven close is a controlled `DecoderException`. Regression-mode seed corpus on the
  PR tier; `JAZZER_FUZZ=1` continuous nightly.
- **CODEC-025 (Jazzer bind-parser fuzz):** `SmppCodecFuzzTest.fuzzBindParser(FuzzedDataProvider)` — valid
  16-byte header with a bind-family `command_id` + arbitrary body (length-capped so the framer forwards a
  frame and the parser — not the framer — is the exercised surface); invariants: no Throwable escapes, and
  any captured cause is a `DecoderException` (never `IndexOutOfBounds`/AIOOBE/NPE = no read past the frame
  limit — exactly what the bounded NUL scan + bounds-checked reads guarantee, generalized).
- **CODEC-012/037/038 (jqwik properties):** `SmppFrameDecoderPropertyTest` (CODEC-012: any chunking of a
  valid PDU reassembles to the identical single frame — generalizes CODEC-002), `SmppCodecForwardingPropertyTest`
  (CODEC-037: parsing a bind request leaves the ORIGINAL frame byte-identical + un-mutated, AD-12), and
  `SmppCodecOpaquePropertyTest` (CODEC-038: opaque non-bind PDUs forward byte-identical with no typed object,
  AD-3). jqwik default 1000 tries each on the PR tier.
- **Decision #2 (Jazzer vs JQF) RESOLVED — Jazzer for fuzz, jqwik for properties, BOTH working on Platform
  6.0.3.** The story's "Read first" #2 (fuzz lib) and AC7 ("default Jazzer for fuzz + jqwik for properties")
  are met as-written; no deviation.
- **⚠️ jqwik silent-skip gotcha (LOAD-BEARING — the T6 investigation's key finding, 2026-07-31):** a Jupiter
  `@DisplayName` OR `@Tag` annotation on a jqwik `@Property` method makes jqwik **discover the method but
  SILENTLY SKIP execution** — the build stays GREEN with a no-op test (a trap that evades AC9/AC10's "no
  skipped/no-op tests" rule). Verified across JUnit Platform 6.0.3 AND 1.14.4, with/without `--enable-preview`,
  with/without `--add-opens`, and with jqwik as the SOLE engine — the skip is annotation-driven, not
  platform/JDK-driven. Fix: every `@Property` method carries NO Jupiter annotations; the display name + tier
  `@Tag`s live at the CLASS level (which jqwik honors), and CODEC-037 (unit) vs CODEC-038 (fuzz) are split
  into separate classes so each keeps its tier tag. (Jazzer `@FuzzTest`, regression-mode via the Jupiter
  engine, is unaffected.) Recorded so T7+ never repeats the trap.
- **Investigation trail (kept for the record):** jqwik initially appeared to skip on Platform 6.0.3 →
  misdiagnosed as a Platform-6 incompatibility → codec was temporarily downgraded to `junit-bom:5.14.4`
  (Platform 1.14.4 = jqwik's declared target) → STILL skipped → user insight (`@DisplayName` on `@Property`)
  → repro'd that BOTH `@DisplayName` AND `@Tag` cause the skip → jqwik runs on native Platform 6.0.3 once the
  annotations are removed → **the downgrade was reverted** (BOM back to 6.0.3; buildSrc + proxy untouched).
  The "jqwik needs Platform 1.14.4 / is JDK-25-incompatible" hypotheses were WRONG — the cause was the
  Jupiter annotations on `@Property`. (jqwik's engine is `net.jqwik.engine.JqwikTestEngine`; Jazzer has no
  separate engine ID — its `@FuzzTest` runs via the Jupiter engine in regression mode.)
- **Tests (verified, 0 skipped):** full codec suite **66** tests, 0 fail / 0 skip / 0 errors (was 61 after T5;
  +5 AC7: CODEC-011/012/025/037/038). **Gates (T6):** CODEC-040 unchanged `{io.netty, org.jspecify,
  org.projectlombok}` (jqwik + Jazzer test-scoped); CODEC-039/041 + AD-35 green; zero `// FIXME` (AC9); zero
  ErrorProne warnings on test compile. `./gradlew clean build :buildSrc:test` GREEN (AC10). **AC7 fully met
  by T6**; story stays `in-progress` (T7 JMH, T8 finalize pending).

- **T7 complete — JMH codec microbenchmarks (AC8; PERF-001..006; AD-7/AD-27).** Applied `me.champeau.jmh`
  `0.7.3` in `proxy/build.gradle.kts` (jmh sourceSet at `proxy/src/jmh/java`, decision #3 RESOLVED); pinned
  `jmhVersion = 1.37`; set `includeTests = false` (benchmarks depend ONLY on the pure codec, AD-7 — never on
  test sources — and this breaks the test↔jmh cycle the T7-c `testImplementation(jmh.output)` edge would
  otherwise create with the plugin's default `includeTests = true`). **Smoke test PASSED on Gradle 9.6.1 /
  JDK 25** (`./gradlew :proxy:jmh` GREEN in ~35s): the flagged "JMH 1.37 ASM unverified on JDK-25 class
  files" risk did NOT materialize — the bytecode generator (`jmhRunBytecodeGenerator`, which the Context7
  docs confirm runs `org.openjdk.jmh.generators.bytecode.JmhBytecodeGenerator` over the compiled `.class`)
  handled the JDK-25 class files cleanly; **no `jmhVersion` bump needed**. The `jmh` task chain is NOT wired
  into `build`/`check` (nightly-tier, AC8); only `compileJmhJava` (plain javac) is pulled into `:proxy:test`.
- **PERF spec reconciliation (act, don't ask — same class as reconciliation #1):** PERF-001/002 name
  `submit_sm`, but the codec is BIND-ONLY (AD-3/AD-7/AD-32 — `SmppCodec` parses only `BIND_FAMILY`;
  `SmppBindEncoder` is the codec's only encode path; there is no submit_sm encoder/typed-decode). AC8 pins
  "input = golden-vector bytes" while AC5 makes the golden corpus bind-only (**zero** submit_sm vectors
  exist) — so PERF-001/002 bench the codec's REAL surfaces: `SmppBindEncoder.encode` (PERF-001) and
  `SmppCodec.decode` (PERF-002) on the golden `bind_transceiver` all-fields vector. PERF-003 honors
  `submit_sm` literally where it IS valid — framing is PDU-agnostic (the framer reads only `command_length`),
  so a submit_sm-shaped opaque PDU is the per-PDU hot path it frames. (Catalog `test-coverage-scenarios.md`
  PERF-001/002 literals still read `submit_sm` upstream — flagged for the next planning-docs pass.)
- **Measured throughput (Temurin 25.0.3; ops/s/core = ops/µs × 10⁶; `@Fork(2)` `@Threads(1)`):** PERF-001
  encode = **8.5×10⁶ ±0.50** ops/s/core; PERF-002 decode = **6.5×10⁶ ±0.18** ops/s/core; PERF-003 framing =
  **10.2×10⁶ ±0.38** ops/s/core. **The encode/decode numbers EXCEED the AC8 bands (3×10⁵–1.5×10⁶ /
  5×10⁵–1.8×10⁶)** — expected, NOT a defect: the bands were sized for the heavier `submit_sm` encode/decode
  the PERF doc assumed; bind-family encode/decode is structurally lighter (7 fixed fields, no TLV parse), so
  it is faster. The codec-capability characterization holds well above any floor; per the PERF overclaim-
  warning the absolute number is codec-only/no-I/O (never relay msg/s). Bands are characterization targets,
  not CI gates.
- **PERF-005 (fork-to-fork variance):** `frameSubmitSm` stdev 0.135 / mean 10.151 → **CoV 1.3%** (encode/
  decode analogous — ±-error half-widths ≈3–6% at 99.9% CI → stdev/mean ≈1%); all well under the 5% gate.
- **PERF-004 (-prof gc, per-op allocation controlled):** ran with `profilers = [gc]` (temp) —
  `encodeBindRequest` **172.3 ±0.13 B/op** (the single framed ByteBuf), `decodeBindRequest` **448.0 B/op**
  (the typed PDU object graph: record + AsciiString fields — zero scratch ByteBufs), `frameSubmitSm`
  **104.0 ±0.001 B/op** (one retainedSlice). Rock-stable across all 6 iterations → no per-op scratch/leak.
  (Config reverted to no-profilers so default throughput runs stay clean; PERF-006 is the durable guard.)
- **PERF-006 (UNIT allocation guard — codec test, P2):** `CodecAllocationGuardTest` wraps a
  `CountingAllocator` (extends `AbstractByteBufAllocator`, counts `newHeapBuffer`/`newDirectBuffer` — slice/
  duplicate views do NOT route there): encode drives **exactly 1** allocation (the AD-2 splice unit) +
  `writerIndex == command_length`; decode drives **0** allocator allocations (the original frame is a
  zero-copy `retainedSlice`) + retains exactly the one original-frame slice (`refCnt == 1`). Satisfies
  PERF-004's assumption deterministically in-CI.
- **Decision #3 hardening adds — both load-bearing + PROVEN:** (1) **ArchUnit rule**
  `JmhIsolationArchitectureTest` (proxy test): `noClasses().that().resideInAPackage("..jmh..").should()
  .dependOnClassesThat().resideInAPackage("..smpp.companion.proxy..")` — green (benchmarks import only
  `smpp.companion.codec` + netty + jmh). The rule sees the real compiled benchmarks because
  `testImplementation(jmh.output)` + `test { dependsOn("compileJmhJava") }` put `compileJmhJava` (plain
  javac) on the test classpath — nightly-tier preserved (no JMH ASM in `build`). **PROVEN via positive
  control**: a temporary `jmh -> ProxyCompanionApplication` dependency made `JmhIsolationArchitectureTest`
  fail; removing it restored GREEN — so the rule sees the benchmark classes and bites (not vacuous). (2) **Null-safety predicate
  widened** (`smpp.null-safety.gradle.kts`: `name == "compileJava" || name == "compileJmhJava"`) — **PROVEN
  via positive control**: a deliberate `@Nullable`-dereference in the benchmark made `:proxy:compileJmhJava`
  fail with `[NullAway] dereferenced expression … is @Nullable`; removing the probe restored GREEN.
  Benchmark classes are JSpecify-clean under `smpp.companion.*`.
- **Gates (T7):** CODEC-040 unchanged `{io.netty, org.jspecify, org.projectlombok}` (PERF-006 is a codec
  test using only netty/junit/assertj — already on the test classpath; no new main dep); CODEC-039/041 +
  AD-35 green; zero `// FIXME` (AC9); `compileJmhJava` NullAway-clean (ErrorProne+NullAway coexist on the
  jmh sourceSet). `./gradlew clean build :buildSrc:test` GREEN (AC10); `:buildSrc:test --rerun-tasks`
  re-green (the widened predicate passes the GradleTestKit positive control). Codec suite **81** tests (was
  79; +2 PERF-006), 0 fail / 0 skip. **AC8 met by T7**; story stays `in-progress` (T8 finalize pending).
- **T8 complete — Gates green + finalize (AC9, AC10).** Finalize task — **no production code added.** Verified:
  (1) **AC9 gates** — **CODEC-039** (`CodecIsolationArchitectureTest`, inward-only ArchUnit) GREEN and now
    load-bearing (analyzes the real `smpp.companion` classes — `SmppCommandIds`/`SmppFrameDecoder`/`SmppCodec`/…);
    **CODEC-040** (`:codec:enforceDependencyAllowlist`) GREEN — allowlist `{io.netty, org.jspecify,
    org.projectlombok}` (jspecify + lombok are `compileOnly`, so codec RUNTIME stays {io.netty}+JDK);
    **CODEC-041** (`CodecPurityGateTest` — 6 buildSrc positive controls incl. the symmetric
    jspecify-accepted + lombok-accepted halves) GREEN; **AD-35** (NullAway @ ERROR) GREEN on `compileJava`
    AND `compileJmhJava` (the T7-widened predicate) — both compiled clean. **Every new codec MAIN
    sub-package carries its own `@NullMarked package-info.java`** — `bind`/`command`/`framer` + the parent
    `codec/` (JSpecify does not propagate to sub-packages; all four carry `@NullMarked` + the JSpecify
    import — confirmed). **Zero `// FIXME` markers** in `codec`/`proxy`/`buildSrc` source (AC9).
  (2) **AC10** — `./gradlew clean build :buildSrc:test` **BUILD SUCCESSFUL** (11s) on Temurin 25.0.3 +
    `--enable-preview`; `:codec:test` = **81 tests / 0 fail / 0 error / 0 skip** (15 classes);
    `:buildSrc:test` = **17 / 0 / 0 / 0**. No test removed or `@Disabled` to make a gate pass. (JMH is
    nightly-tier — NOT in the `build`/`check` graph — so AC10's `build` does not run the microbench; its
    Gradle-9.6.1/JDK-25 smoke-test proof is recorded under T7.)
  (3) **Spec reconciliation #1 CLOSED.** `bind_transceiver = 0x09` (NOT the catalog's `0x0F` — `0x0F` is the
    `ESME_RINVSYSID` *status* code) was recorded under T1 and is now **independently confirmed in-tree by
    CODEC-031** (T5 jSMPP cross-oracle: `org.jsmpp.bean.CommandId.BIND_TRANSCEIVER` decodes every golden
    vector at `0x09`/`0x80000009`), closing the T1 forward-reference. The upstream planning-doc literal
    (`test-coverage-scenarios.md` CODEC-026/029 still read `0x0F`/`0x8000000F`) remains a deferred
    planning-docs edit (`deferred-work.md`) — not a code artifact. **AC9 + AC10 met; Story 1.2 → `review`.**

- `codec/src/main/java/smpp/companion/codec/command/SmppCommandIds.java` (new; +`INTERFACE_VERSION_3_4` T3)
- `codec/src/main/java/smpp/companion/codec/command/package-info.java` (new)
- `codec/src/test/java/smpp/companion/codec/command/SmppCommandIdsTest.java` (new)
- `codec/src/test/java/smpp/companion/codec/command/MaxCommandLengthContractTest.java` (new)
- `codec/src/main/java/smpp/companion/codec/framer/SmppFrameDecoder.java` (new — T2; **rewritten 2026-07-28 → `LengthFieldBasedFrameDecoder` subclass**; see Dev Agent Record)
- `codec/src/main/java/smpp/companion/codec/framer/package-info.java` (new — T2)
- `codec/src/test/java/smpp/companion/codec/framer/SmppFrameDecoderTest.java` (new — T2; CODEC-001..010,013,014,015)
- `codec/src/test/java/smpp/companion/codec/framer/SmppFrameDecoderTcpTest.java` (new — T2; CODEC-034..036)
- `codec/src/main/java/smpp/companion/codec/bind/package-info.java` (new — T3; @NullMarked)
- `codec/src/main/java/smpp/companion/codec/bind/SmppBindPdu.java` (new — T3; sealed interface + ESME_ROK)
- `codec/src/main/java/smpp/companion/codec/bind/SmppBindRequest.java` (new — T3; record)
- `codec/src/main/java/smpp/companion/codec/bind/SmppBindResponse.java` (new — T3; record + isOk(), AD-25)
- `codec/src/main/java/smpp/companion/codec/bind/CoctetStrings.java` (new — T3; bounded C-octet read/write)
- `codec/src/main/java/smpp/companion/codec/bind/SmppCodec.java` (new — T3; bind-branch decoder)
- `codec/src/main/java/smpp/companion/codec/bind/SmppBindEncoder.java` (new — T3; static encoder, CODEC-032)
- `codec/src/test/java/smpp/companion/codec/bind/SmppCodecTest.java` (new — T3; CODEC-016..023, 028, 037)
- `codec/src/test/java/smpp/companion/codec/bind/SmppBindEncoderTest.java` (new — T3; encode round-trip)
- `codec/src/test/java/smpp/companion/codec/golden/GoldenVectorCorpusTest.java` (rewritten — T4; promoted scaffold → non-empty + per-vector provenance/structure assertions, CODEC-030)
- `codec/src/test/resources/golden-vectors/README.md` (rewritten — T4; populated-corpus status + one-line format spec + vector inventory)
- `codec/src/test/resources/golden-vectors/*.smpp` (new — T4; 6 positive + 5 negative golden vectors, hand-authored from `docs/SMPP_v3_4_Issue1_2.pdf`, each a one-line provenance header)
- `codec/build.gradle.kts` (modified — T5; +`testImplementation("org.jsmpp:jsmpp:3.0.2")`, the CODEC-031 interop-only oracle)
- `codec/src/test/java/smpp/companion/codec/golden/GoldenVectors.java` (new — T5; shared corpus loader; scoped reject-marker parse — closes T4 review patch #1)
- `codec/src/test/java/smpp/companion/codec/golden/GoldenVectorCorpusTest.java` (refactored — T5; consumes `GoldenVectors`; CODEC-030 substance preserved)
- `codec/src/test/java/smpp/companion/codec/golden/BindConformanceTest.java` (new — T5; CODEC-031 jSMPP cross-oracle + CODEC-032 encode byte-identity + CODEC-033 negative biting oracle)
- `codec/build.gradle.kts` (modified — T6; +`testImplementation` Jazzer `0.24.0` + jqwik `1.10.1`, both test-scoped; see the jqwik `@Property` annotation gotcha in the Dev Record)
- `codec/src/test/java/smpp/companion/codec/framer/SmppFrameDecoderFuzzTest.java` (new — T6; CODEC-011 Jazzer framer fuzz: arbitrary stream, no-throw + bounded-memory + controlled-close)
- `codec/src/test/java/smpp/companion/codec/framer/SmppFrameDecoderPropertyTest.java` (new — T6; CODEC-012 jqwik chunk-invariance property; annotation-free `@Property`)
- `codec/src/test/java/smpp/companion/codec/bind/SmppCodecFuzzTest.java` (new — T6; CODEC-025 Jazzer bind-parser fuzz: arbitrary body, no-throw + no-over-read)
- `codec/src/test/java/smpp/companion/codec/bind/SmppCodecForwardingPropertyTest.java` (new — T6; CODEC-037 jqwik byte-exact bind forwarding; `@Tag("unit")` class-level — method `@Tag` breaks jqwik)
- `codec/src/test/java/smpp/companion/codec/bind/SmppCodecOpaquePropertyTest.java` (new — T6; CODEC-038 jqwik opaque byte-identity; `@Tag("fuzz")` class-level)
- `proxy/build.gradle.kts` (modified — T7; +`me.champeau.jmh` `0.7.3` plugin + `jmh {}` block (`jmhVersion` 1.37, `includeTests=false`) + `testImplementation(jmh.output)` + `test { dependsOn("compileJmhJava") }` for the ArchUnit classpath — PERF-001..003/005, AC8)
- `buildSrc/src/main/kotlin/smpp.null-safety.gradle.kts` (modified — T7; `mainCompile` widened to `|| name == "compileJmhJava"` — decision #3 hardening add #2; proven via NullAway positive control)
- `proxy/src/jmh/java/smpp/companion/jmh/package-info.java` (new — T7; `@NullMarked` for the benchmark package)
- `proxy/src/jmh/java/smpp/companion/jmh/CodecMicrobenchmarks.java` (new — T7; PERF-001/002/003 JMH benches — bind encode/decode + submit_sm framing; nightly-tier)
- `proxy/src/test/java/smpp/companion/proxy/JmhIsolationArchitectureTest.java` (new — T7; ArchUnit `..jmh..`→`..proxy..` isolation rule — decision #3 hardening add #1)
- `codec/src/test/java/smpp/companion/codec/perf/CodecAllocationGuardTest.java` (new — T7; PERF-006 unit allocation guard — counting allocator: encode=1 buffer, decode=0 scratch)
