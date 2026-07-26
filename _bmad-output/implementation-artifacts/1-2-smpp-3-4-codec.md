# Story 1.2: SMPP 3.4 Codec

Status: ready-for-dev

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
  `bind_*_resp` (e.g. `ESME_RINVPASWD 0x0000000E`) decodes cleanly without raising. Maps: CODEC-018, CODEC-019.
- C-octet-string edge cases (empty / max-length / all-empty); unterminated C-octet-string → no
  over-read / no spin; truncated body → no AIOOBE / no negative-size; header decodes even with junk body. Maps: CODEC-020..023.
- **Password exposed as `char[]`/`byte[]`, never `String`** (zeroization seam; CODEC-024, PRIV-1).
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
  deferred `StringCaseLocaleUsage` fix** at `GoldenVectorCorpusTest.java:67`
  (`.toLowerCase()` → `.toLowerCase(Locale.ROOT)`; add `import java.util.Locale;`) and clear that
  entry in `deferred-work.md`.

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
- CODEC-040 allowlist `{io.netty, org.jspecify}` stays green on both compile AND runtime classpath;
  jspecify stays `compileOnly`. CODEC-041 positive control unchanged.
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

- [ ] **T1 — Command-id source-of-truth** (AC3, AC4)
  - [ ] `smpp.companion.codec.command.SmppCommandIds` with `BIND_FAMILY` = the correct 6-id set
        (spec reconciliation #1) + `MAX_COMMAND_LENGTH = 65536` (AD-30) + response-bit helpers.
  - [ ] `package-info.java` (`@NullMarked`) for the new sub-package.
  - [ ] Unit tests: CODEC-026/027/028/029.
  - [ ] RELAY-026 stub test (AC4); log remainder to `deferred-work.md`.
- [ ] **T2 — `SmppFrameDecoder`** (AC1)
  - [ ] `smpp.companion.codec.framer.SmppFrameDecoder extends ByteToMessageDecoder` (NOT
        `LengthFieldBasedFrameDecoder`). Read `command_length` via `in.getInt(in.readerIndex())`;
        honor the ByteToMessageDecoder contract (check `readableBytes()`, return without moving
        reader index when incomplete).
  - [ ] AD-30 reject policy: `<16` drop+close; `>65536` drop+close; overflow-class
        (`0x7FFFFFFF`/`0x80000000`/`0xFFFFFFFF`) reject **before** any allocation.
  - [ ] `package-info.java` (`@NullMarked`).
  - [ ] Unit tests CODEC-001..015 (use Netty `EmbeddedChannel`); real-TCP tests CODEC-034..036.
- [ ] **T3 — `SmppCodec` bind parser + PDU model + encoder** (AC2, AC6)
  - [ ] `smpp.companion.codec.bind` package: typed bind PDU model (header + `system_id`, `password`
        as `char[]`/`byte[]`, `system_type`, `interface_version`), `SmppCodec` (bind branch:
        `MessageToMessageDecoder`/`ByteToMessageDecoder` over a framed `ByteBuf`), `ESME_ROK`
        predicate, non-mutating slice read, and a bind-family **encoder** (for CODEC-032).
  - [ ] `package-info.java` (`@NullMarked`).
  - [ ] Unit tests CODEC-016..023, CODEC-037.
- [ ] **T4 — Golden-vector corpus** (AC5)
  - [ ] Author `.bin`/`.smpp` bind-family + negative vectors with provenance headers in
        `codec/src/test/resources/golden-vectors/`.
  - [ ] Promote the deferred non-empty assertion; fold in the `Locale.ROOT` fix; clear `deferred-work.md`.
- [ ] **T5 — jSMPP cross-oracle conformance** (AC6)
  - [ ] `testImplementation("org.jsmpp:jsmpp:3.0.2")` on `codec`; CODEC-031 + CODEC-032 tests.
- [ ] **T6 — Fuzz + properties** (AC7)
  - [ ] Add fuzz lib (default Jazzer `com.code-intelligence:jazzer-junit`) + jqwik as
        `testImplementation` on `codec`; CODEC-011, CODEC-025, CODEC-012/037/038.
- [ ] **T7 — JMH microbench** (AC8)
  - [ ] Apply `me.champeau.jmh` (`0.7.3`) in `proxy/build.gradle.kts`; sources at
        `proxy/src/jmh/java/...`; PERF-001..006.
  - [ ] Widen the null-safety predicate to `name == "compileJava" || name == "compileJmhJava"`
        (`buildSrc/.../smpp.null-safety.gradle.kts:37`) — decision #3 hardening add #2; keep
        benchmark classes JSpecify-clean under `smpp.companion.*`.
  - [ ] Add a one-line ArchUnit rule: classes in `..jmh..` may NOT depend on
        `..smpp.companion.proxy..` — decision #3 hardening add #1.
  - [ ] Smoke-test `./gradlew jmh` on Gradle 9.6.1 / JDK 25 (JMH .37 ASM risk); nightly-tier.
- [ ] **T8 — Gates green + finalize** (AC9, AC10)
  - [ ] Confirm CODEC-039/040/041 + AD-35 green; add `@NullMarked package-info.java` to every new
        sub-package; full `./gradlew clean build :buildSrc:test` green.
  - [ ] Record the spec-error correction (reconciliation #1) in the Dev Agent Record.

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

- **Netty 4.2 framing** — `LengthFieldBasedFrameDecoder` treats the length field as *bytes-following*
  by default; SMPP's `command_length` *includes* the field, so don't reach for it. A custom
  `ByteToMessageDecoder` is correct (per decision + CODEC-009/003). Discipline: check `readableBytes()`
  before reading; return **without modifying the reader index** if a frame is incomplete; read the
  length via `in.getInt(in.readerIndex())` — never `getInt(0)`.
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

_(to be filled by dev agent)_

### Debug Log References

### Completion Notes List

### File List
